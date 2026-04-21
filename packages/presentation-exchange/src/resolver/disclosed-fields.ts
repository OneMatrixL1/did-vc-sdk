import type { VPRequest, DocumentRequestNode, DocumentRequest } from '../types/request.js';
import type { VerifiablePresentation } from '../types/response.js';
import type {
  PresentedCredential,
  CredentialProof,
  ZKPProof,
  MerkleDisclosure,
  DGDisclosure,
} from '../types/credential.js';
import type {
  DisclosedField,
  DisclosedDocument,
  DisclosedFieldsResult,
  FieldResult,
  PredicateResult,
} from '../types/disclosed.js';
import { extractConditions } from './field-extractor.js';

// ---------------------------------------------------------------------------
// Chain circuit IDs (not user-facing conditions)
// ---------------------------------------------------------------------------

const CHAIN_CIRCUITS = new Set([
  'sod-validate',
  'dg-bridge',
  'dg13-merklelize',
  'did-delegate',
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Extract disclosed fields from a verified VP response.
 *
 * Maps each request condition to its matching response proof by `conditionID`,
 * producing a flat list of machine-readable `DisclosedField` entries.
 *
 * SECURITY: The `verified` parameter is a mandatory gate. Pass `true` only
 * after `verifyVPResponse()` returns `verified: true`. This prevents
 * accidental extraction from unverified presentations.
 *
 * ```ts
 * const result = verifyVPResponse(request, vp, opts);
 * if (!result.verified) throw new Error('VP failed verification');
 * const fields = extractDisclosedFields(request, vp, true);
 * fields.field('fullName')    // { method: 'merkle', value: 'TRAN GIANG LONG', ... }
 * ```
 */
export function extractDisclosedFields(
  request: VPRequest,
  presentation: VerifiablePresentation,
  verified: true,
): DisclosedFieldsResult {
  const docRequests = collectDocumentRequests(request.rules);
  const documents: DisclosedDocument[] = [];

  for (const entry of presentation.presentationSubmission) {
    const docReq = docRequests.get(entry.docRequestID);
    if (!docReq) continue;

    const cred = presentation.verifiableCredential[entry.credentialIndex];
    if (!cred) continue;

    documents.push(buildDisclosedDocument(docReq, cred));
  }

  return {
    documents,
    field(fieldId: string): FieldResult | undefined {
      for (const doc of documents) {
        const f = doc.getField(fieldId);
        if (f) return f;
      }
      return undefined;
    },
  };
}

// ---------------------------------------------------------------------------
// Build a DisclosedDocument from a DocumentRequest + PresentedCredential
// ---------------------------------------------------------------------------

function buildDisclosedDocument(
  docReq: DocumentRequest,
  cred: PresentedCredential,
): DisclosedDocument {
  const proofs = flattenProofs(cred);
  const { disclose: discloseConds, zkp: zkpConds } = extractConditions(docReq.conditions);

  // Index proofs by conditionID for O(1) lookup
  const merkleByCondition = new Map<string, MerkleDisclosure>();
  const dgByCondition = new Map<string, DGDisclosure>();
  const zkpByCondition = new Map<string, ZKPProof>();

  for (const p of proofs) {
    switch (p.type) {
      case 'MerkleDisclosure':
        merkleByCondition.set(p.conditionID, p);
        break;
      case 'DGDisclosure':
        dgByCondition.set(p.conditionID, p);
        break;
      case 'ZKPProof':
        if (!CHAIN_CIRCUITS.has(p.circuitId)) {
          zkpByCondition.set(p.conditionID, p);
        }
        break;
    }
  }

  const fields: DisclosedField[] = [];

  // Match disclose conditions → MerkleDisclosure or DGDisclosure
  for (const cond of discloseConds) {
    const fieldId = stripJsonPathPrefix(cond.field);

    const merkle = merkleByCondition.get(cond.conditionID);
    if (merkle) {
      fields.push({
        conditionID: cond.conditionID,
        fieldId: merkle.fieldId || fieldId,
        method: 'merkle',
        value: merkle.value,
        predicate: null,
      });
      continue;
    }

    const dg = dgByCondition.get(cond.conditionID);
    if (dg) {
      fields.push({
        conditionID: cond.conditionID,
        fieldId: dg.fieldId || fieldId,
        method: 'dg',
        value: dg.data,
        predicate: null,
      });
      continue;
    }
  }

  // Match ZKP conditions → ZKPProof (predicates)
  for (const cond of zkpConds) {
    const proof = zkpByCondition.get(cond.conditionID);
    if (!proof) continue;

    // Derive fieldId from privateInputs (first value is the field reference)
    const privateValues = Object.values(cond.privateInputs);
    const fieldId = privateValues[0] ?? cond.conditionID;

    const predicate: PredicateResult = {
      circuitId: proof.circuitId,
      publicInputs: proof.publicInputs,
      publicOutputs: proof.publicOutputs,
    };

    fields.push({
      conditionID: cond.conditionID,
      fieldId,
      method: 'predicate',
      value: null,
      predicate,
    });
  }

  // Extract holderDID from did-delegate proof
  const didDelegate = proofs.find(
    (p): p is ZKPProof => p.type === 'ZKPProof' && p.circuitId === 'did-delegate',
  );
  const holderDID = didDelegate
    ? String(didDelegate.publicInputs['did'] ?? '')
    : null;

  // Chain integrity: the core 3-proof chain (sod-validate → dg-bridge →
  // dg13-merklelize) is always required. did-delegate is only required when
  // the document request opted into holder-binding via requireHolderBinding.
  const chainCircuitIds = proofs
    .filter((p): p is ZKPProof => p.type === 'ZKPProof')
    .map(p => p.circuitId);
  const coreChainOk =
    chainCircuitIds.includes('sod-validate') &&
    chainCircuitIds.includes('dg-bridge') &&
    chainCircuitIds.includes('dg13-merklelize');
  const holderBindingOk =
    !docReq.requireHolderBinding || chainCircuitIds.includes('did-delegate');
  const chainVerified = coreChainOk && holderBindingOk;

  // Build field index for getField()
  const fieldIndex = new Map<string, DisclosedField>();
  for (const f of fields) {
    if (!fieldIndex.has(f.fieldId)) {
      fieldIndex.set(f.fieldId, f);
    }
  }

  return {
    docRequestID: docReq.docRequestID,
    schemaType: docReq.schemaType ?? '',
    fields,
    holderDID,
    chainVerified,
    getField(fieldId: string): FieldResult | undefined {
      return fieldIndex.get(fieldId);
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function flattenProofs(cred: PresentedCredential): CredentialProof[] {
  if (!cred.proof) return [];
  return Array.isArray(cred.proof) ? cred.proof : [cred.proof];
}

function collectDocumentRequests(
  node: DocumentRequestNode,
): Map<string, DocumentRequest> {
  const map = new Map<string, DocumentRequest>();
  (function walk(n: DocumentRequestNode): void {
    if (n.type === 'Logical') {
      for (const child of n.values) walk(child);
    } else {
      map.set(n.docRequestID, n);
    }
  })(node);
  return map;
}

function stripJsonPathPrefix(field: string): string {
  const prefix = '$.credentialSubject.';
  if (field.startsWith(prefix)) return field.slice(prefix.length);
  const lastDot = field.lastIndexOf('.');
  return lastDot >= 0 ? field.slice(lastDot + 1) : field;
}
