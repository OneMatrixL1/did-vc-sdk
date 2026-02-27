import type { MatchableCredential } from '../types/credential.js';
import type { VPRequest, DocumentRequest, DocumentRequestNode } from '../types/request.js';
import type {
  VerifiablePresentation,
  PresentedCredential,
  HolderProof,
  SubmissionEntry,
} from '../types/response.js';
import type { CredentialSelection } from '../types/matching.js';
import { extractConditions } from './field-extractor.js';
import { resolveJsonPath } from '../utils/jsonpath.js';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface ResolveOptions {
  /** The holder's DID */
  holder: string;
  /** Sign the presentation envelope (challenge = nonce, domain = verifier.url) */
  signPresentation: (payload: UnsignedPresentation) => Promise<HolderProof>;
  /**
   * Optional: derive a selective-disclosure credential (BBS+ or similar).
   * If not provided, the full credential is included as-is.
   */
  deriveCredential?: (
    credential: MatchableCredential,
    disclosedFields: string[],
  ) => Promise<PresentedCredential>;
}

export interface UnsignedPresentation {
  '@context': string[];
  type: ['VerifiablePresentation'];
  holder: string;
  verifiableCredential: PresentedCredential[];
  presentationSubmission: SubmissionEntry[];
}

// ---------------------------------------------------------------------------
// resolvePresentation
// ---------------------------------------------------------------------------

/**
 * Assemble a VerifiablePresentation from a VPRequest and user selections.
 *
 * This function:
 * 1. Validates that selections cover the request's rules
 * 2. Extracts disclosed fields per credential
 * 3. Optionally derives selective-disclosure credentials
 * 4. Signs the presentation via the provided callback
 */
export async function resolvePresentation(
  request: VPRequest,
  credentials: MatchableCredential[],
  selections: CredentialSelection[],
  options: ResolveOptions,
): Promise<VerifiablePresentation> {
  // Build a map of docRequestID → DocumentRequest for lookup
  const docRequests = collectDocumentRequests(request.rules);

  // Build presented credentials and submission entries
  const presentedCredentials: PresentedCredential[] = [];
  const submission: SubmissionEntry[] = [];

  for (const sel of selections) {
    const docReq = docRequests.get(sel.docRequestID);
    if (!docReq) {
      throw new Error(`Unknown docRequestID: ${sel.docRequestID}`);
    }

    const cred = credentials[sel.credentialIndex];
    if (!cred) {
      throw new Error(
        `Invalid credential index ${sel.credentialIndex} for docRequestID ${sel.docRequestID}`,
      );
    }

    let presented: PresentedCredential;
    if (docReq.disclosureMode === 'full') {
      // Pass the entire credential verbatim — no field filtering, no derivation
      presented = credentialToFull(cred);
    } else if (options.deriveCredential) {
      const { disclose } = extractConditions(docReq.conditions);
      const disclosedFields = disclose.map((d) => d.field);
      presented = await options.deriveCredential(cred, disclosedFields);
    } else {
      const { disclose } = extractConditions(docReq.conditions);
      const disclosedFields = disclose.map((d) => d.field);
      presented = credentialToSelective(cred, disclosedFields);
    }

    const credIndex = presentedCredentials.length;
    presentedCredentials.push(presented);
    submission.push({
      docRequestID: sel.docRequestID,
      credentialIndex: credIndex,
    });
  }

  const unsigned: UnsignedPresentation = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    holder: options.holder,
    verifiableCredential: presentedCredentials,
    presentationSubmission: submission,
  };

  const proof = await options.signPresentation(unsigned);

  return { ...unsigned, proof };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function collectDocumentRequests(
  node: DocumentRequestNode,
): Map<string, DocumentRequest> {
  const map = new Map<string, DocumentRequest>();

  function walk(n: DocumentRequestNode): void {
    if (n.type === 'Logical') {
      for (const child of n.values) {
        walk(child);
      }
    } else {
      map.set(n.docRequestID, n);
    }
  }

  walk(node);
  return map;
}

/**
 * Pass the credential through verbatim — all fields, original proof intact.
 * Used for disclosureMode === 'full'.
 */
function credentialToFull(cred: MatchableCredential): PresentedCredential {
  const subject = Array.isArray(cred.credentialSubject)
    ? { ...cred.credentialSubject[0] }
    : { ...cred.credentialSubject };

  const types = [...(cred.type as readonly string[])];
  const issuer = typeof cred.issuer === 'string'
    ? cred.issuer
    : { ...cred.issuer };

  const presented: PresentedCredential = {
    type: types,
    issuer,
    credentialSubject: subject,
  };

  if (cred['@context']) {
    presented['@context'] = [...(cred['@context'] as string[])];
  }
  if (cred.issuanceDate !== undefined) {
    presented.issuanceDate = cred.issuanceDate as string;
  }
  if (cred.id !== undefined) {
    presented.id = cred.id as string;
  }
  if (cred.proof !== undefined) {
    (presented as Record<string, unknown>).proof = cred.proof;
  }

  return presented;
}

/**
 * Build a selectively-disclosed credential containing only the requested fields.
 * Used for disclosureMode === 'selective' (default).
 */
function credentialToSelective(
  cred: MatchableCredential,
  disclosedFields: string[],
): PresentedCredential {
  const subject = Array.isArray(cred.credentialSubject)
    ? cred.credentialSubject[0]
    : cred.credentialSubject;

  const selectiveSubject: Record<string, unknown> = {};
  if (subject.id !== undefined) {
    selectiveSubject.id = subject.id;
  }

  for (const fieldPath of disclosedFields) {
    const { found, value } = resolveJsonPath(
      { ...cred, credentialSubject: subject },
      fieldPath,
    );
    if (found && fieldPath.startsWith('$.credentialSubject.')) {
      const parts = fieldPath.split('.');
      const lastSeg = parts[parts.length - 1]!;
      selectiveSubject[lastSeg] = value;
    }
  }

  const types = [...(cred.type as readonly string[])];
  const issuer = typeof cred.issuer === 'string'
    ? cred.issuer
    : { ...cred.issuer };

  const presented: PresentedCredential = {
    type: types,
    issuer,
    credentialSubject: selectiveSubject,
  };

  if (cred['@context']) {
    presented['@context'] = [...(cred['@context'] as string[])];
  }
  if (cred.issuanceDate !== undefined) {
    presented.issuanceDate = cred.issuanceDate as string;
  }
  if (cred.id !== undefined) {
    presented.id = cred.id as string;
  }
  if (cred.proof !== undefined) {
    (presented as Record<string, unknown>).proof = cred.proof;
  }

  return presented;
}
