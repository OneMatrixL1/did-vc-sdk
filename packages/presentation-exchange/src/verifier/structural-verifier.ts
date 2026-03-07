import type { VPRequest, DocumentRequestNode, DocumentRequest } from '../types/request.js';
import type { VerifiablePresentation, SubmissionEntry } from '../types/response.js';

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface VerificationResult {
  valid: boolean;
  errors: string[];
}

// ---------------------------------------------------------------------------
// verifyPresentationStructure
// ---------------------------------------------------------------------------

/**
 * Structurally validate a VerifiablePresentation against the original VPRequest.
 *
 * Checks:
 * - VP type is correct
 * - Nonce matches (proof.challenge === request.nonce)
 * - Domain matches (proof.domain === request.verifierUrl)
 * - Every required DocumentRequest is covered by a submission entry
 * - Submission credential indices are valid
 * - Credential types match the document request docTypes
 *
 * Does NOT verify cryptographic proofs (that's the caller's job).
 */
export function verifyPresentationStructure(
  request: VPRequest,
  presentation: VerifiablePresentation,
): VerificationResult {
  const errors: string[] = [];
  validateTypeAndProof(request, presentation, errors);
  validateSubmissions(request, presentation, errors);
  return { valid: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function validateTypeAndProof(
  request: VPRequest,
  presentation: VerifiablePresentation,
  errors: string[],
): void {
  if (
    !presentation.type
    || !presentation.type.includes('VerifiablePresentation')
  ) {
    errors.push('VP must have type "VerifiablePresentation"');
  }

  if (!presentation.proof) {
    errors.push('VP is missing proof');
    return;
  }

  if (presentation.proof.challenge !== request.nonce) {
    errors.push(
      `Nonce mismatch: expected "${request.nonce}", got "${presentation.proof.challenge}"`,
    );
  }

  const expectedDomain = extractDomain(request.verifierUrl);
  if (presentation.proof.domain !== expectedDomain && presentation.proof.domain !== request.verifierUrl) {
    errors.push(
      `Domain mismatch: expected "${expectedDomain}" or "${request.verifierUrl}", got "${presentation.proof.domain}"`,
    );
  }

  if (presentation.proof.proofPurpose !== 'authentication') {
    errors.push(
      `Proof purpose must be "authentication", got "${presentation.proof.proofPurpose}"`,
    );
  }

  if (presentation.requestId !== request.id) {
    errors.push(`Request ID mismatch: expected "${request.id}", got "${presentation.requestId}"`);
  }
  if (presentation.requestNonce !== request.nonce) {
    errors.push(`Request nonce mismatch: expected "${request.nonce}", got "${presentation.requestNonce}"`);
  }
  if (presentation.verifier !== request.verifier) {
    errors.push(`Verifier mismatch: expected "${request.verifier}", got "${presentation.verifier}"`);
  }
}

function validateSubmissions(
  request: VPRequest,
  presentation: VerifiablePresentation,
  errors: string[],
): void {
  const requiredIDs = collectRequiredDocRequestIDs(request.rules);
  const submissionMap = new Map(
    presentation.presentationSubmission.map((s) => [s.docRequestID, s]),
  );

  for (const reqID of requiredIDs) {
    if (!submissionMap.has(reqID)) {
      errors.push(`Missing submission for required docRequestID "${reqID}"`);
    }
  }

  const docRequests = collectAllDocumentRequests(request.rules);

  for (const entry of presentation.presentationSubmission) {
    validateSubmissionEntry(entry, presentation, docRequests, errors);
  }
}

function validateSubmissionEntry(
  entry: SubmissionEntry,
  presentation: VerifiablePresentation,
  docRequests: Map<string, DocumentRequest>,
  errors: string[],
): void {
  if (
    entry.credentialIndex < 0
    || entry.credentialIndex >= presentation.verifiableCredential.length
  ) {
    errors.push(
      `Submission "${entry.docRequestID}" has invalid credentialIndex ${entry.credentialIndex}`,
    );
    return;
  }

  const docReq = docRequests.get(entry.docRequestID);
  if (!docReq) {
    errors.push(`Submission references unknown docRequestID "${entry.docRequestID}"`);
    return;
  }

  const cred = presentation.verifiableCredential[entry.credentialIndex]!;
  const credTypes = cred.type ?? [];
  if (!docReq.docType.some((dt) => credTypes.includes(dt))) {
    errors.push(
      `Credential at index ${entry.credentialIndex} has types [${credTypes.join(', ')}] but docRequestID "${entry.docRequestID}" requires one of [${docReq.docType.join(', ')}]`,
    );
  }
}

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

/**
 * Collect all DocumentRequest IDs that MUST be satisfied.
 * For AND nodes: all children are required.
 * For OR nodes: at least one is required (so we don't mark any as strictly required).
 */
function collectRequiredDocRequestIDs(node: DocumentRequestNode): Set<string> {
  const ids = new Set<string>();
  collectRequired(node, ids, true);
  return ids;
}

function collectRequired(
  node: DocumentRequestNode,
  ids: Set<string>,
  isRequired: boolean,
): void {
  if (node.type === 'DocumentRequest') {
    if (isRequired) {
      ids.add(node.docRequestID);
    }
    return;
  }

  // Logical node
  for (const child of node.values) {
    // AND children are required if parent is required
    // OR children are not individually required
    collectRequired(child, ids, isRequired && node.operator === 'AND');
  }
}

function collectAllDocumentRequests(
  node: DocumentRequestNode,
): Map<string, DocumentRequest> {
  const map = new Map<string, DocumentRequest>();
  function walk(n: DocumentRequestNode): void {
    if (n.type === 'Logical') {
      for (const child of n.values) walk(child);
    } else {
      map.set(n.docRequestID, n);
    }
  }
  walk(node);
  return map;
}
