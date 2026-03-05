import type { MatchableCredential } from '../types/credential.js';
import type { VPRequest, DocumentRequest, DocumentRequestNode } from '../types/request.js';
import type {
  VerifiablePresentation,
  PresentedCredential,
  HolderProof,
  SubmissionEntry,
} from '../types/response.js';
import type { CredentialSelection } from '../types/matching.js';
import type { SchemaResolverMap } from '../types/schema-resolver.js';
import { defaultResolvers } from '../resolvers/index.js';
import { extractConditions } from './field-extractor.js';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface UnsignedPresentation {
  '@context': string[];
  type: ['VerifiablePresentation'];
  holder: string;
  verifiableCredential: PresentedCredential[];
  presentationSubmission: SubmissionEntry[];
}

export interface ResolveOptions {
  /** The holder's DID */
  holder: string;
  /**
   * Optional — extra or overriding resolvers merged on top of
   * the built-in defaults (JsonSchema + ICAO9303SOD).
   */
  resolvers?: SchemaResolverMap;
  /** Sign the presentation envelope (challenge = nonce, domain = verifier.url) */
  signPresentation: (payload: UnsignedPresentation) => Promise<HolderProof>;
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
 * 3. Derives selective-disclosure credentials via the schema resolver
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

  // Validate all selections synchronously first, then derive credentials in parallel
  type ResolvedItem = { docRequestID: string; docReq: DocumentRequest; cred: MatchableCredential };
  const items: ResolvedItem[] = [];

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

    items.push({ docRequestID: sel.docRequestID, docReq, cred });
  }

  const resolvers = { ...defaultResolvers, ...options.resolvers };

  const presentedList = await Promise.all(items.map(({ docReq, cred }) => {
    if (docReq.disclosureMode === 'full') {
      return Promise.resolve(credentialToFull(cred));
    }

    const resolver = resolvers[docReq.schemaType];
    if (!resolver) {
      throw new Error(
        `No SchemaResolver registered for schemaType "${docReq.schemaType}". ` +
        `Available resolvers: [${Object.keys(resolvers).join(', ')}]`,
      );
    }

    const { disclose } = extractConditions(docReq.conditions);
    const disclosedFields = disclose.map((d) => d.field);
    return resolver.deriveCredential(cred, disclosedFields);
  }));

  const presentedCredentials: PresentedCredential[] = [];
  const submission: SubmissionEntry[] = [];

  for (let i = 0; i < items.length; i++) {
    presentedCredentials.push(presentedList[i]!);
    submission.push({ docRequestID: items[i]!.docRequestID, credentialIndex: i });
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
