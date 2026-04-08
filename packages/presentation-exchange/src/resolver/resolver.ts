import type { MatchableCredential } from '../types/credential.js';
import type { VPRequest, DocumentRequest, DocumentRequestNode, KeyDoc } from '../types/request.js';
import type {
  VerifiablePresentation,
  PresentedCredential,
  HolderProof,
  SubmissionEntry,
} from '../types/response.js';
import type { CredentialSelection } from '../types/matching.js';
import type { SchemaProofSystem, ProofSystemMap } from '../types/proof-system.js';
import type { ZKPProvider } from '../types/zkp-provider.js';
import { defaultProofSystems } from '../proof-system/index.js';
import { extractConditions } from './field-extractor.js';
import { signVPResponse, vpResponseContext } from '../signer/vp-signer.js';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface UnsignedPresentation {
  '@context': (string | Record<string, unknown>)[];
  type: ['VerifiablePresentation'];
  holder: string;
  verifier: string;
  requestId: string;
  requestNonce: string;
  verifierCredentials?: PresentedCredential[];
  verifiableCredential: PresentedCredential[];
  presentationSubmission: SubmissionEntry[];
}

export interface ResolveOptions {
  /** The holder's DID. */
  holder: string;
  /** Custom signing callback (challenge = nonce, domain = verifierUrl). */
  signPresentation?: (payload: UnsignedPresentation) => Promise<HolderProof>;
  /** A KeyDoc for automatic signing via credential-sdk. */
  keyDoc?: KeyDoc;
  /** Optional DID resolver forwarded to credential-sdk when using `keyDoc`. */
  didResolver?: object;
  /** Extra or overriding proof systems. */
  proofSystems?: ProofSystemMap;
  /** ZKP provider for generating proofs. */
  zkpProvider?: ZKPProvider;
  /** Callback to provide schema-specific credential data (e.g. ICAO raw bytes). */
  credentialData?: (docRequestID: string, schemaType: string) => unknown;
}

// ---------------------------------------------------------------------------
// resolvePresentation
// ---------------------------------------------------------------------------

export async function resolvePresentation(
  request: VPRequest,
  credentials: MatchableCredential[],
  selections: CredentialSelection[],
  options: ResolveOptions,
): Promise<VerifiablePresentation> {
  const docRequests = collectDocumentRequests(request.rules);
  const systems = { ...defaultProofSystems, ...options.proofSystems };

  type ResolvedItem = { docRequestID: string; docReq: DocumentRequest; cred: MatchableCredential };
  const items: ResolvedItem[] = [];

  for (const sel of selections) {
    const docReq = docRequests.get(sel.docRequestID);
    if (!docReq) throw new Error(`Unknown docRequestID: ${sel.docRequestID}`);
    const cred = credentials[sel.credentialIndex];
    if (!cred) throw new Error(`Invalid credential index ${sel.credentialIndex} for docRequestID ${sel.docRequestID}`);
    items.push({ docRequestID: sel.docRequestID, docReq, cred });
  }

  const presentedList = await Promise.all(items.map(({ docRequestID, docReq, cred }) => {
    if (docReq.disclosureMode === 'full') {
      return Promise.resolve(cred);
    }

    const system = systems[docReq.schemaType];
    if (!system) {
      throw new Error(
        `No SchemaProofSystem registered for schemaType "${docReq.schemaType}". ` +
        `Available: [${Object.keys(systems).join(', ')}]`,
      );
    }

    const { disclose, predicates } = extractConditions(docReq.conditions);

    if (!options.zkpProvider && predicates.length > 0) {
      throw new Error(`ZKPProvider required for predicate conditions in "${docRequestID}"`);
    }

    return system.prove(cred, { disclose, predicates }, {
      nonce: request.nonce,
      holder: options.holder,
      verifierId: request.verifier,
      zkpProvider: options.zkpProvider!,
      credentialData: options.credentialData?.(docRequestID, docReq.schemaType),
    });
  }));

  const presentedCredentials: PresentedCredential[] = [];
  const submission: SubmissionEntry[] = [];

  for (let i = 0; i < items.length; i++) {
    presentedCredentials.push(presentedList[i]!);
    submission.push({ docRequestID: items[i]!.docRequestID, credentialIndex: i });
  }

  const unsigned: UnsignedPresentation = {
    '@context': ['https://www.w3.org/2018/credentials/v1', vpResponseContext],
    type: ['VerifiablePresentation'],
    holder: options.holder,
    verifier: request.verifier,
    requestId: request.id,
    requestNonce: request.nonce,
    ...(request.verifierCredentials?.length ? { verifierCredentials: request.verifierCredentials } : {}),
    verifiableCredential: presentedCredentials,
    presentationSubmission: submission,
  };

  if (options.signPresentation) {
    const proof = await options.signPresentation(unsigned);
    return { ...unsigned, proof };
  }

  if (options.keyDoc) {
    const { keyDoc, didResolver } = options;
    return await signVPResponse(unsigned, keyDoc, request.nonce, request.verifierUrl, didResolver);
  }

  throw new Error('ResolveOptions requires either "signPresentation" or "keyDoc"');
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
