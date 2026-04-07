import type { MatchableCredential } from '../types/credential.js';
import type { VPRequest, DocumentRequest, DocumentRequestNode, KeyDoc } from '../types/request.js';
import type {
  VerifiablePresentation,
  PresentedCredential,
  HolderProof,
  SubmissionEntry,
} from '../types/response.js';
import type { CredentialSelection } from '../types/matching.js';
import type { SchemaResolverMap } from '../types/schema-resolver.js';
import type { MerkleWitnessData } from '../types/merkle.js';
import type { ZKPProvider } from '../types/zkp-provider.js';
import { defaultResolvers } from '../resolvers/index.js';
import { createBBSResolver, isBBSProof } from '../resolvers/bbs-resolver.js';
import { isZKPResolver } from '../resolvers/zkp-icao-schema-resolver.js';
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

/**
 * Options for {@link resolvePresentation}.
 *
 * Provide **one** of `keyDoc` or `signPresentation` to sign the VP envelope:
 *
 * @example
 * // Recommended — automatic signing via createKeyDoc
 * { holder: did, keyDoc: createKeyDoc(did, keypair, 'secp256k1') }
 *
 * // Custom signing callback
 * { holder: did, signPresentation: async (unsigned) => { ... } }
 */
export interface ResolveOptions {
  /** The holder's DID. */
  holder: string;
  /**
   * Optional — extra or overriding resolvers merged on top of
   * the built-in defaults (JsonSchema + ICAO9303SOD).
   */
  resolvers?: SchemaResolverMap;
  /** Custom signing callback (challenge = nonce, domain = verifierUrl). */
  signPresentation?: (payload: UnsignedPresentation) => Promise<HolderProof>;
  /**
   * Alternative to `signPresentation` — a {@link KeyDoc} for automatic signing
   * via credential-sdk. Use {@link createKeyDoc} to create one.
   */
  keyDoc?: KeyDoc;
  /** Optional DID resolver forwarded to credential-sdk when using `keyDoc`. */
  didResolver?: object;
  /** Callback to provide pre-computed Merkle witness data for a docRequestID. */
  merkleWitness?: (docRequestID: string) => MerkleWitnessData | undefined;
  /** ZKP provider for generating proofs (predicates, trust chain). */
  zkpProvider?: ZKPProvider;
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

  const presentedList = await Promise.all(items.map(({ docRequestID, docReq, cred }) => {
    if (docReq.disclosureMode === 'full') {
      return Promise.resolve(cred);
    }

    let resolver = resolvers[docReq.schemaType];
    if (!resolver) {
      throw new Error(
        `No SchemaResolver registered for schemaType "${docReq.schemaType}". ` +
        `Available resolvers: [${Object.keys(resolvers).join(', ')}]`,
      );
    }

    const { disclose, zkp } = extractConditions(docReq.conditions);

    // ZKP mode is required when there are Merkle disclosure conditions or zkp-only mode.
    // Plain ZKP predicate conditions do not require the ZKP resolver for field derivation.
    const isZKPMode = docReq.disclosureMode === 'zkp-only'
      || disclose.some((d) => d.merkleDisclosure);

    if (isZKPMode && !isZKPResolver(resolver)) {
      throw new Error(
        `docRequestID "${docRequestID}" requires ZKP/Merkle but resolver "${docReq.schemaType}" is not ZKP-capable`,
      );
    }

    if (isZKPMode && isZKPResolver(resolver)) {
      const merkleWitness = options.merkleWitness?.(docRequestID);

      if (!merkleWitness) {
        throw new Error(
          `ZKP/Merkle conditions require merkleWitness for docRequestID "${docRequestID}"`,
        );
      }

      return resolver.deriveCredentialWithZKP(
        cred,
        disclose,
        zkp,
        merkleWitness,
        {
          nonce: request.nonce,
          verifierId: request.verifier,
          zkpProvider: options.zkpProvider,
        },
      );
    }

    if (isBBSProof(cred)) {
      resolver = createBBSResolver(resolver);
    }

    const disclosedFields = disclose.map((d) => d.field);

    return resolver.deriveCredential(cred, disclosedFields, { nonce: request.nonce });
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
