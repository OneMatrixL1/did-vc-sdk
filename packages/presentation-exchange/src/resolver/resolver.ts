import type { MatchableCredential, ZKPProof, CredentialProof } from '../types/credential.js';
import type { VPRequest, VerifierDisclosure, DocumentRequest, DocumentRequestNode, KeyDoc } from '../types/request.js';
import type {
  VerifiablePresentation,
  PresentedCredential,
  HolderProof,
  SubmissionEntry,
} from '../types/response.js';
import type { CredentialSelection } from '../types/matching.js';
import type { SchemaResolverMap } from '../types/schema-resolver.js';
import { defaultResolvers } from '../resolvers/index.js';
import { createBBSResolver, isBBSProof } from '../resolvers/bbs-resolver.js';
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
  /** @deprecated Use `verifierDisclosure` instead. */
  verifierCredentials?: PresentedCredential[];
  verifierDisclosure?: VerifierDisclosure;
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
   * the built-in defaults (ICAO9303SOD).
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
  /**
   * Pre-computed ZKP proofs keyed by conditionID.
   * When provided, these proofs are attached to derived credentials
   * for any matching ZKP conditions in the request.
   */
  zkpProofs?: Map<string, ZKPProof>;
  /**
   * Additional disclosure proofs (MerkleDisclosure, DGDisclosure) to attach
   * alongside ZKP proofs. These carry the actual disclosed field values.
   */
  disclosureProofs?: CredentialProof[];
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

  const presentedList = await Promise.all(items.map(async ({ docReq, cred }) => {
    if (docReq.disclosureMode === 'full') {
      return cred as PresentedCredential;
    }

    let resolver = resolvers[docReq.schemaType];
    if (!resolver) {
      throw new Error(
        `No SchemaResolver registered for schemaType "${docReq.schemaType}". ` +
        `Available resolvers: [${Object.keys(resolvers).join(', ')}]`,
      );
    }

    if (isBBSProof(cred)) {
      resolver = createBBSResolver(resolver);
    }

    const { disclose, zkp } = extractConditions(docReq.conditions);
    const disclosedFields = disclose.map((d) => d.field);
    const derived = await resolver.deriveCredential(cred, disclosedFields, { nonce: request.nonce });

    // Attach ZKP proofs: chain proofs (always) + condition-specific proofs
    if (options.zkpProofs && options.zkpProofs.size > 0) {
      const proofArr: unknown[] = [];

      // Add all chain proofs (sod-validate, dg-bridge, dg13-merklelize, did-delegate)
      for (const [key, proof] of options.zkpProofs) {
        if (key.startsWith('chain-')) {
          proofArr.push(proof);
        }
      }

      // Add condition-specific ZKP proofs (predicates etc.)
      for (const cond of zkp) {
        const proof = options.zkpProofs.get(cond.conditionID);
        if (proof) {
          proofArr.push(proof);
        }
      }

      // Add disclosure proofs (MerkleDisclosure, DGDisclosure)
      if (options.disclosureProofs) {
        proofArr.push(...options.disclosureProofs);
      }

      // ZKP proofs replace the raw SOD proof — verifier trusts the ZKP chain
      if (proofArr.length > 0) {
        (derived as Record<string, unknown>).proof =
          proofArr.length === 1 ? proofArr[0] : proofArr;
      }
    }

    return derived;
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
    ...(request.verifierDisclosure ? { verifierDisclosure: request.verifierDisclosure } : {}),
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
