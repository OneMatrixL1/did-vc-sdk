import type { LocalizableString } from './localization.js';
import type { PresentedCredential } from './response.js';

export type ProofSystem = 'groth16' | 'plonk' | 'halo2' | 'bulletproofs';

// ---------------------------------------------------------------------------
// Verifier info
// ---------------------------------------------------------------------------

/** @deprecated Use flat verifier fields on VPRequest instead. */
export interface VerifierInfo {
  id: string;
  name: LocalizableString;
  url: string;
  /** Verifier's credentials proving their identity (selectively disclosed). */
  credentials?: PresentedCredential[];
}

// ---------------------------------------------------------------------------
// Verifier request proof (mirrors HolderProof on the VP side)
// ---------------------------------------------------------------------------

export interface VerifierRequestProof {
  type: string;
  created?: string;
  cryptosuite?: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  challenge: string;
  domain: string;
  proofValue?: string;
  jws?: string;
}

export interface DiscloseCondition {
  type: 'DocumentCondition';
  conditionID: string;
  field: string;
  operator: 'disclose';
  optional?: boolean;
  purpose?: LocalizableString;
}

export interface ZKPCondition {
  type: 'DocumentCondition';
  conditionID: string;
  operator: 'zkp';
  circuitId: string;
  proofSystem: ProofSystem;
  purpose?: LocalizableString;
  circuitHash?: string;
  privateInputs: Record<string, string>;
  publicInputs: Record<string, unknown>;
  dependsOn?: Record<string, string>;
}

export interface LogicalConditionNode {
  type: 'Logical';
  operator: 'AND' | 'OR';
  values: (LogicalConditionNode | DiscloseCondition | ZKPCondition)[];
}

export type DocumentConditionNode =
  | LogicalConditionNode
  | DiscloseCondition
  | ZKPCondition;

// ---------------------------------------------------------------------------
// Rules tree (recursive)
// ---------------------------------------------------------------------------

export type DisclosureMode = 'selective' | 'full';

export interface DocumentRequest {
  type: 'DocumentRequest';
  docRequestID: string;
  docType: string[];
  /**
   * Identifies the schema/resolution strategy for this document request.
   * The resolver for this type must be present in the SchemaResolverMap.
   *  - 'JsonSchema': JSONPath-based field resolution (standard W3C VC)
   *  - 'ICAO9303SOD': ICAO profile field ID resolution (encoded DG blobs)
   */
  schemaType: string;
  issuer?: string | string[];
  name?: LocalizableString;
  purpose?: LocalizableString;
  /**
   * 'selective' (default) — only disclosed fields / ZKP proofs are included.
   * 'full'                — entire credential is passed verbatim; conditions are ignored.
   *                         Trusted-verifier enforcement will be layered on top in a future release.
   */
  disclosureMode?: DisclosureMode;
  conditions: DocumentConditionNode[];
}

/**
 * LogicalRequestNode.values uses an inline union instead of the DocumentRequestNode
 * type alias to avoid a circular forward reference.
 */
export interface LogicalRequestNode {
  type: 'Logical';
  operator: 'AND' | 'OR';
  values: (LogicalRequestNode | DocumentRequest)[];
}

export type DocumentRequestNode = LogicalRequestNode | DocumentRequest;

// ---------------------------------------------------------------------------
// Top-level request
// ---------------------------------------------------------------------------

export interface VPRequest {
  '@context'?: string[];
  type: ['VerifiablePresentationRequest'];
  id: string;
  version: string;
  name: LocalizableString;
  nonce: string;
  verifier: string;
  verifierName: LocalizableString;
  verifierUrl: string;
  verifierCredentials?: PresentedCredential[];
  createdAt: string;
  expiresAt?: string;
  rules: DocumentRequestNode;
  proof?: VerifierRequestProof;
}

/** VPRequest without proof — the payload passed to a signing callback. */
export type UnsignedVPRequest = Omit<VPRequest, 'proof'>;

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

/**
 * Key document passed to credential-sdk's `signPresentation`.
 * Contains the DID key identifier, type, keypair, and controller DID.
 */
export interface KeyDoc {
  /** Fully-qualified key ID, e.g. `'did:ethr:0x...#controller'` */
  id: string;
  /** Key type, e.g. `'EcdsaSecp256k1VerificationKey2019'` */
  type: string;
  /** Crypto keypair instance (library-specific) */
  keypair: unknown;
  /** Controller DID */
  controller: string;
}
