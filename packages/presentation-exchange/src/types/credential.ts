// ---------------------------------------------------------------------------
// Proof system & credential proof types (shared leaf — no type-file imports)
// ---------------------------------------------------------------------------

export type ProofSystem = 'groth16' | 'plonk' | 'fflonk' | 'halo2' | 'stark' | (string & {});

export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: string;
  proofValue?: string;
  sodSignature?: string;
  dgHashes?: Record<string, string>;
  [key: string]: unknown;
}

export interface ZKPProof {
  type: 'ZKPProof';
  conditionID: string;
  circuitId: string;
  proofSystem: ProofSystem;
  publicInputs: Record<string, unknown>;
  publicOutputs: Record<string, unknown>;
  proofValue: string;
}

/**
 * Merkle disclosure — reveals a single DG13 field with its Merkle path.
 *
 * Verification: recompute leaf from packed data, walk siblings to root,
 * check commitment matches dg13-merklelize publicOutputs.commitment.
 */
export interface MerkleDisclosure {
  type: 'MerkleDisclosure';
  /** Links to the condition that requested this disclosure. */
  conditionID: string;
  /** Profile field ID (e.g. 'fullName', 'dateOfBirth'). */
  fieldId: string;
  /** 1-based DG13 field index. */
  tagId: number;
  /** Byte length of the raw field value. */
  length: string;
  /** 4 packed 31-byte chunks as hex field elements. */
  data: [string, string, string, string];
  /** Per-leaf entropy (hex), domain-bound for linkability protection. */
  entropy: string;
  /** Merkle path from leaf to root (4 sibling hashes, hex). */
  siblings: string[];
  /** Decoded UTF-8 value (convenience — verification uses packed data). */
  value: string;
}

/**
 * DG disclosure — reveals a raw Data Group blob (e.g. dg2 photo) with
 * an embedded dg-bridge ZKP proof linking it to the SOD signature.
 *
 * Verification:
 *   1. SHA256(data) → dgHash
 *   2. zkpProvider.verify(dgBridgeProof)
 *   3. dgHash === dgBridgeProof.publicOutputs.dgBinding
 *   4. dgBridgeProof.publicInputs.eContentBinding === chain sod-validate eContentBinding
 *   5. dgBridgeProof.publicInputs.domain === chain domain
 */
export interface DGDisclosure {
  type: 'DGDisclosure';
  /** Links to the condition that requested this disclosure. */
  conditionID: string;
  /** Profile field ID (e.g. 'photo'). */
  fieldId: string;
  /** ICAO Data Group number (e.g. 2 for facial image). */
  dgNumber: number;
  /** Raw DG data (base64-encoded). */
  data: string;
  /** Embedded dg-bridge ZKP proof proving dgBinding is in SOD. */
  dgBridgeProof: ZKPProof;
}

export type CredentialProof = DataIntegrityProof | ZKPProof | MerkleDisclosure | DGDisclosure;

// ---------------------------------------------------------------------------
// Presented credential (may have derived proof)
// ---------------------------------------------------------------------------

export interface PresentedCredential {
  '@context'?: string[];
  id?: string;
  type: string[] | readonly string[];
  issuer: string | { id: string; name?: string };
  issuanceDate?: string;
  credentialSubject: Record<string, unknown>;
  proof?: CredentialProof | CredentialProof[];
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Matchable credential (structural supertype for matching against a VPRequest)
// ---------------------------------------------------------------------------

/**
 * Structural supertype for credentials that can be matched against a VPRequest.
 * Compatible with the app's existing VerifiableCredential from vc.types.ts
 * without requiring an import or conversion.
 */
export interface MatchableCredential {
  type: readonly string[] | string[];
  issuer: string | { id: string; name?: string };
  credentialSubject: Record<string, unknown>;
  proof?: CredentialProof | CredentialProof[] | undefined;
  [key: string]: unknown;
}

/** Extract issuer ID string from a MatchableCredential */
export function getCredentialIssuerId(cred: MatchableCredential): string {
  return typeof cred.issuer === 'string' ? cred.issuer : cred.issuer.id;
}
