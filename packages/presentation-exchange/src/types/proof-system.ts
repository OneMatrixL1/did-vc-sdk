import type { MatchableCredential, PresentedCredential } from './credential.js';
import type { DiscloseCondition } from './request.js';
import type { PredicateCondition } from './condition.js';
import type { ZKPProvider } from './zkp-provider.js';

// ---------------------------------------------------------------------------
// Contexts passed to prove / verify
// ---------------------------------------------------------------------------

export interface ProveContext {
  nonce?: string;
  holder?: string;
  verifierId?: string;
  zkpProvider: ZKPProvider;
  /** Schema-specific credential data (e.g. ICAO raw bytes). */
  credentialData?: unknown;
}

/**
 * Result of verifying a DSC (Document Signer Certificate) against trusted CSCAs.
 */
export interface DSCVerificationResult {
  /** Whether the DSC is signed by a trusted CSCA. */
  trusted: boolean;
  /** Extracted EC public key from the DSC certificate. */
  publicKey: { x: number[]; y: number[] };
}

export interface VerifyContext {
  zkpProvider: ZKPProvider;

  /**
   * Verify that a DSC certificate is trusted (signed by a known CSCA)
   * and extract its public key for comparison with sod-verify inputs.
   *
   * If not provided, CSCA→DSC verification is skipped (unsafe — testing only).
   */
  verifyDSC?: (dscCertificate: string) => Promise<DSCVerificationResult>;

  /**
   * Request nonce + holder DID for salt binding verification.
   * If provided, the verifier checks that all proof salts match deriveSalt(nonce, holder).
   * If omitted, salt binding is not enforced (unsafe — testing only).
   */
  nonce?: string;
  holder?: string;
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

export interface ProofVerificationResult {
  verified: boolean;
  /** Field values disclosed via ZKP field-reveal proofs. */
  disclosedFields: Record<string, string>;
  errors: string[];
}

// ---------------------------------------------------------------------------
// SchemaProofSystem — unified prove + verify per schema type
// ---------------------------------------------------------------------------

/**
 * Schema-specific proof system that handles both proving and verification.
 *
 * Each implementation encapsulates all schema-specific logic:
 * - ICAO: pipeline (parse DG13 → merklelize → field-reveal → predicates)
 * - BBS: BBS+ selective disclosure derivation
 *
 * Developers never interact with circuits, Merkle trees, or proof chaining.
 * They call `.disclose()` / `.inRange()` / `.equals()` on the builder,
 * and the proof system handles everything internally.
 */
export interface SchemaProofSystem {
  readonly schemaType: string;

  /** Resolve a field value from a credential (used by matcher). */
  resolveField(
    credential: MatchableCredential,
    field: string,
  ): { found: boolean; value?: unknown };

  /** Build a presented credential with proofs for the given conditions. */
  prove(
    credential: MatchableCredential,
    conditions: {
      disclose: DiscloseCondition[];
      predicates: PredicateCondition[];
    },
    context: ProveContext,
  ): Promise<PresentedCredential>;

  /** Verify the proofs on a presented credential against the requested conditions. */
  verify(
    credential: PresentedCredential,
    conditions: {
      disclose: DiscloseCondition[];
      predicates: PredicateCondition[];
    },
    context: VerifyContext,
  ): Promise<ProofVerificationResult>;
}

export type ProofSystemMap = Record<string, SchemaProofSystem>;
