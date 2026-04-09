// ---------------------------------------------------------------------------
// ZKP Proof Bundle — generic array of typed proof entries
// ---------------------------------------------------------------------------

/**
 * A single ZKP proof entry. Self-describing via `circuitId`.
 *
 * zkp-provider verifies each entry independently (pure math).
 * presentation-exchange checks the binding chain between entries (domain logic).
 */
export interface ZKPProofEntry {
  circuitId: string;
  proofValue: string;
  publicInputs: Record<string, unknown>;
  publicOutputs: Record<string, unknown>;

  /** Links this proof to a request condition. Absent for chain proofs (sod-verify, dg-map, dg13-merklelize). */
  conditionID?: string;
}

// ---------------------------------------------------------------------------
// Merkle Disclosure — raw Merkle proof for field reveal (no ZKP needed)
// ---------------------------------------------------------------------------

/**
 * A raw Merkle inclusion proof that reveals a field value.
 *
 * No ZKP is needed for disclosure — the value is public anyway.
 * The verifier recomputes the leaf hash and walks the Merkle path
 * to verify inclusion against the dg13-merklelize commitment.
 *
 * ~100x smaller and ~1000x faster than a ZKP field-reveal proof.
 */
export interface MerkleDisclosure {
  conditionID: string;
  tagId: string;                        // hex — which field (1-indexed)
  length: string;                       // hex — byte length of value
  data: [string, string, string, string]; // hex — 4 packed field elements (31 bytes each)
  packedHash: string;                   // hex — Poseidon2 hash of immutable fields
  siblings: string[];                   // hex — Merkle path (5 levels for 32-leaf tree)
}

// ---------------------------------------------------------------------------
// ICAO 9303 ZKP Proof Bundle
// ---------------------------------------------------------------------------

/**
 * Proof bundle for ICAO credentials (CCCD, Passport).
 *
 * Contains:
 * - ZKP proofs for the binding chain (sod-verify → dg-map → dg13-merklelize)
 *   and predicates (date comparisons, field equality)
 * - Raw Merkle disclosures for revealed fields (no ZKP overhead)
 *
 * Binding chain:
 *   sod-verify.econtent_binding → dg-map.input.econtent_binding
 *   dg-map.dg_binding          → dg13-merklelize.binding
 *   dg13.commitment            → disclosure/predicate.commitment
 */
export interface ICAO9303ZKPProofBundle {
  type: 'ICAO9303ZKPProofBundle';
  proofs: ZKPProofEntry[];

  /** Raw Merkle proofs for disclosed fields. Verified via Poseidon2, no ZKP. */
  disclosures?: MerkleDisclosure[];

  /**
   * DSC (Document Signer Certificate) in base64 DER.
   * The verifier checks that this certificate is signed by a trusted CSCA
   * and that its public key matches `pubkey_x`/`pubkey_y` in the sod-verify proof.
   */
  dscCertificate?: string;
}

// ---------------------------------------------------------------------------
// Type guard
// ---------------------------------------------------------------------------

export function isICAOProofBundle(proof: unknown): proof is ICAO9303ZKPProofBundle {
  return !!proof && typeof proof === 'object' && (proof as Record<string, unknown>).type === 'ICAO9303ZKPProofBundle';
}
