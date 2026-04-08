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
// ICAO 9303 ZKP Proof Bundle
// ---------------------------------------------------------------------------

/**
 * Proof bundle for ICAO credentials (CCCD, Passport).
 *
 * Contains an ordered array of ZKP proofs. The binding chain:
 *   sod-verify.econtent_binding → dg-map.input.econtent_binding
 *   dg-map.dg_binding          → dg13-merklelize.binding
 *   dg13.commitment            → field-reveal/predicate.input.commitment
 *
 * zkp-provider: verify each entry independently.
 * presentation-exchange: verify the chain linking between entries.
 */
export interface ICAO9303ZKPProofBundle {
  type: 'ICAO9303ZKPProofBundle';
  proofs: ZKPProofEntry[];

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
