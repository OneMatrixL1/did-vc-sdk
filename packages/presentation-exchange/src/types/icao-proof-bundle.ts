// ---------------------------------------------------------------------------
// ICAO 9303 ZKP Proof Bundle
// ---------------------------------------------------------------------------

/**
 * Structured proof bundle for ICAO credentials (CCCD, Passport).
 *
 * Replaces the flat `ZKPProof[] + MerkleDisclosureProof[]` with a typed
 * structure that makes the proof chain implicit:
 *
 *   sod → dg13 → fieldReveals / predicates
 *
 * No `dependsOn` wiring. The verifier checks commitment linkage structurally:
 * - dg13.publicInputs references sod.publicOutputs.dg13Hash
 * - fieldReveals/predicates reference dg13.publicOutputs.commitment
 */
export interface ICAO9303ZKPProofBundle {
  type: 'ICAO9303ZKPProofBundle';

  /** SOD signature verification proof (pure ECDSA). */
  sodVerify: {
    proofValue: string;
    publicOutputs: { econtent_binding: string; [key: string]: unknown };
  };

  /** DG map proof — extracts DG13 hash from signed eContent. */
  dgMap: {
    proofValue: string;
    publicOutputs: { dg_binding: string; [key: string]: unknown };
  };

  /** DG13 merklelization proof — builds Merkle tree, outputs commitment. */
  dg13: {
    proofValue: string;
    publicOutputs: { binding: string; identity: string; commitment: string; [key: string]: unknown };
  };

  /** Field reveal proofs — one per `.disclose()` condition. */
  fieldReveals: ICAOFieldReveal[];

  /** Predicate proofs — one per `.inRange()` / `.greaterThan()` / etc. */
  predicates: ICAOPredicateProof[];
}

export interface ICAOFieldReveal {
  conditionID: string;
  field: string;
  fieldValue: string;
  proofValue: string;
  publicInputs: { commitment: string; salt: string; tagId: number };
}

export interface ICAOPredicateProof {
  conditionID: string;
  operator: string;
  field: string;
  params: Record<string, unknown>;
  result: unknown;
  proofValue: string;
  publicInputs: Record<string, unknown>;
  publicOutputs: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Type guard
// ---------------------------------------------------------------------------

export function isICAOProofBundle(proof: unknown): proof is ICAO9303ZKPProofBundle {
  return !!proof && typeof proof === 'object' && (proof as Record<string, unknown>).type === 'ICAO9303ZKPProofBundle';
}
