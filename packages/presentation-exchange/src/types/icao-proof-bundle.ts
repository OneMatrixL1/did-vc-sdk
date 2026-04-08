// ---------------------------------------------------------------------------
// ICAO 9303 ZKP Proof Bundle
// ---------------------------------------------------------------------------

/**
 * Structured proof bundle for ICAO credentials (CCCD, Passport).
 *
 * Proof chain:
 *   sodVerify → dgMap → dg13 → fieldReveals / predicates
 *
 * The verifier checks binding linkage:
 * - dg13.output_0 (binding) must equal dgMap.output_0 (dg_binding)
 * - fieldReveals/predicates reference dg13.output_2 (commitment)
 */
export interface ICAO9303ZKPProofBundle {
  type: 'ICAO9303ZKPProofBundle';

  sodVerify: ICAOProofStep;
  dgMap: ICAOProofStep;
  dg13: ICAOProofStep;

  fieldReveals: ICAOFieldReveal[];
  predicates: ICAOPredicateProof[];
}

export interface ICAOProofStep {
  proofValue: string;
  publicInputs: Record<string, unknown>;
  publicOutputs: Record<string, unknown>;
}

export interface ICAOFieldReveal {
  conditionID: string;
  field: string;
  fieldValue: string;
  proofValue: string;
  publicInputs: Record<string, unknown>;
  publicOutputs: Record<string, unknown>;
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
