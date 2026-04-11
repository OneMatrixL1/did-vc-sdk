import type { ProofSystemMap } from '../types/proof-system.js';
import { createICAO9303ProofSystem } from './icao9303-proof-system.js';

export { executePipeline } from './pipeline.js';
export type { PipelineStep, ComputeStep, ProveStep, PipelineState, ProveResult } from './pipeline.js';

export { createICAO9303ProofSystem } from './icao9303-proof-system.js';
export type { ICAOCredentialData, ICAO9303ProofSystemOptions } from './icao9303-proof-system.js';

/** Default proof systems. ICAO is registered without poseidon2 — it must be provided at runtime. */
export const defaultProofSystems: ProofSystemMap = {
  'ICAO9303SOD': createICAO9303ProofSystem(),
};
