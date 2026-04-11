/**
 * ProofPipeline — sequential compute/prove steps with shared state bag.
 *
 * Used internally by proof systems (e.g. ICAO9303) to orchestrate
 * credential parsing, tree building, and circuit proving.
 *
 * Not part of the public API.
 */

import type { ZKPProvider, ZKPProveResult } from '../types/zkp-provider.js';

// ---------------------------------------------------------------------------
// Step types
// ---------------------------------------------------------------------------

export interface ComputeStep {
  kind: 'compute';
  label: string;
  run(state: PipelineState): Promise<void>;
}

export interface ProveStep {
  kind: 'prove';
  label: string;
  circuitId: string;
  buildInputs(state: PipelineState): {
    privateInputs: Record<string, unknown>;
    publicInputs: Record<string, unknown>;
  };
  processOutputs(state: PipelineState, result: ZKPProveResult): void;
  /** Which conditionIDs this proof satisfies. */
  satisfies: string[];
}

export type PipelineStep = ComputeStep | ProveStep;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

export interface ProveResult {
  label: string;
  circuitId: string;
  proofValue: string;
  publicInputs: Record<string, unknown>;
  publicOutputs: Record<string, unknown>;
  satisfies: string[];
}

export interface PipelineState {
  /** Shared key-value bag — compute steps write, prove steps read. */
  bag: Map<string, unknown>;
  /** Accumulated proof results. */
  proofs: ProveResult[];
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

export async function executePipeline(
  steps: PipelineStep[],
  initialBag: Record<string, unknown>,
  zkpProvider: ZKPProvider,
): Promise<PipelineState> {
  const state: PipelineState = {
    bag: new Map(Object.entries(initialBag)),
    proofs: [],
  };

  for (const step of steps) {
    if (step.kind === 'compute') {
      await step.run(state);
    } else {
      const { privateInputs, publicInputs } = step.buildInputs(state);
      const result = await zkpProvider.prove({
        circuitId: step.circuitId,
        privateInputs,
        publicInputs,
      });

      state.proofs.push({
        label: step.label,
        circuitId: step.circuitId,
        proofValue: result.proofValue,
        publicInputs,
        publicOutputs: result.publicOutputs,
        satisfies: step.satisfies,
      });

      step.processOutputs(state, result);
    }
  }

  return state;
}
