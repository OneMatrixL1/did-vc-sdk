/**
 * ZKP proving/verification provider interface.
 *
 * Abstracts the proving backend (CLI nargo+bb, WASM @aztec/bb.js, or remote service)
 * so the presentation-exchange layer is backend-agnostic.
 */

export interface ZKPProveParams {
  circuitId: string;
  privateInputs: Record<string, unknown>;
  publicInputs: Record<string, unknown>;
}

export interface ZKPProveResult {
  proofValue: string;
  publicOutputs: Record<string, unknown>;
  vkHash?: string;
}

export interface ZKPVerifyParams {
  circuitId: string;
  proofValue: string;
  publicInputs: Record<string, unknown>;
  publicOutputs: Record<string, unknown>;
  vkHash?: string;
}

export interface ZKPProvider {
  prove(params: ZKPProveParams): Promise<ZKPProveResult>;
  verify(params: ZKPVerifyParams): Promise<boolean>;
}

export interface Poseidon2Hasher {
  hash(inputs: bigint[], len: number): bigint;
}
