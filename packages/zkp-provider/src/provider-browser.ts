/**
 * Browser-compatible ZKPProvider — no fs imports.
 * Circuits MUST be passed via config.circuits (preloaded via fetch).
 */

export interface ZKPProveParams {
  circuitId: string;
  privateInputs: Record<string, unknown>;
  publicInputs: Record<string, unknown>;
}

export interface ZKPProveResult {
  proofValue: string;
  publicOutputs: Record<string, unknown>;
}

export interface ZKPVerifyParams {
  circuitId: string;
  proofValue: string;
  publicInputs: Record<string, unknown>;
  publicOutputs: Record<string, unknown>;
}

export interface ZKPProvider {
  prove(params: ZKPProveParams): Promise<ZKPProveResult>;
  verify(params: ZKPVerifyParams): Promise<boolean>;
}

export interface WasmProviderConfig {
  circuits?: Record<string, unknown>;
  threads?: number;
}

interface BackendEntry {
  backend: {
    generateProof(witness: unknown): Promise<{ proof: Uint8Array; publicInputs: string[] }>;
    verifyProof(proof: { proof: Uint8Array; publicInputs: string[] }): Promise<boolean>;
    getVerificationKey(): Promise<unknown>;
  };
  noir: {
    execute(inputs: unknown): Promise<{ witness: unknown; returnValue: unknown }>;
  };
}

export async function createWasmZKPProviderBrowser(config?: WasmProviderConfig): Promise<ZKPProvider & { destroy(): void }> {
  const { Barretenberg, UltraHonkBackend } = await import('@aztec/bb.js');
  const { Noir } = await import('@noir-lang/noir_js');

  const externalCircuits = config?.circuits ?? {};
  const backends = new Map<string, BackendEntry>();

  // bb.js 4.x: shared Barretenberg API instance (auto-detects Wasm/WasmWorker)
  const api = await Barretenberg.new();

  async function getBackend(circuitId: string): Promise<BackendEntry> {
    const existing = backends.get(circuitId);
    if (existing) return existing;

    const artifact = externalCircuits[circuitId];
    if (!artifact) {
      throw new Error(
        `Circuit "${circuitId}" not provided. In browser mode, all circuits must be passed via config.circuits.`,
      );
    }

    const noir = new Noir(artifact as any);
    const backend = new UltraHonkBackend((artifact as any).bytecode, api);
    await backend.getVerificationKey();

    const entry: BackendEntry = { backend, noir };
    backends.set(circuitId, entry);
    return entry;
  }

  return {
    async prove(params: ZKPProveParams): Promise<ZKPProveResult> {
      const { backend, noir } = await getBackend(params.circuitId);
      const inputs: Record<string, unknown> = { ...params.privateInputs, ...params.publicInputs };
      const { witness, returnValue } = await noir.execute(inputs);
      const { proof } = await backend.generateProof(witness);
      const publicOutputs = parseReturnValue(returnValue, params.circuitId);
      return { proofValue: uint8ArrayToBase64(proof), publicOutputs };
    },

    async verify(params: ZKPVerifyParams): Promise<boolean> {
      const { backend } = await getBackend(params.circuitId);
      const proof = base64ToUint8Array(params.proofValue);
      const publicInputs = toPublicInputsArray(params.publicInputs, params.publicOutputs);
      try {
        return await backend.verifyProof({ proof, publicInputs });
      } catch {
        return false;
      }
    },

    destroy(): void {
      backends.clear();
    },
  };
}

function uint8ArrayToBase64(buf: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < buf.length; i++) {
    binary += String.fromCharCode(buf[i]!);
  }
  return btoa(binary);
}

function base64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const OUTPUT_NAMES: Record<string, string[]> = {
  'sod-verify': ['econtent_binding'],
  'sod-validate': ['binding'],
  'dg-map': ['dg_binding'],
  'dg13-merklelize': ['binding', 'identity', 'commitment'],
  'dg13-field-reveal': ['length', 'data_0', 'data_1', 'data_2', 'data_3'],
};

function parseReturnValue(returnValue: unknown, circuitId?: string): Record<string, unknown> {
  if (returnValue && typeof returnValue === 'object' && !Array.isArray(returnValue)) {
    return returnValue as Record<string, unknown>;
  }
  if (Array.isArray(returnValue)) {
    const names = circuitId ? OUTPUT_NAMES[circuitId] : undefined;
    const outputs: Record<string, unknown> = {};
    for (let i = 0; i < returnValue.length; i++) {
      const key = names && i < names.length ? names[i]! : `output_${i}`;
      outputs[key] = String(returnValue[i]);
    }
    return outputs;
  }
  return {};
}

function flattenValues(obj: Record<string, unknown>): string[] {
  const result: string[] = [];
  for (const value of Object.values(obj)) {
    if (Array.isArray(value)) {
      result.push(...value.map(String));
    } else {
      result.push(String(value));
    }
  }
  return result;
}

function toPublicInputsArray(
  inputs: Record<string, unknown>,
  outputs: Record<string, unknown>,
): string[] {
  return [...flattenValues(inputs), ...flattenValues(outputs)];
}
