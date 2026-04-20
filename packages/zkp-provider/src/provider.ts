/**
 * WASM ZKPProvider using @aztec/bb.js UltraHonkBackend + @noir-lang/noir_js.
 *
 * Circuits are loaded from bundled artifacts (circuits/*.json).
 * Each circuit backend is initialized lazily on first use.
 */

export interface CircuitArtifact {
  bytecode: string;
  abi: unknown;
}

export interface ZKPProveParams {
  circuitId: string;
  privateInputs: Record<string, unknown>;
  publicInputs: Record<string, unknown>;
}

export interface ZKPProveResult {
  /**
   * Opaque envelope: base64 of [numPub(4 BE) | publicInputs(32*n) | proofBytes].
   * Used for SDK-local round-trip verification.
   */
  proofValue: string;
  /** Raw proof bytes as 0x-prefixed hex. Feed this directly to on-chain verifiers. */
  proofBytes: string;
  /** Public signals: ordered bytes32 (0x-hex) values — the `publicInputs` parameter on-chain verifiers expect. */
  publicSignals: string[];
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
  circuits?: Record<string, CircuitArtifact>;
  threads?: number;
}

interface BackendEntry {
  backend: {
    generateProof(witness: unknown, options?: unknown): Promise<{ proof: Uint8Array; publicInputs: string[] }>;
    verifyProof(proof: { proof: Uint8Array; publicInputs: string[] }, options?: unknown): Promise<boolean>;
    getVerificationKey(options?: unknown): Promise<unknown>;
  };
  noir: {
    execute(inputs: unknown): Promise<{ witness: unknown; returnValue: unknown }>;
  };
}

export async function createWasmZKPProvider(config?: WasmProviderConfig): Promise<ZKPProvider & { destroy(): void }> {
  const { Barretenberg, UltraHonkBackend } = await import('@aztec/bb.js');
  const { Noir } = await import('@noir-lang/noir_js');

  const externalCircuits = config?.circuits ?? {};
  const backends = new Map<string, BackendEntry>();

  const api = await Barretenberg.new();

  async function getBackend(circuitId: string): Promise<BackendEntry> {
    const existing = backends.get(circuitId);
    if (existing) return existing;

    const artifact = externalCircuits[circuitId];
    if (!artifact) {
      throw new Error(
        `Circuit "${circuitId}" not found. Pass circuits via WasmProviderConfig.circuits. ` +
        `Available: [${Object.keys(externalCircuits).join(', ')}]`,
      );
    }
    const noir = new Noir(artifact as any);
    const backend = new UltraHonkBackend((artifact as any).bytecode, api);
    // Warm up VK under EVM target so prove/verify round-trip is consistent.
    await backend.getVerificationKey({ verifierTarget: 'evm' });

    const entry: BackendEntry = { backend, noir };
    backends.set(circuitId, entry);
    return entry;
  }

  return {
    async prove(params: ZKPProveParams): Promise<ZKPProveResult> {
      const { backend, noir } = await getBackend(params.circuitId);
      const inputs: Record<string, unknown> = { ...params.privateInputs, ...params.publicInputs };
      const { witness, returnValue } = await noir.execute(inputs);
      // verifierTarget: 'evm' → Keccak transcript + ZK (UltraKeccakZKFlavor).
      // Matches the deployed UniversalHonkVerifier and the native plugin.
      const { proof, publicInputs } = await backend.generateProof(witness, {
        verifierTarget: 'evm',
      });
      const publicOutputs = parseReturnValue(returnValue, params.circuitId);

      // Encode full proof: [num_public_inputs(4 BE)][public_inputs as 32-byte fields][proof bytes]
      // This format is compatible with noir_rs verify_ultra_honk.
      const numPub = publicInputs.length;
      const fullProof = new Uint8Array(4 + numPub * 32 + proof.length);
      const view = new DataView(fullProof.buffer);
      view.setUint32(0, numPub, false); // big-endian
      for (let i = 0; i < numPub; i++) {
        const hexStr = publicInputs[i]!.replace(/^0x/, '');
        for (let j = 0; j < 32; j++) {
          fullProof[4 + i * 32 + j] = parseInt(hexStr.substring(j * 2, j * 2 + 2), 16) || 0;
        }
      }
      fullProof.set(proof, 4 + numPub * 32);

      const publicSignals = publicInputs.map((pi) => {
        const hex = pi.replace(/^0x/, '').padStart(64, '0');
        return '0x' + hex;
      });

      return {
        proofValue: uint8ArrayToBase64(fullProof),
        proofBytes: '0x' + uint8ArrayToHex(proof),
        publicSignals,
        publicOutputs,
      };
    },

    async verify(params: ZKPVerifyParams): Promise<boolean> {
      const { backend } = await getBackend(params.circuitId);
      const fullProof = base64ToUint8Array(params.proofValue);

      // Decode full proof: [num_pub(4 BE)][public_inputs][proof]
      const view = new DataView(fullProof.buffer, fullProof.byteOffset, fullProof.byteLength);
      const numPub = view.getUint32(0, false);
      const pubEnd = 4 + numPub * 32;
      const publicInputs: string[] = [];
      for (let i = 0; i < numPub; i++) {
        let hex = '';
        for (let j = 0; j < 32; j++) {
          hex += fullProof[4 + i * 32 + j]!.toString(16).padStart(2, '0');
        }
        publicInputs.push('0x' + hex);
      }
      const proof = fullProof.slice(pubEnd);

      try {
        return await backend.verifyProof(
          { proof, publicInputs },
          { verifierTarget: 'evm' },
        );
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
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(buf).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < buf.length; i++) {
    binary += String.fromCharCode(buf[i]!);
  }
  return btoa(binary);
}

function uint8ArrayToHex(buf: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i]!.toString(16).padStart(2, '0');
  }
  return hex;
}

function base64ToUint8Array(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Named output mapping — struct field names from circuit return types
// ---------------------------------------------------------------------------

const OUTPUT_NAMES: Record<string, string[]> = {
  'sod-validate': ['eContentBinding', 'dscPubKeyHash'],
  'dg-bridge': ['dgBinding'],
  'dg13-merklelize': ['dgBinding', 'identity', 'commitment'],
  'unique-identity': ['dgBinding', 'identity'],
  'did-delegate': ['dgBinding'],
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

