import { describe, it, expect, beforeAll } from 'vitest';
import { Buffer } from 'buffer';
import { executePipeline } from '../../src/proof-system/pipeline.js';
import type { PipelineStep } from '../../src/proof-system/pipeline.js';
import { createWasmZKPProvider, createPoseidon2Hasher, buildMerkleTree } from '@1matrix/zkp-provider';
import type { ZKPProvider, Poseidon2Hasher } from '@1matrix/zkp-provider';
import { fieldIdToTagId } from '../../src/resolvers/zkp-field-mapping.js';

let zkpProvider: ZKPProvider & { destroy(): void };
let poseidon2: Poseidon2Hasher;

beforeAll(async () => {
  poseidon2 = await createPoseidon2Hasher();
  zkpProvider = await createWasmZKPProvider();
}, 60000);

// Helper: pack a string into 4 field elements of 31 bytes each
function packString(value: string): bigint[] {
  const bytes = Buffer.from(value, 'utf-8');
  const pf: bigint[] = [];
  for (let f = 0; f < 4; f++) {
    let felt = 0n;
    for (let b = 0; b < 31; b++) {
      const idx = f * 31 + b;
      if (idx < bytes.length) felt = felt * 256n + BigInt(bytes[idx]!);
    }
    pf.push(felt);
  }
  return pf;
}

function buildFields(data: Record<number, string>) {
  const fields = Array.from({ length: 32 }, (_, i) => ({
    tagId: i + 1,
    length: data[i + 1] ? Buffer.from(data[i + 1]!, 'utf-8').length : 0,
    packedFields: data[i + 1] ? packString(data[i + 1]!) : [0n, 0n, 0n, 0n],
    packedHash: 0n,
  }));
  const immutablePacked: bigint[] = [];
  for (const idx of [0, 2, 5, 7, 12]) immutablePacked.push(...fields[idx]!.packedFields);
  const ph = poseidon2.hash(immutablePacked, 20);
  for (const f of fields) f.packedHash = ph;
  return fields;
}

describe('executePipeline', () => {
  it('runs compute steps and shares state via bag', async () => {
    const steps: PipelineStep[] = [
      {
        kind: 'compute', label: 'step-1',
        async run(state) { state.bag.set('value', 42); },
      },
      {
        kind: 'compute', label: 'step-2',
        async run(state) {
          const prev = state.bag.get('value') as number;
          state.bag.set('doubled', prev * 2);
        },
      },
    ];

    const result = await executePipeline(steps, {}, zkpProvider);
    expect(result.bag.get('value')).toBe(42);
    expect(result.bag.get('doubled')).toBe(84);
    expect(result.proofs).toHaveLength(0);
  });

  it('runs real compute → prove pipeline with dg13-field-reveal', async () => {
    const toHex = (v: bigint) => '0x' + v.toString(16);
    const DG13 = { 4: 'Nu' }; // gender only

    const steps: PipelineStep[] = [
      // Compute: build Merkle tree
      {
        kind: 'compute', label: 'build-tree',
        async run(state) {
          const fields = buildFields(DG13);
          const salt = 77n;
          const tree = buildMerkleTree(fields, salt, poseidon2);
          state.bag.set('fields', fields);
          state.bag.set('salt', salt);
          state.bag.set('tree', tree);
          state.bag.set('commitment', tree.commitment);
        },
      },
      // Prove: reveal gender
      {
        kind: 'prove', label: 'reveal-gender',
        circuitId: 'dg13-field-reveal',
        buildInputs(state) {
          const fields = state.bag.get('fields') as ReturnType<typeof buildFields>;
          const tree = state.bag.get('tree') as ReturnType<typeof buildMerkleTree>;
          const salt = state.bag.get('salt') as bigint;
          const leafIndex = fieldIdToTagId('gender') - 1;
          const gf = fields[leafIndex]!;
          return {
            privateInputs: {
              siblings: tree.getSiblings(leafIndex).map(toHex),
              length: toHex(BigInt(gf.length)),
              data: gf.packedFields.map(toHex),
              packed_hash: toHex(gf.packedHash),
            },
            publicInputs: {
              commitment: toHex(tree.commitment),
              salt: toHex(salt),
              tag_id: toHex(BigInt(fieldIdToTagId('gender'))),
            },
          };
        },
        processOutputs(state, result) {
          state.bag.set('genderOutput', result.publicOutputs);
        },
        satisfies: ['c1'],
      },
    ];

    const result = await executePipeline(steps, {}, zkpProvider);

    expect(result.proofs).toHaveLength(1);
    expect(result.proofs[0].label).toBe('reveal-gender');
    expect(result.proofs[0].circuitId).toBe('dg13-field-reveal');
    expect(result.proofs[0].proofValue.length).toBeGreaterThan(100);
    expect(result.proofs[0].satisfies).toEqual(['c1']);

    // Gender output should be 'Nu' packed
    const outputs = result.bag.get('genderOutput') as Record<string, string>;
    expect(outputs).toBeDefined();
  }, 120000);

  it('passes initial bag values to compute steps', async () => {
    const steps: PipelineStep[] = [
      {
        kind: 'compute', label: 'read',
        async run(state) {
          const bytes = state.bag.get('dg13Bytes');
          state.bag.set('parsed', bytes !== undefined);
        },
      },
    ];

    const result = await executePipeline(steps, { dg13Bytes: new Uint8Array([1, 2, 3]) }, zkpProvider);
    expect(result.bag.get('parsed')).toBe(true);
  });
});
