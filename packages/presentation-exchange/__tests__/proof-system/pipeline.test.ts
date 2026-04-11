import { describe, it, expect, beforeAll } from 'vitest';
import { executePipeline } from '../../src/proof-system/pipeline.js';
import type { PipelineStep } from '../../src/proof-system/pipeline.js';
import { createWasmZKPProvider, createPoseidon2Hasher, buildMerkleTree } from '@1matrix/zkp-provider';
import type { ZKPProvider, Poseidon2Hasher } from '@1matrix/zkp-provider';
import { fieldIdToTagId } from '../../src/resolvers/zkp-field-mapping.js';
import { MOTHER_DG13_FIELDS, buildMerkleLeaves } from '../fixtures/cccd-factory.js';

let zkpProvider: ZKPProvider & { destroy(): void };
let poseidon2: Poseidon2Hasher;

beforeAll(async () => {
  poseidon2 = await createPoseidon2Hasher();
  zkpProvider = await createWasmZKPProvider();
}, 60000);

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

  it('runs real compute -> prove pipeline with dg13-field-reveal', async () => {
    const toHex = (v: bigint) => '0x' + v.toString(16);

    const steps: PipelineStep[] = [
      {
        kind: 'compute', label: 'build-tree',
        async run(state) {
          const fields = buildMerkleLeaves(MOTHER_DG13_FIELDS, poseidon2.hash);
          const salt = 77n;
          const tree = buildMerkleTree(fields, salt, poseidon2);
          state.bag.set('fields', fields);
          state.bag.set('salt', salt);
          state.bag.set('tree', tree);
          state.bag.set('commitment', tree.commitment);
        },
      },
      {
        kind: 'prove', label: 'reveal-gender',
        circuitId: 'dg13-field-reveal',
        buildInputs(state) {
          const fields = state.bag.get('fields') as ReturnType<typeof buildMerkleLeaves>;
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
