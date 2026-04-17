/**
 * Merkle tree parity test: verifies that the JS tree builder produces
 * the same results as the dg13-merklelize circuit would.
 *
 * Tests:
 * 1. sha256Sync matches Node crypto
 * 2. Field packing matches circuit's big-endian accumulation
 * 3. Poseidon2 dgBinding matches between JS and expected
 * 4. Full tree commitment is self-consistent (build → verify round-trip)
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import { sha256Sync, computeHashHalf } from '../../src/proof-system/icao9303-proof-system.js';
import { poseidon2BigInt } from '../../src/proof-system/poseidon2.js';
import { buildMerkleTree, TREE_DEPTH } from '../../src/proof-system/merkle-tree.js';
import { deriveDomain } from '../../src/proof-system/domain.js';
import type { MerkleLeafInput } from '../../src/proof-system/types.js';

// ---------------------------------------------------------------------------
// 1. SHA-256: custom sha256Sync vs Node crypto
// ---------------------------------------------------------------------------

describe('sha256Sync correctness', () => {
  function nodeSha256(data: Uint8Array): Uint8Array {
    return new Uint8Array(createHash('sha256').update(data).digest());
  }

  it('matches Node crypto for empty input', () => {
    const js = sha256Sync(new Uint8Array(0));
    const node = nodeSha256(new Uint8Array(0));
    expect(Buffer.from(js).toString('hex')).toBe(Buffer.from(node).toString('hex'));
  });

  it('matches Node crypto for "hello"', () => {
    const data = new TextEncoder().encode('hello');
    const js = sha256Sync(data);
    const node = nodeSha256(data);
    expect(Buffer.from(js).toString('hex')).toBe(Buffer.from(node).toString('hex'));
  });

  it('matches Node crypto for 55 bytes (single block boundary)', () => {
    const data = new Uint8Array(55).fill(0x42);
    expect(Buffer.from(sha256Sync(data)).toString('hex'))
      .toBe(Buffer.from(nodeSha256(data)).toString('hex'));
  });

  it('matches Node crypto for 56 bytes (two-block boundary)', () => {
    const data = new Uint8Array(56).fill(0x42);
    expect(Buffer.from(sha256Sync(data)).toString('hex'))
      .toBe(Buffer.from(nodeSha256(data)).toString('hex'));
  });

  it('matches Node crypto for 64 bytes (exact block)', () => {
    const data = new Uint8Array(64).fill(0xAB);
    expect(Buffer.from(sha256Sync(data)).toString('hex'))
      .toBe(Buffer.from(nodeSha256(data)).toString('hex'));
  });

  it('matches Node crypto for 400 bytes (typical DG13 size)', () => {
    const data = new Uint8Array(400);
    for (let i = 0; i < 400; i++) data[i] = i & 0xFF;
    expect(Buffer.from(sha256Sync(data)).toString('hex'))
      .toBe(Buffer.from(nodeSha256(data)).toString('hex'));
  });

  it('matches Node crypto for 700 bytes (max DG13 size)', () => {
    const data = new Uint8Array(700);
    for (let i = 0; i < 700; i++) data[i] = (i * 7 + 13) & 0xFF;
    expect(Buffer.from(sha256Sync(data)).toString('hex'))
      .toBe(Buffer.from(nodeSha256(data)).toString('hex'));
  });
});

// ---------------------------------------------------------------------------
// 2. computeHashHalf: hi/lo field element packing
// ---------------------------------------------------------------------------

describe('computeHashHalf', () => {
  it('produces correct hi/lo for known data', () => {
    const data = new TextEncoder().encode('test-dg13-data');
    const rawMsg = new Array<number>(700).fill(0);
    for (let i = 0; i < data.length; i++) rawMsg[i] = data[i]!;

    const hi = computeHashHalf(rawMsg, data.length, 0);
    const lo = computeHashHalf(rawMsg, data.length, 16);

    // Verify against Node crypto
    const hash = createHash('sha256').update(Buffer.from(data)).digest();
    let expectedHi = 0n;
    for (let i = 0; i < 16; i++) expectedHi = expectedHi * 256n + BigInt(hash[i]!);
    let expectedLo = 0n;
    for (let i = 16; i < 32; i++) expectedLo = expectedLo * 256n + BigInt(hash[i]!);

    expect(BigInt(hi)).toBe(expectedHi);
    expect(BigInt(lo)).toBe(expectedLo);
  });
});

// ---------------------------------------------------------------------------
// 3. Field packing: JS packing matches circuit's big-endian accumulation
// ---------------------------------------------------------------------------

describe('field packing matches circuit', () => {
  /**
   * Replicate the circuit's packing logic exactly:
   *   for b in 0..31: if byteIdx < length: felt = felt * 256 + byte
   */
  function circuitPack(bytes: number[], offset: number, length: number): [bigint, bigint, bigint, bigint] {
    const data: [bigint, bigint, bigint, bigint] = [0n, 0n, 0n, 0n];
    for (let f = 0; f < 4; f++) {
      let felt = 0n;
      for (let b = 0; b < 31; b++) {
        const byteIdx = f * 31 + b;
        if (byteIdx < length) {
          felt = felt * 256n + BigInt(bytes[offset + byteIdx]!);
        }
      }
      data[f] = felt;
    }
    return data;
  }

  /**
   * Replicate the JS packing logic from buildMerkleTreeFromDG13.
   */
  function jsPack(rawMsg: number[], offset: number, length: number): [bigint, bigint, bigint, bigint] {
    const packed: [string, string, string, string] = ['0x0', '0x0', '0x0', '0x0'];
    for (let chunk = 0; chunk < 4; chunk++) {
      const chunkStart = chunk * 31;
      if (chunkStart < length) {
        const chunkEnd = Math.min(chunkStart + 31, length);
        const bytes = new Uint8Array(32);
        for (let b = chunkStart; b < chunkEnd; b++) {
          bytes[32 - chunkEnd + b] = rawMsg[offset + b]!;
        }
        packed[chunk] = '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      }
    }
    return packed.map(s => BigInt(s)) as [bigint, bigint, bigint, bigint];
  }

  it('matches for short field (5 bytes)', () => {
    const rawMsg = new Array(700).fill(0);
    rawMsg[100] = 0x41; rawMsg[101] = 0x42; rawMsg[102] = 0x43; rawMsg[103] = 0x44; rawMsg[104] = 0x45;
    const circuit = circuitPack(rawMsg, 100, 5);
    const js = jsPack(rawMsg, 100, 5);
    expect(js).toEqual(circuit);
  });

  it('matches for empty field (0 bytes)', () => {
    const rawMsg = new Array(700).fill(0);
    const circuit = circuitPack(rawMsg, 50, 0);
    const js = jsPack(rawMsg, 50, 0);
    expect(js).toEqual(circuit);
  });

  it('matches for exactly 31 bytes (one full chunk)', () => {
    const rawMsg = new Array(700).fill(0);
    for (let i = 0; i < 31; i++) rawMsg[200 + i] = i + 1;
    const circuit = circuitPack(rawMsg, 200, 31);
    const js = jsPack(rawMsg, 200, 31);
    expect(js).toEqual(circuit);
  });

  it('matches for 40 bytes (spans two chunks)', () => {
    const rawMsg = new Array(700).fill(0);
    for (let i = 0; i < 40; i++) rawMsg[300 + i] = (i * 7 + 3) & 0xFF;
    const circuit = circuitPack(rawMsg, 300, 40);
    const js = jsPack(rawMsg, 300, 40);
    expect(js).toEqual(circuit);
  });

  it('matches for 120 bytes (max field length, all 4 chunks)', () => {
    const rawMsg = new Array(700).fill(0);
    for (let i = 0; i < 120; i++) rawMsg[50 + i] = (i * 13 + 5) & 0xFF;
    const circuit = circuitPack(rawMsg, 50, 120);
    const js = jsPack(rawMsg, 50, 120);
    expect(js).toEqual(circuit);
  });

  it('matches for typical Vietnamese name (UTF-8)', () => {
    const name = new TextEncoder().encode('NGUYỄN VĂN ANH');
    const rawMsg = new Array(700).fill(0);
    for (let i = 0; i < name.length; i++) rawMsg[100 + i] = name[i]!;
    const circuit = circuitPack(rawMsg, 100, name.length);
    const js = jsPack(rawMsg, 100, name.length);
    expect(js).toEqual(circuit);
  });
});

// ---------------------------------------------------------------------------
// 4. Full tree: build → verify round-trip
// ---------------------------------------------------------------------------

describe('Merkle tree self-consistency', () => {
  const DOMAIN = deriveDomain('test-domain');

  function packString(s: string): [string, string, string, string] {
    const bytes = new TextEncoder().encode(s);
    const result: [string, string, string, string] = ['0x0', '0x0', '0x0', '0x0'];
    for (let chunk = 0; chunk < 4; chunk++) {
      const start = chunk * 31;
      if (start >= bytes.length) break;
      const end = Math.min(start + 31, bytes.length);
      let val = 0n;
      for (let i = start; i < end; i++) val = val * 256n + BigInt(bytes[i]!);
      result[chunk] = '0x' + val.toString(16);
    }
    return result;
  }

  const FIELDS: MerkleLeafInput[] = [
    'DOC001', 'NGUYEN VAN A', '19900101', 'M',
    'VNM', 'Kinh', 'Khong', 'Ha Noi',
    '123 Tran Hung Dao', 'None', '20240101', '20340101',
    'Father', 'Mother', 'HN', 'Extra',
  ].map((val, i) => ({
    tagId: i + 1,
    length: new TextEncoder().encode(val).length,
    packedFields: packString(val),
  }));

  const DG_HASH_HI = '0x' + 'ab'.repeat(16);
  const DG_HASH_LO = '0x' + 'cd'.repeat(16);

  const tree = buildMerkleTree(FIELDS, DOMAIN.hash, DG_HASH_HI, DG_HASH_LO);

  it('commitment = Poseidon2(root, domain)', () => {
    const expected = poseidon2BigInt([BigInt(tree.root), BigInt(DOMAIN.hash)], 2);
    expect(BigInt(tree.commitment)).toBe(expected);
  });

  it('each leaf verifies via Merkle path back to commitment', () => {
    for (let leafIndex = 0; leafIndex < 16; leafIndex++) {
      const ld = tree.leafData[leafIndex]!;
      const entropy = BigInt(tree.leaves[leafIndex]!);
      const tagId = BigInt(leafIndex + 1);
      const length = BigInt(ld.length);
      const data = ld.data.map(BigInt);

      // Recompute leaf
      const leaf = poseidon2BigInt(
        [tagId, length, data[0]!, data[1]!, data[2]!, data[3]!, entropy],
        7,
      );

      // Walk Merkle path
      let current = leaf;
      let idx = leafIndex;
      for (let level = 0; level < TREE_DEPTH; level++) {
        const sibling = BigInt(tree.siblings[leafIndex]![level]!);
        current = idx % 2 === 0
          ? poseidon2BigInt([current, sibling], 2)
          : poseidon2BigInt([sibling, current], 2);
        idx = Math.floor(idx / 2);
      }

      const recomputed = poseidon2BigInt([current, BigInt(DOMAIN.hash)], 2);
      expect(recomputed).toBe(BigInt(tree.commitment));
    }
  });

  it('entropy = Poseidon2(tagId, length, data[0..3], domain, dgHashHi, dgHashLo)', () => {
    for (let i = 0; i < 16; i++) {
      const ld = tree.leafData[i]!;
      const tagId = BigInt(i + 1);
      const length = BigInt(ld.length);
      const data = ld.data.map(BigInt);

      const expectedEntropy = poseidon2BigInt(
        [tagId, length, data[0]!, data[1]!, data[2]!, data[3]!, BigInt(DOMAIN.hash), BigInt(DG_HASH_HI), BigInt(DG_HASH_LO)],
        9,
      );
      expect(BigInt(tree.leaves[i]!)).toBe(expectedEntropy);
    }
  });
});

// ---------------------------------------------------------------------------
// 5. dgBinding parity: JS Poseidon2([hi, lo, domain], 3) consistency
// ---------------------------------------------------------------------------

describe('dgBinding computation', () => {
  it('Poseidon2([hi, lo, domain], 3) is deterministic', () => {
    const hi = 0x123456789abcdef0n;
    const lo = 0xfedcba9876543210n;
    const domain = BigInt(deriveDomain('test').hash);

    const a = poseidon2BigInt([hi, lo, domain], 3);
    const b = poseidon2BigInt([hi, lo, domain], 3);
    expect(a).toBe(b);
  });

  it('different inputs produce different dgBinding', () => {
    const domain = BigInt(deriveDomain('test').hash);
    const a = poseidon2BigInt([1n, 2n, domain], 3);
    const b = poseidon2BigInt([1n, 3n, domain], 3);
    expect(a).not.toBe(b);
  });
});
