/**
 * DG13 parser tests — builds real ICAO DG13 TLV structures and
 * verifies field extraction and witness building.
 */
import { describe, it, expect } from 'vitest';
import { buildDG13WitnessData } from '../../src/proof-system/dg13-parser.js';

function toBase64(arr: Uint8Array): string {
  return btoa(String.fromCharCode(...arr));
}

/** Encode DER length — handles both short form (<128) and long form. */
function derLen(len: number): number[] {
  if (len < 0x80) return [len];
  if (len < 0x100) return [0x81, len];
  return [0x82, (len >> 8) & 0xff, len & 0xff];
}

/**
 * Build a real DG13 binary structure matching Vietnamese CCCD format.
 *
 * Structure:
 *   0x6D len { SEQUENCE { INTEGER version, OID, SET { field SEQUENCEs... } } }
 * Each field: SEQUENCE { INTEGER tagId, UTF8STRING value }
 */
function buildDG13(fields: { tagId: number; value: string }[]): Uint8Array {
  const fieldEntries: number[][] = [];
  for (const f of fields) {
    const valueBytes = new TextEncoder().encode(f.value);
    const content = [0x02, 0x01, f.tagId, 0x0c, ...derLen(valueBytes.length), ...valueBytes];
    fieldEntries.push([0x30, ...derLen(content.length), ...content]);
  }

  const flatFields = fieldEntries.flat();
  const set = [0x31, ...derLen(flatFields.length), ...flatFields];
  const version = [0x02, 0x01, 0x00];
  const oid = [0x06, 0x01, 0x00];
  const seqContent = [...version, ...oid, ...set];
  const inner = [0x30, ...derLen(seqContent.length), ...seqContent];
  const outer = [0x6d, ...derLen(inner.length), ...inner];

  return new Uint8Array(outer);
}

describe('DG13 parser', () => {
  const FIELDS = [
    { tagId: 1, value: '079203012345' },       // documentNumber
    { tagId: 2, value: 'NGUYEN VAN ANH' },      // fullName
    { tagId: 3, value: '25/03/2003' },           // dateOfBirth
    { tagId: 4, value: 'Nam' },                  // gender
    { tagId: 5, value: 'Viet Nam' },             // nationality
    { tagId: 6, value: 'Kinh' },                 // ethnicity
    { tagId: 7, value: 'Phat giao' },            // religion
    { tagId: 8, value: 'Ha Noi' },               // hometown
    { tagId: 9, value: '123 Tran Hung Dao, HN' }, // permanentAddress
  ];

  const dg13 = buildDG13(FIELDS);
  const dg13Base64 = toBase64(dg13);

  it('extracts correct number of real fields', () => {
    const witness = buildDG13WitnessData(dg13Base64);
    // 9 real fields should have non-zero lengths
    for (let i = 0; i < 9; i++) {
      expect(witness.fieldLengths[i]).toBeGreaterThan(0);
    }
    // Remaining 23 fields should have zero length (padded)
    for (let i = 9; i < 32; i++) {
      expect(witness.fieldLengths[i]).toBe(0);
    }
  });

  it('field lengths match actual UTF-8 byte lengths', () => {
    const witness = buildDG13WitnessData(dg13Base64);
    for (let i = 0; i < FIELDS.length; i++) {
      const expectedLen = new TextEncoder().encode(FIELDS[i]!.value).length;
      expect(witness.fieldLengths[i]).toBe(expectedLen);
    }
  });

  it('field data at offsets matches original values', () => {
    const witness = buildDG13WitnessData(dg13Base64);
    for (let i = 0; i < FIELDS.length; i++) {
      const offset = witness.fieldOffsets[i]!;
      const length = witness.fieldLengths[i]!;
      const extractedBytes = witness.rawMsg.slice(offset, offset + length);
      const expectedBytes = Array.from(new TextEncoder().encode(FIELDS[i]!.value));
      expect(extractedBytes).toEqual(expectedBytes);
    }
  });

  it('rawMsg is exactly 700 bytes', () => {
    const witness = buildDG13WitnessData(dg13Base64);
    expect(witness.rawMsg).toHaveLength(700);
  });

  it('rawMsg starts with original DG13 bytes verbatim', () => {
    const witness = buildDG13WitnessData(dg13Base64);
    for (let i = 0; i < dg13.length; i++) {
      expect(witness.rawMsg[i]).toBe(dg13[i]);
    }
  });

  it('dgLen matches original DG13 size', () => {
    const witness = buildDG13WitnessData(dg13Base64);
    expect(witness.dgLen).toBe(dg13.length);
  });

  it('padding entries have correct TLV structure', () => {
    const witness = buildDG13WitnessData(dg13Base64);
    // Padding starts at dgLen, each entry is 7 bytes: 30 05 02 01 [tagId] 0C 00
    let pos = dg13.length;
    for (let i = FIELDS.length; i < 32; i++) {
      expect(witness.rawMsg[pos]).toBe(0x30);
      expect(witness.rawMsg[pos + 1]).toBe(0x05);
      expect(witness.rawMsg[pos + 2]).toBe(0x02);
      expect(witness.rawMsg[pos + 3]).toBe(0x01);
      expect(witness.rawMsg[pos + 4]).toBe(i + 1); // tagId = index + 1
      expect(witness.rawMsg[pos + 5]).toBe(0x0c);
      expect(witness.rawMsg[pos + 6]).toBe(0x00);
      pos += 7;
    }
  });

  it('rejects DG13 with wrong outer tag', () => {
    const bad = new Uint8Array(dg13);
    bad[0] = 0x30; // SEQUENCE instead of 0x6D
    expect(() => buildDG13WitnessData(toBase64(bad))).toThrow('Expected DG13 tag 0x6D');
  });

  it('rejects DG13 exceeding 700 bytes', () => {
    // Build DG13 with a very long field
    const longField = { tagId: 1, value: 'x'.repeat(680) };
    const huge = buildDG13([longField]);
    expect(() => buildDG13WitnessData(toBase64(huge))).toThrow('exceeds 700 max');
  });
});
