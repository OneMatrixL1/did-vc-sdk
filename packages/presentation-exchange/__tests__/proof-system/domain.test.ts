/**
 * Domain derivation tests — verifies field element packing math.
 */
import { describe, it, expect } from 'vitest';
import { packStringToFieldHex } from '../../src/proof-system/domain.js';

describe('packStringToFieldHex', () => {
  it('packs "1matrix" into correct hex representation', () => {
    const hex = packStringToFieldHex('1matrix');
    // "1matrix" = bytes [0x31, 0x6d, 0x61, 0x74, 0x72, 0x69, 0x78]
    // Right-aligned in 32 bytes → 25 zero bytes + 7 content bytes
    expect(hex).toMatch(/^0x[0-9a-f]{64}$/);

    const bytes = hex.slice(2);
    // First 25 bytes (50 hex chars) are zero
    expect(bytes.slice(0, 50)).toBe('0'.repeat(50));
    // Last 7 bytes are "1matrix" in hex
    expect(bytes.slice(50)).toBe('316d6174726978');
  });

  it('packs single ASCII byte correctly', () => {
    const hex = packStringToFieldHex('A');
    const bytes = hex.slice(2);
    expect(bytes.slice(0, 62)).toBe('0'.repeat(62));
    expect(bytes.slice(62)).toBe('41'); // 'A' = 0x41
  });

  it('packs 31-byte string (max capacity) correctly', () => {
    const str = 'abcdefghijklmnopqrstuvwxyz12345'; // exactly 31 bytes
    const hex = packStringToFieldHex(str);
    const bytes = hex.slice(2);
    // First byte is 0x00, remaining 31 bytes are the string
    expect(bytes.slice(0, 2)).toBe('00');
    // Verify each character
    for (let i = 0; i < 31; i++) {
      const charHex = str.charCodeAt(i).toString(16).padStart(2, '0');
      expect(bytes.slice(2 + i * 2, 4 + i * 2)).toBe(charHex);
    }
  });

  it('throws for 32-byte string (exceeds BN254 field)', () => {
    expect(() => packStringToFieldHex('a'.repeat(32))).toThrow('exceeds 31 UTF-8 bytes');
  });

  it('counts UTF-8 bytes, not characters', () => {
    // "é" is 2 UTF-8 bytes, so 16 of them = 32 bytes → too big
    expect(() => packStringToFieldHex('é'.repeat(16))).toThrow('exceeds 31 UTF-8 bytes');
    // 15 of them = 30 bytes → fits
    expect(() => packStringToFieldHex('é'.repeat(15))).not.toThrow();
  });

  it('empty string produces all zeros', () => {
    expect(packStringToFieldHex('')).toBe('0x' + '0'.repeat(64));
  });

  it('different strings produce different hex values', () => {
    const a = packStringToFieldHex('1matrix');
    const b = packStringToFieldHex('partner');
    expect(a).not.toBe(b);
  });
});
