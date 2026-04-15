/**
 * Domain derivation — converts a human-readable domain name into a
 * BN254 field element via Poseidon2 hashing.
 */

import type { Domain } from './types.js';
import { poseidon2 } from './poseidon2.js';

/** Default domain used at credential import and for quick sharing. */
export const DEFAULT_DOMAIN_NAME = '1matrix';

/**
 * Derive a {@link Domain} from a human-readable name.
 *
 * The name is packed into a single BN254 field element (max 31 UTF-8 bytes)
 * and hashed with Poseidon2 to produce a deterministic domain hash.
 */
export function deriveDomain(name: string): Domain {
  const packed = packStringToFieldHex(name);
  const hash = poseidon2([packed], 1);
  return { name, hash };
}

/**
 * Pack a UTF-8 string into a single BN254 field element (hex).
 *
 * The string is encoded as UTF-8 bytes, then right-aligned (big-endian)
 * into a 32-byte buffer. Max 31 bytes to stay below the BN254 prime.
 */
export function packStringToFieldHex(str: string): string {
  const bytes = new TextEncoder().encode(str);
  if (bytes.length > 31) {
    throw new Error(`Domain name "${str}" exceeds 31 UTF-8 bytes (got ${bytes.length})`);
  }
  const padded = new Uint8Array(32);
  padded.set(bytes, 32 - bytes.length);
  return '0x' + Array.from(padded).map(b => b.toString(16).padStart(2, '0')).join('');
}
