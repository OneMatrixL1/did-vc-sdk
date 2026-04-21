/**
 * DG15 Active Authentication parser.
 *
 * DG15 (tag 0x6F) carries a SubjectPublicKeyInfo (SPKI) holding the chip's
 * RSA public key. The did-delegate circuit needs:
 *   - the raw DG15 bytes (so it can hash them into dgBinding)
 *   - the offset of the RSA modulus INTEGER inside those bytes
 *   - the modulus bytes themselves (to build limb inputs + Barrett redc)
 *
 * DG15 layout (after the outer 0x6F ICAO envelope):
 *   30 LL                                SEQUENCE (SPKI)
 *     30 LL                              SEQUENCE (AlgorithmIdentifier)
 *       06 09 2A 86 48 86 F7 0D 01 01 01 OID rsaEncryption
 *       05 00                            NULL
 *     03 LL 00                           BIT STRING (prefixed by unused-bits byte)
 *       30 LL                            SEQUENCE (RSAPublicKey)
 *         02 LL [00] <modulus>           INTEGER modulus (N)
 *         02 LL <exponent>               INTEGER exponent (e)
 */

export interface DG15ParseResult {
  /** Raw DG15 bytes (unmodified, padded to fixed length by caller). */
  readonly rawBytes: Uint8Array;
  /** Byte offset inside rawBytes where the modulus integer *contents* begin. */
  readonly modulusOffset: number;
  /** Modulus as big-endian bytes (leading-zero INTEGER byte already stripped). */
  readonly modulusBytes: Uint8Array;
  /** Public exponent, as a JS number (AA keys always use a small e). */
  readonly exponent: number;
}

export function parseDG15(dg15Base64: string): DG15ParseResult {
  const raw = base64ToBytes(dg15Base64);

  // Step past the outer application tag (0x6F) + BER length envelope.
  let offset = readTagLength(raw, 0, 0x6f).contentOffset;
  const spkiOffset = offset;

  // SPKI SEQUENCE (0x30)
  offset = readTagLength(raw, offset, 0x30).contentOffset;

  // AlgorithmIdentifier SEQUENCE (0x30) — step past; we don't validate the OID here.
  const algIdent = readTagLength(raw, offset, 0x30);
  offset = algIdent.contentOffset + algIdent.contentLength;

  // BIT STRING (0x03) carrying the RSAPublicKey
  const bitStr = readTagLength(raw, offset, 0x03);
  // First content byte is the "number of unused bits" (always 0 for RSA keys).
  offset = bitStr.contentOffset + 1;

  // RSAPublicKey SEQUENCE (0x30)
  offset = readTagLength(raw, offset, 0x30).contentOffset;

  // modulus INTEGER (0x02)
  const modInt = readTagLength(raw, offset, 0x02);
  let modContentOffset = modInt.contentOffset;
  let modContentLength = modInt.contentLength;
  // DER INTEGERs that would otherwise be negative carry a leading 0x00 pad.
  if (modContentLength > 0 && raw[modContentOffset] === 0x00) {
    modContentOffset += 1;
    modContentLength -= 1;
  }
  const modulusBytes = raw.slice(modContentOffset, modContentOffset + modContentLength);

  // exponent INTEGER
  const expInt = readTagLength(raw, modInt.contentOffset + modInt.contentLength, 0x02);
  let expBytes = raw.slice(expInt.contentOffset, expInt.contentOffset + expInt.contentLength);
  if (expBytes.length > 0 && expBytes[0] === 0x00) expBytes = expBytes.slice(1);
  let exponent = 0;
  for (let i = 0; i < expBytes.length; i++) exponent = (exponent << 8) | (expBytes[i] ?? 0);

  // Sanity: modulus must start within the raw buffer we'll ship to the circuit.
  if (modContentOffset >= raw.length) {
    throw new Error(`DG15 modulus offset ${modContentOffset} out of range (raw len ${raw.length})`);
  }
  void spkiOffset; // silence unused — useful for debugging

  return {
    rawBytes: raw,
    modulusOffset: modContentOffset,
    modulusBytes,
    exponent,
  };
}

// ---------------------------------------------------------------------------
// Low-level BER helpers
// ---------------------------------------------------------------------------

function readTagLength(
  buf: Uint8Array,
  offset: number,
  expectedTag: number,
): { contentOffset: number; contentLength: number } {
  if (buf[offset] !== expectedTag) {
    throw new Error(
      `DG15 parse: expected tag 0x${expectedTag.toString(16)} at offset ${offset}, got 0x${(buf[offset] ?? 0).toString(16)}`,
    );
  }
  let cursor = offset + 1;
  const first = buf[cursor++] ?? 0;
  let length: number;
  if (first < 0x80) {
    length = first;
  } else {
    const n = first & 0x7f;
    if (n === 0 || n > 4) throw new Error(`DG15 parse: unsupported BER length form (${n} octets)`);
    length = 0;
    for (let i = 0; i < n; i++) length = (length << 8) | (buf[cursor++] ?? 0);
  }
  return { contentOffset: cursor, contentLength: length };
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
