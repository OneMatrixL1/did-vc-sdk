/**
 * Self-signed CCCD credential factory for testing.
 *
 * Builds real:
 *   - DG13 TLV bytes (Vietnamese CCCD format)
 *   - LDS Security Object (eContent) with SHA-256(DG13)
 *   - CMS signedAttrs with messageDigest = SHA-256(eContent)
 *   - ECDSA brainpoolP384r1 signature over signedAttrs
 *   - Circuit inputs matching sod-verify, dg-map, dg13-merklelize exactly
 *
 * No mocks. The circuits can verify these signatures.
 */

import { Buffer } from 'buffer';
import crypto from 'crypto';
import type { MatchableCredential } from '../../src/types/credential.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_ECONTENT = 320;
const MAX_SIGNED_ATTRS = 200;
const MAX_DG_BYTES = 700;

// brainpoolP384r1 curve order for signature canonicalization
const CURVE_ORDER = BigInt(
  '0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565',
);
const HALF_N = CURVE_ORDER / 2n;

// OID bytes
const SHA256_OID = Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]); // 2.16.840.1.101.3.4.2.1
const CONTENT_TYPE_OID = Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03]); // 1.2.840.113549.1.9.3
const MESSAGE_DIGEST_OID = Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04]); // 1.2.840.113549.1.9.4
const LDS_SECURITY_OBJECT_OID = Buffer.from([0x67, 0x81, 0x08, 0x01, 0x01, 0x01]); // 2.23.136.1.1.1

// ---------------------------------------------------------------------------
// DG13 TLV encoding
// Pattern: 0x30 [seqLen] 0x02 0x01 [tagNum] 0x0C [strLen] [UTF-8 value]
// ---------------------------------------------------------------------------

export function encodeDG13Field(tagNum: number, value: string): Buffer {
  const strBuf = Buffer.from(value, 'utf-8');
  const intTag = Buffer.from([0x02, 0x01, tagNum]);
  const strTag = Buffer.from([0x0c, strBuf.length]);
  const inner = Buffer.concat([intTag, strTag, strBuf]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

export function buildDG13Bytes(fields: Record<number, string>): Uint8Array {
  const parts = Object.entries(fields)
    .sort(([a], [b]) => Number(a) - Number(b))
    .map(([tag, val]) => encodeDG13Field(Number(tag), val));
  return new Uint8Array(Buffer.concat(parts));
}

// ---------------------------------------------------------------------------
// DG13 circuit inputs (raw_msg, field_offsets, field_lengths for dg13-merklelize)
// ---------------------------------------------------------------------------

export interface DG13CircuitInputs {
  rawMsg: number[];        // [u8; 700] padded
  dgLen: number;           // original DG13 length (hashed for SOD binding)
  fieldOffsets: number[];   // [u32; 32]
  fieldLengths: number[];   // [u32; 32]
}

export function buildDG13CircuitInputs(dg13Fields: Record<number, string>): DG13CircuitInputs {
  const dg13Bytes = buildDG13Bytes(dg13Fields);
  const dgLen = dg13Bytes.length;

  const rawMsg = new Array(MAX_DG_BYTES).fill(0);
  for (let i = 0; i < dgLen; i++) rawMsg[i] = dg13Bytes[i]!;

  // Parse field offsets from the TLV structure
  const fieldOffsets = new Array(32).fill(0);
  const fieldLengths = new Array(32).fill(0);

  let pos = 0;
  const sortedTags = Object.keys(dg13Fields).map(Number).sort((a, b) => a - b);
  for (const tagNum of sortedTags) {
    const value = dg13Fields[tagNum]!;
    const strBuf = Buffer.from(value, 'utf-8');
    // Skip: 0x30 [seqLen] 0x02 0x01 [tagNum] 0x0C [strLen]
    const valueOffset = pos + 7;
    fieldOffsets[tagNum - 1] = valueOffset;
    fieldLengths[tagNum - 1] = strBuf.length;
    pos += 2 + 3 + 2 + strBuf.length; // seq header + int tag + str tag + value
  }

  // Append dummy fields for missing tags (circuit requires 32 fields)
  let appendPos = dgLen;
  for (let i = 0; i < 32; i++) {
    if (fieldOffsets[i] === 0 && fieldLengths[i] === 0 && !dg13Fields[i + 1]) {
      const tagId = i + 1;
      rawMsg[appendPos] = 0x30;
      rawMsg[appendPos + 1] = 0x05;
      rawMsg[appendPos + 2] = 0x02;
      rawMsg[appendPos + 3] = 0x01;
      rawMsg[appendPos + 4] = tagId;
      rawMsg[appendPos + 5] = 0x0c;
      rawMsg[appendPos + 6] = 0x00;
      fieldOffsets[i] = appendPos + 7;
      fieldLengths[i] = 0;
      appendPos += 7;
    }
  }

  return { rawMsg, dgLen, fieldOffsets, fieldLengths };
}

// ---------------------------------------------------------------------------
// LDS Security Object (eContent)
//
// SEQUENCE {
//   INTEGER 0 (version)
//   AlgorithmIdentifier { SHA-256 }
//   SEQUENCE OF { SEQUENCE { INTEGER dgNum, OCTET STRING hash } }
// }
//
// Circuit constraint: SHA-256 OID at byte offset 8
// This requires outer SEQUENCE length to use long form (0x81 xx)
// so we include 3 DG entries (DG1, DG2, DG13) to push length > 127
// ---------------------------------------------------------------------------

function buildEContent(dgHashes: Array<{ dgNumber: number; hash: Buffer }>): Buffer {
  // DG hash entries
  const dgEntries = dgHashes.map(({ dgNumber, hash }) =>
    Buffer.concat([
      Buffer.from([0x30, 0x25]),           // SEQUENCE, length 37
      Buffer.from([0x02, 0x01, dgNumber]), // INTEGER dgNumber
      Buffer.from([0x04, 0x20]),           // OCTET STRING, length 32
      hash,
    ]),
  );
  const dgSeqContent = Buffer.concat(dgEntries);
  const dgSeq = Buffer.concat([
    Buffer.from([0x30, dgSeqContent.length]),
    dgSeqContent,
  ]);

  // AlgorithmIdentifier { SHA-256 }
  const algId = Buffer.concat([
    Buffer.from([0x30, 0x0b]),       // SEQUENCE, length 11
    Buffer.from([0x06, 0x09]),       // OID, length 9
    SHA256_OID,
  ]);

  // version = 0
  const version = Buffer.from([0x02, 0x01, 0x00]);

  const innerContent = Buffer.concat([version, algId, dgSeq]);
  const innerLen = innerContent.length;

  // Use long form length (0x81 xx) to place OID at offset 8
  const outerHeader = Buffer.from([0x30, 0x81, innerLen]);

  return Buffer.concat([outerHeader, innerContent]);
}

// ---------------------------------------------------------------------------
// CMS signedAttrs
//
// SET {
//   SEQUENCE { contentType OID, SET { LDS Security Object OID } }
//   SEQUENCE { messageDigest OID, SET { OCTET STRING eContentHash } }
// }
//
// Circuit constraint: digest_offset - 15 must point to messageDigest OID
// ---------------------------------------------------------------------------

function buildSignedAttrs(eContentHash: Buffer): Buffer {
  // contentType attribute
  const contentTypeAttr = Buffer.concat([
    Buffer.from([0x30, 0x15]),          // SEQUENCE, length 21
    Buffer.from([0x06, 0x09]),          // OID tag + length
    CONTENT_TYPE_OID,                    // 9 bytes
    Buffer.from([0x31, 0x08]),          // SET, length 8
    Buffer.from([0x06, 0x06]),          // OID tag + length
    LDS_SECURITY_OBJECT_OID,            // 6 bytes
  ]);

  // messageDigest attribute
  const messageDigestAttr = Buffer.concat([
    Buffer.from([0x30, 0x2f]),          // SEQUENCE, length 47
    Buffer.from([0x06, 0x09]),          // OID tag + length
    MESSAGE_DIGEST_OID,                  // 9 bytes
    Buffer.from([0x31, 0x22]),          // SET, length 34
    Buffer.from([0x04, 0x20]),          // OCTET STRING, length 32
    eContentHash,                        // 32 bytes
  ]);

  const setContent = Buffer.concat([contentTypeAttr, messageDigestAttr]);
  // Outer SET (tag 0x31 for DER signing)
  return Buffer.concat([Buffer.from([0x31, setContent.length]), setContent]);
}

// ---------------------------------------------------------------------------
// SOD circuit inputs
// ---------------------------------------------------------------------------

export interface SODCircuitInputs {
  econtent: number[];        // [u8; 320] padded
  econtentLen: number;
  signedAttrs: number[];     // [u8; 200] padded
  signedAttrsLen: number;
  dgOffset: number;          // DG13 entry offset in eContent
  digestOffset: number;      // messageDigest value offset in signedAttrs
  signatureR: number[];      // [u8; 48]
  signatureS: number[];      // [u8; 48] canonical
  pubkeyX: number[];         // [u8; 48]
  pubkeyY: number[];         // [u8; 48]
}

function findDGEntry(econtent: Buffer, dgNumber: number): number {
  for (let i = 0; i < econtent.length - 38; i++) {
    if (
      econtent[i] === 0x30 &&
      econtent[i + 1] === 0x25 &&
      econtent[i + 2] === 0x02 &&
      econtent[i + 3] === 0x01 &&
      econtent[i + 4] === dgNumber &&
      econtent[i + 5] === 0x04 &&
      econtent[i + 6] === 0x20
    ) {
      return i;
    }
  }
  throw new Error(`DG${dgNumber} entry not found in eContent`);
}

function findMessageDigest(signedAttrs: Buffer): number {
  const oid = MESSAGE_DIGEST_OID;
  for (let i = 0; i <= signedAttrs.length - 45; i++) {
    let match = true;
    for (let j = 0; j < oid.length; j++) {
      if (signedAttrs[i + j] !== oid[j]) { match = false; break; }
    }
    if (match) {
      let pos = i + oid.length;
      if (signedAttrs[pos] === 0x31) {
        pos += 2;
        if (signedAttrs[pos] === 0x04 && signedAttrs[pos + 1] === 0x20) {
          return pos + 2;
        }
      }
    }
  }
  throw new Error('messageDigest not found in signedAttrs');
}

function parseEcdsaSig(sig: Buffer): { r: Buffer; s: Buffer } {
  let pos = 2;
  const rLen = sig[pos + 1]!;
  const rRaw = sig.slice(pos + 2, pos + 2 + rLen);
  pos = pos + 2 + rLen;
  const sLen = sig[pos + 1]!;
  const sRaw = sig.slice(pos + 2, pos + 2 + sLen);

  const r = rRaw.length > 48
    ? rRaw.slice(rRaw.length - 48)
    : Buffer.concat([Buffer.alloc(48 - rRaw.length), rRaw]);
  const s = sRaw.length > 48
    ? sRaw.slice(sRaw.length - 48)
    : Buffer.concat([Buffer.alloc(48 - sRaw.length), sRaw]);

  return { r, s };
}

function canonicalizeS(s: Buffer): Buffer {
  const sVal = BigInt('0x' + s.toString('hex'));
  if (sVal > HALF_N) {
    const canonical = CURVE_ORDER - sVal;
    return Buffer.from(canonical.toString(16).padStart(96, '0'), 'hex');
  }
  return s;
}

function parseTLV(buf: Buffer, offset: number) {
  const tag = buf[offset]!;
  let lenOff = offset + 1;
  let length: number;
  if (buf[lenOff]! < 0x80) {
    length = buf[lenOff]!;
    lenOff += 1;
  } else {
    const n = buf[lenOff]! & 0x7f;
    length = 0;
    for (let i = 0; i < n; i++) length = (length << 8) | buf[lenOff + 1 + i]!;
    lenOff += 1 + n;
  }
  return { tag, length, valueOffset: lenOff, totalLength: lenOff - offset + length };
}

function extractPubkeyXY(publicKey: crypto.KeyObject): { x: Buffer; y: Buffer } {
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  // SPKI: SEQUENCE { SEQUENCE(algId), BIT STRING(ecPoint) }
  const outer = parseTLV(spki, 0);
  let pos = outer.valueOffset;
  const algId = parseTLV(spki, pos);
  pos += algId.totalLength;
  const bitStr = parseTLV(spki, pos);
  // BIT STRING content: 00(unused bits) 04(uncompressed) x(48) y(48)
  const ecPoint = spki.slice(bitStr.valueOffset + 1, bitStr.valueOffset + bitStr.length);
  return {
    x: Buffer.from(ecPoint.slice(1, 49)),
    y: Buffer.from(ecPoint.slice(49, 97)),
  };
}

// ---------------------------------------------------------------------------
// Field packing (matches circuit packing: 4 x 31-byte field elements)
// ---------------------------------------------------------------------------

export function packString(value: string): bigint[] {
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

export type MerkleLeaf = {
  tagId: number;
  length: number;
  packedFields: bigint[];
  packedHash: bigint;
};

export function buildMerkleLeaves(
  fieldData: Record<number, string>,
  poseidon2Hash: (inputs: bigint[], len: number) => bigint,
): MerkleLeaf[] {
  const fields: MerkleLeaf[] = Array.from({ length: 32 }, (_, i) => {
    const tagId = i + 1;
    const value = fieldData[tagId];
    const valueBytes = value ? Buffer.from(value, 'utf-8') : Buffer.alloc(0);

    const packedFields: bigint[] = [];
    for (let f = 0; f < 4; f++) {
      let felt = 0n;
      for (let b = 0; b < 31; b++) {
        const byteIdx = f * 31 + b;
        if (byteIdx < valueBytes.length) {
          felt = felt * 256n + BigInt(valueBytes[byteIdx]!);
        }
      }
      packedFields.push(felt);
    }

    return { tagId, length: valueBytes.length, packedFields, packedHash: 0n };
  });

  // Compute packed_hash from immutable fields (indices 0, 2, 5, 7, 12)
  const immutablePacked: bigint[] = [];
  for (const idx of [0, 2, 5, 7, 12]) {
    immutablePacked.push(...fields[idx]!.packedFields);
  }
  const packedHash = poseidon2Hash(immutablePacked, 20);
  for (const f of fields) f.packedHash = packedHash;

  return fields;
}

// ---------------------------------------------------------------------------
// Full self-signed CCCD credential
// ---------------------------------------------------------------------------

export interface SelfSignedCCCD {
  credential: MatchableCredential;
  dg13Fields: Record<number, string>;
  dg13Bytes: Uint8Array;
  sodInputs: SODCircuitInputs;
  dg13CircuitInputs: DG13CircuitInputs;
  salt: bigint;
  dgHash: Buffer;            // SHA-256(DG13 bytes) for binding verification
  /** DSC certificate (base64 DER SPKI of the signing key) — for CSCA trust anchor testing. */
  dscCertificate: string;
}

export function createSelfSignedCCCD(
  dg13Fields: Record<number, string>,
  salt?: bigint,
): SelfSignedCCCD {
  // 1. Build DG13 bytes
  const dg13Bytes = buildDG13Bytes(dg13Fields);
  const dgHash = crypto.createHash('sha256').update(dg13Bytes).digest();

  // 2. Build dummy DG1/DG2 hashes (random) + real DG13 hash
  const dg1Hash = crypto.createHash('sha256').update(Buffer.from('DG1-dummy')).digest();
  const dg2Hash = crypto.createHash('sha256').update(Buffer.from('DG2-dummy')).digest();

  // 3. Build eContent (LDS Security Object)
  const econtent = buildEContent([
    { dgNumber: 1, hash: dg1Hash },
    { dgNumber: 2, hash: dg2Hash },
    { dgNumber: 13, hash: dgHash },
  ]);

  // 4. Hash eContent
  const econtentHash = crypto.createHash('sha256').update(econtent).digest();

  // 5. Build signedAttrs with messageDigest = SHA-256(eContent)
  const signedAttrs = buildSignedAttrs(econtentHash);

  // 6. Generate ECDSA brainpoolP384r1 keypair and sign
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'brainpoolP384r1',
  });
  const signatureDer = crypto.sign('SHA256', signedAttrs, privateKey);

  // 7. Parse and canonicalize signature
  const { r: sigR, s: sigS } = parseEcdsaSig(signatureDer);
  const canonicalS = canonicalizeS(sigS);

  // 8. Extract public key coordinates
  const { x: pubX, y: pubY } = extractPubkeyXY(publicKey);

  // 9. Find circuit offsets
  const dgOffset = findDGEntry(econtent, 13);
  const digestOffset = findMessageDigest(signedAttrs);

  // 10. Pad to circuit sizes
  const econtentArr = new Array(MAX_ECONTENT).fill(0);
  for (let i = 0; i < econtent.length; i++) econtentArr[i] = econtent[i]!;

  const signedAttrsArr = new Array(MAX_SIGNED_ATTRS).fill(0);
  for (let i = 0; i < signedAttrs.length; i++) signedAttrsArr[i] = signedAttrs[i]!;

  // 11. Generate salt
  if (salt === undefined) {
    const saltBytes = crypto.randomBytes(31);
    salt = BigInt('0x' + saltBytes.toString('hex'));
  }

  const sodInputs: SODCircuitInputs = {
    econtent: econtentArr,
    econtentLen: econtent.length,
    signedAttrs: signedAttrsArr,
    signedAttrsLen: signedAttrs.length,
    dgOffset,
    digestOffset,
    signatureR: Array.from(sigR),
    signatureS: Array.from(canonicalS),
    pubkeyX: Array.from(pubX),
    pubkeyY: Array.from(pubY),
  };

  const dg13CircuitInputs = buildDG13CircuitInputs(dg13Fields);

  const credential: MatchableCredential = {
    type: ['VerifiableCredential', 'CCCDCredential'],
    issuer: 'did:web:cccd.gov.vn',
    credentialSubject: {
      fullName: dg13Fields[2],
      dateOfBirth: dg13Fields[3],
      documentNumber: dg13Fields[1],
      gender: dg13Fields[4],
      nationality: dg13Fields[5],
      ethnicity: dg13Fields[6],
      religion: dg13Fields[7],
      hometown: dg13Fields[8],
      permanentAddress: dg13Fields[9],
      identifyingMarks: dg13Fields[10],
      issueDate: dg13Fields[11],
      expiryDate: dg13Fields[12],
      parentsInfo: dg13Fields[13],
      dg13: Buffer.from(dg13Bytes).toString('base64'),
    },
    proof: { dgProfile: 'VN-CCCD-2024' },
  };

  // Export DSC certificate (SPKI DER of the signing key, base64-encoded)
  const dscCertificate = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  return {
    credential,
    dg13Fields,
    dg13Bytes,
    sodInputs,
    dg13CircuitInputs,
    salt,
    dgHash,
    dscCertificate,
  };
}

// ---------------------------------------------------------------------------
// Pre-defined field data
// ---------------------------------------------------------------------------

export const PARENT_DG13_FIELDS: Record<number, string> = {
  1: '012345678901',     // documentNumber
  2: 'Nguyen Van A',     // fullName
  3: '15/03/1985',       // dateOfBirth
  4: 'Nam',              // gender
  5: 'Viet Nam',         // nationality
  6: 'Kinh',             // ethnicity
  7: 'Khong',            // religion
  8: 'Ha Noi',           // hometown
  9: '456 Pho Hue',      // permanentAddress
  10: 'Khong',           // identifyingMarks
  11: '01/01/2024',      // issueDate
  12: '01/01/2034',      // expiryDate
  13: 'Nguyen Van X',    // parentsInfo
};

export const CHILD_DG13_FIELDS: Record<number, string> = {
  1: '098765432109',
  2: 'Nguyen Van C',
  3: '15/06/2015',
  4: 'Nam',
  5: 'Viet Nam',
  6: 'Kinh',
  7: 'Khong',
  8: 'Ha Noi',
  9: '789 Le Loi',
  10: 'Khong',
  11: '01/06/2024',
  12: '01/06/2034',
  13: 'Nguyen Van A',
};

export const MOTHER_DG13_FIELDS: Record<number, string> = {
  1: '012345678902',
  2: 'Nguyen Thi B',
  3: '15/03/1995',
  4: 'Nu',
  5: 'Viet Nam',
  6: 'Kinh',
  7: 'Khong',
  8: 'Ha Noi',
  9: '123 Duong Lang',
  10: 'Khong',
  11: '01/01/2024',
  12: '01/01/2034',
  13: 'Nguyen Van A',
};

// Pre-built fixtures (each has unique keypair + SOD)
export const parentCCCD = createSelfSignedCCCD(PARENT_DG13_FIELDS);
export const childCCCD = createSelfSignedCCCD(CHILD_DG13_FIELDS);
export const motherCCCD = createSelfSignedCCCD(MOTHER_DG13_FIELDS);

/**
 * Creates a mock verifyDSC callback that trusts the given DSC certificates.
 * Extracts EC public key (x, y) from SPKI DER and marks as trusted.
 */
export function createMockVerifyDSC(trustedDscCerts: string[]) {
  const trustedSet = new Set(trustedDscCerts);
  return async (dscCertificate: string) => {
    const trusted = trustedSet.has(dscCertificate);
    const spki = Buffer.from(dscCertificate, 'base64');
    // Parse SPKI to extract EC point: SEQUENCE { SEQUENCE(algId), BIT STRING(04||x||y) }
    const outer = parseTLV(spki, 0);
    let pos = outer.valueOffset;
    const algId = parseTLV(spki, pos);
    pos += algId.totalLength;
    const bitStr = parseTLV(spki, pos);
    // BIT STRING: 00(unused bits) 04(uncompressed) x(48) y(48)
    const ecPoint = spki.slice(bitStr.valueOffset + 1, bitStr.valueOffset + bitStr.length);
    const x = Array.from(ecPoint.slice(1, 49));
    const y = Array.from(ecPoint.slice(49, 97));
    return { trusted, publicKey: { x, y } };
  };
}

// Non-CCCD credential for negative tests
export const passportCredential: MatchableCredential = {
  type: ['VerifiableCredential', 'PassportCredential'],
  issuer: 'did:web:passport.gov.vn',
  credentialSubject: {
    fullName: 'Nguyen Van B',
    dateOfBirth: '01/01/1990',
    passportNumber: 'B1234567',
  },
};

// Incomplete CCCD for edge-case tests
export const incompleteCCCD = createSelfSignedCCCD({
  1: '999888777666',
  2: 'Tran Thi D',
});
