/**
 * SOD parser tests — builds real CMS ContentInfo binary structures and
 * verifies the parser extracts correct byte ranges.
 */
import { describe, it, expect } from 'vitest';
import {
  extractEContent,
  extractSignerInfo,
  extractCertFromSOD,
  extractPubkeyFromCert,
  findDGEntry,
  findMessageDigest,
  parseEcdsaSig,
  canonicalizeS,
  buildSODWitnessData,
} from '../../src/proof-system/sod-parser.js';

// ---------------------------------------------------------------------------
// Helpers: build real DER structures
// ---------------------------------------------------------------------------

/** Encode DER length (handles short + long form). */
function derLength(len: number): number[] {
  if (len < 0x80) return [len];
  if (len < 0x100) return [0x81, len];
  return [0x82, (len >> 8) & 0xff, len & 0xff];
}

/** Build a DER SEQUENCE containing raw content bytes. */
function derSequence(content: number[]): number[] {
  return [0x30, ...derLength(content.length), ...content];
}

/** Build a DER SET containing raw content bytes. */
function derSet(content: number[]): number[] {
  return [0x31, ...derLength(content.length), ...content];
}

/** Build a DER OCTET STRING. */
function derOctetString(data: number[]): number[] {
  return [0x04, ...derLength(data.length), ...data];
}

/** Build a DER INTEGER from a byte array. */
function derInteger(bytes: number[]): number[] {
  return [0x02, ...derLength(bytes.length), ...bytes];
}

/** Build a DER OID (pre-encoded value bytes). */
function derOID(encoded: number[]): number[] {
  return [0x06, ...derLength(encoded.length), ...encoded];
}

/** Build a context-tagged [n] EXPLICIT wrapper. */
function derExplicit(tagNum: number, content: number[]): number[] {
  return [0xa0 | tagNum, ...derLength(content.length), ...content];
}

/** Build a context-tagged [n] IMPLICIT wrapper. */
function derImplicit(tagNum: number, content: number[]): number[] {
  return [0xa0 | tagNum, ...derLength(content.length), ...content];
}

/** Build a BIT STRING wrapping content. */
function derBitString(data: number[]): number[] {
  // 0x00 = unused bits count
  return [0x03, ...derLength(data.length + 1), 0x00, ...data];
}

/** OID for signedData (1.2.840.113549.1.7.2) */
const OID_SIGNED_DATA = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/** OID for sha-256 */
const OID_SHA256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/** OID for ldsSecurityObject */
const OID_LDS = [0x67, 0x81, 0x08, 0x01, 0x01, 0x01];
/** OID for messageDigest (1.2.840.113549.1.9.4) */
const OID_MSG_DIGEST = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

// Fixed test data
// eContent must contain a DG13 entry for buildSODWitnessData to succeed.
// Pattern: SEQUENCE(30 25) { INTEGER(02 01 0D), OCTET STRING(04 20, 32 bytes hash) }
const DG13_HASH = Array.from({ length: 32 }, (_, i) => 0x40 + i);
const DG13_ENTRY = [0x30, 0x25, 0x02, 0x01, 13, 0x04, 0x20, ...DG13_HASH];
const ECONTENT_PAYLOAD = [0xDE, 0xAD, ...DG13_ENTRY, 0xBE, 0xEF];
const DIGEST_VALUE = Array.from({ length: 32 }, (_, i) => i); // 0x00..0x1f
const SIGNATURE_DER_R = Array.from({ length: 48 }, () => 0xAA);
const SIGNATURE_DER_S = Array.from({ length: 48 }, () => 0x11);
const PUBKEY_X = Array.from({ length: 48 }, () => 0xBB);
const PUBKEY_Y = Array.from({ length: 48 }, () => 0xCC);

/**
 * Build a real CMS ContentInfo → SignedData structure as raw bytes.
 * This mirrors exactly the structure our parser navigates.
 */
function buildRealSOD(): Uint8Array {
  // eContent (wrapped in OID + [0] EXPLICIT + OCTET STRING)
  const eContentOctet = derOctetString(ECONTENT_PAYLOAD);
  const eContentExplicit = derExplicit(0, eContentOctet);
  const encapContentInfo = derSequence([...derOID(OID_LDS), ...eContentExplicit]);

  // signedAttrs as [0] IMPLICIT SET
  const digestAttr = derSequence([
    ...derOID(OID_MSG_DIGEST),
    ...derSet(derOctetString(DIGEST_VALUE)),
  ]);
  const signedAttrsContent = [...digestAttr];
  const signedAttrsImplicit = derImplicit(0, signedAttrsContent);

  // Signature OCTET STRING (DER-encoded ECDSA r,s)
  const ecdsaDer = derSequence([
    ...derInteger(SIGNATURE_DER_R),
    ...derInteger(SIGNATURE_DER_S),
  ]);
  const signatureOctet = derOctetString(ecdsaDer);

  // Certificate: minimal TBSCert with SPKI containing EC point
  const ecPoint = [0x04, ...PUBKEY_X, ...PUBKEY_Y]; // uncompressed
  const spki = derSequence([
    ...derSequence(derOID(OID_SHA256)), // algorithm identifier (dummy)
    ...derBitString(ecPoint),
  ]);
  const tbsCert = derSequence([
    ...derExplicit(0, derInteger([0x02])), // version v3
    ...derInteger([0x01]),                  // serial
    ...derSequence(derOID(OID_SHA256)),     // sig algorithm
    ...derSequence([]),                     // issuer
    ...derSequence([]),                     // validity
    ...derSequence([]),                     // subject
    ...spki,
  ]);
  const cert = derSequence([
    ...tbsCert,
    ...derSequence(derOID(OID_SHA256)),     // sig algorithm
    ...derBitString([0x00]),                // signature value (dummy)
  ]);
  const certificatesImplicit = derImplicit(0, cert);

  // SignerInfo
  const signerInfo = derSequence([
    ...derInteger([0x01]),                  // version
    ...derSequence([]),                     // sid (empty for test)
    ...derSequence(derOID(OID_SHA256)),     // digestAlgorithm
    ...signedAttrsImplicit,                 // signedAttrs [0]
    ...derSequence(derOID(OID_SHA256)),     // signatureAlgorithm
    ...signatureOctet,                      // signature
  ]);

  // SignedData
  const signedData = derSequence([
    ...derInteger([0x01]),                  // version
    ...derSet(derSequence(derOID(OID_SHA256))), // digestAlgorithms
    ...encapContentInfo,
    ...certificatesImplicit,
    ...derSet(signerInfo),                  // signerInfos
  ]);

  // ContentInfo
  const contentInfo = derSequence([
    ...derOID(OID_SIGNED_DATA),
    ...derExplicit(0, signedData),
  ]);

  return new Uint8Array(contentInfo);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SOD parser with real CMS binary', () => {
  const sod = buildRealSOD();

  it('extractEContent returns the exact eContent payload', () => {
    const econtent = extractEContent(sod);
    expect(Array.from(econtent)).toEqual(ECONTENT_PAYLOAD);
  });

  it('extractSignerInfo returns signedAttrs with tag changed to 0x31', () => {
    const { signedAttrsDer } = extractSignerInfo(sod);
    // First byte must be 0x31 (SET) not 0xA0 (IMPLICIT [0])
    expect(signedAttrsDer[0]).toBe(0x31);
    // Must contain the messageDigest OID
    const oidBytes = OID_MSG_DIGEST;
    let found = false;
    for (let i = 0; i < signedAttrsDer.length - oidBytes.length; i++) {
      if (oidBytes.every((b, j) => signedAttrsDer[i + j] === b)) {
        found = true;
        break;
      }
    }
    expect(found).toBe(true);
  });

  it('extractSignerInfo returns signature bytes containing r and s', () => {
    const { signatureBytes } = extractSignerInfo(sod);
    // signatureBytes is the DER-encoded ECDSA signature
    // Parse it and verify r/s
    const { r, s } = parseEcdsaSig(signatureBytes);
    expect(Array.from(r)).toEqual(SIGNATURE_DER_R);
    expect(Array.from(s)).toEqual(SIGNATURE_DER_S);
  });

  it('extractCertFromSOD returns a valid certificate DER', () => {
    const certDer = extractCertFromSOD(sod);
    // Certificate starts with SEQUENCE tag
    expect(certDer[0]).toBe(0x30);
    // Should be large enough to contain SPKI
    expect(certDer.length).toBeGreaterThan(50);
  });

  it('extractPubkeyFromCert extracts correct x,y coordinates', () => {
    const certDer = extractCertFromSOD(sod);
    const { x, y } = extractPubkeyFromCert(certDer);
    expect(Array.from(x)).toEqual(PUBKEY_X);
    expect(Array.from(y)).toEqual(PUBKEY_Y);
  });
});

describe('findDGEntry', () => {
  it('finds DG13 in a real eContent-like structure', () => {
    // Build an LDS Security Object fragment with DG1 and DG13 entries
    // Each entry: SEQUENCE(30 25) { INTEGER(02 01 dgNum), OCTET STRING(04 20 ...32 bytes...) }
    const dg1Entry = [0x30, 0x25, 0x02, 0x01, 1, 0x04, 0x20, ...new Array(32).fill(0xAA)];
    const dg13Entry = [0x30, 0x25, 0x02, 0x01, 13, 0x04, 0x20, ...new Array(32).fill(0xBB)];
    const econtent = new Uint8Array([...dg1Entry, ...dg13Entry]);

    expect(findDGEntry(econtent, 1)).toBe(0);
    expect(findDGEntry(econtent, 13)).toBe(dg1Entry.length);
    expect(findDGEntry(econtent, 2)).toBe(-1);
  });
});

describe('findMessageDigest', () => {
  it('finds digest value in real signedAttrs structure', () => {
    // Build: SET { SEQUENCE { OID msgDigest, SET { OCTET STRING(32 bytes) } } }
    const digestValue = Array.from({ length: 32 }, (_, i) => 0x50 + i);
    const signedAttrs = new Uint8Array([
      0x31, 0x80, // SET (using dummy length)
      ...derSequence([
        ...derOID(OID_MSG_DIGEST),
        ...derSet(derOctetString(digestValue)),
      ]),
    ]);

    const offset = findMessageDigest(signedAttrs);
    expect(offset).toBeGreaterThan(0);
    // Verify bytes at offset match the digest
    for (let i = 0; i < 32; i++) {
      expect(signedAttrs[offset + i]).toBe(digestValue[i]);
    }
  });
});

describe('parseEcdsaSig', () => {
  it('parses real DER ECDSA with leading zero padding', () => {
    // r has leading 0x00 (DER integer padding for positive), s is short
    const r = [0x00, 0x01, 0x02, 0x03, 0x04];
    const s = [0x05, 0x06];
    const der = new Uint8Array(derSequence([...derInteger(r), ...derInteger(s)]));

    const result = parseEcdsaSig(der, 4);
    // r should be trimmed to last 4 bytes
    expect(Array.from(result.r)).toEqual([0x01, 0x02, 0x03, 0x04]);
    // s should be left-padded to 4 bytes
    expect(Array.from(result.s)).toEqual([0x00, 0x00, 0x05, 0x06]);
  });
});

describe('canonicalizeS', () => {
  const BRAINPOOL_ORDER = BigInt(
    '0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565',
  );
  const HALF_ORDER = BRAINPOOL_ORDER / 2n;

  it('leaves low-S values unchanged', () => {
    // S = 1 (well below half-order)
    const s = new Uint8Array(48);
    s[47] = 1;
    expect(canonicalizeS(s)).toEqual(s);
  });

  it('leaves S exactly at half-order unchanged', () => {
    const hex = HALF_ORDER.toString(16).padStart(96, '0');
    const s = new Uint8Array(48);
    for (let i = 0; i < 48; i++) s[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    // S == halfOrder should NOT be canonicalized (only > triggers it)
    expect(canonicalizeS(s)).toEqual(s);
  });

  it('canonicalizes S = order - 1 to 1', () => {
    const val = BRAINPOOL_ORDER - 1n;
    const hex = val.toString(16).padStart(96, '0');
    const s = new Uint8Array(48);
    for (let i = 0; i < 48; i++) s[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);

    const result = canonicalizeS(s);
    const resultVal = BigInt('0x' + Array.from(result).map(b => b.toString(16).padStart(2, '0')).join(''));
    expect(resultVal).toBe(1n);
  });

  it('canonicalizes S = order - 2 to 2', () => {
    const val = BRAINPOOL_ORDER - 2n;
    const hex = val.toString(16).padStart(96, '0');
    const s = new Uint8Array(48);
    for (let i = 0; i < 48; i++) s[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);

    const result = canonicalizeS(s);
    const resultVal = BigInt('0x' + Array.from(result).map(b => b.toString(16).padStart(2, '0')).join(''));
    expect(resultVal).toBe(2n);
  });
});

describe('buildSODWitnessData end-to-end', () => {
  it('builds witness from a real CMS structure', () => {
    const sod = buildRealSOD();
    const b64 = btoa(String.fromCharCode(...sod));

    const witness = buildSODWitnessData(b64);

    // Verify extracted pubkey matches what we put in
    expect(witness.pubkeyX).toEqual(PUBKEY_X);
    expect(witness.pubkeyY).toEqual(PUBKEY_Y);

    // eContent padded to 320
    expect(witness.econtent).toHaveLength(320);
    expect(witness.econtent.slice(0, ECONTENT_PAYLOAD.length)).toEqual(ECONTENT_PAYLOAD);
    expect(witness.econtent[ECONTENT_PAYLOAD.length]).toBe(0); // padding

    expect(witness.econtentLen).toBe(ECONTENT_PAYLOAD.length);

    // signedAttrs padded to 200
    expect(witness.signedAttrs).toHaveLength(200);
    expect(witness.signedAttrsLen).toBeGreaterThan(0);
    expect(witness.signedAttrs[0]).toBe(0x31); // SET tag

    // Signature r,s should be 48 bytes each
    expect(witness.signatureR).toHaveLength(48);
    expect(witness.signatureS).toHaveLength(48);
    expect(witness.signatureR).toEqual(SIGNATURE_DER_R);

    // digestOffset should be positive
    expect(witness.digestOffset).toBeGreaterThan(0);
  });
});
