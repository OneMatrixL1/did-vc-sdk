/**
 * SOD (Security Object Document) binary parser.
 *
 * Extracts raw byte arrays needed for ZKP circuit witnesses from the
 * CMS SignedData structure embedded in ICAO e-passport SOD.
 *
 * Ported from did-circuits/sdk/src/input/sod-parser.ts — uses Uint8Array
 * instead of Node.js Buffer for browser/mobile compatibility.
 */

// ---------------------------------------------------------------------------
// TLV (Tag-Length-Value) DER parsing
// ---------------------------------------------------------------------------

interface TLV {
  tag: number;
  length: number;
  headerLen: number;
  valueOffset: number;
  totalLength: number;
}

function parseTLV(buf: Uint8Array, offset: number): TLV {
  const tag = buf[offset]!;
  let lenOffset = offset + 1;
  let length: number;

  if (buf[lenOffset]! < 0x80) {
    length = buf[lenOffset]!;
    lenOffset += 1;
  } else {
    const numLenBytes = buf[lenOffset]! & 0x7f;
    length = 0;
    for (let i = 0; i < numLenBytes; i++) {
      length = (length << 8) | buf[lenOffset + 1 + i]!;
    }
    lenOffset += 1 + numLenBytes;
  }

  const headerLen = lenOffset - offset;
  return {
    tag,
    length,
    headerLen,
    valueOffset: lenOffset,
    totalLength: headerLen + length,
  };
}

// ---------------------------------------------------------------------------
// SOD structure navigation
// ---------------------------------------------------------------------------

/**
 * Navigate to the SignedData SEQUENCE inside a CMS ContentInfo.
 * Handles both raw SEQUENCE (0x30) and ICAO tag 0x77 wrappers.
 */
function navigateToSignedData(buf: Uint8Array): number {
  let pos = 0;
  const outer = parseTLV(buf, pos);
  pos = outer.valueOffset;

  // Handle tag 0x77 (Application 23) wrapper
  if (outer.tag === 0x77) {
    pos = parseTLV(buf, pos).valueOffset;
  }

  // Skip OID
  const oid = parseTLV(buf, pos);
  pos = oid.valueOffset + oid.length;

  // Enter [0] EXPLICIT wrapper
  pos = parseTLV(buf, pos).valueOffset;

  // Enter SignedData SEQUENCE
  return parseTLV(buf, pos).valueOffset;
}

// ---------------------------------------------------------------------------
// Public extraction functions
// ---------------------------------------------------------------------------

/** Extract eContent (LDS Security Object) from SOD. */
export function extractEContent(buf: Uint8Array): Uint8Array {
  let pos = navigateToSignedData(buf);

  // Skip version
  pos += parseTLV(buf, pos).totalLength;
  // Skip digestAlgorithms
  pos += parseTLV(buf, pos).totalLength;

  // EncapsulatedContentInfo
  const encap = parseTLV(buf, pos);
  pos = encap.valueOffset;

  // Skip OID
  pos += parseTLV(buf, pos).totalLength;

  // [0] EXPLICIT wrapper
  pos = parseTLV(buf, pos).valueOffset;

  // OCTET STRING containing eContent
  const octet = parseTLV(buf, pos);
  return buf.slice(octet.valueOffset, octet.valueOffset + octet.length);
}

/** Extract signed attributes DER and signature bytes from SOD's SignerInfo. */
export function extractSignerInfo(buf: Uint8Array): {
  signedAttrsDer: Uint8Array;
  signatureBytes: Uint8Array;
} {
  let pos = navigateToSignedData(buf);

  // Skip version, digestAlgorithms, encapContentInfo
  pos += parseTLV(buf, pos).totalLength;
  pos += parseTLV(buf, pos).totalLength;
  pos += parseTLV(buf, pos).totalLength;

  // Skip [0] certificates (if present)
  const certs = parseTLV(buf, pos);
  if ((certs.tag & 0xe0) === 0xa0) {
    pos += certs.totalLength;
  }

  // Skip [1] CRLs (if present)
  const maybeCrls = parseTLV(buf, pos);
  if (maybeCrls.tag === 0xa1) {
    pos += maybeCrls.totalLength;
  }

  // SignerInfos SET → first SignerInfo SEQUENCE
  pos = parseTLV(buf, pos).valueOffset;
  pos = parseTLV(buf, pos).valueOffset;

  // Skip version, sid, digestAlgorithm
  pos += parseTLV(buf, pos).totalLength;
  pos += parseTLV(buf, pos).totalLength;
  pos += parseTLV(buf, pos).totalLength;

  // signedAttrs [0] IMPLICIT
  const signedAttrs = parseTLV(buf, pos);
  const signedAttrsDer = new Uint8Array(signedAttrs.totalLength);
  signedAttrsDer.set(buf.slice(pos, pos + signedAttrs.totalLength));
  // Change tag from [0] IMPLICIT (0xA0) to SET (0x31) for hashing
  signedAttrsDer[0] = 0x31;

  pos = signedAttrs.valueOffset + signedAttrs.length;

  // Skip signatureAlgorithm
  pos += parseTLV(buf, pos).totalLength;

  // Signature OCTET STRING
  const sigOctet = parseTLV(buf, pos);
  const signatureBytes = buf.slice(sigOctet.valueOffset, sigOctet.valueOffset + sigOctet.length);

  return { signedAttrsDer, signatureBytes };
}

/** Extract DS certificate DER from SOD's certificates field. */
export function extractCertFromSOD(buf: Uint8Array): Uint8Array {
  let pos = navigateToSignedData(buf);

  // Skip version, digestAlgorithms, encapContentInfo
  pos += parseTLV(buf, pos).totalLength;
  pos += parseTLV(buf, pos).totalLength;
  pos += parseTLV(buf, pos).totalLength;

  // [0] certificates
  const certs = parseTLV(buf, pos);
  const certSeq = parseTLV(buf, certs.valueOffset);

  return buf.slice(certs.valueOffset, certs.valueOffset + certSeq.totalLength);
}

/**
 * Extract uncompressed EC public key (x, y) from a DER-encoded X.509 certificate.
 *
 * Walks: Certificate SEQUENCE → tbsCertificate → subjectPublicKeyInfo →
 * BIT STRING → uncompressed point (04 || x || y).
 */
export function extractPubkeyFromCert(certDer: Uint8Array): {
  x: Uint8Array;
  y: Uint8Array;
} {
  // Certificate SEQUENCE
  const cert = parseTLV(certDer, 0);
  // tbsCertificate SEQUENCE
  const tbs = parseTLV(certDer, cert.valueOffset);
  let pos = tbs.valueOffset;

  // Skip version [0] EXPLICIT (if present)
  const first = parseTLV(certDer, pos);
  if (first.tag === 0xa0) {
    pos += first.totalLength;
  }

  // Skip serialNumber
  pos += parseTLV(certDer, pos).totalLength;
  // Skip signature algorithm
  pos += parseTLV(certDer, pos).totalLength;
  // Skip issuer
  pos += parseTLV(certDer, pos).totalLength;
  // Skip validity
  pos += parseTLV(certDer, pos).totalLength;
  // Skip subject
  pos += parseTLV(certDer, pos).totalLength;

  // subjectPublicKeyInfo SEQUENCE
  const spki = parseTLV(certDer, pos);
  let spkiPos = spki.valueOffset;

  // Skip AlgorithmIdentifier
  spkiPos += parseTLV(certDer, spkiPos).totalLength;

  // BIT STRING containing the EC point
  const bitStr = parseTLV(certDer, spkiPos);
  // Skip unused-bits byte (0x00)
  const ecPoint = certDer.slice(bitStr.valueOffset + 1, bitStr.valueOffset + bitStr.length);

  if (ecPoint[0] !== 0x04) {
    throw new Error('Only uncompressed EC points (0x04) are supported');
  }

  const coordLen = (ecPoint.length - 1) / 2;
  return {
    x: ecPoint.slice(1, 1 + coordLen),
    y: ecPoint.slice(1 + coordLen),
  };
}

// ---------------------------------------------------------------------------
// Circuit-specific helpers
// ---------------------------------------------------------------------------

/**
 * Find a DataGroup entry in eContent by DG number.
 * Searches for the pattern: SEQUENCE(0x30) len=0x25, INTEGER tag=dgNumber, OCTET STRING len=0x20.
 */
export function findDGEntry(econtent: Uint8Array, dgNumber: number): number {
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
  return -1;
}

/**
 * Find the messageDigest attribute value offset within signed attributes.
 * OID 1.2.840.113549.1.9.4 = messageDigest.
 */
export function findMessageDigest(signedAttrs: Uint8Array): number {
  const oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

  for (let i = 0; i <= signedAttrs.length - 45; i++) {
    let match = true;
    for (let j = 0; j < oid.length; j++) {
      if (signedAttrs[i + j] !== oid[j]) {
        match = false;
        break;
      }
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
  return -1;
}

/** Parse DER-encoded ECDSA signature into r and s (padded to coordLen bytes). */
export function parseEcdsaSig(
  sigBuf: Uint8Array,
  coordLen = 48,
): { r: Uint8Array; s: Uint8Array } {
  let pos = 2; // skip SEQUENCE tag + length

  const rLen = sigBuf[pos + 1]!;
  const rRaw = sigBuf.slice(pos + 2, pos + 2 + rLen);
  pos = pos + 2 + rLen;

  const sLen = sigBuf[pos + 1]!;
  const sRaw = sigBuf.slice(pos + 2, pos + 2 + sLen);

  return {
    r: padOrTrim(rRaw, coordLen),
    s: padOrTrim(sRaw, coordLen),
  };
}

function padOrTrim(buf: Uint8Array, len: number): Uint8Array {
  if (buf.length > len) {
    return buf.slice(buf.length - len);
  }
  if (buf.length < len) {
    const padded = new Uint8Array(len);
    padded.set(buf, len - buf.length);
    return padded;
  }
  return buf;
}

// ---------------------------------------------------------------------------
// BrainpoolP384r1 S-value canonicalization
// ---------------------------------------------------------------------------

const BRAINPOOL_ORDER = BigInt(
  '0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565',
);

/**
 * Canonicalize ECDSA S value for BrainpoolP384r1.
 * If s > order/2, replace with order - s (low-S normalization).
 */
export function canonicalizeS(s: Uint8Array): Uint8Array {
  const sHex = Array.from(s).map(b => b.toString(16).padStart(2, '0')).join('');
  const sVal = BigInt('0x' + sHex);

  if (sVal > BRAINPOOL_ORDER / 2n) {
    const canonical = BRAINPOOL_ORDER - sVal;
    const hex = canonical.toString(16).padStart(s.length * 2, '0');
    const result = new Uint8Array(s.length);
    for (let i = 0; i < result.length; i++) {
      result[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return result;
  }

  return s;
}

// ---------------------------------------------------------------------------
// Composite: build full SOD witness data
// ---------------------------------------------------------------------------

export interface SODWitnessData {
  pubkeyX: number[];       // 48 bytes
  pubkeyY: number[];       // 48 bytes
  econtent: number[];      // padded to 320
  econtentLen: number;
  signedAttrs: number[];   // padded to 200
  signedAttrsLen: number;
  dgOffset: number;
  digestOffset: number;
  signatureR: number[];    // 48 bytes
  signatureS: number[];    // 48 bytes, canonicalized
}

/**
 * Parse SOD base64 and build all data needed for sod-verify and dg-map circuits.
 */
export function buildSODWitnessData(sodBase64: string): SODWitnessData {
  const sodBytes = base64ToUint8Array(sodBase64);

  const econtent = extractEContent(sodBytes);
  if (econtent.length > 320) {
    throw new Error(`eContent ${econtent.length} bytes exceeds 320 max`);
  }

  const { signedAttrsDer, signatureBytes } = extractSignerInfo(sodBytes);
  if (signedAttrsDer.length > 200) {
    throw new Error(`signedAttrs ${signedAttrsDer.length} bytes exceeds 200 max`);
  }

  const digestOffset = findMessageDigest(signedAttrsDer);
  if (digestOffset < 0) {
    throw new Error('messageDigest not found in signedAttrs');
  }

  const dgOffset = findDGEntry(econtent, 13);
  if (dgOffset < 0) {
    throw new Error('DG13 entry not found in eContent');
  }

  const { r, s } = parseEcdsaSig(signatureBytes);
  const finalS = canonicalizeS(s);

  const certDer = extractCertFromSOD(sodBytes);
  const pubkey = extractPubkeyFromCert(certDer);

  // Pad to circuit-expected sizes
  const econtentArr = new Array<number>(320).fill(0);
  for (let i = 0; i < econtent.length; i++) econtentArr[i] = econtent[i]!;

  const signedAttrsArr = new Array<number>(200).fill(0);
  for (let i = 0; i < signedAttrsDer.length; i++) signedAttrsArr[i] = signedAttrsDer[i]!;

  return {
    pubkeyX: Array.from(pubkey.x),
    pubkeyY: Array.from(pubkey.y),
    econtent: econtentArr,
    econtentLen: econtent.length,
    signedAttrs: signedAttrsArr,
    signedAttrsLen: signedAttrsDer.length,
    dgOffset,
    digestOffset,
    signatureR: Array.from(r),
    signatureS: Array.from(finalS),
  };
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function base64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
