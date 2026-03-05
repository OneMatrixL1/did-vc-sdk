import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import forge from 'node-forge';
import { Buffer } from 'buffer';
import { ec as EC, curves } from 'elliptic';

const { PresetCurve } = curves;

// OIDs
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_ECDSA_SHA384 = '1.2.840.10045.4.3.3';
const OID_RSA_SHA384 = '1.2.840.113549.1.1.12';
const OID_BRAINPOOL_P256R1 = '1.3.36.3.3.2.8.1.1.7';
const OID_BRAINPOOL_P384R1 = '1.3.36.3.3.2.8.1.1.11';

type HashAlg = 'SHA256' | 'SHA384';

export interface DGHashResult {
  dgNumber: number;
  expectedHash: string;
  calculatedHash: string;
  isValid: boolean;
}

export interface SignerCertificate {
  subject: string;
  issuer: string;
  validFrom: Date;
  validTo: Date;
}

export interface SODVerificationResult {
  signatureValid: boolean;
  certificateChainValid: boolean;
  passiveAuthSuccess: boolean;
  dgHashes: DGHashResult[];
  dsCertificate?: string;
  signerCertificate?: SignerCertificate;
}

function detectHashAlg(sigAlgoOID: string): HashAlg {
  return sigAlgoOID === OID_ECDSA_SHA384 || sigAlgoOID === OID_RSA_SHA384
    ? 'SHA384'
    : 'SHA256';
}

function hashWithForge(alg: HashAlg, data: Buffer): string {
  const md = alg === 'SHA384' ? forge.md.sha384.create() : forge.md.sha256.create();
  md.update(data.toString('binary'), 'raw');
  return md.digest().toHex();
}

function toArrayBuffer(buf: Buffer): ArrayBuffer {
  const ab = new ArrayBuffer(buf.byteLength);
  new Uint8Array(ab).set(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
  return ab;
}

/**
 * Extracts raw uncompressed EC public key point (04||X||Y) from SPKI DER bytes.
 */
function extractECPointFromSPKI(spkiDer: Buffer): Uint8Array {
  const asn1 = asn1js.fromBER(toArrayBuffer(spkiDer));
  if (asn1.offset === -1) throw new Error('Invalid SPKI ASN.1 DER');

  const spki = asn1.result as asn1js.Sequence;
  const subjectPublicKey = spki.valueBlock.value[1] as asn1js.BitString;
  if (subjectPublicKey.idBlock.tagNumber !== 3) throw new Error('Expected BIT STRING in SPKI');

  let raw = new Uint8Array(subjectPublicKey.valueBlock.valueHex);
  if (raw[0] === 0x00) raw = raw.slice(1); // strip unused-bits byte
  if (raw[0] !== 0x04) throw new Error('Only uncompressed EC points supported');

  return raw;
}

function buildBrainpoolCurve(oid: string, hashAlg: HashAlg) {
  if (oid === OID_BRAINPOOL_P256R1) {
    return new EC(new PresetCurve({
      type: 'short',
      prime: null,
      p: 'A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377',
      a: '7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9',
      b: '26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6',
      n: 'A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7',
      hash: hashAlg.toLowerCase(),
      gRed: false,
      g: [
        '8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262',
        '547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997',
      ],
    }));
  }

  // OID_BRAINPOOL_P384R1
  return new EC(new PresetCurve({
    type: 'short',
    prime: null,
    p: '8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53',
    a: '7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826',
    b: '04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11',
    n: '8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565',
    hash: hashAlg.toLowerCase(),
    gRed: false,
    g: [
      '1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E',
      '8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315',
    ],
  }));
}

/**
 * Low-level signature verification.
 * Uses Node.js crypto when available, falls back to elliptic for unsupported curves.
 */
async function verifySignatureLowLevel(
  hashAlg: HashAlg,
  data: Buffer,
  signature: Buffer,
  publicKeyDer: ArrayBuffer,
  curveOID: string,
): Promise<boolean> {
  if (typeof process !== 'undefined' && process.versions?.node) {
    try {
      const crypto = await import('crypto');
      return crypto.verify(
        hashAlg,
        data,
        {
          key: Buffer.from(publicKeyDer), format: 'der', type: 'spki', dsaEncoding: 'der',
        },
        signature,
      );
    } catch {
      // Fall through to elliptic
    }
  }

  const isBrainpool = curveOID === OID_BRAINPOOL_P256R1 || curveOID === OID_BRAINPOOL_P384R1;
  const ec = isBrainpool
    ? buildBrainpoolCurve(curveOID, hashAlg)
    : new EC('p256');

  const pubHex = Buffer.from(extractECPointFromSPKI(Buffer.from(publicKeyDer))).toString('hex');
  const key = ec.keyFromPublic(pubHex, 'hex');
  const hashHex = hashWithForge(hashAlg, data);

  return key.verify(hashHex, signature);
}

/**
 * Verifies the DS certificate was signed by the CSCA root.
 */
async function verifyCertificateChain(dsc: pkijs.Certificate, csca: pkijs.Certificate): Promise<boolean> {
  const signature = Buffer.from(dsc.signatureValue.valueBlock.valueHex);
  const tbsDer = Buffer.from(dsc.tbsView);
  const cscaPublicKeyDer = csca.subjectPublicKeyInfo.toSchema().toBER(false);
  const hashAlg = detectHashAlg(dsc.signatureAlgorithm.algorithmId);

  return verifySignatureLowLevel(hashAlg, tbsDer, signature, cscaPublicKeyDer, '');
}

/**
 * Verifies the CMS signature inside the SOD.
 */
async function verifySignature(signedData: pkijs.SignedData): Promise<boolean> {
  try {
    const signerInfo = signedData.signerInfos[0];
    const signature = Buffer.from(signerInfo.signature.valueBlock.valueHex);

    const schema = signerInfo.signedAttrs!.toSchema();
    schema.idBlock.tagClass = 1;
    schema.idBlock.tagNumber = 17;
    const signedAttrsDer = schema.toBER(false);

    const messageDigestAttr = signerInfo.signedAttrs!.attributes.find(
      (attr) => attr.type === OID_MESSAGE_DIGEST,
    );
    if (!messageDigestAttr) throw new Error('No messageDigest attribute in SOD');

    const digestValue = messageDigestAttr.values[0] as asn1js.OctetString;
    const expectedDigest = Buffer.from(digestValue.valueBlock.valueHex).toString('hex');

    const eContent = signedData.encapContentInfo.eContent!;
    const encapContent = eContent.valueBlock.valueHex;

    const hashAlg = detectHashAlg(signerInfo.signatureAlgorithm.algorithmId);
    const actualDigest = hashWithForge(hashAlg, Buffer.from(encapContent));

    if (expectedDigest !== actualDigest) return false;

    const certItem = signedData.certificates![0];
    if (!(certItem instanceof pkijs.Certificate)) {
      throw new Error('SOD contains unsupported certificate format');
    }
    const publicKeyDer = certItem.subjectPublicKeyInfo.toSchema().toBER(false);

    let curveOID = '';
    try {
      const parsed = asn1js.fromBER(publicKeyDer);
      const spki = parsed.result as asn1js.Sequence;
      const algorithmIdentifier = spki.valueBlock.value[0] as asn1js.Sequence;
      const parameters = algorithmIdentifier.valueBlock.value[1];
      curveOID = parameters ? (parameters as asn1js.ObjectIdentifier).valueBlock.toString() : '';
    } catch { /* ignore — RSA keys have no curve OID */ }

    return verifySignatureLowLevel(
      hashAlg,
      Buffer.from(signedAttrsDer),
      signature,
      publicKeyDer,
      curveOID,
    );
  } catch (e) {
    console.error('Signature verification failed:', e);
    return false;
  }
}

/**
 * Parses the SOD ASN.1 structure and returns the SignedData.
 * Handles both direct ContentInfo SEQUENCE and Tag 0x77 (Application 23) wrappers.
 */
async function parseSOD(sodBase64: string): Promise<pkijs.SignedData> {
  const sodBuffer = Buffer.from(sodBase64, 'base64');
  const asn1 = asn1js.fromBER(toArrayBuffer(sodBuffer));
  if (asn1.offset === -1) throw new Error('Failed to parse ASN.1 from SOD');

  const contentInfo = new pkijs.ContentInfo();
  const root = asn1.result as asn1js.Constructed;

  if (root.idBlock.tagClass === 1 && root.idBlock.tagNumber === 16) {
    contentInfo.fromSchema(root);
  } else if (root.idBlock.tagClass === 2 && root.idBlock.tagNumber === 23) {
    const inner = root.valueBlock.value[0];
    if (!inner || inner.idBlock.tagNumber !== 16) throw new Error('Invalid SOD wrapper content');
    contentInfo.fromSchema(inner);
  } else {
    const firstByte = sodBuffer.length > 0 ? `0x${sodBuffer[0]!.toString(16)}` : 'empty';
    throw new Error(`Unsupported SOD wrapper tag: ${firstByte}`);
  }

  if (!contentInfo.content) throw new Error('SOD ContentInfo has no content');

  if (typeof process !== 'undefined' && process.versions?.node) {
    const { webcrypto } = await import('crypto');
    const nodeCrypto = webcrypto as globalThis.Crypto;
    const engine = new pkijs.CryptoEngine({ crypto: nodeCrypto, subtle: nodeCrypto.subtle });
    pkijs.setEngine('node', nodeCrypto, engine);
  }

  return new pkijs.SignedData({ schema: contentInfo.content });
}

/**
 * Extracts the DS certificate info from SignedData.
 */
function extractCertificateInfo(cert: pkijs.Certificate): { dsCertificate: string; signerCertificate: SignerCertificate } {
  return {
    dsCertificate: Buffer.from(cert.toSchema().toBER(false)).toString('base64'),
    signerCertificate: {
      subject: cert.subject.typesAndValues.map((tv) => `${tv.type}=${tv.value.valueBlock.value}`).join(', '),
      issuer: cert.issuer.typesAndValues.map((tv) => `${tv.type}=${tv.value.valueBlock.value}`).join(', '),
      validFrom: cert.notBefore.value,
      validTo: cert.notAfter.value,
    },
  };
}

/**
 * Verifies DS certificate against the CSCA root.
 */
async function verifyCSCA(cert: pkijs.Certificate, cscaCertBase64: string): Promise<boolean> {
  try {
    const cscaBuffer = Buffer.from(cscaCertBase64, 'base64');
    const cscaAsn1 = asn1js.fromBER(toArrayBuffer(cscaBuffer));
    const csca = new pkijs.Certificate({ schema: cscaAsn1.result });
    return await verifyCertificateChain(cert, csca);
  } catch (e) {
    console.error('CSCA verification error:', e);
    return false;
  }
}

/**
 * Verifies Data Group hashes against those stored in the LDS Security Object.
 */
function verifyDGHashes(signedData: pkijs.SignedData, rawDataGroups: Record<string, string>): DGHashResult[] {
  const eContent = signedData.encapContentInfo.eContent!;
  const ldsAsn1 = asn1js.fromBER(eContent.valueBlock.valueHex);
  if (ldsAsn1.offset === -1) throw new Error('Failed to parse LDS Security Object');

  const ldsData = ldsAsn1.result as asn1js.Sequence;
  const dgHashesSequence = (ldsData.valueBlock.value[2] as asn1js.Sequence).valueBlock.value;
  const results: DGHashResult[] = [];

  for (const dgHash of dgHashesSequence) {
    const fields = (dgHash as asn1js.Sequence).valueBlock.value;
    const dgNumber = (fields[0] as asn1js.Integer).valueBlock.valueDec;
    const expectedHash = Buffer.from((fields[1] as asn1js.OctetString).valueBlock.valueHex).toString('hex');
    const rawDG = rawDataGroups[`dg${dgNumber}`];

    if (rawDG) {
      const calculatedHash = hashWithForge('SHA256', Buffer.from(rawDG, 'base64'));
      results.push({
        dgNumber, expectedHash, calculatedHash, isValid: expectedHash === calculatedHash,
      });
    }
  }

  return results;
}

/**
 * Passive Authentication verifier for ICAO 9303 SOD.
 * Checks the SOD CMS signature and verifies each Data Group hash.
 */
export class SODVerifier {
  static async verify(
    sodBase64: string,
    rawDataGroups: Record<string, string>,
    cscaCertBase64?: string,
  ): Promise<SODVerificationResult> {
    const signedData = await parseSOD(sodBase64);

    const signatureValid = await verifySignature(signedData);
    const dgHashes = verifyDGHashes(signedData, rawDataGroups);

    const result: SODVerificationResult = {
      signatureValid,
      certificateChainValid: false,
      passiveAuthSuccess: signatureValid && dgHashes.every((dg) => dg.isValid),
      dgHashes,
    };

    if (signedData.certificates?.length) {
      const certItem = signedData.certificates[0];
      if (!(certItem instanceof pkijs.Certificate)) {
        throw new Error('SOD contains unsupported certificate format');
      }

      const certInfo = extractCertificateInfo(certItem);
      result.dsCertificate = certInfo.dsCertificate;
      result.signerCertificate = certInfo.signerCertificate;

      if (cscaCertBase64) {
        result.certificateChainValid = await verifyCSCA(certItem, cscaCertBase64);
      }
    }

    return result;
  }
}
