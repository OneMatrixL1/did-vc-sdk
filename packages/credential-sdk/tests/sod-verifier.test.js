import crypto from "crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { SODVerifier } from "../src/icao/sod-verifier";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toArrayBuffer(buf) {
  const ab = new ArrayBuffer(buf.byteLength);
  new Uint8Array(ab).set(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
  return ab;
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest();
}

// ---------------------------------------------------------------------------
// Synthetic SOD fixture generator
//
// Builds a valid ICAO 9303 SOD entirely with raw asn1js ASN.1 primitives,
// avoiding pkijs serialization quirks. The resulting structure is:
//
//   ContentInfo (SEQUENCE) {
//     contentType: OID signedData
//     content: [0] EXPLICIT SignedData {
//       version: 1
//       digestAlgorithms: SET OF { AlgorithmIdentifier sha256 }
//       encapContentInfo: {
//         eContentType: OID ldsSecurityObject
//         eContent: [0] EXPLICIT OCTET STRING { LDS Security Object DER }
//       }
//       certificates: [0] IMPLICIT { Certificate DER }
//       signerInfos: SET OF { SignerInfo }
//     }
//   }
// ---------------------------------------------------------------------------

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_LDS_SECURITY_OBJECT = "2.23.136.1.1.1";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_RSA_SHA256 = "1.2.840.113549.1.1.11";

/**
 * Build the LDS Security Object ASN.1 structure:
 *   SEQUENCE {
 *     INTEGER 0,
 *     AlgorithmIdentifier { sha256 },
 *     SEQUENCE OF { SEQUENCE { INTEGER dgNumber, OCTET STRING hash } }
 *   }
 */
function buildLDSSecurityObject(dgEntries) {
  const dgHashValues = dgEntries.map(({ dgNumber, hash }) =>
    new asn1js.Sequence({
      value: [
        new asn1js.Integer({ value: dgNumber }),
        new asn1js.OctetString({ valueHex: toArrayBuffer(hash) }),
      ],
    })
  );

  return new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 0 }),
      new asn1js.Sequence({
        value: [new asn1js.ObjectIdentifier({ value: OID_SHA256 })],
      }),
      new asn1js.Sequence({ value: dgHashValues }),
    ],
  });
}

/**
 * Build a self-signed X.509 v3 certificate as raw DER bytes using asn1js.
 * Returns { certDer: Buffer, privateKey: crypto.KeyObject }.
 */
function buildCertificateDER({ subjectCN, issuerCN, publicKey, signingKey }) {
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });

  // Build Name for issuer/subject: SEQUENCE { SET { SEQUENCE { OID CN, UTF8String } } }
  function buildName(cn) {
    return new asn1js.Sequence({
      value: [
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: "2.5.4.3" }),
                new asn1js.Utf8String({ value: cn }),
              ],
            }),
          ],
        }),
      ],
    });
  }

  // Validity: SEQUENCE { UTCTime notBefore, UTCTime notAfter }
  const validity = new asn1js.Sequence({
    value: [
      new asn1js.UTCTime({ valueDate: new Date("2020-01-01T00:00:00Z") }),
      new asn1js.UTCTime({ valueDate: new Date("2030-01-01T00:00:00Z") }),
    ],
  });

  // AlgorithmIdentifier for RSA-SHA256
  const rsaSha256AlgId = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: OID_RSA_SHA256 }),
      new asn1js.Null(),
    ],
  });

  // Parse SPKI from DER
  const spkiAsn1 = asn1js.fromBER(toArrayBuffer(publicKeyDer));

  // TBSCertificate
  const tbsCertificate = new asn1js.Sequence({
    value: [
      // version [0] EXPLICIT INTEGER 2 (v3)
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.Integer({ value: 2 })],
      }),
      // serialNumber
      new asn1js.Integer({ value: 1 }),
      // signature algorithm
      rsaSha256AlgId,
      // issuer
      buildName(issuerCN),
      // validity
      validity,
      // subject
      buildName(subjectCN),
      // subjectPublicKeyInfo
      spkiAsn1.result,
    ],
  });

  const tbsDer = Buffer.from(tbsCertificate.toBER(false));
  const tbsSignature = crypto.sign("SHA256", tbsDer, signingKey);

  // Full Certificate: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  const certificate = new asn1js.Sequence({
    value: [
      tbsCertificate,
      rsaSha256AlgId,
      new asn1js.BitString({ valueHex: toArrayBuffer(tbsSignature) }),
    ],
  });

  return Buffer.from(certificate.toBER(false));
}

/**
 * Generate a self-signed RSA certificate.
 * Returns { certDer: Buffer, privateKey: crypto.KeyObject }.
 */
function generateSelfSignedCert() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  const certDer = buildCertificateDER({
    subjectCN: "Test DS",
    issuerCN: "Test CSCA",
    publicKey,
    signingKey: privateKey,
  });

  return { certDer, privateKey };
}

/**
 * Generate a CSCA root certificate (self-signed) and a DS certificate signed by it.
 * Returns { cscaCertDer: Buffer, dsCertDer: Buffer, dsPrivateKey: crypto.KeyObject }.
 */
function generateCertificateChain() {
  const { publicKey: cscaPublicKey, privateKey: cscaPrivateKey } =
    crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const { publicKey: dsPublicKey, privateKey: dsPrivateKey } =
    crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

  const cscaCertDer = buildCertificateDER({
    subjectCN: "Test CSCA Root",
    issuerCN: "Test CSCA Root",
    publicKey: cscaPublicKey,
    signingKey: cscaPrivateKey,
  });

  const dsCertDer = buildCertificateDER({
    subjectCN: "Test DS Certificate",
    issuerCN: "Test CSCA Root",
    publicKey: dsPublicKey,
    signingKey: cscaPrivateKey,
  });

  return { cscaCertDer, dsCertDer, dsPrivateKey };
}

/**
 * Build signed attributes as a SET (tag 0x31) for signing, and also as
 * a context-tagged [0] IMPLICIT SET for embedding in SignerInfo.
 *
 * Returns { signedAttrsDerForSigning: Buffer, signedAttrsImplicit: asn1js.Constructed }
 */
function buildSignedAttrs(ldsDigest) {
  // contentType attribute
  const contentTypeAttr = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: OID_CONTENT_TYPE }),
      new asn1js.Set({
        value: [new asn1js.ObjectIdentifier({ value: OID_LDS_SECURITY_OBJECT })],
      }),
    ],
  });

  // messageDigest attribute
  const messageDigestAttr = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: OID_MESSAGE_DIGEST }),
      new asn1js.Set({
        value: [new asn1js.OctetString({ valueHex: toArrayBuffer(ldsDigest) })],
      }),
    ],
  });

  // For signing: encode as SET (UNIVERSAL tag 17)
  const signedAttrsSet = new asn1js.Set({
    value: [contentTypeAttr, messageDigestAttr],
  });
  const signedAttrsDerForSigning = Buffer.from(signedAttrsSet.toBER(false));

  // For embedding in SignerInfo: IMPLICIT [0] (context class 3, tagNumber 0, constructed)
  const signedAttrsImplicit = new asn1js.Constructed({
    idBlock: { tagClass: 3, tagNumber: 0 },
    value: [contentTypeAttr, messageDigestAttr],
  });

  return { signedAttrsDerForSigning, signedAttrsImplicit };
}

/**
 * Build the IssuerAndSerialNumber from cert DER for SignerInfo.sid.
 */
function buildIssuerAndSerialNumber(certDer) {
  const certAsn1 = asn1js.fromBER(toArrayBuffer(certDer));
  const tbsCert = certAsn1.result.valueBlock.value[0];
  // TBSCertificate fields: [0]version, serialNumber, sigAlg, issuer, ...
  // With explicit version tag at index 0, serial is index 1, sigAlg is 2, issuer is 3
  const serialNumber = tbsCert.valueBlock.value[1];
  const issuer = tbsCert.valueBlock.value[3];

  return new asn1js.Sequence({
    value: [issuer, serialNumber],
  });
}

/**
 * Build a complete CMS ContentInfo wrapping SignedData for a synthetic SOD.
 * Built entirely with raw asn1js to avoid pkijs serialization issues.
 *
 * @param {Object} opts
 * @param {Record<number, Buffer>} opts.dgData - map of DG number to raw DG content
 * @param {Buffer} opts.certDer - DER-encoded DS certificate
 * @param {crypto.KeyObject} opts.privateKey - private key for signing
 * @returns {string} base64-encoded ContentInfo DER
 */
function buildSOD({ dgData, certDer, privateKey }) {
  // 1. Build LDS Security Object
  const dgEntries = Object.entries(dgData).map(([num, data]) => ({
    dgNumber: Number(num),
    hash: sha256(data),
  }));
  const ldsObject = buildLDSSecurityObject(dgEntries);
  const ldsObjectDer = ldsObject.toBER(false);

  // 2. Compute messageDigest (SHA-256 of LDS Security Object DER)
  const ldsDigest = sha256(Buffer.from(ldsObjectDer));

  // 3. Build signed attributes and sign them
  const { signedAttrsDerForSigning, signedAttrsImplicit } = buildSignedAttrs(ldsDigest);
  const signatureValue = crypto.sign("SHA256", signedAttrsDerForSigning, privateKey);

  // 4. Build IssuerAndSerialNumber from cert
  const issuerAndSerialNumber = buildIssuerAndSerialNumber(certDer);

  // 5. AlgorithmIdentifier helpers
  const sha256AlgId = new asn1js.Sequence({
    value: [new asn1js.ObjectIdentifier({ value: OID_SHA256 })],
  });
  const rsaSha256AlgId = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: OID_RSA_SHA256 }),
      new asn1js.Null(),
    ],
  });

  // 6. Build SignerInfo
  const signerInfo = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 1 }), // version
      issuerAndSerialNumber,             // sid
      sha256AlgId,                       // digestAlgorithm
      signedAttrsImplicit,               // signedAttrs [0] IMPLICIT
      rsaSha256AlgId,                    // signatureAlgorithm
      new asn1js.OctetString({ valueHex: toArrayBuffer(signatureValue) }), // signature
    ],
  });

  // 7. Build encapContentInfo with eContent wrapped in [0] EXPLICIT
  const encapContentInfo = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: OID_LDS_SECURITY_OBJECT }),
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [
          new asn1js.OctetString({ valueHex: ldsObjectDer }),
        ],
      }),
    ],
  });

  // 8. Parse the certificate DER into an ASN.1 object for embedding
  const certAsn1 = asn1js.fromBER(toArrayBuffer(certDer));

  // 9. Build certificates [0] IMPLICIT SET OF Certificate
  const certificatesImplicit = new asn1js.Constructed({
    idBlock: { tagClass: 3, tagNumber: 0 },
    value: [certAsn1.result],
  });

  // 10. Build SignedData
  const signedData = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 1 }),               // version
      new asn1js.Set({ value: [sha256AlgId] }),        // digestAlgorithms
      encapContentInfo,                                 // encapContentInfo
      certificatesImplicit,                             // certificates [0]
      new asn1js.Set({ value: [signerInfo] }),          // signerInfos
    ],
  });

  // 11. Build ContentInfo
  const contentInfo = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: OID_SIGNED_DATA }),
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [signedData],
      }),
    ],
  });

  const contentInfoDer = contentInfo.toBER(false);
  return Buffer.from(contentInfoDer).toString("base64");
}

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------

/**
 * Creates sample DG data and the rawDataGroups record expected by SODVerifier.
 */
function createSampleDGData() {
  const dg1Content = Buffer.from("MRZ data for testing DG1");
  const dg2Content = Buffer.from("Face image data for testing DG2");

  const dgData = {
    1: dg1Content,
    2: dg2Content,
  };

  const rawDataGroups = {
    dg1: dg1Content.toString("base64"),
    dg2: dg2Content.toString("base64"),
  };

  return { dgData, rawDataGroups };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("SODVerifier", () => {
  let selfSignedCertDer;
  let selfSignedPrivateKey;
  let sampleDgData;
  let sampleRawDataGroups;
  let validSODBase64;

  beforeAll(() => {
    const { certDer, privateKey } = generateSelfSignedCert();
    selfSignedCertDer = certDer;
    selfSignedPrivateKey = privateKey;

    const { dgData, rawDataGroups } = createSampleDGData();
    sampleDgData = dgData;
    sampleRawDataGroups = rawDataGroups;

    validSODBase64 = buildSOD({
      dgData: sampleDgData,
      certDer: selfSignedCertDer,
      privateKey: selfSignedPrivateKey,
    });
  });

  describe("valid SOD with matching DG hashes", () => {
    test("should return passiveAuthSuccess true and all dgHashes valid", async () => {
      const result = await SODVerifier.verify(validSODBase64, sampleRawDataGroups);

      expect(result.signatureValid).toBe(true);
      expect(result.passiveAuthSuccess).toBe(true);
      expect(result.dgHashes).toHaveLength(2);

      for (const dgHash of result.dgHashes) {
        expect(dgHash.isValid).toBe(true);
        expect(dgHash.expectedHash).toBe(dgHash.calculatedHash);
      }

      // Verify DG numbers are present
      const dgNumbers = result.dgHashes.map((dg) => dg.dgNumber).sort();
      expect(dgNumbers).toEqual([1, 2]);
    });

    test("should extract signer certificate information", async () => {
      const result = await SODVerifier.verify(validSODBase64, sampleRawDataGroups);

      expect(result.dsCertificate).toBeDefined();
      expect(typeof result.dsCertificate).toBe("string");

      expect(result.signerCertificate).toBeDefined();
      expect(result.signerCertificate.subject).toContain("Test DS");
      expect(result.signerCertificate.issuer).toContain("Test CSCA");
      expect(result.signerCertificate.validFrom).toBeInstanceOf(Date);
      expect(result.signerCertificate.validTo).toBeInstanceOf(Date);
    });
  });

  describe("tampered DG data", () => {
    test("should return passiveAuthSuccess false when DG content does not match", async () => {
      const tamperedDataGroups = {
        dg1: Buffer.from("TAMPERED MRZ data that does not match").toString("base64"),
        dg2: sampleRawDataGroups.dg2,
      };

      const result = await SODVerifier.verify(validSODBase64, tamperedDataGroups);

      // Signature over the SOD itself is still valid
      expect(result.signatureValid).toBe(true);

      // But passive auth fails because DG hash mismatches
      expect(result.passiveAuthSuccess).toBe(false);

      // DG1 should be invalid, DG2 should still be valid
      const dg1 = result.dgHashes.find((dg) => dg.dgNumber === 1);
      const dg2 = result.dgHashes.find((dg) => dg.dgNumber === 2);

      expect(dg1).toBeDefined();
      expect(dg1.isValid).toBe(false);
      expect(dg1.expectedHash).not.toBe(dg1.calculatedHash);

      expect(dg2).toBeDefined();
      expect(dg2.isValid).toBe(true);
    });
  });

  describe("invalid base64 SOD", () => {
    test("should throw an error for completely invalid base64", async () => {
      await expect(
        SODVerifier.verify("not-valid-base64!!@@##", {})
      ).rejects.toThrow();
    });

    test("should throw an error for valid base64 but invalid ASN.1", async () => {
      const garbage = Buffer.from("this is not ASN.1 data at all").toString("base64");
      await expect(
        SODVerifier.verify(garbage, {})
      ).rejects.toThrow();
    });
  });

  describe("SOD with CSCA certificate chain", () => {
    test("should return certificateChainValid true when DS cert is signed by CSCA", async () => {
      const { cscaCertDer, dsCertDer, dsPrivateKey } = generateCertificateChain();
      const { dgData, rawDataGroups } = createSampleDGData();

      const sodBase64 = buildSOD({
        dgData,
        certDer: dsCertDer,
        privateKey: dsPrivateKey,
      });

      const cscaCertBase64 = cscaCertDer.toString("base64");

      const result = await SODVerifier.verify(sodBase64, rawDataGroups, cscaCertBase64);

      expect(result.signatureValid).toBe(true);
      expect(result.passiveAuthSuccess).toBe(true);
      expect(result.certificateChainValid).toBe(true);
      expect(result.dgHashes).toHaveLength(2);
    });

    test("should return certificateChainValid false when CSCA does not match", async () => {
      const { certDer: unrelatedCertDer } = generateSelfSignedCert();
      const { dsCertDer, dsPrivateKey } = generateCertificateChain();
      const { dgData, rawDataGroups } = createSampleDGData();

      const sodBase64 = buildSOD({
        dgData,
        certDer: dsCertDer,
        privateKey: dsPrivateKey,
      });

      // Provide the unrelated cert as CSCA
      const wrongCscaBase64 = unrelatedCertDer.toString("base64");

      const result = await SODVerifier.verify(sodBase64, rawDataGroups, wrongCscaBase64);

      expect(result.signatureValid).toBe(true);
      expect(result.passiveAuthSuccess).toBe(true);
      expect(result.certificateChainValid).toBe(false);
    });

    test("should return certificateChainValid false when no CSCA is provided", async () => {
      const result = await SODVerifier.verify(validSODBase64, sampleRawDataGroups);
      expect(result.certificateChainValid).toBe(false);
    });
  });
});
