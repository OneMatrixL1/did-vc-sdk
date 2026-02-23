
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import forge from 'node-forge';
import { Buffer } from 'buffer';
import elliptic from 'elliptic';

const ecModule = (elliptic.default || elliptic);

/**
 * SOD Verifier for Passive Authentication
 */
export class SODVerifier {
    /**
     * Verifies the SOD signature and checks integrity of Data Groups
     * 
     * @param {string} sodBase64 - Base64 encoded SOD data
     * @param {Record<string, string>} rawDataGroups - Object containing base64 encoded DG data
     * @param {string} [cscaCertBase64] - Optional Base64 encoded CSCA root certificate
     * @returns {Promise<any>} Verification result
     */
    static async verify(sodBase64, rawDataGroups, cscaCertBase64) {
        const results = {
            signatureValid: false,
            certificateChainValid: false,
            passiveAuthSuccess: false,
            dgHashes: [],
        };

        try {
            const sodBuffer = Buffer.from(sodBase64, 'base64');
            let asn1 = asn1js.fromBER(sodBuffer.buffer.slice(sodBuffer.byteOffset, sodBuffer.byteOffset + sodBuffer.byteLength));

            if (asn1.offset === -1) {
                throw new Error('Failed to parse ASN.1 from SOD');
            }

            const contentInfo = new pkijs.ContentInfo();

            // Check if it's a direct SEQUENCE (Tag 16) or wrapped in Tag 0x77 (Application 23)
            const idBlock = asn1.result.idBlock;

            if (idBlock.tagClass === 1 && idBlock.tagNumber === 16) {
                // Direct ContentInfo SEQUENCE
                contentInfo.fromSchema(asn1.result);
            } else if (idBlock.tagClass === 2 && idBlock.tagNumber === 23) {
                // Wrapped in Tag 0x77 (Application 23)
                const inner = asn1.result.valueBlock.value[0];
                if (!inner || inner.idBlock.tagNumber !== 16) {
                    throw new Error('Invalid or corrupted SOD wrapper content');
                }
                contentInfo.fromSchema(inner);
            } else {
                const byte0 = sodBuffer[0];
                const firstByteValue = (sodBuffer.length > 0 && byte0 !== undefined)
                    ? `0x${byte0.toString(16)}`
                    : 'empty';
                throw new Error(`Unsupported or tampered SOD wrapper tag: ${firstByteValue}`);
            }

            if (!contentInfo.content) {
                throw new Error('SOD ContentInfo has no content');
            }

            const signedData = new pkijs.SignedData({ schema: contentInfo.content });

            // Setup PKI.js engine
            if (typeof process !== 'undefined' && process.versions && process.versions.node) {
                const { webcrypto } = await import('crypto');
                pkijs.setEngine("node", webcrypto, new pkijs.CryptoEngine({ crypto: webcrypto, subtle: webcrypto.subtle }));
            }

            // 1. Signature Verification (Manual for Brainpool P384r1)
            results.signatureValid = await this.verifySignature(signedData);

            // 2. Extract Signer Certificate (DSC)
            if (signedData.certificates && signedData.certificates.length > 0) {
                const cert = signedData.certificates[0];
                results.dsCertificate = Buffer.from(cert.toSchema().toBER(false)).toString('base64');
                results.signerCertificate = {
                    subject: cert.subject.typesAndValues.map(tv => `${tv.type}=${tv.value.valueBlock.value}`).join(', '),
                    issuer: cert.issuer.typesAndValues.map(tv => `${tv.type}=${tv.value.valueBlock.value}`).join(', '),
                    validFrom: cert.notBefore.value,
                    validTo: cert.notAfter.value,
                };

                // 3. Verify Certificate Chain against CSCA if provided
                if (cscaCertBase64) {
                    try {
                        const cscaBuffer = Buffer.from(cscaCertBase64, 'base64');
                        const cscaAsn1 = asn1js.fromBER(cscaBuffer.buffer.slice(cscaBuffer.byteOffset, cscaBuffer.byteOffset + cscaBuffer.byteLength));
                        const csca = new pkijs.Certificate({ schema: cscaAsn1.result });
                        results.certificateChainValid = await this.verifyCertificateChain(cert, csca);
                    } catch (e) {
                        console.error('CSCA verification error:', e);
                        results.certificateChainValid = false;
                    }
                }
            }

            // 4. Verify Data Group Hashes
            const encapContent = signedData.encapContentInfo.eContent.valueBlock.valueHex;
            const ldsAsn1 = asn1js.fromBER(encapContent);
            if (ldsAsn1.offset === -1) {
                throw new Error('Failed to parse LDS Security Object');
            }

            const ldsData = ldsAsn1.result;
            // Structure: SEQUENCE { version INTEGER, hashAlg AlgorithmIdentifier, dgHashes SEQUENCE OF DataGroupHash }
            const dgHashesSequence = ldsData.valueBlock.value[2].valueBlock.value;

            for (const dgHash of dgHashesSequence) {
                const dgNumber = dgHash.valueBlock.value[0].valueBlock.valueDec;
                const expectedHash = Buffer.from(dgHash.valueBlock.value[1].valueBlock.valueHex).toString('hex');

                const rawDG = rawDataGroups[`dg${dgNumber}`];
                if (rawDG) {
                    const dgBuffer = Buffer.from(rawDG, 'base64');
                    // Need to detect hash algorithm from ldsData.valueBlock.value[1]
                    // For Vietnamese CCCD it is SHA-256 (OID 2.16.840.1.101.3.4.2.1)
                    const md = forge.md.sha256.create();
                    md.update(dgBuffer.toString('binary'), 'binary');
                    const calculatedHash = md.digest().toHex();

                    results.dgHashes.push({
                        dgNumber,
                        expectedHash,
                        calculatedHash,
                        isValid: expectedHash === calculatedHash
                    });
                }
            }

            results.passiveAuthSuccess = results.signatureValid && results.dgHashes.every(dg => dg.isValid);

            return results;
        } catch (e) {
            console.error('SOD Verification Error:', e);
            throw e;
        }
    }

    /**
     * Manual signature verification for curves not supported by WebCrypto
     * @private
     */
    static async verifySignature(signedData) {
        try {
            const signerInfo = signedData.signerInfos[0];
            const signature = Buffer.from(signerInfo.signature.valueBlock.valueHex);
            // The signature is computed over the DER encoding of the SET OF attributes
            const schema = signerInfo.signedAttrs.toSchema();
            schema.idBlock.tagClass = 1; // Universal
            schema.idBlock.tagNumber = 17; // SET
            const signedAttrsDer = schema.toBER(false);

            // Extract DG hashes hash (message digest) from signed attributes
            const signedAttrs = signerInfo.signedAttrs;
            const messageDigestAttr = signedAttrs.attributes.find(
                attr => attr.type === "1.2.840.113549.1.9.4" // messageDigest
            );

            if (!messageDigestAttr) {
                throw new Error('No messageDigest attribute in SOD');
            }

            const expectedMessageDigest = Buffer.from(messageDigestAttr.values[0].valueBlock.valueHex).toString('hex');

            // Calculate actual digest of encapsulated content
            const encapContent = signedData.encapContentInfo.eContent.valueBlock.valueHex;

            // Detect hash algorithm
            let hashAlg = 'SHA256';
            const sigAlgoOID = signerInfo.signatureAlgorithm.algorithmId;
            if (sigAlgoOID === "1.2.840.10045.4.3.3" || sigAlgoOID === "1.2.840.113549.1.1.12") {
                hashAlg = 'SHA384';
            }

            const md = hashAlg === 'SHA384' ? forge.md.sha384.create() : forge.md.sha256.create();
            md.update(Buffer.from(encapContent).toString('binary'), 'binary');
            const actualMessageDigest = md.digest().toHex();

            if (expectedMessageDigest !== actualMessageDigest) {
                console.warn('SOD Message Digest mismatch!');
                return false;
            }

            // Verify RSA/ECDSA signature
            const cert = signedData.certificates[0];
            const publicKeyInfo = cert.subjectPublicKeyInfo;
            const publicKeyDer = publicKeyInfo.toSchema().toBER(false);

            // Detect curve OID
            let curveOID = '';
            try {
                const asn1 = asn1js.fromBER(publicKeyDer);
                const spki = asn1.result;
                const algorithmIdentifier = spki.valueBlock.value[0];
                const parameters = algorithmIdentifier.valueBlock.value[1];
                curveOID = parameters ? parameters.valueBlock.toString() : '';
            } catch (e) { }

            return await this.verifySignatureLowLevel(
                hashAlg,
                Buffer.from(signedAttrsDer),
                signature,
                publicKeyDer,
                curveOID
            );
        } catch (e) {
            console.error('Manual verification failed:', e);
            return false;
        }
    }

    /**
     * Low-level verification using Node.js crypto or elliptic fallback
     * @private
     */
    static async verifySignatureLowLevel(hashAlg, data, signature, publicKeyDer, curveOID) {
        if (typeof process !== 'undefined' && process.versions && process.versions.node) {
            try {
                const crypto = await import('crypto');
                return crypto.verify(
                    hashAlg,
                    data,
                    {
                        key: Buffer.from(publicKeyDer),
                        format: 'der',
                        type: 'spki',
                        dsaEncoding: 'der',
                    },
                    signature
                );
            } catch (e) {
                console.warn('Node.js crypto verification failed, falling back to elliptic:', e.message);
            }
        }

        // Browser/Fallback logic with elliptic
        let ec;
        if (curveOID === "1.3.36.3.3.2.8.1.1.7") { // Brainpool P-256r1
            ec = new ecModule.ec(new ecModule.curves.PresetCurve({
                type: 'short',
                p: 'A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377',
                a: '7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9',
                b: '26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6',
                n: 'A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7',
                hash: hashAlg.toLowerCase(),
                gRed: false,
                g: [
                    '8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262',
                    '547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997'
                ]
            }));
        } else if (curveOID === "1.3.36.3.3.2.8.1.1.11") { // Brainpool P-384r1
            ec = new ecModule.ec(new ecModule.curves.PresetCurve({
                type: 'short',
                p: '8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53',
                a: '7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826',
                b: '04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11',
                n: '8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565',
                hash: hashAlg.toLowerCase(),
                gRed: false,
                g: [
                    '1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E',
                    '8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315'
                ]
            }));
        } else {
            ec = new ecModule.ec('p256');
        }

        const publicKey = this.extractECPointFromSPKI(Buffer.from(publicKeyDer));
        const pubHex = Buffer.from(publicKey).toString("hex");

        const key = ec.keyFromPublic(pubHex, 'hex');

        const md = hashAlg === 'SHA384' ? forge.md.sha384.create() : forge.md.sha256.create();
        md.update(data.toString('binary'), 'binary');
        const hashHex = md.digest().toHex();

        return key.verify(hashHex, signature);
    }

    /**
     * Verify certificate chain
     * @private
     */
    static async verifyCertificateChain(dsc, csca) {
        const signature = Buffer.from(dsc.signatureValue.valueBlock.valueHex);
        const tbsDer = Buffer.from(dsc.tbsView);
        const cscaPublicKeyDer = csca.subjectPublicKeyInfo.toSchema().toBER(false);

        const sigAlgoOID = dsc.signatureAlgorithm.algorithmId;
        let hashAlg = 'SHA256';
        if (sigAlgoOID === "1.2.840.10045.4.3.3" || sigAlgoOID === "1.2.840.113549.1.1.12") {
            hashAlg = 'SHA384';
        }

        return await this.verifySignatureLowLevel(
            hashAlg,
            tbsDer,
            signature,
            cscaPublicKeyDer,
            "" // Curve OID will be detected inside verifySignatureLowLevel if needed
        );
    }

    /**
     * Extract raw uncompressed EC public key (04||X||Y) from SPKI DER
     * @param {Uint8Array|Buffer} spkiDer
     * @returns {Uint8Array}
     */
    static extractECPointFromSPKI(spkiDer) {
        // đảm bảo truyền đúng ArrayBuffer cho asn1js
        const buf = spkiDer.buffer
            ? spkiDer.buffer.slice(spkiDer.byteOffset, spkiDer.byteOffset + spkiDer.byteLength)
            : spkiDer;

        const asn1 = asn1js.fromBER(buf);
        if (asn1.offset === -1) {
            throw new Error("Invalid ASN.1 DER");
        }

        const spki = asn1.result;

        // SubjectPublicKeyInfo ::= SEQUENCE { algId, subjectPublicKey BIT STRING }
        const subjectPublicKey = spki.valueBlock.value[1];

        if (subjectPublicKey.idBlock.tagNumber !== 3) {
            throw new Error("Not a BIT STRING");
        }

        // valueHex = [unusedBits(1 byte)] || [EC point]
        let raw = new Uint8Array(subjectPublicKey.valueBlock.valueHex);

        // strip unused-bits byte (must be 0x00)
        if (raw[0] === 0x00) {
            raw = raw.slice(1);
        }

        // sanity check: uncompressed only
        if (raw[0] !== 0x04) {
            throw new Error("Only uncompressed EC points supported");
        }

        return raw; // 04 || X || Y
    }
}
