import jsigs from 'jsonld-signatures';
// @ts-ignore
import { SODVerifier } from '../../utils/index.js';

/**
 * ICAO9303SODSignature - Signature suite for ICAO 9303 SOD (Security Object for Document)
 * 
 * This suite is used by CCCD Verifiable Credentials to verify the integrity of
 * data groups against a signed CMS object (SOD).
 */
export default class ICAO9303SODSignature extends jsigs.suites.LinkedDataSignature {
    constructor(options = {}) {
        super({
            type: 'ICAO9303SODSignature',
            ...options
        });
        this.alg = 'RS256'; // Generic placeholder
    }

    /**
     * Determine if this suite can verify a specific proof
     * @param {object} options
     * @returns {Promise<boolean>}
     */
    async matchProof({ proof }) {
        return proof.type === 'ICAO9303SODSignature';
    }

    /**
     * Verify the proof
     * @param {object} options
     * @returns {Promise<object>}
     */
    async verifyProof({ proof, document, documentLoader, purpose }) {
        try {
            // 1. Validate proof purpose (authorization check)
            const verifier = {
                // Simple verifier that just returns the verification method
                // In a real flow, this might resolve a DID
                async verify() {
                    return true;
                }
            };

            // 2. Perform SOD verification using SODVerifier
            const credentialSubject = document.credentialSubject || document;
            const result = await SODVerifier.verify(proof.sod, credentialSubject, proof.dsCertificate);

            if (!result.passiveAuthSuccess) {
                throw new Error(`SOD verification failed: ${result.error || 'Signature or DG hash mismatch'}`);
            }

            // 3. Return the expected structure for jsonld-signatures
            const verificationMethod = {
                id: proof.verificationMethod,
                controller: 'did:web:cccd.gov.vn' // Default controller for CCCD
            };

            if (purpose) {
                const purposeResult = await purpose.validate(proof, {
                    document,
                    suite: this,
                    verificationMethod,
                    documentLoader
                });
                if (!purposeResult.valid) {
                    throw purposeResult.error;
                }
            }

            return {
                verified: true,
                verificationMethod,
                purposeResult: { valid: true }
            };
        } catch (error) {
            return {
                verified: false,
                error
            };
        }
    }
}
