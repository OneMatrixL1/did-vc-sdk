
import VerifiableCredential from './verifiable-credential';
import { SODVerifier } from '../utils/sod-verifier';
import { DGParser } from '../utils/dg-parser';

/**
 * Vietnamese CCCD Verifiable Credential logic
 */
class CCCDVerifiableCredential extends VerifiableCredential {
    /**
     * Create a new CCCD Verifiable Credential from SOD data and extracted DG data.
     * This method verifies the SOD before creating the VC instance.
     * 
     * @param {string} id - id of the credential
     * @param {string} sodBase64 - Base64 encoded SOD data
     * @param {Record<string, string>} rawDataGroups - Object containing base64 encoded DG data
     * @param {object} extractedData - Data extracted from DGs (e.g., name, dob)
     * @param {string} [cscaCertBase64] - Optional Base64 encoded CSCA root certificate
     * @returns {Promise<CCCDVerifiableCredential>}
     */
    static async createVC(id, sodBase64, rawDataGroups, extractedData, cscaCertBase64) {
        // 1. Verify SOD
        const verificationResult = await SODVerifier.verify(sodBase64, rawDataGroups, cscaCertBase64);

        if (!verificationResult.passiveAuthSuccess) {
            throw new Error('Passive Authentication failed: SOD signature or Data Group hashes are invalid');
        }

        // 2. Initialize instance
        const vc = new this(id);

        // 3. Set exact context and type as requested
        vc.setContext([
            'https://www.w3.org/ns/credentials/v2',
            'https://cccd.gov.vn/credentials/v1'
        ]);
        vc.type = ['VerifiableCredential', 'CCCDCredential'];

        // 4. Set requested issuer and dates
        vc.setIssuer('did:web:cccd.gov.vn');
        vc.validFrom = new Date().toISOString();

        // 5. Set subject data as raw Data Groups with Hardware-linked DID
        const subjectId = `did:vbsn:cccd:${rawDataGroups.dg15 || extractedData.documentNumber}`;
        vc.credentialSubject = {
            id: subjectId,
            dg1: rawDataGroups.dg1,
            dg2: rawDataGroups.dg2,
            dg13: rawDataGroups.dg13,
            dg14: rawDataGroups.dg14,
            dg15: rawDataGroups.dg15,
            com: rawDataGroups.com
        };

        // 6. Set credentialSchema
        vc.credentialSchema = {
            id: 'https://cccd.gov.vn/schemas/cccd/1.0.0',
            type: 'JsonSchema'
        };

        // 7. Set detailed proof object with link to subject
        vc.proof = {
            type: 'ICAO9303SODSignature',
            proofVersion: '1.0.0',
            icaoVersion: '9303-11',
            dgProfile: 'VN-CCCD-2024',
            verificationMethod: `${subjectId}#sod`,
            proofPurpose: 'assertionMethod',
            created: new Date().toISOString(),
            sod: sodBase64,
            dsCertificate: verificationResult.dsCertificate
        };

        return vc;
    }

    /**
     * Verifies the cryptographic integrity of a CCCD Verifiable Credential.
     * This checks if the embedded SOD signature is valid, if the Data Groups match SOD hashes,
     * and optionally verifies the certificate chain against a CSCA root.
     * 
     * @param {object} vcJson - The JSON representation of the Verifiable Credential
     * @param {string} [cscaCertBase64] - Optional Base64 encoded CSCA root certificate
     * @returns {Promise<any>} Detailed verification report
     */
    static async verifyVC(vcJson, cscaCertBase64) {
        if (!vcJson.proof || vcJson.proof.type !== 'ICAO9303SODSignature') {
            throw new Error('Invalid VC: Missing or unsupported ICAO 9303 SOD proof');
        }

        const { sod } = vcJson.proof;
        const subject = vcJson.credentialSubject || {};

        // Collect DGs from subject
        const dataGroups = {};
        ['dg1', 'dg2', 'dg13', 'dg14', 'dg15', 'com'].forEach(dg => {
            if (subject[dg]) dataGroups[dg] = subject[dg];
        });

        if (!sod) {
            throw new Error('Invalid VC proof: Missing SOD');
        }

        if (Object.keys(dataGroups).length === 0) {
            throw new Error('Invalid VC: Missing Data Groups in credentialSubject');
        }

        // 1. Cryptographic Verification (Passive Authentication)
        const cryptoResult = await SODVerifier.verify(sod, dataGroups, cscaCertBase64);

        // 2. Document Expiry Check
        let documentExpired = false;
        let expiryDate = null;

        try {
            const parsedData = DGParser.parse(dataGroups);
            const expiryStr = parsedData.dateOfExpiry;

            if (expiryStr) {
                // Handle DD/MM/YYYY (common in DG13) or YYMMDD (standard MRZ)
                if (expiryStr.includes('/')) {
                    const [d, m, y] = expiryStr.split('/').map(Number);
                    expiryDate = new Date(y, m - 1, d);
                } else if (expiryStr.length === 6 && /^\d+$/.test(expiryStr)) {
                    const year = parseInt(expiryStr.substring(0, 2));
                    const month = parseInt(expiryStr.substring(2, 4));
                    const day = parseInt(expiryStr.substring(4, 6));
                    const fullYear = year + (year < 70 ? 2000 : 1900);
                    expiryDate = new Date(fullYear, month - 1, day);
                }

                if (expiryDate && expiryDate < new Date()) {
                    documentExpired = true;
                }
            }
        } catch (e) {
            console.warn('Document status check skipped: Invalid expiry date format');
        }

        // 3. Return comprehensive report
        return {
            valid: cryptoResult.passiveAuthSuccess && !documentExpired,
            passiveAuthentication: {
                success: cryptoResult.passiveAuthSuccess,
                details: {
                    signatureValid: cryptoResult.signatureValid,
                    dgHashesMatched: cryptoResult.dgHashes.every(dg => dg.isValid),
                    dgHashes: cryptoResult.dgHashes
                }
            },
            certificateVerification: {
                cscaLinked: cryptoResult.certificateChainValid,
                signerCertificate: cryptoResult.signerCertificate
            },
            documentStatus: {
                expired: documentExpired,
                expiryDate: expiryDate ? expiryDate.toISOString().split('T')[0] : 'unknown'
            }
        };
    }

    /**
     * Exports identity data by parsing the raw Data Groups stored in the VC.
     * 
     * @param {object} vcJson - The JSON representation of the Verifiable Credential
     * @returns {object} Decoded identity data
     */
    static exportData(vcJson) {
        const subject = vcJson.credentialSubject || {};
        const dataGroups = {};
        ['dg1', 'dg2', 'dg13', 'dg14', 'dg15', 'com'].forEach(dg => {
            if (subject[dg]) dataGroups[dg] = subject[dg];
        });

        if (Object.keys(dataGroups).length === 0) {
            throw new Error('No Data Groups found in VC subject');
        }

        const parsedData = DGParser.parse(dataGroups);
        const { photo, ...otherParsedData } = parsedData;

        // Final profile object construction
        const profile = {
            // Base fields from MRZ (DG1) as fallback
            issuingCountry: parsedData.issuingCountry || '',
            documentNumber: parsedData.documentNumber || '',
            firstName: parsedData.firstName || '',
            lastName: parsedData.lastName || '',
            nationality: parsedData.nationality || '',
            gender: parsedData.gender || '',
            dateOfExpiry: parsedData.dateOfExpiry || '',
            passportMRZ: parsedData.passportMRZ || '',
            dateOfBirth: parsedData.dateOfBirth || '',
            documentType: parsedData.documentType || '',

            // Rich fields from DG13 (overwrite matches if available)
            ...otherParsedData
        };

        // Ensure 'photo' is the absolute last key
        return {
            ...profile,
            photo: photo || ''
        };
    }
}

export default CCCDVerifiableCredential;
