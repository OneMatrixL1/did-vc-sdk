import VerifiableCredential from '../../vc/verifiable-credential.js';
import { SODVerifier } from '../sod-verifier.js';
import { VN_CCCD_2024 } from '../icao-profile/index.js';

/**
 * Creates a CCCD (Căn Cước Công Dân) Verifiable Credential from SOD data.
 * Verifies the SOD passive authentication before building the credential.
 *
 * @param {string} sodBase64 - Base64 encoded SOD data
 * @param {Record<string, string>} rawDataGroups - Base64 encoded DG data keyed by DG name
 * @param {string} [cscaCertBase64] - Optional Base64 encoded CSCA root certificate
 * @returns {Promise<VerifiableCredential>}
 */
export async function issueCredential(
  sodBase64: string,
  rawDataGroups: Record<string, string>,
  cscaCertBase64?: string,
): Promise<VerifiableCredential> {
  const verificationResult = await SODVerifier.verify(sodBase64, rawDataGroups, cscaCertBase64);

  if (!verificationResult.passiveAuthSuccess) {
    throw new Error('Passive Authentication failed: SOD signature or Data Group hashes are invalid');
  }

  const vc = new VerifiableCredential();

  vc.addContext('https://cccd.gov.vn/credentials/v1');
  vc.type = ['VerifiableCredential', 'CCCDCredential'];
  vc.setIssuer('did:web:cccd.gov.vn');

  const subjectId = `did:vbsn:cccd:${rawDataGroups.dg15}`;
  vc.credentialSubject = {
    id: subjectId,
    dg1: rawDataGroups.dg1,
    dg2: rawDataGroups.dg2,
    dg13: rawDataGroups.dg13,
    dg14: rawDataGroups.dg14,
    dg15: rawDataGroups.dg15,
    com: rawDataGroups.com,
  };

  vc.credentialSchema = {
    id: 'https://cccd.gov.vn/schemas/cccd/1.0.0',
    type: 'JsonSchema',
  };

  vc.proof = {
    type: 'ICAO9303SODSignature',
    dgProfile: VN_CCCD_2024.profileId,
    proofPurpose: 'assertionMethod',
    created: new Date().toISOString(),
    sod: sodBase64,
    dsCertificate: verificationResult.dsCertificate,
  };

  return vc;
}
