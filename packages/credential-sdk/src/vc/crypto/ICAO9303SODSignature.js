import { SODVerifier } from '../../icao/sod-verifier.js';

/**
 * Proof suite for ICAO 9303 SOD (Security Object for Document).
 * Verifies integrity of Data Groups against a government-signed CMS/PKCS#7 SOD.
 * Not a Linked Data Signature — the SOD is the pre-existing government proof.
 *
 * Delegation is verified via ZKP (did-delegate circuit) in the VP layer,
 * not via raw RSA here. The delegationCertificate in the VC proof is metadata only.
 */
export default class ICAO9303SODSignature {
  get type() {
    return 'ICAO9303SODSignature';
  }

  async matchProof({ proof }) {
    return proof.type === 'ICAO9303SODSignature';
  }

  async verifyProof({ proof, document }) {
    try {
      const credentialSubject = document.credentialSubject || document;
      const result = await SODVerifier.verify(proof.sod, credentialSubject);

      if (!result.passiveAuthSuccess) {
        throw new Error(`SOD verification failed: ${result.error || 'Signature or DG hash mismatch'}`);
      }

      return { verified: true };
    } catch (error) {
      return { verified: false, error };
    }
  }
}
