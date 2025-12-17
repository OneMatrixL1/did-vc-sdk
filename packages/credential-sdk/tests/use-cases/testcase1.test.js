/**
 * TESTCASE 1: KYC Verification with Selective Disclosure
 *
 * Scenario:
 * - User logs into System A and receives a KYC credential
 * - User logs into System B and uses VP to authenticate
 * - System B verifies the VP with selective disclosure
 *
 * KYC Credential contains:
 * - Full name (Ho ten)
 * - Date of birth (Ngay sinh)
 * - Gender (Gioi tinh)
 * - Place of birth (Noi sinh)
 * - Nationality (Quoc tich)
 * - ID number, issue/expiry date (Giay to tuy than)
 * - Permanent address (Dia chi thuong tru)
 */

import {
  CREDENTIALS_V1,
  BBS_V1,
  createTestSetup,
  deriveCredential,
  createSignedVP,
  verifyVP,
  issueCredentialWithBBS,
} from './utils';

// =============================================================================
// Test Data
// =============================================================================

const TEST_KYC_DATA = {
  fullName: 'Nguyen Van A',
  dateOfBirth: '1990-01-15',
  gender: 'Male',
  placeOfBirth: 'Ha Noi, Viet Nam',
  nationality: 'Vietnamese',
  idNumber: '001090012345',
  idIssueDate: '2020-01-01',
  idExpiryDate: '2030-01-01',
  permanentAddress: '123 Pho Hue, Hai Ba Trung, Ha Noi',
};

// Field paths for selective disclosure
const FIELD_SUBJECT_ID = 'credentialSubject.id';
const FIELD_FULL_NAME = 'credentialSubject.fullName';
const FIELD_DATE_OF_BIRTH = 'credentialSubject.dateOfBirth';
const FIELD_NATIONALITY = 'credentialSubject.nationality';

const FIELDS_FOR_VERIFICATION = [
  FIELD_SUBJECT_ID,
  FIELD_FULL_NAME,
  FIELD_DATE_OF_BIRTH,
  FIELD_NATIONALITY,
];

// Inline KYC context
const KYC_CONTEXT = {
  '@context': {
    '@version': 1.1,
    '@protected': true,
    id: '@id',
    type: '@type',
    kyc: 'https://example.com/kyc#',
    KYCCredential: 'kyc:KYCCredential',
    fullName: 'kyc:fullName',
    dateOfBirth: 'kyc:dateOfBirth',
    gender: 'kyc:gender',
    placeOfBirth: 'kyc:placeOfBirth',
    nationality: 'kyc:nationality',
    idNumber: 'kyc:idNumber',
    idIssueDate: 'kyc:idIssueDate',
    idExpiryDate: 'kyc:idExpiryDate',
    permanentAddress: 'kyc:permanentAddress',
    publicKeyBase58: 'https://ld.truvera.io/security#publicKeyBase58',
  },
};

const VERIFIER_DOMAIN = 'https://systemb.example.com';

// =============================================================================
// Test Suite
// =============================================================================

describe('TESTCASE 1: KYC Verification', () => {
  let issuer;
  let holder;
  let verifier;
  let kycCredential;

  beforeAll(async () => {
    const setup = await createTestSetup();
    issuer = setup.issuer;
    holder = setup.holder;
    verifier = setup.verifier;
  }, 30000);

  // ===========================================================================
  // Scenario 1: Issue KYC Credential at System A
  // ===========================================================================

  describe('Scenario 1: System A issues KYC credential', () => {
    test('should issue KYC credential with BBS signature', async () => {
      const unsignedCredential = {
        '@context': [CREDENTIALS_V1, BBS_V1, KYC_CONTEXT],
        type: ['VerifiableCredential', 'KYCCredential'],
        id: 'urn:uuid:cred-kyc-12345',
        issuer: issuer.did,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holder.did,
          ...TEST_KYC_DATA,
        },
      };

      kycCredential = await issueCredentialWithBBS(issuer.keyDoc, unsignedCredential);

      expect(kycCredential).toBeDefined();
      expect(kycCredential.issuer).toBe(issuer.did);
      expect(kycCredential.credentialSubject.fullName).toBe(TEST_KYC_DATA.fullName);
      expect(kycCredential.proof.type).toBe('Bls12381BBSSignatureDock2023');
    }, 30000);
  });

  // ===========================================================================
  // Scenario 2: User presents VP to System B
  // ===========================================================================

  describe('Scenario 2: User authenticates at System B with VP', () => {
    const challenge = 'challenge-from-systemB';

    test('should verify VP with selective disclosure', async () => {
      // User derives credential revealing only necessary fields
      const derivedCred = deriveCredential(
        kycCredential,
        FIELDS_FOR_VERIFICATION,
        'nonce-verification',
      );

      // User creates and signs VP
      const vp = await createSignedVP({
        derivedCredential: derivedCred,
        holderDID: holder.did,
        holderKeyDoc: holder.keyDoc,
        challenge,
        domain: VERIFIER_DOMAIN,
        contexts: [KYC_CONTEXT],
      });

      const vpJson = vp.toJSON();

      // System B verifies VP
      const result = await verifyVP(vpJson, verifier, challenge, VERIFIER_DOMAIN);
      expect(result.verified).toBe(true);

      // Validate revealed fields from VP
      const vcFromVP = vpJson.verifiableCredential[0];

      expect(vcFromVP.issuer).toBe(issuer.did);
      expect(vpJson.holder).toBe(vcFromVP.credentialSubject.id);
      expect(vcFromVP.credentialSubject.fullName).toBe(TEST_KYC_DATA.fullName);
      expect(vcFromVP.credentialSubject.dateOfBirth).toBe(TEST_KYC_DATA.dateOfBirth);
      expect(vcFromVP.credentialSubject.nationality).toBe(TEST_KYC_DATA.nationality);

      // Sensitive fields should not be revealed
      expect(vcFromVP.credentialSubject.idNumber).toBeUndefined();
      expect(vcFromVP.credentialSubject.permanentAddress).toBeUndefined();
    }, 30000);
  });

});
