/**
 * TESTCASE 2: KYC Credential with Age Predicate (ZKP)
 *
 * Scenario:
 * - User creates KYC VC from System A with age information
 * - System B requires proof that user is older than 18
 * - User can prove age > 18 using ZKP predicate without revealing actual age
 *
 * Flow:
 * 1. User logs into System A, receives KYC VC with BBS signature (includes age)
 * 2. User logs into System B, uses ZKP predicate to prove age >= 18
 * 3. System B verifies user meets age requirement without seeing actual age
 */

import {
  CREDENTIALS_V1,
  BBS_V1,
  createTestSetup,
  createSignedVP,
  verifyVP,
  issueCredentialWithBBS,
} from './utils';

import { Presentation } from '../../src/vc';

// =============================================================================
// Test Data
// =============================================================================

const TEST_KYC_DATA = {
  fullName: 'Nguyen Van A',
  age: 25, // User is 25 years old
  birthPlace: 'Hanoi',
  nationality: 'Vietnamese',
  idNumber: 'CCCD123456789',
};

// Field paths for selective disclosure
const FIELD_SUBJECT_ID = 'credentialSubject.id';
const FIELD_BIRTH_PLACE = 'credentialSubject.birthPlace';
const FIELD_NATIONALITY = 'credentialSubject.nationality';
const FIELD_AGE = 'credentialSubject.age';

// Inline KYC context with age as integer
const KYC_CONTEXT = {
  '@context': {
    '@version': 1.1,
    '@protected': true,
    id: '@id',
    type: '@type',
    kyc: 'https://example.com/kyc#',
    KYCCredential: 'kyc:KYCCredential',
    fullName: 'kyc:fullName',
    age: 'kyc:age',
    birthPlace: 'kyc:birthPlace',
    nationality: 'kyc:nationality',
    idNumber: 'kyc:idNumber',
    publicKeyBase58: 'https://ld.truvera.io/security#publicKeyBase58',
  },
};

const VERIFIER_DOMAIN = 'https://systemb.example.com';

// =============================================================================
// Test Suite
// =============================================================================

describe('TESTCASE 2: KYC with Age Predicate (ZKP)', () => {
  let issuer; // System A
  let holder; // User
  let verifier; // System B
  let kycCredential;

  beforeAll(async () => {
    const setup = await createTestSetup();
    issuer = setup.issuer;
    holder = setup.holder;
    verifier = setup.verifier;
  }, 30000);

  // ===========================================================================
  // Scenario 1: System A issues KYC credential with age
  // ===========================================================================

  describe('Scenario 1: System A issues KYC credential with age', () => {
    test('should issue KYC credential with BBS signature including age', async () => {
      const unsignedCredential = {
        '@context': [CREDENTIALS_V1, BBS_V1, KYC_CONTEXT],
        type: ['VerifiableCredential', 'KYCCredential'],
        id: 'urn:uuid:kyc-cred-12345',
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
      expect(kycCredential.credentialSubject.age).toBe(TEST_KYC_DATA.age);
      expect(kycCredential.credentialSubject.birthPlace).toBe(TEST_KYC_DATA.birthPlace);
      expect(kycCredential.proof.type).toBe('Bls12381BBSSignatureDock2023');
    }, 30000);
  });

  // ===========================================================================
  // Scenario 2: User proves age >= 18 to System B using ZKP
  // ===========================================================================

  describe('Scenario 2: User proves age >= 18 with ZKP predicate', () => {
    const challenge = 'challenge-from-systemB';

    test('should prove age >= 18 using ZKP bounds without revealing actual age', async () => {
      // Create presentation with age bound check
      const presentation = new Presentation();
      const credIdx = await presentation.addCredentialToPresent(kycCredential);

      // Reveal birthPlace and nationality for verification
      presentation.addAttributeToReveal(credIdx, [
        FIELD_SUBJECT_ID,
        FIELD_BIRTH_PLACE,
        FIELD_NATIONALITY,
      ]);

      // Use ZKP bounds to prove age >= 18 without revealing the actual value
      // enforceBounds(credIdx, attributeName, min, max)
      // min is inclusive, max is exclusive: [min, max)
      // To prove age >= 18, we use min=18, max=150 (reasonable upper bound)
      presentation.presBuilder.enforceBounds(credIdx, FIELD_AGE, 18, 150);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-age-bound-proof',
      });

      expect(derivedCredentials.length).toBe(1);
      const derivedCred = derivedCredentials[0];

      // Verify bounds info is included in the proof
      expect(derivedCred.proof.bounds).toBeDefined();

      // User creates and signs VP with the derived credential
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
      expect(vcFromVP.credentialSubject.birthPlace).toBe(TEST_KYC_DATA.birthPlace);
      expect(vcFromVP.credentialSubject.nationality).toBe(TEST_KYC_DATA.nationality);

      // Age should NOT be revealed - only proven via ZKP bounds
      expect(vcFromVP.credentialSubject.age).toBeUndefined();

      // Verify bounds proof is included with correct structure
      expect(vcFromVP.proof.bounds).toBeDefined();
      expect(vcFromVP.proof.bounds.credentialSubject).toBeDefined();
      expect(vcFromVP.proof.bounds.credentialSubject.age).toBeDefined();
      expect(vcFromVP.proof.bounds.credentialSubject.age[0].min).toBe(18);
      expect(vcFromVP.proof.bounds.credentialSubject.age[0].max).toBe(150);
      expect(vcFromVP.proof.bounds.credentialSubject.age[0].protocol).toBe('Bulletproofs++');
    }, 60000);

    test('should verify birthPlace = Hanoi with selective disclosure', async () => {
      // Create presentation revealing only birthPlace
      const presentation = new Presentation();
      await presentation.addCredentialToPresent(kycCredential);

      presentation.addAttributeToReveal(0, [
        FIELD_SUBJECT_ID,
        FIELD_BIRTH_PLACE,
      ]);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-birthplace',
      });

      const derivedCred = derivedCredentials[0];

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

      // Validate birthPlace is revealed and equals "Hanoi"
      const vcFromVP = vpJson.verifiableCredential[0];
      expect(vcFromVP.credentialSubject.birthPlace).toBe('Hanoi');

      // Age should not be revealed
      expect(vcFromVP.credentialSubject.age).toBeUndefined();
    }, 30000);

    test('SECURITY: System B rejects VP with tampered birthPlace', async () => {
      // Create valid derived credential
      const presentation = new Presentation();
      await presentation.addCredentialToPresent(kycCredential);

      presentation.addAttributeToReveal(0, [
        FIELD_SUBJECT_ID,
        FIELD_BIRTH_PLACE,
      ]);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-tamper-test',
      });

      const derivedCred = derivedCredentials[0];

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

      // Tamper with the birthPlace in the VP
      vpJson.verifiableCredential[0].credentialSubject.birthPlace = 'Ho Chi Minh';

      // System B verifies tampered VP - should fail
      const result = await verifyVP(vpJson, verifier, challenge, VERIFIER_DOMAIN);
      expect(result.verified).toBe(false);
    }, 30000);

    test('should confirm holder ownership of KYC credential', async () => {
      // Helper function to verify holder ownership
      function verifyHolderOwnership(derivedCred, authenticatedDID) {
        const credentialSubjectDID = derivedCred.credentialSubject.id;

        if (!credentialSubjectDID) {
          throw new Error('Credential must reveal credentialSubject.id for holder verification');
        }

        if (credentialSubjectDID !== authenticatedDID) {
          throw new Error(
            'Holder ownership verification failed: '
            + `credential belongs to ${credentialSubjectDID}, `
            + `but presenter authenticated as ${authenticatedDID}`,
          );
        }

        return true;
      }

      const presentation = new Presentation();
      await presentation.addCredentialToPresent(kycCredential);

      presentation.addAttributeToReveal(0, [
        FIELD_SUBJECT_ID, // MUST reveal for holder binding
        FIELD_BIRTH_PLACE,
        FIELD_NATIONALITY,
      ]);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-holder-check',
      });

      const derivedCred = derivedCredentials[0];

      // User authenticates to System B
      const authenticatedUserDID = holder.did;

      // Verify holder ownership
      expect(() => {
        verifyHolderOwnership(derivedCred, authenticatedUserDID);
      }).not.toThrow();

      expect(derivedCred.credentialSubject.id).toBe(authenticatedUserDID);
      expect(derivedCred.credentialSubject.birthPlace).toBe('Hanoi');
      expect(derivedCred.credentialSubject.age).toBeUndefined(); // Age is hidden
    }, 30000);
  });
});
