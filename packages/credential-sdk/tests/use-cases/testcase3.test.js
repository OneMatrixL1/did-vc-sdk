/**
 * TESTCASE 3: Cross-System Customer Tier Verification
 *
 * Use Case:
 * - System B agrees that if User has VIP1 tier at System A, they can directly
 *   upgrade to VIP1 at System B without accumulating points
 *
 * Flow:
 * 1. User logs into System A, receives VC about "customer tier"
 * 2. User logs into System B, uses the customer tier VC
 * 3. System B verifies user has VIP1 status from System A
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

const TEST_TIER_DATA = {
  tier: 'VIP1',
  tierName: 'VIP Level 1',
  tierDescription: 'First tier of VIP membership',
  totalSpent: '$250,000',
  memberSince: '2020-01-15',
  accountId: 'ACC-12345',
};

// Field paths for selective disclosure
const FIELD_SUBJECT_ID = 'credentialSubject.id';
const FIELD_TIER = 'credentialSubject.tier';
const FIELD_TOTAL_SPENT = 'credentialSubject.totalSpent';

const FIELDS_FOR_VERIFICATION = [FIELD_SUBJECT_ID, FIELD_TIER, FIELD_TOTAL_SPENT];

// Inline customer tier context
const CUSTOMER_TIER_CONTEXT = {
  '@context': {
    '@version': 1.1,
    '@protected': true,
    id: '@id',
    type: '@type',
    ct: 'https://example.com/customer-tier#',
    CustomerTierCredential: 'ct:CustomerTierCredential',
    tier: 'ct:tier',
    tierName: 'ct:tierName',
    tierDescription: 'ct:tierDescription',
    totalSpent: 'ct:totalSpent',
    memberSince: 'ct:memberSince',
    accountId: 'ct:accountId',
    publicKeyBase58: 'https://ld.truvera.io/security#publicKeyBase58',
  },
};

const VERIFIER_DOMAIN = 'https://systemb.example.com';

// =============================================================================
// Test Suite
// =============================================================================

describe('TESTCASE 3: Customer Tier Verification', () => {
  let issuer; // System A
  let holder; // User
  let verifier; // System B
  let vipCredential;

  beforeAll(async () => {
    const setup = await createTestSetup();
    issuer = setup.issuer;
    holder = setup.holder;
    verifier = setup.verifier;
  }, 30000);

  // ===========================================================================
  // Scenario 1: Issue VIP credential at System A
  // ===========================================================================

  describe('Scenario 1: System A issues VIP credential', () => {
    test('should issue VIP1 credential with BBS signature', async () => {
      const unsignedCredential = {
        '@context': [CREDENTIALS_V1, BBS_V1, CUSTOMER_TIER_CONTEXT],
        type: ['VerifiableCredential', 'CustomerTierCredential'],
        id: 'urn:uuid:cred-vip1-12345',
        issuer: issuer.did,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holder.did,
          ...TEST_TIER_DATA,
        },
      };

      vipCredential = await issueCredentialWithBBS(issuer.keyDoc, unsignedCredential);

      expect(vipCredential).toBeDefined();
      expect(vipCredential.issuer).toBe(issuer.did);
      expect(vipCredential.credentialSubject.tier).toBe(TEST_TIER_DATA.tier);
      expect(vipCredential.proof.type).toBe('Bls12381BBSSignatureDock2023');
    }, 30000);
  });

  // ===========================================================================
  // Scenario 2: User presents VP to System B
  // ===========================================================================

  describe('Scenario 2: User verifies VIP status at System B', () => {
    const challenge = 'challenge-from-systemB';

    test('should verify VIP1 status with selective disclosure', async () => {
      // User derives credential revealing only tier info
      const derivedCred = deriveCredential(
        vipCredential,
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
        contexts: [CUSTOMER_TIER_CONTEXT],
      });

      const vpJson = vp.toJSON();

      // System B verifies VP
      const result = await verifyVP(vpJson, verifier, challenge, VERIFIER_DOMAIN);
      expect(result.verified).toBe(true);

      // Validate revealed fields
      const vcFromVP = vpJson.verifiableCredential[0];

      expect(vcFromVP.issuer).toBe(issuer.did);
      expect(vpJson.holder).toBe(vcFromVP.credentialSubject.id);
      expect(vcFromVP.credentialSubject.tier).toBe(TEST_TIER_DATA.tier);
      expect(vcFromVP.credentialSubject.totalSpent).toBe(TEST_TIER_DATA.totalSpent);

      // Sensitive fields should not be revealed
      expect(vcFromVP.credentialSubject.tierName).toBeUndefined();
      expect(vcFromVP.credentialSubject.memberSince).toBeUndefined();
      expect(vcFromVP.credentialSubject.accountId).toBeUndefined();
    }, 30000);
  });

});
