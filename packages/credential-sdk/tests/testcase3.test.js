/**
 * TESTCASE 3: Cross-System Customer Tier Verification (BBS Selective Disclosure)
 *
 * Use Case:
 * - System B agrees that if User has VIP1 tier at System A, they can directly
 *   upgrade to VIP1 at System B without accumulating points
 *
 * Flow:
 * 1. User logs into System A, receives VC about "customer tier"
 * 2. User logs into System B, uses the customer tier VC
 * 3. System B verifies user has VIP1 status from System A
 *
 * Actors:
 * - System A (Issuer): BBS keypair - issues customer tier credential
 * - User (Holder): Secp256k1 keypair - derives credential with selective disclosure
 * - System B (Verifier): verifies derived credential
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import {
  issueCredential,
  VerifiablePresentation,
  Presentation,
} from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import {
  Bls12381BBS23DockVerKeyName,
  EcdsaSecp256k1RecoveryMethod2020Name,
} from '../src/vc/crypto/constants';
import { Secp256k1Keypair } from '../src/keypairs';
import {
  EthrDIDModule,
  addressToDID,
  keypairToAddress,
  verifyPresentationOptimistic,
} from '../src/modules/ethr-did';

// =============================================================================
// Constants
// =============================================================================

const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';
const BBS_V1 = 'https://ld.truvera.io/security/bbs23/v1';
const VIETCHAIN_NETWORK = 'vietchain';
const VIETCHAIN_CHAIN_ID = 84005;

const NETWORK_CONFIG = {
  name: VIETCHAIN_NETWORK,
  rpcUrl: 'https://rpc.vietcha.in',
  registry: '0xF0889fb2473F91c068178870ae2e1A0408059A03',
  chainId: VIETCHAIN_CHAIN_ID,
};

const CUSTOMER_TIER_CONTEXT = 'https://raw.githubusercontent.com/OneMatrixL1/did-vc-sdk/testcase3/packages/credential-sdk/tests/testcase3/customer-tier-context.json';

// Field paths
const FIELD_SUBJECT_ID = 'credentialSubject.id';
const FIELD_TIER = 'credentialSubject.tier';
const FIELD_TOTAL_SPENT = 'credentialSubject.totalSpent';

// Fields that System B requires to verify VIP1 status
const REQUIRED_FIELDS_FOR_VERIFIER = [FIELD_SUBJECT_ID, FIELD_TIER, FIELD_TOTAL_SPENT];

// Minimal fields for security tests
const REVEAL_ID_AND_TIER = [FIELD_SUBJECT_ID, FIELD_TIER];

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Creates a Secp256k1 key document for VP signing
 */
function createSecp256k1KeyDoc(keypair, did) {
  const publicKeyBytes = keypair.publicKey().secp256k1.bytes;
  return {
    id: `${did}#controller`,
    controller: did,
    type: EcdsaSecp256k1RecoveryMethod2020Name,
    keypair,
    publicKeyBase58: b58.encode(publicKeyBytes),
  };
}

/**
 * Derives a credential with selective disclosure from original BBS credential
 */
function deriveCredentialWithSelectiveDisclosure(credential, revealFields, nonce) {
  const presentation = new Presentation();
  presentation.addCredentialToPresent(credential);
  presentation.addAttributeToReveal(0, revealFields);
  const derivedCredentials = presentation.deriveCredentials({ nonce });
  return derivedCredentials[0];
}

/**
 * Creates and signs a Verifiable Presentation
 */
async function createSignedPresentation(derivedCred, holderDID, holderKeyDoc, challenge, domain) {
  const vp = new VerifiablePresentation(`urn:uuid:vp-${Date.now()}`);
  vp.addContext(BBS_V1);
  vp.addContext(CUSTOMER_TIER_CONTEXT);
  vp.setHolder(holderDID);
  vp.addCredential(derivedCred);
  await vp.sign(holderKeyDoc, challenge, domain);
  return vp;
}

// =============================================================================
// Test Suite
// =============================================================================

describe('TESTCASE 3: Cross-System Customer Tier Verification', () => {
  // System A (Issuer) - BBS keypair
  let issuerKeyPair;
  let issuerDID;
  let issuerKeyDoc;

  // User (Holder) - Secp256k1 keypair
  let holderKeypair;
  let holderDID;
  let holderKeyDoc;

  // System B (Verifier)
  let ethrModule;

  // Credential issued by System A
  let vip1Credential;

  beforeAll(async () => {
    await initializeWasm();

    // Initialize System A (Issuer) with BBS keypair
    issuerKeyPair = Bls12381BBSKeyPairDock2023.generate({
      id: 'system-a-key',
      controller: 'temp',
    });
    issuerDID = addressToDID(keypairToAddress(issuerKeyPair), VIETCHAIN_NETWORK);
    issuerKeyDoc = {
      id: `${issuerDID}#keys-bbs`,
      controller: issuerDID,
      type: Bls12381BBS23DockVerKeyName,
      keypair: issuerKeyPair,
    };

    // Initialize User (Holder) with Secp256k1 keypair
    holderKeypair = Secp256k1Keypair.random();
    holderDID = addressToDID(keypairToAddress(holderKeypair), VIETCHAIN_NETWORK);
    holderKeyDoc = createSecp256k1KeyDoc(holderKeypair, holderDID);

    // Initialize System B (Verifier)
    ethrModule = new EthrDIDModule({
      networks: [NETWORK_CONFIG],
    });
  }, 30000);

  // ===========================================================================
  // Scenario 1: User gets VIP1 at System A, presents to System B
  // ===========================================================================

  describe('Scenario 1: Cross-system VIP tier verification', () => {
    const challenge = 'challenge-from-systemB';
    const domain = 'https://systemb.example.com';

    test('should issue VIP1 credential at System A and verify at System B', async () => {
      // Step 1: System A issues VIP1 credential to user
      const unsignedCredential = {
        '@context': [CREDENTIALS_V1, BBS_V1, CUSTOMER_TIER_CONTEXT],
        type: ['VerifiableCredential', 'CustomerTierCredential'],
        id: 'urn:uuid:cred-vip1-12345',
        issuer: issuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDID,
          tier: 'VIP1',
          tierName: 'VIP Level 1',
          tierDescription: 'First tier of VIP membership',
          totalSpent: '$250,000',
          memberSince: '2020-01-15',
          accountId: 'ACC-12345',
        },
      };

      vip1Credential = await issueCredential(issuerKeyDoc, unsignedCredential);

      expect(vip1Credential).toBeDefined();
      expect(vip1Credential.issuer).toBe(issuerDID);
      expect(vip1Credential.credentialSubject.tier).toBe('VIP1');
      expect(vip1Credential.proof.type).toBe('Bls12381BBSSignatureDock2023');

      // Step 2: User derives credential with selective disclosure
      const derivedCred = deriveCredentialWithSelectiveDisclosure(
        vip1Credential,
        REQUIRED_FIELDS_FOR_VERIFIER,
        'nonce-verification',
      );

      // Step 3: User creates and signs VP
      const vp = await createSignedPresentation(
        derivedCred,
        holderDID,
        holderKeyDoc,
        challenge,
        domain,
      );

      const vpJson = vp.toJSON();

      // Step 4: System B verifies VP cryptographically
      const result = await verifyPresentationOptimistic(vpJson, {
        module: ethrModule,
        challenge,
        domain,
      });
      expect(result.verified).toBe(true);

      // Step 5: System B validates the revealed data
      const credential = vpJson.verifiableCredential[0];

      // Verify issuer is trusted (System A)
      expect(credential.issuer).toBe(issuerDID);

      // Verify holder binding: VP holder must match credential subject
      expect(vpJson.holder).toBe(credential.credentialSubject.id);

      // Verify VIP1 tier data
      expect(credential.credentialSubject.id).toBe(holderDID);
      expect(credential.credentialSubject.tier).toBe('VIP1');
      expect(credential.credentialSubject.totalSpent).toBe('$250,000');

      // Verify sensitive fields are not exposed
      expect(credential.credentialSubject.tierName).toBeUndefined();
      expect(credential.credentialSubject.memberSince).toBeUndefined();
      expect(credential.credentialSubject.accountId).toBeUndefined();
    }, 30000);
  });

  // ===========================================================================
  // Scenario 2: Security Tests
  // ===========================================================================

  describe('Scenario 2: Security validations', () => {
    const challenge = 'security-test-challenge';
    const domain = 'https://systemb.example.com';

    test('should reject tampered credential (modified tier value)', async () => {
      const derivedCred = deriveCredentialWithSelectiveDisclosure(
        vip1Credential,
        ['credentialSubject.tier'],
        'nonce-tamper-test',
      );

      // Tamper with the tier value
      const tamperedCred = {
        ...derivedCred,
        credentialSubject: {
          ...derivedCred.credentialSubject,
          tier: 'VIP3', // TAMPERED
        },
      };

      const vp = await createSignedPresentation(
        tamperedCred,
        holderDID,
        holderKeyDoc,
        challenge,
        domain,
      );

      const result = await verifyPresentationOptimistic(vp.toJSON(), {
        module: ethrModule,
        challenge,
        domain,
      });

      // BBS proof verification should fail because data was tampered
      expect(result.verified).toBe(false);
    }, 30000);

    test('should detect forged credential (attacker issues VC with fake subject)', async () => {
      // Attacker creates their own BBS keypair and issues a fake VIP1 credential
      const attackerIssuerKeypair = Bls12381BBSKeyPairDock2023.generate({ id: 'attacker-issuer-key' });
      const attackerIssuerDID = addressToDID(keypairToAddress(attackerIssuerKeypair), VIETCHAIN_NETWORK);
      const attackerIssuerKeyDoc = {
        id: `${attackerIssuerDID}#keys-bbs`,
        controller: attackerIssuerDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: attackerIssuerKeypair,
      };

      // Attacker's holder identity
      const attackerKeypair = Secp256k1Keypair.random();
      const attackerDID = addressToDID(keypairToAddress(attackerKeypair), VIETCHAIN_NETWORK);
      const attackerKeyDoc = createSecp256k1KeyDoc(attackerKeypair, attackerDID);

      // Attacker issues fake credential claiming they are VIP1
      const fakeCredential = await issueCredential(attackerIssuerKeyDoc, {
        '@context': [CREDENTIALS_V1, BBS_V1, CUSTOMER_TIER_CONTEXT],
        type: ['VerifiableCredential', 'CustomerTierCredential'],
        id: 'urn:uuid:fake-vip1',
        issuer: attackerIssuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: attackerDID,
          tier: 'VIP1',
          totalSpent: '$999,999',
        },
      });

      // Attacker derives and presents credential
      const derivedCred = deriveCredentialWithSelectiveDisclosure(
        fakeCredential,
        REVEAL_ID_AND_TIER,
        'nonce-forged',
      );

      const attackerVP = await createSignedPresentation(
        derivedCred,
        attackerDID,
        attackerKeyDoc,
        challenge,
        domain,
      );

      const vpJson = attackerVP.toJSON();

      // SDK verification passes (cryptographically valid)
      const result = await verifyPresentationOptimistic(vpJson, {
        module: ethrModule,
        challenge,
        domain,
      });
      expect(result.verified).toBe(true);

      // Holder binding passes (attacker is both holder and subject)
      const credential = vpJson.verifiableCredential[0];
      expect(vpJson.holder).toBe(credential.credentialSubject.id);

      // BUT: Issuer is NOT System A - this is a forged credential!
      expect(credential.issuer).toBe(attackerIssuerDID);
      expect(credential.issuer).not.toBe(issuerDID);

      // System B must check issuer is trusted (System A)
    }, 30000);

    test('should reject credential with tampered issuer', async () => {
      // Attacker creates valid credential from their own issuer
      const attackerIssuerKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'attacker-issuer-key-2',
        controller: 'temp',
      });
      const attackerIssuerDID = addressToDID(keypairToAddress(attackerIssuerKeypair), VIETCHAIN_NETWORK);
      const attackerIssuerKeyDoc = {
        id: `${attackerIssuerDID}#keys-bbs`,
        controller: attackerIssuerDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: attackerIssuerKeypair,
      };

      const attackerKeypair = Secp256k1Keypair.random();
      const attackerDID = addressToDID(keypairToAddress(attackerKeypair), VIETCHAIN_NETWORK);
      const attackerKeyDoc = createSecp256k1KeyDoc(attackerKeypair, attackerDID);

      // Attacker issues credential with their issuer
      const attackerCredential = await issueCredential(attackerIssuerKeyDoc, {
        '@context': [CREDENTIALS_V1, BBS_V1, CUSTOMER_TIER_CONTEXT],
        type: ['VerifiableCredential', 'CustomerTierCredential'],
        id: 'urn:uuid:attacker-cred',
        issuer: attackerIssuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: attackerDID,
          tier: 'VIP1',
          totalSpent: '$999,999',
        },
      });

      // Derive credential
      const derivedCred = deriveCredentialWithSelectiveDisclosure(
        attackerCredential,
        REVEAL_ID_AND_TIER,
        'nonce-tamper-issuer',
      );

      // Attacker tampers issuer to look like System A
      const tamperedCred = {
        ...derivedCred,
        issuer: issuerDID, // FAKE System A as issuer
      };

      const attackerVP = await createSignedPresentation(
        tamperedCred,
        attackerDID,
        attackerKeyDoc,
        challenge,
        domain,
      );

      const vpJson = attackerVP.toJSON();

      // SDK should reject because issuer was tampered (BBS proof won't match)
      const result = await verifyPresentationOptimistic(vpJson, {
        module: ethrModule,
        challenge,
        domain,
      });

      expect(result.verified).toBe(false);
    }, 30000);

    test('should detect stolen credential attack via holder binding check', async () => {
      // Attacker steals user's derived credential
      const stolenCred = deriveCredentialWithSelectiveDisclosure(
        vip1Credential,
        REVEAL_ID_AND_TIER,
        'nonce-stolen',
      );

      // Attacker creates their own identity
      const attackerKeypair = Secp256k1Keypair.random();
      const attackerDID = addressToDID(keypairToAddress(attackerKeypair), VIETCHAIN_NETWORK);
      const attackerKeyDoc = createSecp256k1KeyDoc(attackerKeypair, attackerDID);

      // Attacker creates VP with their DID but stolen credential
      const attackerVP = await createSignedPresentation(
        stolenCred,
        attackerDID, // Attacker's DID
        attackerKeyDoc,
        challenge,
        domain,
      );

      const vpJson = attackerVP.toJSON();

      // SDK cryptographic verification passes (VP signature + VC proof are valid)
      const sdkResult = await verifyPresentationOptimistic(vpJson, {
        module: ethrModule,
        challenge,
        domain,
      });
      expect(sdkResult.verified).toBe(true);

      // Holder binding check catches the attack
      const credential = vpJson.verifiableCredential[0];
      expect(vpJson.holder).toBe(attackerDID);
      expect(credential.credentialSubject.id).toBe(holderDID);
      expect(vpJson.holder).not.toBe(credential.credentialSubject.id);
    }, 30000);
  });
});
