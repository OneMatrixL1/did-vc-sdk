/**
 * TESTCASE 3: Cross-System Customer Tier Verification (BBS Selective Disclosure)
 *
 * Scenario:
 * - System A (Issuer) issues VIP credential to User using BBS signature
 * - User (Holder) creates derived credential revealing specific attributes
 * - System B (Verifier) verifies the derived credential using Optimistic verification
 *
 * This test uses:
 * - BBS signatures for Issuer (System A)
 * - BBS Selective Disclosure for User presentation
 * - Optimistic verification (no blockchain RPC, real HTTP for contexts)
 *
 * Run: npm test -- testcase3
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import {
  issueCredential,
} from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import { Secp256k1Keypair } from '../src/keypairs';
import {
  EthrDIDModule,
  addressToDID,
  keypairToAddress,
  verifyCredentialOptimistic,
} from '../src/modules/ethr-did';

// Constants
const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';
const BBS_V1 = 'https://ld.truvera.io/security/bbs23/v1';
const VIETCHAIN_NETWORK = 'vietchain';
const VIETCHAIN_CHAIN_ID = 84005;

// Network configuration
const networkConfig = {
  name: VIETCHAIN_NETWORK,
  rpcUrl: 'https://rpc.vietcha.in',
  registry: '0xF0889fb2473F91c068178870ae2e1A0408059A03',
  chainId: VIETCHAIN_CHAIN_ID,
};

// Custom context URL (live on GitHub)
const CUSTOMER_TIER_CONTEXT = 'https://raw.githubusercontent.com/OneMatrixL1/did-vc-sdk/testcase3/packages/credential-sdk/tests/testcase3/customer-tier-context.json';

describe('TESTCASE 3: Cross-System Customer Tier Verification', () => {
  // System A (Issuer)
  let systemAKeypair;
  let systemADID;
  let systemAKeyDoc;

  // User (Holder)
  let userKeypair;
  let userDID;

  // System B (Verifier) - uses EthrDIDModule
  let systemBModule;

  // Credentials
  let vip1Credential;

  beforeAll(async () => {
    // Initialize WASM for BBS operations
    await initializeWasm();

    // ========== Setup System A (Issuer) with BBS ==========
    systemAKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'system-a-key',
      controller: 'temp',
    });

    systemADID = addressToDID(keypairToAddress(systemAKeypair), VIETCHAIN_NETWORK);

    systemAKeyDoc = {
      id: `${systemADID}#keys-bbs`,
      controller: systemADID,
      type: Bls12381BBS23DockVerKeyName,
      keypair: systemAKeypair,
    };

    expect(systemADID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);

    // ========== Setup User (Holder) with Secp256k1 ==========
    userKeypair = Secp256k1Keypair.random();

    userDID = addressToDID(keypairToAddress(userKeypair), VIETCHAIN_NETWORK);

    // ========== Setup System B (Verifier) ==========
    systemBModule = new EthrDIDModule({
      networks: [networkConfig],
    });
  }, 30000);

  describe('Scenario 1: System A issues customer tier credential', () => {
    test('System A issues VIP1 credential to user with BBS signature', async () => {
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1,
          BBS_V1,
          CUSTOMER_TIER_CONTEXT,
        ],
        type: ['VerifiableCredential', 'CustomerTierCredential'],
        id: 'urn:uuid:cred-vip1-12345',
        issuer: systemADID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: userDID,
          tier: 'VIP1',
          tierName: 'VIP Level 1',
          tierDescription: 'First tier of VIP membership',
          totalSpent: '$250,000',
          memberSince: '2020-01-15',
          accountId: 'ACC-12345',
        },
      };

      vip1Credential = await issueCredential(systemAKeyDoc, unsignedCredential);

      expect(vip1Credential).toBeDefined();
      expect(vip1Credential.issuer).toBe(systemADID);
      expect(vip1Credential.credentialSubject.tier).toBe('VIP1');
      expect(vip1Credential.proof).toBeDefined();
      expect(vip1Credential.proof.type).toBe('Bls12381BBSSignatureDock2023');
      expect(vip1Credential.proof.publicKeyBase58).toBeDefined();
    }, 30000);
  });

  describe('Scenario 2: User presents credential to System B', () => {
    test('User creates derived credential (VP) revealing specific attributes', async () => {
      // 1. User prepares Presentation with Selective Disclosure
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      // 2. Add credential and select attributes to reveal
      await presentation.addCredentialToPresent(vip1Credential);

      // Reveal all fields required by System B
      presentation.addAttributeToReveal(0, [
        'credentialSubject.id',
        'credentialSubject.tier',
        // 'credentialSubject.tierName',
        // 'credentialSubject.tierDescription',
        'credentialSubject.totalSpent',
        // 'credentialSubject.memberSince',
        // 'credentialSubject.accountId',
      ]);

      // 3. Derive credentials (this generates the ZK proof)
      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-123',
      });

      expect(derivedCredentials.length).toBe(1);
      const derivedCred = derivedCredentials[0];

      // 4. System B verifies the derived credential using Optimistic verification
      // This uses the embedded publicKeyBase58 in the proof to derive address
      // and compare with DID - no blockchain RPC needed!
      const result = await verifyCredentialOptimistic(derivedCred, {
        module: systemBModule,
      });

      expect(result.verified).toBe(true);
      expect(result.results[0].verified).toBe(true);

      // Validate revealed data is present
      expect(derivedCred.credentialSubject.tier).toBe('VIP1');
      expect(derivedCred.credentialSubject.totalSpent).toBe('$250,000');
    }, 30000);

    test('SECURITY: System B rejects derived credential with tampered values', async () => {
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      await presentation.addCredentialToPresent(vip1Credential);
      presentation.addAttributeToReveal(0, ['credentialSubject.tier']);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-bad',
      });

      // Tamper with the derived credential (User tries to fake VIP3)
      const tamperedCred = {
        ...derivedCredentials[0],
        credentialSubject: {
          ...derivedCredentials[0].credentialSubject,
          tier: 'VIP3', // TAMPERED!
        },
      };

      const result = await verifyCredentialOptimistic(tamperedCred, {
        module: systemBModule,
      });

      expect(result.verified).toBe(false);
    }, 30000);

    test('🚨 VULNERABILITY: Attacker can replay stolen derived credential', async () => {
      // Legitimate User creates derived credential
      const { default: Presentation } = await import('../src/vc/presentation');
      const userPresentation = new Presentation();

      await userPresentation.addCredentialToPresent(vip1Credential);
      userPresentation.addAttributeToReveal(0, [
        'credentialSubject.id',
        'credentialSubject.tier',
        'credentialSubject.totalSpent',
      ]);

      const userDerivedCreds = userPresentation.deriveCredentials({
        nonce: 'nonce-user-123',
      });

      const userDerivedCred = userDerivedCreds[0];

      // ========== ATTACK SCENARIO ==========
      // Attacker intercepts or steals User's derived credential
      // Attacker creates fake identity
      const attackerKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'attacker-key',
        controller: 'temp',
      });
      const attackerDID = addressToDID(keypairToAddress(attackerKeypair), VIETCHAIN_NETWORK);

      // Attacker presents stolen credential to System B
      const result = await verifyCredentialOptimistic(userDerivedCred, {
        module: systemBModule,
      });

      // 🚨 VULNERABILITY: Verification passes even though attacker is not the credential subject!
      expect(result.verified).toBe(true);

      // The credential says it belongs to userDID
      expect(userDerivedCred.credentialSubject.id).toBe(userDID);

      // But System B has NO WAY to verify that the presenter is actually userDID
      // Attacker (attackerDID) can use User's (userDID) credential!
    }, 30000);

    test('✅ SECURE: System B verifies holder ownership with authentication', async () => {
      /**
       * Utility function to verify holder ownership
       * In production, this should check against authenticated session
       */
      function verifyHolderOwnership(derivedCred, authenticatedDID) {
        const credentialSubjectDID = derivedCred.credentialSubject.id;

        if (!credentialSubjectDID) {
          throw new Error('Credential must reveal credentialSubject.id for holder verification');
        }

        if (credentialSubjectDID !== authenticatedDID) {
          throw new Error(
            `Holder ownership verification failed: ` +
            `credential belongs to ${credentialSubjectDID}, ` +
            `but presenter authenticated as ${authenticatedDID}`,
          );
        }

        return true;
      }

      // User creates derived credential
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      await presentation.addCredentialToPresent(vip1Credential);
      presentation.addAttributeToReveal(0, [
        'credentialSubject.id',  // MUST reveal for holder binding
        'credentialSubject.tier',
        'credentialSubject.totalSpent',
      ]);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-secure-123',
      });

      const derivedCred = derivedCredentials[0];

      // Scenario: User authenticates to System B and presents credential
      const authenticatedUserDID = userDID;  // From authentication layer (e.g., DID Auth, OAuth)

      // System B verification flow
      const cryptoResult = await verifyCredentialOptimistic(derivedCred, {
        module: systemBModule,
      });

      expect(cryptoResult.verified).toBe(true);

      // Additional holder ownership check
      expect(() => {
        verifyHolderOwnership(derivedCred, authenticatedUserDID);
      }).not.toThrow();

      // Success: Both cryptographic proof AND holder ownership verified
      expect(derivedCred.credentialSubject.id).toBe(authenticatedUserDID);
    }, 30000);

    test('✅ SECURE: System B rejects credential when holder mismatch', async () => {
      function verifyHolderOwnership(derivedCred, authenticatedDID) {
        const credentialSubjectDID = derivedCred.credentialSubject.id;

        if (credentialSubjectDID !== authenticatedDID) {
          throw new Error(
            `Holder ownership verification failed: ` +
            `credential belongs to ${credentialSubjectDID}, ` +
            `but presenter authenticated as ${authenticatedDID}`,
          );
        }

        return true;
      }

      // User creates derived credential
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      await presentation.addCredentialToPresent(vip1Credential);
      presentation.addAttributeToReveal(0, [
        'credentialSubject.id',
        'credentialSubject.tier',
      ]);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-attacker-123',
      });

      const userDerivedCred = derivedCredentials[0];

      // Scenario: Attacker steals credential and tries to use it
      const attackerKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'attacker-key',
        controller: 'temp',
      });
      const attackerDID = addressToDID(keypairToAddress(attackerKeypair), VIETCHAIN_NETWORK);

      // Attacker authenticates as themselves
      const authenticatedAttackerDID = attackerDID;

      // Cryptographic verification passes (credential is valid)
      const cryptoResult = await verifyCredentialOptimistic(userDerivedCred, {
        module: systemBModule,
      });

      expect(cryptoResult.verified).toBe(true);

      // But holder ownership check FAILS
      expect(() => {
        verifyHolderOwnership(userDerivedCred, authenticatedAttackerDID);
      }).toThrow('Holder ownership verification failed');


      // System B correctly rejects presentation
    }, 30000);

    test('⚠️ PRIVACY TRADE-OFF: Hiding credentialSubject.id prevents holder verification', async () => {
      // User wants maximum privacy: hide credentialSubject.id
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      await presentation.addCredentialToPresent(vip1Credential);
      presentation.addAttributeToReveal(0, [
        // 'credentialSubject.id',  ← NOT revealed for privacy
        'credentialSubject.tier',
        'credentialSubject.totalSpent',
      ]);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-privacy-123',
      });

      const derivedCred = derivedCredentials[0];

      // Cryptographic verification passes
      const result = await verifyCredentialOptimistic(derivedCred, {
        module: systemBModule,
      });

      expect(result.verified).toBe(true);

      // BUT: credentialSubject.id is hidden
      expect(derivedCred.credentialSubject.id).toBeUndefined();

      // Manual holder verification CANNOT work
      function verifyHolderOwnership(derivedCred, authenticatedDID) {
        const credentialSubjectDID = derivedCred.credentialSubject.id;

        if (!credentialSubjectDID) {
          throw new Error('Cannot verify holder: credentialSubject.id is hidden');
        }

        if (credentialSubjectDID !== authenticatedDID) {
          throw new Error('Holder mismatch');
        }

        return true;
      }

      // Attempt to verify ownership fails
      expect(() => {
        verifyHolderOwnership(derivedCred, userDID);
      }).toThrow('Cannot verify holder: credentialSubject.id is hidden');

      // ⚠️ TRADE-OFF:
      // ✅ Privacy: credentialSubject.id is hidden
      // ❌ Security: Cannot prevent replay attacks (no holder binding)
      //
      // To solve this, need cryptographic holder binding (not yet in SDK):
      // - User signs presentation with their private key
      // - Signature proves ownership without revealing ID
      // - Verifier checks signature + BBS proof
    }, 30000);
  });
});
