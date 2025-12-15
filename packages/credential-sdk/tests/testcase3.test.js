/**
 * TESTCASE 3: Cross-System Customer Tier Verification (BBS Selective Disclosure)
 *
 * Bài toán:
 * - User đăng nhập hệ thống A, được cấp VC về "cấp khách hàng" (BBS signature)
 * - User đăng nhập hệ thống B, dùng VC với selective disclosure
 * - Hệ thống B xác minh user có VIP1 (chỉ xem 3 fields: id, tier, totalSpent)
 *
 * Flow:
 * 1. System A (Issuer): BBS keypair → issue VC
 * 2. User (Holder): Secp256k1 keypair → derive credential (selective disclosure)
 * 3. System B (Verifier): verify derived credential
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import {
  issueCredential,
  VerifiablePresentation,
} from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName, EcdsaSecp256k1RecoveryMethod2020Name } from '../src/vc/crypto/constants';
import { Secp256k1Keypair } from '../src/keypairs';
import {
  EthrDIDModule,
  addressToDID,
  keypairToAddress,
  verifyCredentialOptimistic,
  verifyPresentationOptimistic,
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

// Custom context URL
const CUSTOMER_TIER_CONTEXT = 'https://raw.githubusercontent.com/OneMatrixL1/did-vc-sdk/testcase3/packages/credential-sdk/tests/testcase3/customer-tier-context.json';

describe('TESTCASE 3: Cross-System Customer Tier Verification', () => {
  // System A (Issuer) - BBS keypair
  let systemAKeypair;
  let systemADID;
  let systemAKeyDoc;

  // User (Holder) - Secp256k1 keypair
  let userKeypair;
  let userDID;
  let userKeyDoc;

  // System B (Verifier)
  let systemBModule;

  // Credential
  let vip1Credential;

  beforeAll(async () => {
    await initializeWasm();

    // ========== System A (Issuer) with BBS ==========
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

    // ========== User (Holder) with Secp256k1 ==========
    userKeypair = Secp256k1Keypair.random();
    userDID = addressToDID(keypairToAddress(userKeypair), VIETCHAIN_NETWORK);

    // Create userKeyDoc for VP signing (RecoveryMethod2020 for ethr-did)
    const userPublicKeyBytes = userKeypair._publicKey();
    const userPublicKeyBase58 = b58.encode(userPublicKeyBytes);

    userKeyDoc = {
      id: `${userDID}#controller`,
      controller: userDID,
      type: EcdsaSecp256k1RecoveryMethod2020Name,
      keypair: userKeypair,
      publicKeyBase58: userPublicKeyBase58,
    };

    // ========== System B (Verifier) ==========
    systemBModule = new EthrDIDModule({
      networks: [networkConfig],
    });
  }, 30000);

  describe('Scenario 1: System A issues VIP credential', () => {
    test('System A issues VIP1 credential to user with BBS signature', async () => {
      const unsignedCredential = {
        '@context': [CREDENTIALS_V1, BBS_V1, CUSTOMER_TIER_CONTEXT],
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
      expect(vip1Credential.proof.type).toBe('Bls12381BBSSignatureDock2023');
    }, 30000);
  });

  describe('Scenario 2: User presents credential to System B', () => {
    test('User derives credential with selective disclosure (3 fields)', async () => {
      // 1. User prepares selective disclosure
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      await presentation.addCredentialToPresent(vip1Credential);

      // 2. Reveal only 3 required fields
      presentation.addAttributeToReveal(0, [
        'credentialSubject.id',
        'credentialSubject.tier',
        'credentialSubject.totalSpent',
      ]);

      // 3. Derive credential (BBS ZK proof)
      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-123',
      });

      expect(derivedCredentials.length).toBe(1);

      const derivedCred = derivedCredentials[0];

      // 4. Validate revealed fields (selective disclosure works)
      expect(derivedCred.credentialSubject.id).toBe(userDID);
      expect(derivedCred.credentialSubject.tier).toBe('VIP1');
      expect(derivedCred.credentialSubject.totalSpent).toBe('$250,000');

      // Hidden fields
      expect(derivedCred.credentialSubject.tierName).toBeUndefined();
      expect(derivedCred.credentialSubject.tierDescription).toBeUndefined();

      // 5. Wrap derived credential in VP (holder proof)
      const challenge = 'challenge-from-systemB-123';
      const domain = 'https://systemb.example.com';

      const vp = new VerifiablePresentation('urn:uuid:vp-presentation-123');
      vp.addContext(BBS_V1);
      vp.addContext(CUSTOMER_TIER_CONTEXT);
      vp.setHolder(userDID);
      vp.addCredential(derivedCred);

      // 6. User signs VP with Secp256k1 key
      await vp.sign(userKeyDoc, challenge, domain);

      // 7. System B verifies VP
      const result = await verifyPresentationOptimistic(vp.toJSON(), {
        module: systemBModule,
        challenge,
        domain,
      });

      if (!result.verified) {
        console.log('VP Error:', result.error?.message || result.error);
        console.log('VP Errors:', result.error?.errors?.map(e => e.message));
      }

      expect(result.verified).toBe(true);
    }, 30000);

    test('SECURITY: System B rejects VP with tampered credential', async () => {
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      await presentation.addCredentialToPresent(vip1Credential);

      presentation.addAttributeToReveal(0, ['credentialSubject.tier']);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'nonce-tamper',
      });

      // Tamper tier value after derivation
      const tamperedCred = {
        ...derivedCredentials[0],
        credentialSubject: {
          ...derivedCredentials[0].credentialSubject,
          tier: 'VIP3',  // TAMPERED!
        },
      };

      // Wrap tampered cred in VP
      const challenge = 'challenge-tamper-test';
      const domain = 'https://systemb.example.com';

      const vp = new VerifiablePresentation('urn:uuid:vp-tampered');
      vp.addContext(BBS_V1);
      vp.addContext(CUSTOMER_TIER_CONTEXT);
      vp.setHolder(userDID);
      vp.addCredential(tamperedCred);  // Add tampered credential

      await vp.sign(userKeyDoc, challenge, domain);

      // System B verifies VP - should FAIL because BBS proof doesn't match
      const result = await verifyPresentationOptimistic(vp.toJSON(), {
        module: systemBModule,
        challenge,
        domain,
      });

      expect(result.verified).toBe(false);
    }, 30000);

    test('🚨 ATTACK: Attacker steals derived credential - SDK does NOT auto-check holder', async () => {
      /**
       * ATTACK SCENARIO:
       * 1. User creates valid derived credential
       * 2. Attacker intercepts/steals this derived credential
       * 3. Attacker creates their own VP, puts stolen credential inside
       * 4. Attacker signs VP with their own key
       *
       * RESULT: SDK verifies VP as valid because:
       * - VP signature is valid (attacker's signature)
       * - VC proof is valid (original BBS proof)
       * - SDK does NOT check that VP.holder === VC.credentialSubject.id
       */

      // 1. User creates valid derived credential
      const { default: Presentation } = await import('../src/vc/presentation');
      const userPresentation = new Presentation();
      await userPresentation.addCredentialToPresent(vip1Credential);
      userPresentation.addAttributeToReveal(0, [
        'credentialSubject.id',
        'credentialSubject.tier',
      ]);

      const derivedCredentials = userPresentation.deriveCredentials({
        nonce: 'nonce-stolen',
      });

      const stolenCred = derivedCredentials[0];

      // 2. Attacker creates their own keypair
      const attackerKeypair = Secp256k1Keypair.random();
      const attackerDID = addressToDID(keypairToAddress(attackerKeypair), VIETCHAIN_NETWORK);

      const attackerPublicKeyBytes = attackerKeypair._publicKey();
      const attackerPublicKeyBase58 = b58.encode(attackerPublicKeyBytes);

      const attackerKeyDoc = {
        id: `${attackerDID}#controller`,
        controller: attackerDID,
        type: EcdsaSecp256k1RecoveryMethod2020Name,
        keypair: attackerKeypair,
        publicKeyBase58: attackerPublicKeyBase58,
      };

      // 3. Attacker creates VP with THEIR holder, but STOLEN credential
      const challenge = 'challenge-attack-test';
      const domain = 'https://systemb.example.com';

      const attackerVP = new VerifiablePresentation('urn:uuid:vp-attacker');
      attackerVP.addContext(BBS_V1);
      attackerVP.addContext(CUSTOMER_TIER_CONTEXT);
      attackerVP.setHolder(attackerDID);  // Attacker's DID
      attackerVP.addCredential(stolenCred);  // Stolen credential with userDID

      // 4. Attacker signs VP with their key
      await attackerVP.sign(attackerKeyDoc, challenge, domain);

      // 5. SDK verification PASSES (this is the vulnerability!)
      const result = await verifyPresentationOptimistic(attackerVP.toJSON(), {
        module: systemBModule,
        challenge,
        domain,
      });

      // ⚠️ SDK says verified=true because it only checks:
      // - VP signature valid (attacker's) ✓
      // - VC proof valid (original BBS) ✓
      // - Does NOT check holder === credentialSubject.id ❌
      expect(result.verified).toBe(true);

      // PROOF: VP holder is ATTACKER, but credential subject is USER
      expect(attackerVP.holder).toBe(attackerDID);
      expect(stolenCred.credentialSubject.id).toBe(userDID);
      expect(attackerVP.holder).not.toBe(stolenCred.credentialSubject.id);
    }, 30000);

    test('✅ SECURE: Manual holder check prevents stolen credential attack', async () => {
      /**
       * Application-level security: manually verify holder === credentialSubject.id
       */

      function verifyHolderBinding(vpJson) {
        const holder = vpJson.holder;
        const creds = vpJson.verifiableCredential || [];

        for (const cred of creds) {
          const subjectId = cred.credentialSubject?.id;

          if (subjectId && subjectId !== holder) {
            throw new Error(
              `Holder binding mismatch: VP holder is ${holder}, ` +
              `but credential subject is ${subjectId}`
            );
          }
        }

        return true;
      }

      // Attacker's VP from previous test
      const { default: Presentation } = await import('../src/vc/presentation');
      const userPresentation = new Presentation();
      await userPresentation.addCredentialToPresent(vip1Credential);
      userPresentation.addAttributeToReveal(0, ['credentialSubject.id', 'credentialSubject.tier']);

      const derivedCredentials = userPresentation.deriveCredentials({ nonce: 'nonce-secure' });
      const stolenCred = derivedCredentials[0];

      const attackerKeypair = Secp256k1Keypair.random();
      const attackerDID = addressToDID(keypairToAddress(attackerKeypair), VIETCHAIN_NETWORK);

      const attackerKeyDoc = {
        id: `${attackerDID}#controller`,
        controller: attackerDID,
        type: EcdsaSecp256k1RecoveryMethod2020Name,
        keypair: attackerKeypair,
        publicKeyBase58: b58.encode(attackerKeypair._publicKey()),
      };

      const attackerVP = new VerifiablePresentation('urn:uuid:vp-attacker-2');
      attackerVP.addContext(BBS_V1);
      attackerVP.addContext(CUSTOMER_TIER_CONTEXT);
      attackerVP.setHolder(attackerDID);
      attackerVP.addCredential(stolenCred);

      await attackerVP.sign(attackerKeyDoc, 'challenge-secure', 'https://systemb.example.com');

      const vpJson = attackerVP.toJSON();

      // SDK verification passes
      const result = await verifyPresentationOptimistic(vpJson, {
        module: systemBModule,
        challenge: 'challenge-secure',
        domain: 'https://systemb.example.com',
      });

      expect(result.verified).toBe(true);

      // BUT manual holder check FAILS - catches the attack!
      expect(() => verifyHolderBinding(vpJson)).toThrow('Holder binding mismatch');
    }, 30000);
  });
});
