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

    // ========== Setup User (Holder) with BBS ==========
    userKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'user-key',
      controller: 'temp',
    });

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
  });
});
