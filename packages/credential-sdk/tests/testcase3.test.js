/**
 * TESTCASE 3: Cross-System Customer Tier Verification with BBS Signatures
 *
 * Real-world Flow:
 * 1. System A (e-commerce) issues VIP tier credential to user with BBS signature
 * 2. User presents credential to System B via Verifiable Presentation (VP)
 * 3. System B verifies the VP and embedded VC using optimistic DID resolution
 *
 * Uses:
 * - did:ethr:vietchain:... (ethr-did module)
 * - BBS signatures (Bls12381BBSKeyPairDock2023)
 * - EthrDIDModule with optimistic: true (no custom helpers needed)
 *
 * Run: npm test -- testcase3
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import {
  issueCredential,
  verifyCredential,
  VerifiablePresentation,
} from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
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

// Network configuration (same as ethr-did-optimistic.test.js)
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

  // User (Holder) - needs keypair to sign VP
  let userKeypair;
  let userDID;
  let userKeyDoc;

  // System B (Verifier) - uses EthrDIDModule
  let systemBModule;

  // Credentials
  let vip1Credential;

  beforeAll(async () => {
    // Initialize WASM for BBS operations
    await initializeWasm();

    // ========== Setup System A (Issuer) with BBS ==========
    // Following pattern from ethr-did-optimistic.test.js
    systemAKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'system-a-key',
      controller: 'temp',
    });

    systemADID = addressToDID(keypairToAddress(systemAKeypair), VIETCHAIN_NETWORK);

    // Simple keyDoc - no custom helpers needed!
    systemAKeyDoc = {
      id: `${systemADID}#keys-bbs`,
      controller: systemADID,
      type: Bls12381BBS23DockVerKeyName,
      keypair: systemAKeypair,
    };

    expect(systemADID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);

    // ========== Setup User (Holder) ==========
    // User needs keys to sign the VP
    userKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'user-key',
      controller: 'temp',
    });

    userDID = addressToDID(keypairToAddress(userKeypair), VIETCHAIN_NETWORK);

    userKeyDoc = {
      id: `${userDID}#keys-bbs`,
      controller: userDID,
      type: Bls12381BBS23DockVerKeyName,
      keypair: userKeypair,
    };

    expect(userDID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);

    // ========== Setup System B (Verifier) with EthrDIDModule ==========
    // Uses optimistic: true for verification without RPC calls
    systemBModule = new EthrDIDModule({
      networks: [networkConfig],
      optimistic: true,
    });
  });

  describe('Scenario 1: System A issues customer tier credential', () => {
    test('System A issues VIP1 credential to user with BBS signature', async () => {
      // Build unsigned credential
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1,
          BBS_V1,
          CUSTOMER_TIER_CONTEXT,
        ],
        type: ['VerifiableCredential', 'CustomerTierCredential'],
        id: 'urn:uuid:cred-vip1',
        issuer: systemADID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: userDID,
          tier: 'VIP1',
          tierName: 'VIP1 - Premium Customer',
          tierDescription: 'Top tier customer from System A E-commerce',
          totalSpent: '$250,000',
          memberSince: '2020-03-15',
          accountId: 'SYSCUST-12345',
        },
      };

      // Issue credential using SDK
      vip1Credential = await issueCredential(systemAKeyDoc, unsignedCredential);

      // Validate BBS signature
      expect(vip1Credential).toBeDefined();
      expect(vip1Credential.issuer).toBe(systemADID);
      expect(vip1Credential.credentialSubject.id).toBe(userDID);
      expect(vip1Credential.credentialSubject.tier).toBe('VIP1');
      expect(vip1Credential.proof).toBeDefined();
      expect(vip1Credential.proof.type).toBe('Bls12381BBSSignatureDock2023');

      // BBS proof should contain embedded public key for address verification
      expect(vip1Credential.proof.publicKeyBase58).toBeDefined();
    }, 30000);
  });

  describe('Scenario 2: User presents credential to System B', () => {
    test('User creates transferable Verifiable Presentation (VP) from VC', async () => {
      // 1. User creates a VP and adds the credential
      const vp = new VerifiablePresentation('urn:uuid:vp-12345');
      vp.addCredential(vip1Credential);
      vp.setHolder(userDID);

      // 2. User signs the VP with their key
      await vp.sign(userKeyDoc, 'nonce-123', 'domain-abc', systemBModule);

      // Verify structure
      expect(vp.proof).toBeDefined();
      expect(vp.credentials.length).toBe(1);
      expect(vp.holder).toBe(userDID);

      // 3. System B verifies the VP
      // This verifies BOTH the VP signature (User) AND the embedded VC signature (System A)
      const result = await vp.verify({
        challenge: 'nonce-123',
        domain: 'domain-abc',
        resolver: systemBModule,
        forceRevocationCheck: false,
      });

      expect(result.verified).toBe(true);
      expect(result.credentialResults[0].verified).toBe(true);
    }, 30000);

    test('SECURITY: System B rejects VP with tampered inner VC', async () => {
      // Create valid VP first
      const vp = new VerifiablePresentation('urn:uuid:vp-tampered-vc');

      // Tamper with credential BEFORE adding to VP (or deep copy modify)
      const tamperedVC = {
        ...vip1Credential,
        credentialSubject: {
          ...vip1Credential.credentialSubject,
          tier: 'VIP3', // TAMPERED!
        },
      };

      vp.addCredential(tamperedVC);
      vp.setHolder(userDID);
      await vp.sign(userKeyDoc, 'nonce-bad', 'domain-bad', systemBModule);

      const result = await vp.verify({
        challenge: 'nonce-bad',
        domain: 'domain-bad',
        resolver: systemBModule,
      });

      // VP Signature is valid (signed by User), but embedded VC signature is invalid
      // So overall verification must fail or credentialResults must show failure
      expect(result.verified).toBe(false);
      expect(result.credentialResults[0].verified).toBe(false);
    }, 30000);

    test('SECURITY: System B rejects VP with tampered VP signature', async () => {
      // Create valid VP
      const vp = new VerifiablePresentation('urn:uuid:vp-tampered-sig');
      vp.addCredential(vip1Credential);
      vp.setHolder(userDID);
      await vp.sign(userKeyDoc, 'nonce-123', 'domain-abc', systemBModule);

      // Tamper with VP structure after signing
      vp.id = 'urn:uuid:changed-id';

      const result = await vp.verify({
        challenge: 'nonce-123',
        domain: 'domain-abc',
        resolver: systemBModule,
      });

      expect(result.verified).toBe(false);
    }, 30000);

    test('SECURITY: System B rejects expired credential in VP', async () => {
      // Issue expired credential
      const expiredCredential = await issueCredential(systemAKeyDoc, {
        '@context': [
          CREDENTIALS_V1,
          BBS_V1,
          CUSTOMER_TIER_CONTEXT,
        ],
        type: ['VerifiableCredential', 'CustomerTierCredential'],
        id: 'urn:uuid:cred-expired',
        issuer: systemADID,
        issuanceDate: '2023-01-01T00:00:00Z',
        expirationDate: '2023-12-31T23:59:59Z',
        credentialSubject: {
          id: userDID,
          tier: 'VIP1',
        },
      });

      const vp = new VerifiablePresentation('urn:uuid:vp-expired');
      vp.addCredential(expiredCredential);
      vp.setHolder(userDID);
      await vp.sign(userKeyDoc, 'nonce-exp', 'domain-exp', systemBModule);

      const result = await vp.verify({
        challenge: 'nonce-exp',
        domain: 'domain-exp',
        resolver: systemBModule,
      });

      expect(result.verified).toBe(false);
      expect(result.credentialResults[0].error.message).toMatch(/expired/i);
    }, 30000);
  });
});
