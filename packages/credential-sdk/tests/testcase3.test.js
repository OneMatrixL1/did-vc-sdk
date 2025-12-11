/**
 * TESTCASE 3: Cross-System Customer Tier Verification with BBS Signatures
 *
 * Real-world Flow:
 * 1. System A (e-commerce) issues VIP tier credential to user with BBS signature
 * 2. User presents credential to System B
 * 3. System B verifies the credential using optimistic DID resolution
 *
 * Uses:
 * - did:ethr:vietchain:... (ethr-did module)
 * - BBS signatures (Bls12381BBSKeyPairDock2023)
 * - EthrDIDModule with optimistic: true (no custom helpers needed)
 *
 * Run: npm test -- testcase3
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';
import {
  issueCredential,
  verifyCredential,
} from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import {
  EthrDIDModule,
  addressToDID,
  keypairToAddress,
} from '../src/modules/ethr-did';
import customerTierContext from './testcase3/customer-tier-context.json';

// Setup mock to avoid network calls
mockFetch();

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

  // User (Holder)
  let userDID;

  // System B (Verifier) - uses EthrDIDModule
  let systemBModule;

  // Credentials
  let vip1Credential;

  beforeAll(async () => {
    // Fetch custom context from GitHub and cache for jsonld
    const realFetch = require('node-fetch');
    try {
      const response = await realFetch(CUSTOMER_TIER_CONTEXT);
      const contextData = await response.json();
      networkCache[CUSTOMER_TIER_CONTEXT] = contextData;
    } catch (error) {
      // Fallback to local if GitHub is unavailable
      console.error('Failed to fetch custom context from GitHub:', error);
      networkCache[CUSTOMER_TIER_CONTEXT] = customerTierContext;
    }

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

    // ========== Setup User (just a DID, no keypair needed for this flow) ==========
    // User is the credential subject - they just receive the VC
    const userKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'user-key',
      controller: 'temp',
    });
    userDID = addressToDID(keypairToAddress(userKeypair), VIETCHAIN_NETWORK);

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
        issuer: systemADID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: userDID,
          customerTier: {
            tier: 'VIP1',
            tierName: 'VIP1 - Premium Customer',
            tierDescription: 'Top tier customer from System A E-commerce',
            totalSpent: '$250,000',
            memberSince: '2020-03-15',
            accountId: 'SYSCUST-12345',
          },
        },
      };

      // Issue credential using SDK
      vip1Credential = await issueCredential(systemAKeyDoc, unsignedCredential);

      // Validate BBS signature
      expect(vip1Credential).toBeDefined();
      expect(vip1Credential.issuer).toBe(systemADID);
      expect(vip1Credential.credentialSubject.id).toBe(userDID);
      expect(vip1Credential.credentialSubject.customerTier.tier).toBe('VIP1');
      expect(vip1Credential.proof).toBeDefined();
      expect(vip1Credential.proof.type).toBe('Bls12381BBSSignatureDock2023');

      // BBS proof should contain embedded public key for address verification
      expect(vip1Credential.proof.publicKeyBase58).toBeDefined();
    }, 30000);
  });

  describe('Scenario 2: System B verifies credential using EthrDIDModule', () => {
    test('System B verifies VIP1 credential with optimistic resolution', async () => {
      // System B uses EthrDIDModule with optimistic: true
      // No need for VP - just verify the credential directly
      const result = await verifyCredential(vip1Credential, {
        resolver: systemBModule,
      });

      expect(result.verified).toBe(true);
    }, 30000);

    test('SECURITY: System B rejects tampered credential', async () => {
      // Tamper with credential
      const tamperedVC = {
        ...vip1Credential,
        credentialSubject: {
          ...vip1Credential.credentialSubject,
          customerTier: {
            ...vip1Credential.credentialSubject.customerTier,
            tier: 'VIP3', // TAMPERED!
            tierName: 'VIP3 - TAMPERED!',
          },
        },
      };

      const result = await verifyCredential(tamperedVC, {
        resolver: systemBModule,
      });

      // Must fail because BBS signature is invalid
      expect(result.verified).toBe(false);
    }, 30000);

    test('SECURITY: System B rejects expired credential', async () => {
      // Issue expired credential
      const expiredCredential = await issueCredential(systemAKeyDoc, {
        '@context': [
          CREDENTIALS_V1,
          BBS_V1,
          CUSTOMER_TIER_CONTEXT,
        ],
        type: ['VerifiableCredential', 'CustomerTierCredential'],
        issuer: systemADID,
        issuanceDate: '2023-01-01T00:00:00Z',
        expirationDate: '2023-12-31T23:59:59Z', // Expired
        credentialSubject: {
          id: userDID,
          customerTier: {
            tier: 'VIP1',
            tierName: 'VIP1 - Expired',
            tierDescription: 'Expired customer tier',
          },
        },
      });

      expect(expiredCredential.proof.type).toBe('Bls12381BBSSignatureDock2023');

      const result = await verifyCredential(expiredCredential, {
        resolver: systemBModule,
      });

      // Must fail due to expiration
      expect(result.verified).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error.message).toMatch(/expired/i);
    }, 30000);

    test('SECURITY: System B rejects credential with wrong public key', async () => {
      // Generate a different keypair
      const wrongKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'wrong-key',
        controller: 'temp',
      });

      const b58 = await import('bs58');
      const wrongPublicKey = b58.default.encode(new Uint8Array(wrongKeypair.publicKeyBuffer));

      // Replace publicKeyBase58 with wrong key
      const tamperedVC = {
        ...vip1Credential,
        proof: {
          ...vip1Credential.proof,
          publicKeyBase58: wrongPublicKey,
        },
      };

      const result = await verifyCredential(tamperedVC, {
        resolver: systemBModule,
      });

      // Must fail - address derived from wrong public key won't match DID
      expect(result.verified).toBe(false);
    }, 30000);
  });
});
