/**
 * Integration tests for dual-address ethr DIDs
 *
 * These tests verify dual-address DID support:
 * - DID format: did:ethr:[network:]0xSecp256k1Address:0xBBSAddress
 * - DID creation from both secp256k1 and BBS keypairs
 * - VC issuance and verification with BBS signatures
 * - Strict BBS address validation
 *
 * Environment Variables (REQUIRED):
 * ----------------------------------
 * ETHR_NETWORK_RPC_URL   - RPC endpoint URL (e.g., https://rpc.vietcha.in)
 *
 * Optional Environment Variables:
 * -------------------------------
 * ETHR_NETWORK           - Network name (default: vietchain)
 * ETHR_REGISTRY_ADDRESS  - DID Registry contract address
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { EthrDIDModule } from '../src/modules/ethr-did';
import {
  createDualDID,
  parseDID,
  isEthrDID,
  isDualAddressEthrDID,
  generateDefaultDocument,
  ETHR_BBS_KEY_ID,
} from '../src/modules/ethr-did/utils';
import { issueCredential, verifyCredential } from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Secp256k1Keypair } from '../src/keypairs';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import mockFetch from './mocks/fetch';

// Skip if no RPC URL provided
const SKIP_INTEGRATION = !process.env.ETHR_NETWORK_RPC_URL;

// Configuration from environment
const networkConfig = SKIP_INTEGRATION
  ? null
  : {
    name: process.env.ETHR_NETWORK || 'vietchain',
    rpcUrl: process.env.ETHR_NETWORK_RPC_URL,
    registry:
        process.env.ETHR_REGISTRY_ADDRESS
        || '0xF0889fb2473F91c068178870ae2e1A0408059A03',
  };

// Context URLs
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';

// Enable mock fetch for context URLs
mockFetch();

describe('Dual-Address ethr DIDs Integration', () => {
  let module;
  let secp256k1Keypair;
  let bbsKeypair;
  let dualDID;

  beforeAll(async () => {
    if (SKIP_INTEGRATION) {
      console.log('Skipping integration tests - ETHR_NETWORK_RPC_URL not set');
      return;
    }

    // Initialize WASM for BBS operations
    await initializeWasm();

    // Create module
    module = new EthrDIDModule({
      networks: [networkConfig],
      defaultNetwork: networkConfig.name,
    });

    // Create keypairs
    secp256k1Keypair = Secp256k1Keypair.random();
    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'integration-test-key',
      controller: 'temp',
    });

    // Create dual-address DID
    dualDID = await module.createDualAddressDID(secp256k1Keypair, bbsKeypair);
  });

  describe('DID Creation', () => {
    test('creates dual-address DID from module', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL');
        return;
      }

      expect(dualDID).toBeDefined();
      expect(isDualAddressEthrDID(dualDID)).toBe(true);

      const parsed = parseDID(dualDID);
      expect(parsed.isDualAddress).toBe(true);
      expect(parsed.network).toBe(networkConfig.name);
    });

    test('creates dual-address DID with createDualDID utility', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL');
        return;
      }

      const did = createDualDID(secp256k1Keypair, bbsKeypair, networkConfig.name);
      expect(isDualAddressEthrDID(did)).toBe(true);
      expect(did).toBe(dualDID);
    });
  });

  describe('DID Document Generation', () => {
    test('generates document with both verification methods', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL');
        return;
      }

      const doc = generateDefaultDocument(dualDID, { chainId: 84005 });

      expect(doc.id).toBe(dualDID);
      expect(doc.verificationMethod).toHaveLength(2);

      // Check controller method
      const controller = doc.verificationMethod.find((vm) => vm.id.endsWith('#controller'));
      expect(controller).toBeDefined();
      expect(controller.type).toBe('EcdsaSecp256k1RecoveryMethod2020');

      // Check BBS method
      const bbsKey = doc.verificationMethod.find((vm) => vm.id.endsWith('#keys-bbs'));
      expect(bbsKey).toBeDefined();
      expect(bbsKey.type).toBe('Bls12381BBSRecoveryMethod2023');
    });
  });

  describe('Credential Issuance and Verification', () => {
    let keyDoc;

    beforeAll(() => {
      if (SKIP_INTEGRATION) return;

      keyDoc = {
        id: `${dualDID}${ETHR_BBS_KEY_ID}`,
        controller: dualDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: bbsKeypair,
      };
    });

    test('issues credential with dual-address DID', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL');
        return;
      }

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: dualDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Integration Test Subject',
        },
      };

      const signedCredential = await issueCredential(keyDoc, credential);

      expect(signedCredential.proof).toBeDefined();
      expect(signedCredential.proof.publicKeyBase58).toBeDefined();
      expect(signedCredential.proof.verificationMethod).toContain(dualDID);
    });

    test('verifies credential with dual-address DID using optimistic resolution', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL');
        return;
      }

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: dualDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Verification Test Subject',
        },
      };

      const signedCredential = await issueCredential(keyDoc, credential);

      // Use optimistic resolution (no blockchain call needed)
      const resolver = {
        supports: (id) => isEthrDID(id.split('#')[0]),
        resolve: (id) => {
          const didPart = id.split('#')[0];
          const doc = generateDefaultDocument(didPart, { chainId: 84005 });

          if (id.includes('#')) {
            const fragment = id.split('#')[1];
            const vm = doc.verificationMethod.find(
              (v) => v.id === id || v.id.endsWith(`#${fragment}`),
            );
            if (vm) {
              return { '@context': doc['@context'], ...vm };
            }
          }
          return doc;
        },
      };

      const result = await verifyCredential(signedCredential, { resolver });

      expect(result.verified).toBe(true);
    });

    // NOTE: Real blockchain resolution for dual-address DIDs requires contract upgrade
    // to support the new address format. For now, dual-address DIDs work with optimistic
    // resolution (which doesn't require blockchain calls for unchanged DIDs).
    test.skip('verifies credential with real blockchain resolution (requires contract upgrade)', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL');
        return;
      }

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: dualDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Blockchain Resolution Test Subject',
        },
      };

      const signedCredential = await issueCredential(keyDoc, credential);

      // Use real blockchain resolution via module
      // This will work after contract upgrade to support dual-address DIDs
      const result = await verifyCredential(signedCredential, { resolver: module });

      expect(result.verified).toBe(true);
    });
  });

  describe('Strict BBS Address Validation', () => {
    test('rejects credential signing with mismatched BBS keypair', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL');
        return;
      }

      // Create a different BBS keypair that doesn't match the DID
      const wrongBBSKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'wrong-key',
        controller: 'temp',
      });

      const wrongKeyDoc = {
        id: `${dualDID}${ETHR_BBS_KEY_ID}`,
        controller: dualDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: wrongBBSKeypair,
      };

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: dualDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Should Fail',
        },
      };

      // Signing succeeds (no signing-time validation, like Dock module)
      const signedCredential = await issueCredential(wrongKeyDoc, credential);
      expect(signedCredential.proof).toBeDefined();

      // But verification should fail because keypair doesn't match DID's BBS address
      const resolver = {
        supports: (id) => isEthrDID(id.split('#')[0]),
        resolve: (id) => {
          const didPart = id.split('#')[0];
          const doc = generateDefaultDocument(didPart, { chainId: 84005 });

          if (id.includes('#')) {
            const fragment = id.split('#')[1];
            const vm = doc.verificationMethod.find(
              (v) => v.id === id || v.id.endsWith(`#${fragment}`),
            );
            if (vm) {
              return { '@context': doc['@context'], ...vm };
            }
          }
          return doc;
        },
      };

      const result = await verifyCredential(signedCredential, { resolver });
      expect(result.verified).toBe(false);
    });
  });

  describe('Backward Compatibility', () => {
    test('single-address DID still works', async () => {
      if (SKIP_INTEGRATION) {
        console.log('Skipping - no RPC URL');
        return;
      }

      // Create single-address DID from BBS keypair
      const singleDID = await module.createNewDID(bbsKeypair);

      expect(isEthrDID(singleDID)).toBe(true);
      expect(isDualAddressEthrDID(singleDID)).toBe(false);

      const singleKeyDoc = {
        id: `${singleDID}${ETHR_BBS_KEY_ID}`,
        controller: singleDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: bbsKeypair,
      };

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: singleDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Single Address Test',
        },
      };

      const signedCredential = await issueCredential(singleKeyDoc, credential);
      expect(signedCredential.proof).toBeDefined();

      // Verify using optimistic resolution
      const resolver = {
        supports: (id) => isEthrDID(id.split('#')[0]),
        resolve: (id) => {
          const didPart = id.split('#')[0];
          return generateDefaultDocument(didPart, { chainId: 84005 });
        },
      };

      const result = await verifyCredential(signedCredential, { resolver });
      expect(result.verified).toBe(true);
    });
  });
});
