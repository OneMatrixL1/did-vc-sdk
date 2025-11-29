/**
 * Unit tests for verifyCredentialOptimistic()
 *
 * Tests the optimistic verification helper that tries optimistic resolution first,
 * then falls back to blockchain if verification fails.
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import { issueCredential } from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import {
  EthrDIDModule,
  keypairToAddress,
  addressToDID,
  verifyCredentialOptimistic,
  createMemoryStorageAdapter,
} from '../src/modules/ethr-did';
import mockFetch from './mocks/fetch';

// Context URLs
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';
const VIETCHAIN_NETWORK = 'vietchain';
const VIETCHAIN_CHAIN_ID = 84005;

// Network configuration
const networkConfig = {
  name: VIETCHAIN_NETWORK,
  rpcUrl: 'https://rpc.vietcha.in',
  registry: '0xF0889fb2473F91c068178870ae2e1A0408059A03',
  chainId: VIETCHAIN_CHAIN_ID,
};

// Enable mock fetch
mockFetch();

describe('verifyCredentialOptimistic()', () => {
  let bbsKeypair;
  let ethrDID;
  let keyDoc;
  let signedCredential;
  let module;

  beforeAll(async () => {
    await initializeWasm();

    // Create BBS keypair and derive ethr DID
    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'verify-optimistic-test-key',
      controller: 'temp',
    });

    const address = keypairToAddress(bbsKeypair);
    ethrDID = addressToDID(address, VIETCHAIN_NETWORK);

    keyDoc = {
      id: `${ethrDID}#keys-bbs`,
      controller: ethrDID,
      type: Bls12381BBS23DockVerKeyName,
      keypair: bbsKeypair,
    };

    // Create module
    module = new EthrDIDModule({
      networks: [networkConfig],
    });

    // Issue credential
    const unsignedCredential = {
      '@context': [
        CREDENTIALS_V1_CONTEXT,
        CREDENTIALS_EXAMPLES_CONTEXT,
        BBS_V1_CONTEXT,
      ],
      type: ['VerifiableCredential'],
      issuer: ethrDID,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: 'did:example:holder',
        alumniOf: 'Optimistic Verification University',
      },
    };

    signedCredential = await issueCredential(keyDoc, unsignedCredential);
  });

  describe('Basic functionality', () => {
    test('throws if module is not provided', async () => {
      await expect(
        verifyCredentialOptimistic(signedCredential, {}),
      ).rejects.toThrow('module is required');
    });

    test('throws if credential has no issuer', async () => {
      const badCredential = { ...signedCredential };
      delete badCredential.issuer;

      await expect(
        verifyCredentialOptimistic(badCredential, { module }),
      ).rejects.toThrow('credential.issuer is required');
    });

    test('verifies valid credential without storage', async () => {
      const result = await verifyCredentialOptimistic(signedCredential, { module });

      expect(result.verified).toBe(true);
    });

    test('fails verification for tampered credential', async () => {
      const tampered = {
        ...signedCredential,
        credentialSubject: {
          ...signedCredential.credentialSubject,
          alumniOf: 'Fake University',
        },
      };

      const result = await verifyCredentialOptimistic(tampered, { module });

      expect(result.verified).toBe(false);
    });

    test('fails verification for wrong public key', async () => {
      const wrongKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'wrong-key',
        controller: 'temp',
      });
      const wrongPublicKey = b58.encode(new Uint8Array(wrongKeypair.publicKeyBuffer));

      const tampered = {
        ...signedCredential,
        proof: {
          ...signedCredential.proof,
          publicKeyBase58: wrongPublicKey,
        },
      };

      const result = await verifyCredentialOptimistic(tampered, { module });

      expect(result.verified).toBe(false);
    });
  });

  describe('With memory storage', () => {
    test('verifies credential and does not mark DID on success', async () => {
      const storage = createMemoryStorageAdapter();

      const result = await verifyCredentialOptimistic(signedCredential, {
        module,
        storage,
      });

      expect(result.verified).toBe(true);
      expect(await storage.has(ethrDID)).toBe(false);
    });

    test('marks DID in storage when verification fails', async () => {
      const storage = createMemoryStorageAdapter();

      const tampered = {
        ...signedCredential,
        credentialSubject: {
          ...signedCredential.credentialSubject,
          alumniOf: 'Fake University',
        },
      };

      const result = await verifyCredentialOptimistic(tampered, {
        module,
        storage,
      });

      expect(result.verified).toBe(false);
      // DID should be marked as needing blockchain
      expect(await storage.has(ethrDID)).toBe(true);
    });

    test('skips optimistic when DID is in storage', async () => {
      const storage = createMemoryStorageAdapter();

      // Pre-mark DID as needing blockchain
      await storage.set(ethrDID);

      const result = await verifyCredentialOptimistic(signedCredential, {
        module,
        storage,
      });

      // Should still verify (goes directly to blockchain)
      expect(result.verified).toBe(true);
    });

    test('storage.clear() resets the cache', async () => {
      const storage = createMemoryStorageAdapter();

      await storage.set(ethrDID);
      expect(await storage.has(ethrDID)).toBe(true);

      storage.clear();
      expect(await storage.has(ethrDID)).toBe(false);
    });
  });

  describe('Issuer DID extraction', () => {
    test('handles string issuer', async () => {
      const result = await verifyCredentialOptimistic(signedCredential, { module });
      expect(result.verified).toBe(true);
    });

    test('extracts DID from object issuer', async () => {
      // Test that DID extraction works for object issuer format
      // This tests the extraction logic, not verification (modifying issuer invalidates signature)
      const storage = createMemoryStorageAdapter();

      const credentialWithObjectIssuer = {
        ...signedCredential,
        issuer: { id: ethrDID, name: 'Test Issuer' },
      };

      // Will fail verification (signature invalid) but should mark the correct DID
      await verifyCredentialOptimistic(credentialWithObjectIssuer, { module, storage });

      // The DID should have been extracted correctly and marked in storage
      expect(await storage.has(ethrDID)).toBe(true);
    });
  });

  describe('Storage adapter patterns', () => {
    test('works with async storage adapter', async () => {
      // Simulate async storage (like Redis)
      const asyncStorage = {
        _cache: new Set(),
        has: async (did) => {
          await new Promise((r) => setTimeout(r, 1)); // Simulate async delay
          return asyncStorage._cache.has(did);
        },
        set: async (did) => {
          await new Promise((r) => setTimeout(r, 1));
          asyncStorage._cache.add(did);
        },
      };

      const result = await verifyCredentialOptimistic(signedCredential, {
        module,
        storage: asyncStorage,
      });

      expect(result.verified).toBe(true);
    });

    test('works with custom prefix storage', async () => {
      const prefix = 'custom:prefix:';
      const cache = new Map();

      const customStorage = {
        has: (did) => Promise.resolve(cache.has(`${prefix}${did}`)),
        set: (did) => Promise.resolve(cache.set(`${prefix}${did}`, true)),
      };

      const result = await verifyCredentialOptimistic(signedCredential, {
        module,
        storage: customStorage,
      });

      expect(result.verified).toBe(true);
    });
  });

  describe('Pass-through options', () => {
    test('passes additional options to verifyCredential', async () => {
      // Test that extra options like skipRevocationCheck are passed through
      const result = await verifyCredentialOptimistic(signedCredential, {
        module,
        skipRevocationCheck: true,
        skipSchemaCheck: true,
      });

      expect(result.verified).toBe(true);
    });
  });
});

describe('createMemoryStorageAdapter()', () => {
  test('has() returns false for unknown DIDs', async () => {
    const storage = createMemoryStorageAdapter();
    expect(await storage.has('did:ethr:0x123')).toBe(false);
  });

  test('set() marks DID as known', async () => {
    const storage = createMemoryStorageAdapter();
    await storage.set('did:ethr:0x123');
    expect(await storage.has('did:ethr:0x123')).toBe(true);
  });

  test('clear() removes all DIDs', async () => {
    const storage = createMemoryStorageAdapter();
    await storage.set('did:ethr:0x111');
    await storage.set('did:ethr:0x222');
    await storage.set('did:ethr:0x333');

    storage.clear();

    expect(await storage.has('did:ethr:0x111')).toBe(false);
    expect(await storage.has('did:ethr:0x222')).toBe(false);
    expect(await storage.has('did:ethr:0x333')).toBe(false);
  });

  test('different instances have separate caches', async () => {
    const storage1 = createMemoryStorageAdapter();
    const storage2 = createMemoryStorageAdapter();

    await storage1.set('did:ethr:0x123');

    expect(await storage1.has('did:ethr:0x123')).toBe(true);
    expect(await storage2.has('did:ethr:0x123')).toBe(false);
  });
});
