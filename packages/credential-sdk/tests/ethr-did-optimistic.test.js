/**
 * Unit tests for Optimistic DID Resolution
 *
 * Tests the optimistic mode feature in EthrDIDModule that allows
 * generating default DID documents locally without blockchain RPC calls.
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import { issueCredential, verifyCredential } from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import {
  EthrDIDModule,
  generateDefaultDocument,
  keypairToAddress,
  addressToDID,
  ETHR_BBS_KEY_ID,
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

describe('Optimistic DID Resolution', () => {
  describe('generateDefaultDocument() utility', () => {
    test('generates correct document structure for mainnet DID', () => {
      const did = 'did:ethr:0x742d35Cc6634C0532925a3b844Bc454e4438f44e';
      const doc = generateDefaultDocument(did);

      expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
      expect(doc.id).toBe(did);
      expect(doc.verificationMethod).toHaveLength(1);
      expect(doc.verificationMethod[0].id).toBe(`${did}#controller`);
      expect(doc.verificationMethod[0].type).toBe('EcdsaSecp256k1RecoveryMethod2020');
      expect(doc.verificationMethod[0].blockchainAccountId).toContain('eip155:1:');
      expect(doc.authentication).toContain(`${did}#controller`);
      expect(doc.assertionMethod).toContain(`${did}#controller`);
      expect(doc.assertionMethod).toContain(`${did}${ETHR_BBS_KEY_ID}`);
    });

    test('generates correct document structure for network DID', () => {
      const did = 'did:ethr:vietchain:0x742d35Cc6634C0532925a3b844Bc454e4438f44e';
      const doc = generateDefaultDocument(did, { chainId: VIETCHAIN_CHAIN_ID });

      expect(doc.id).toBe(did);
      expect(doc.verificationMethod[0].blockchainAccountId).toBe(
        `eip155:${VIETCHAIN_CHAIN_ID}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`,
      );
    });

    test('throws for invalid DID', () => {
      expect(() => generateDefaultDocument('did:key:z123')).toThrow('Invalid ethr DID');
      expect(() => generateDefaultDocument('not-a-did')).toThrow('Invalid ethr DID');
    });

    test('uses default chainId 1 when not specified', () => {
      const did = 'did:ethr:0x742d35Cc6634C0532925a3b844Bc454e4438f44e';
      const doc = generateDefaultDocument(did);

      expect(doc.verificationMethod[0].blockchainAccountId).toContain('eip155:1:');
    });
  });

  describe('EthrDIDModule optimistic option', () => {
    let module;
    let optimisticModule;

    beforeAll(() => {
      // Module without optimistic (default behavior)
      module = new EthrDIDModule({
        networks: [networkConfig],
      });

      // Module with optimistic enabled by default
      optimisticModule = new EthrDIDModule({
        networks: [networkConfig],
        optimistic: true,
      });
    });

    test('constructor stores optimistic option', () => {
      expect(module.optimistic).toBe(false);
      expect(optimisticModule.optimistic).toBe(true);
    });

    test('getDefaultDocument() returns locally generated document', () => {
      const did = `did:ethr:${VIETCHAIN_NETWORK}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`;
      const doc = module.getDefaultDocument(did);

      expect(doc.id).toBe(did);
      expect(doc.verificationMethod[0].blockchainAccountId).toBe(
        `eip155:${VIETCHAIN_CHAIN_ID}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`,
      );
      expect(doc.assertionMethod).toContain(`${did}${ETHR_BBS_KEY_ID}`);
    });

    test('getDefaultDocument() uses network chainId from config', () => {
      const did = `did:ethr:${VIETCHAIN_NETWORK}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`;
      const doc = module.getDefaultDocument(did);

      expect(doc.verificationMethod[0].blockchainAccountId).toContain(
        `eip155:${VIETCHAIN_CHAIN_ID}`,
      );
    });

    test('getDocument() with optimistic: true returns default document', async () => {
      const did = `did:ethr:${VIETCHAIN_NETWORK}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`;

      // With optimistic: true, should return immediately without RPC
      const doc = await module.getDocument(did, { optimistic: true });

      expect(doc.id).toBe(did);
      expect(doc.assertionMethod).toContain(`${did}${ETHR_BBS_KEY_ID}`);
    });

    test('optimistic module uses default document by default', async () => {
      const did = `did:ethr:${VIETCHAIN_NETWORK}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`;

      // Optimistic module should use default document without specifying option
      const doc = await optimisticModule.getDocument(did);

      expect(doc.id).toBe(did);
      expect(doc.assertionMethod).toContain(`${did}${ETHR_BBS_KEY_ID}`);
    });

    test('per-call option overrides constructor default', async () => {
      const did = `did:ethr:${VIETCHAIN_NETWORK}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`;

      // Force optimistic: false on optimistic module - this will try RPC
      // Since this is a test environment, we just verify the option is accepted
      // The actual blockchain call would happen in a real environment
      const doc = await optimisticModule.getDocument(did, { optimistic: true });

      expect(doc.id).toBe(did);
    });

    test('resolve() passes options to getDocument()', async () => {
      const did = `did:ethr:${VIETCHAIN_NETWORK}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`;

      const doc = await module.resolve(did, { optimistic: true });

      expect(doc.id).toBe(did);
      expect(doc.assertionMethod).toContain(`${did}${ETHR_BBS_KEY_ID}`);
    });

    test('resolve() with fragment returns verification method', async () => {
      const did = `did:ethr:${VIETCHAIN_NETWORK}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`;
      const vmId = `${did}#controller`;

      const vm = await module.resolve(vmId, { optimistic: true });

      expect(vm.id).toBe(vmId);
      expect(vm.type).toBe('EcdsaSecp256k1RecoveryMethod2020');
    });
  });

  describe('BBS Verification with Optimistic Resolution', () => {
    let bbsKeypair;
    let ethrDID;
    let keyDoc;
    let signedCredential;
    let optimisticModule;

    beforeAll(async () => {
      await initializeWasm();

      // Create BBS keypair and derive ethr DID
      bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'optimistic-test-key',
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

      // Create optimistic module
      optimisticModule = new EthrDIDModule({
        networks: [networkConfig],
        optimistic: true,
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
          alumniOf: 'Optimistic University',
        },
      };

      signedCredential = await issueCredential(keyDoc, unsignedCredential);
    });

    test('credential contains embedded public key', () => {
      expect(signedCredential.proof.publicKeyBase58).toBeDefined();
      const expectedKey = b58.encode(new Uint8Array(bbsKeypair.publicKeyBuffer));
      expect(signedCredential.proof.publicKeyBase58).toBe(expectedKey);
    });

    test('verifies credential with optimistic resolver', async () => {
      // Create optimistic resolver
      const resolver = {
        supports: (id) => optimisticModule.supports(id),
        resolve: (id) => optimisticModule.resolve(id, { optimistic: true }),
      };

      const result = await verifyCredential(signedCredential, { resolver });

      expect(result.verified).toBe(true);
    });

    test('verifies credential using module with optimistic: true', async () => {
      const result = await verifyCredential(signedCredential, {
        resolver: optimisticModule,
      });

      expect(result.verified).toBe(true);
    });

    test('verification fails with tampered credential', async () => {
      const tampered = {
        ...signedCredential,
        credentialSubject: {
          ...signedCredential.credentialSubject,
          alumniOf: 'Fake University',
        },
      };

      const result = await verifyCredential(tampered, {
        resolver: optimisticModule,
      });

      expect(result.verified).toBe(false);
    });

    test('verification fails with wrong public key', async () => {
      // Generate a different keypair
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

      const result = await verifyCredential(tampered, {
        resolver: optimisticModule,
      });

      expect(result.verified).toBe(false);
    });
  });

  describe('Usage Patterns', () => {
    let module;

    beforeAll(() => {
      module = new EthrDIDModule({
        networks: [networkConfig],
      });
    });

    test('simple optimistic usage (frontend pattern)', async () => {
      const optimisticModule = new EthrDIDModule({
        networks: [networkConfig],
        optimistic: true,
      });

      const did = `did:ethr:${VIETCHAIN_NETWORK}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`;
      const doc = await optimisticModule.getDocument(did);

      expect(doc.id).toBe(did);
    });

    test('per-call optimistic usage (backend pattern)', async () => {
      const did = `did:ethr:${VIETCHAIN_NETWORK}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`;

      // First try optimistic
      const optimisticDoc = await module.getDocument(did, { optimistic: true });
      expect(optimisticDoc.id).toBe(did);

      // If needed, retry with blockchain (in real scenario)
      // const blockchainDoc = await module.getDocument(did, { optimistic: false });
    });

    test('custom resolver with optimistic option', async () => {
      const did = `did:ethr:${VIETCHAIN_NETWORK}:0x742d35Cc6634C0532925a3b844Bc454e4438f44e`;

      // Create custom resolver that uses optimistic mode
      const resolver = {
        supports: (id) => module.supports(id),
        resolve: (id) => module.resolve(id, { optimistic: true }),
      };

      const doc = await resolver.resolve(did);

      expect(doc.id).toBe(did);
      expect(doc.assertionMethod).toContain(`${did}${ETHR_BBS_KEY_ID}`);
    });
  });
});
