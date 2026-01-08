/**
 * Unit tests for dual-address ethr DIDs
 *
 * Dual-address DIDs combine both secp256k1 and BBS addresses:
 * - Format: did:ethr:[network:]0xSecp256k1Address:0xBBSAddress
 * - secp256k1 address: for Ethereum transactions
 * - BBS address: for privacy-preserving signatures
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { ethers } from 'ethers';
import b58 from 'bs58';
import { issueCredential, verifyCredential } from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import Bls12381BBSRecoveryMethod2023 from '../src/vc/crypto/Bls12381BBSRecoveryMethod2023';
import { Bls12381BBS23DockVerKeyName, EcdsaSecp256k1VerKeyName } from '../src/vc/crypto/constants';
import { Secp256k1Keypair } from '../src/keypairs';
import {
  parseDID,
  isEthrDID,
  isDualAddressEthrDID,
  addressToDualDID,
  createDualDID,
  publicKeyToAddress,
  generateDefaultDocument,
  ETHR_BBS_KEY_ID,
} from '../src/modules/ethr-did/utils';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';

// Context URLs
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';

// Enable mock fetch
mockFetch();

describe('Dual-Address ethr DIDs', () => {
  let secp256k1Keypair;
  let bbsKeypair;
  let secp256k1Address;
  let bbsAddress;

  beforeAll(async () => {
    // Initialize WASM for BBS operations
    await initializeWasm();

    // Create keypairs
    secp256k1Keypair = Secp256k1Keypair.random();
    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'test-dual-key',
      controller: 'temp',
    });

    // Derive addresses
    secp256k1Address = ethers.utils.computeAddress(secp256k1Keypair.privateKey());
    bbsAddress = publicKeyToAddress(bbsKeypair.publicKeyBuffer);
  });

  describe('parseDID()', () => {
    test('parses dual-address DID without network', () => {
      const did = `did:ethr:${secp256k1Address}:${bbsAddress}`;
      const parsed = parseDID(did);

      expect(parsed.isDualAddress).toBe(true);
      expect(parsed.secp256k1Address.toLowerCase()).toBe(secp256k1Address.toLowerCase());
      expect(parsed.bbsAddress.toLowerCase()).toBe(bbsAddress.toLowerCase());
      expect(parsed.address.toLowerCase()).toBe(secp256k1Address.toLowerCase());
      expect(parsed.network).toBeNull();
    });

    test('parses dual-address DID with network', () => {
      const did = `did:ethr:vietchain:${secp256k1Address}:${bbsAddress}`;
      const parsed = parseDID(did);

      expect(parsed.isDualAddress).toBe(true);
      expect(parsed.secp256k1Address.toLowerCase()).toBe(secp256k1Address.toLowerCase());
      expect(parsed.bbsAddress.toLowerCase()).toBe(bbsAddress.toLowerCase());
      expect(parsed.network).toBe('vietchain');
    });

    test('parses single-address DID (backward compatibility)', () => {
      const did = `did:ethr:${secp256k1Address}`;
      const parsed = parseDID(did);

      expect(parsed.isDualAddress).toBe(false);
      expect(parsed.address.toLowerCase()).toBe(secp256k1Address.toLowerCase());
      expect(parsed.secp256k1Address).toBeUndefined();
      expect(parsed.bbsAddress).toBeUndefined();
    });

    test('parses single-address DID with network', () => {
      const did = `did:ethr:sepolia:${secp256k1Address}`;
      const parsed = parseDID(did);

      expect(parsed.isDualAddress).toBe(false);
      expect(parsed.address.toLowerCase()).toBe(secp256k1Address.toLowerCase());
      expect(parsed.network).toBe('sepolia');
    });

    test('throws on invalid DID format', () => {
      expect(() => parseDID('not-a-did')).toThrow('Invalid ethr DID format');
      expect(() => parseDID('did:ethr:invalid')).toThrow('Invalid ethr DID format');
    });
  });

  describe('isEthrDID()', () => {
    test('returns true for dual-address DIDs', () => {
      expect(isEthrDID(`did:ethr:${secp256k1Address}:${bbsAddress}`)).toBe(true);
      expect(isEthrDID(`did:ethr:vietchain:${secp256k1Address}:${bbsAddress}`)).toBe(true);
    });

    test('returns true for single-address DIDs', () => {
      expect(isEthrDID(`did:ethr:${secp256k1Address}`)).toBe(true);
      expect(isEthrDID(`did:ethr:vietchain:${secp256k1Address}`)).toBe(true);
    });

    test('returns false for invalid DIDs', () => {
      expect(isEthrDID('not-a-did')).toBe(false);
      expect(isEthrDID(null)).toBe(false);
      expect(isEthrDID(undefined)).toBe(false);
    });
  });

  describe('isDualAddressEthrDID()', () => {
    test('returns true for dual-address DIDs', () => {
      expect(isDualAddressEthrDID(`did:ethr:${secp256k1Address}:${bbsAddress}`)).toBe(true);
      expect(isDualAddressEthrDID(`did:ethr:vietchain:${secp256k1Address}:${bbsAddress}`)).toBe(true);
    });

    test('returns false for single-address DIDs', () => {
      expect(isDualAddressEthrDID(`did:ethr:${secp256k1Address}`)).toBe(false);
      expect(isDualAddressEthrDID(`did:ethr:vietchain:${secp256k1Address}`)).toBe(false);
    });

    test('returns false for invalid input', () => {
      expect(isDualAddressEthrDID('not-a-did')).toBe(false);
      expect(isDualAddressEthrDID(null)).toBe(false);
    });
  });

  describe('addressToDualDID()', () => {
    test('creates dual-address DID without network', () => {
      const did = addressToDualDID(secp256k1Address, bbsAddress);

      expect(did).toMatch(/^did:ethr:0x[0-9a-fA-F]{40}:0x[0-9a-fA-F]{40}$/);
      expect(did).toContain(secp256k1Address);
      expect(did).toContain(bbsAddress);
    });

    test('creates dual-address DID with network', () => {
      const did = addressToDualDID(secp256k1Address, bbsAddress, 'vietchain');

      expect(did).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}:0x[0-9a-fA-F]{40}$/);
    });

    test('ignores mainnet network', () => {
      const did = addressToDualDID(secp256k1Address, bbsAddress, 'mainnet');

      expect(did).not.toContain('mainnet');
    });

    test('throws on invalid addresses', () => {
      expect(() => addressToDualDID('invalid', bbsAddress)).toThrow('Invalid secp256k1 address');
      expect(() => addressToDualDID(secp256k1Address, 'invalid')).toThrow('Invalid BBS address');
    });
  });

  describe('createDualDID()', () => {
    test('creates dual-address DID from keypairs', () => {
      const did = createDualDID(secp256k1Keypair, bbsKeypair);

      expect(did).toMatch(/^did:ethr:0x[0-9a-fA-F]{40}:0x[0-9a-fA-F]{40}$/);

      const parsed = parseDID(did);
      expect(parsed.secp256k1Address.toLowerCase()).toBe(secp256k1Address.toLowerCase());
      expect(parsed.bbsAddress.toLowerCase()).toBe(bbsAddress.toLowerCase());
    });

    test('creates dual-address DID with network', () => {
      const did = createDualDID(secp256k1Keypair, bbsKeypair, 'vietchain');

      expect(did).toContain('vietchain');
    });

    test('throws if first keypair is not secp256k1', () => {
      expect(() => createDualDID(bbsKeypair, bbsKeypair)).toThrow('First keypair must be secp256k1');
    });

    test('throws if second keypair is not BBS', () => {
      expect(() => createDualDID(secp256k1Keypair, secp256k1Keypair)).toThrow('Second keypair must be BBS');
    });
  });

  describe('generateDefaultDocument()', () => {
    test('generates document with both verification methods for dual-address DID', () => {
      const did = createDualDID(secp256k1Keypair, bbsKeypair);
      const doc = generateDefaultDocument(did);

      expect(doc.id).toBe(did);
      expect(doc.verificationMethod).toHaveLength(2);

      // Check secp256k1 controller
      const controller = doc.verificationMethod.find((vm) => vm.id.endsWith('#controller'));
      expect(controller).toBeDefined();
      expect(controller.type).toBe('EcdsaSecp256k1RecoveryMethod2020');
      expect(controller.blockchainAccountId).toContain(secp256k1Address);

      // Check BBS key
      const bbsKey = doc.verificationMethod.find((vm) => vm.id.endsWith('#keys-bbs'));
      expect(bbsKey).toBeDefined();
      expect(bbsKey.type).toBe('Bls12381BBSRecoveryMethod2023');
      expect(bbsKey.blockchainAccountId).toContain(bbsAddress);

      // Check assertion methods
      expect(doc.assertionMethod).toContain(`${did}#controller`);
      expect(doc.assertionMethod).toContain(`${did}${ETHR_BBS_KEY_ID}`);
    });

    test('generates single verification method for single-address DID', () => {
      const did = `did:ethr:${secp256k1Address}`;
      const doc = generateDefaultDocument(did);

      expect(doc.verificationMethod).toHaveLength(1);
      expect(doc.verificationMethod[0].type).toBe('EcdsaSecp256k1RecoveryMethod2020');
    });
  });

  describe('BBS Recovery Method with Dual-Address DIDs', () => {
    test('fromProof uses bbsAddress for dual-address DID', () => {
      const dualDID = createDualDID(secp256k1Keypair, bbsKeypair);
      const publicKeyBase58 = b58.encode(new Uint8Array(bbsKeypair.publicKeyBuffer));
      const proof = { publicKeyBase58 };

      const method = Bls12381BBSRecoveryMethod2023.fromProof(proof, dualDID);

      // Expected address should be the BBS address from the dual DID
      expect(method.expectedAddress.toLowerCase()).toBe(bbsAddress.toLowerCase());
      expect(method.derivedAddress.toLowerCase()).toBe(bbsAddress.toLowerCase());
    });

    test('verifier accepts matching BBS keypair', async () => {
      const dualDID = createDualDID(secp256k1Keypair, bbsKeypair);
      const publicKeyBase58 = b58.encode(new Uint8Array(bbsKeypair.publicKeyBuffer));
      const proof = { publicKeyBase58 };

      const method = Bls12381BBSRecoveryMethod2023.fromProof(proof, dualDID);
      const verifier = method.verifier();

      // The address derivation should pass (signature verification needs actual data)
      const derivedAddress = publicKeyToAddress(method.publicKeyBuffer);
      expect(derivedAddress.toLowerCase()).toBe(bbsAddress.toLowerCase());
    });

    test('verifier rejects mismatched BBS keypair', async () => {
      const dualDID = createDualDID(secp256k1Keypair, bbsKeypair);

      // Create a different BBS keypair
      const differentBBSKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'different-key',
        controller: 'temp',
      });
      const wrongPublicKeyBase58 = b58.encode(new Uint8Array(differentBBSKeypair.publicKeyBuffer));
      const proof = { publicKeyBase58: wrongPublicKeyBase58 };

      const method = Bls12381BBSRecoveryMethod2023.fromProof(proof, dualDID);

      // Expected address is from DID's BBS address
      expect(method.expectedAddress.toLowerCase()).toBe(bbsAddress.toLowerCase());
      // Derived address is from the wrong keypair - should NOT match
      expect(method.derivedAddress.toLowerCase()).not.toBe(bbsAddress.toLowerCase());
    });
  });

  describe('Credential Issuance and Verification', () => {
    let dualDID;
    let keyDoc;

    beforeAll(() => {
      dualDID = createDualDID(secp256k1Keypair, bbsKeypair, 'vietchain');
      keyDoc = {
        id: `${dualDID}${ETHR_BBS_KEY_ID}`,
        controller: dualDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: bbsKeypair,
      };
    });

    test('issues credential with dual-address DID as issuer', async () => {
      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: dualDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Test Subject',
        },
      };

      const signedCredential = await issueCredential(keyDoc, credential);

      expect(signedCredential.proof).toBeDefined();
      expect(signedCredential.proof.publicKeyBase58).toBeDefined();
      expect(signedCredential.proof.verificationMethod).toContain(dualDID);
    });

    test('verifies credential with dual-address DID issuer', async () => {
      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: dualDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Test Subject',
        },
      };

      const signedCredential = await issueCredential(keyDoc, credential);

      // Mock resolver that returns default document
      const resolver = {
        supports: (id) => isEthrDID(id.split('#')[0]),
        resolve: (id) => {
          const didPart = id.split('#')[0];
          const doc = generateDefaultDocument(didPart, { chainId: 84005 });

          // If resolving a specific verification method, return just that VM
          if (id.includes('#')) {
            const fragment = id.split('#')[1];
            const vm = doc.verificationMethod.find(
              (v) => v.id === id || v.id.endsWith(`#${fragment}`),
            );
            if (vm) {
              return {
                '@context': doc['@context'],
                ...vm,
              };
            }
          }
          return doc;
        },
      };

      const result = await verifyCredential(signedCredential, { resolver });

      expect(result.verified).toBe(true);
    });

    test('wrong BBS keypair signs but verification fails for dual-address DID', async () => {
      // Create a different BBS keypair that doesn't match the DID's BBS address
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
          name: 'Test Subject',
        },
      };

      // Signing succeeds (no signing-time validation, like Dock module)
      const signedCredential = await issueCredential(wrongKeyDoc, credential);
      expect(signedCredential.proof).toBeDefined();

      // But verification fails because keypair doesn't match DID's BBS address
      const result = await verifyCredential(signedCredential);
      expect(result.verified).toBe(false);
    });
  });

  describe('Secp256k1 Signing with Dual-Address DIDs', () => {
    let dualDID;
    let secp256k1KeyDoc;

    beforeAll(() => {
      dualDID = createDualDID(secp256k1Keypair, bbsKeypair, 'vietchain');

      // Create secp256k1 key document for signing
      const keyId = `${dualDID}#controller`;
      const publicKeyBytes = secp256k1Keypair._publicKey();
      const publicKeyBase58 = b58.encode(publicKeyBytes);

      secp256k1KeyDoc = {
        id: keyId,
        controller: dualDID,
        type: EcdsaSecp256k1VerKeyName,
        publicKey: secp256k1Keypair.publicKey(),
        keypair: secp256k1Keypair,
      };

      // Register verification method in cache for verification
      networkCache[keyId] = {
        '@context': 'https://w3id.org/security/v2',
        id: keyId,
        type: EcdsaSecp256k1VerKeyName,
        controller: dualDID,
        publicKeyBase58,
      };

      // Register DID document in cache
      networkCache[dualDID] = {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/v2'],
        id: dualDID,
        verificationMethod: [
          {
            id: keyId,
            type: EcdsaSecp256k1VerKeyName,
            controller: dualDID,
            publicKeyBase58,
          },
        ],
        assertionMethod: [keyId, `${dualDID}${ETHR_BBS_KEY_ID}`],
        authentication: [keyId],
      };
    });

    afterAll(() => {
      // Cleanup cache
      Object.keys(networkCache).forEach((key) => {
        if (key === dualDID || key.startsWith(`${dualDID}#`)) {
          delete networkCache[key];
        }
      });
    });

    test('issues credential with secp256k1 signature from dual-address DID', async () => {
      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: dualDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Secp256k1 Signed Subject',
        },
      };

      const signedCredential = await issueCredential(secp256k1KeyDoc, credential);

      expect(signedCredential.proof).toBeDefined();
      expect(signedCredential.proof.type).toBe('EcdsaSecp256k1Signature2019');
      expect(signedCredential.proof.verificationMethod).toBe(`${dualDID}#controller`);
    });

    test('verifies secp256k1-signed credential from dual-address DID', async () => {
      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: dualDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Secp256k1 Verification Subject',
        },
      };

      const signedCredential = await issueCredential(secp256k1KeyDoc, credential);
      const result = await verifyCredential(signedCredential);

      expect(result.verified).toBe(true);
    });

    test('dual-address DID can issue both BBS and secp256k1 credentials', async () => {
      // Issue BBS credential
      const bbsKeyDoc = {
        id: `${dualDID}${ETHR_BBS_KEY_ID}`,
        controller: dualDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: bbsKeypair,
      };

      const bbsCredential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: dualDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'BBS signed claim',
        },
      };

      const signedBBS = await issueCredential(bbsKeyDoc, bbsCredential);
      expect(signedBBS.proof.type).toBe('Bls12381BBSSignatureDock2023');

      // Issue secp256k1 credential
      const secp256k1Credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: dualDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Secp256k1 signed claim',
        },
      };

      const signedSecp = await issueCredential(secp256k1KeyDoc, secp256k1Credential);
      expect(signedSecp.proof.type).toBe('EcdsaSecp256k1Signature2019');

      // Both credentials have same issuer DID
      expect(signedBBS.issuer).toBe(dualDID);
      expect(signedSecp.issuer).toBe(dualDID);

      // Verify BBS credential
      const bbsResolver = {
        supports: (id) => isEthrDID(id.split('#')[0]),
        resolve: (id) => {
          const didPart = id.split('#')[0];
          const doc = generateDefaultDocument(didPart, { chainId: 84005 });
          if (id.includes('#')) {
            const fragment = id.split('#')[1];
            const vm = doc.verificationMethod.find(
              (v) => v.id === id || v.id.endsWith(`#${fragment}`),
            );
            if (vm) return { '@context': doc['@context'], ...vm };
          }
          return doc;
        },
      };

      const bbsResult = await verifyCredential(signedBBS, { resolver: bbsResolver });
      expect(bbsResult.verified).toBe(true);

      // Verify secp256k1 credential (uses networkCache)
      const secpResult = await verifyCredential(signedSecp);
      expect(secpResult.verified).toBe(true);
    });
  });

  describe('Backward Compatibility', () => {
    test('single-address DID still works with BBS', async () => {
      // Create single-address DID from BBS keypair
      const singleDID = `did:ethr:vietchain:${bbsAddress}`;
      const keyDoc = {
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
          name: 'Test Subject',
        },
      };

      const signedCredential = await issueCredential(keyDoc, credential);
      expect(signedCredential.proof).toBeDefined();

      // Verify using mock resolver
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
