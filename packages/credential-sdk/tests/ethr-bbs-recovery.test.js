/**
 * Unit tests for BBS address-based recovery verification with ethr DIDs
 *
 * These tests verify that BBS-signed credentials with embedded public keys
 * can be verified without requiring on-chain public key storage. The verification
 * process derives the Ethereum address from the BBS public key and compares
 * it with the DID's address.
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import { issueCredential, verifyCredential } from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import Bls12381BBSRecoveryMethod2023 from '../src/vc/crypto/Bls12381BBSRecoveryMethod2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import {
  keypairToAddress,
  addressToDID,
  publicKeyToAddress,
} from '../src/modules/ethr-did/utils';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';

// Context URLs
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';
const VIETCHAIN_NETWORK = 'vietchain';

// Enable mock fetch
mockFetch();

describe('BBS Address-Based Recovery Verification', () => {
  let bbsKeypair;
  let ethrDID;
  let keyDoc;

  beforeAll(async () => {
    // Initialize WASM for BBS operations
    await initializeWasm();

    // Create BBS keypair and derive ethr DID
    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'test-recovery-key',
      controller: 'temp',
    });

    const address = keypairToAddress(bbsKeypair);
    ethrDID = addressToDID(address, VIETCHAIN_NETWORK);

    // Create key document for signing
    keyDoc = {
      id: `${ethrDID}#keys-bbs`,
      controller: ethrDID,
      type: Bls12381BBS23DockVerKeyName,
      keypair: bbsKeypair,
    };
  });

  describe('Bls12381BBSRecoveryMethod2023', () => {
    test('constructs from public key and controller', () => {
      const publicKeyBase58 = b58.encode(new Uint8Array(bbsKeypair.publicKeyBuffer));
      const address = keypairToAddress(bbsKeypair);

      const method = new Bls12381BBSRecoveryMethod2023(publicKeyBase58, ethrDID, address);

      expect(method.publicKeyBase58).toBe(publicKeyBase58);
      expect(method.controller).toBe(ethrDID);
      expect(method.expectedAddress).toBe(address);
      expect(method.derivedAddress.toLowerCase()).toBe(address.toLowerCase());
    });

    test('fromProof extracts public key and validates DID address', () => {
      const publicKeyBase58 = b58.encode(new Uint8Array(bbsKeypair.publicKeyBuffer));
      const proof = { publicKeyBase58 };

      const method = Bls12381BBSRecoveryMethod2023.fromProof(proof, ethrDID);

      expect(method.publicKeyBase58).toBe(publicKeyBase58);
      expect(method.controller).toBe(ethrDID);
      // Derived address should match the DID's address
      const didAddress = ethrDID.split(':').pop();
      expect(method.derivedAddress.toLowerCase()).toBe(didAddress.toLowerCase());
    });

    test('throws if proof missing publicKeyBase58', () => {
      expect(() => {
        Bls12381BBSRecoveryMethod2023.fromProof({}, ethrDID);
      }).toThrow('proof.publicKeyBase58 required');
    });

    test('throws if publicKeyBase58 has invalid length', () => {
      // 64 bytes instead of 96 or 192
      const invalidKey = b58.encode(new Uint8Array(64).fill(1));
      expect(() => {
        Bls12381BBSRecoveryMethod2023.fromProof({ publicKeyBase58: invalidKey }, ethrDID);
      }).toThrow('Invalid BBS public key length: expected 96 bytes (compressed G2) or 192 bytes (uncompressed G2), got 64');
    });

    test('verifier factory rejects mismatched address', async () => {
      const publicKeyBuffer = new Uint8Array(bbsKeypair.publicKeyBuffer);
      const wrongAddress = '0x0000000000000000000000000000000000000000';

      const verifier = Bls12381BBSRecoveryMethod2023.verifierFactory(
        publicKeyBuffer,
        wrongAddress,
      );

      // Should fail because address doesn't match
      const result = await verifier.verify({
        data: [new Uint8Array([1, 2, 3])],
        signature: new Uint8Array(100),
      });

      expect(result).toBe(false);
    });
  });

  describe('Credential Issuance with Embedded Public Key', () => {
    test('proof contains publicKeyBase58 when signing with BBS keypair', async () => {
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
          id: 'did:example:holder123',
          alumniOf: 'Test University',
        },
      };

      const signedVC = await issueCredential(keyDoc, unsignedCredential);

      expect(signedVC.proof).toBeDefined();
      expect(signedVC.proof.type).toBe('Bls12381BBSSignatureDock2023');
      expect(signedVC.proof.publicKeyBase58).toBeDefined();

      // Verify the embedded public key matches the keypair
      const expectedPublicKey = b58.encode(new Uint8Array(bbsKeypair.publicKeyBuffer));
      expect(signedVC.proof.publicKeyBase58).toBe(expectedPublicKey);
    });
  });

  describe('Self-Contained Verification (No Mock DID Document)', () => {
    let signedCredential;

    beforeAll(async () => {
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential', 'AlumniCredential'],
        issuer: ethrDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder456',
          alumniOf: 'Recovery Test University',
        },
      };

      signedCredential = await issueCredential(keyDoc, unsignedCredential);
    });

    test('verifies credential using embedded public key (no BBS key in DID doc)', async () => {
      // Set up a minimal DID document for purpose validation
      // IMPORTANT: This document does NOT contain the BBS public key -
      // it only has the default EcdsaSecp256k1RecoveryMethod2020 for controller validation.
      // The BBS public key comes from the proof itself (embedded publicKeyBase58).
      const keyId = `${ethrDID}#keys-bbs`;
      networkCache[ethrDID] = {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/v2'],
        id: ethrDID,
        verificationMethod: [
          {
            // Default recovery method - NO BBS public key here
            id: `${ethrDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: ethrDID,
            blockchainAccountId: `eip155:1:${ethrDID.split(':').pop()}`,
          },
        ],
        assertionMethod: [`${ethrDID}#controller`, keyId],
        authentication: [`${ethrDID}#controller`],
      };

      const result = await verifyCredential(signedCredential);

      // Debug output
      if (!result.verified) {
        console.log('Verification failed:');
        console.log('Error:', result.error);
        console.log('Results:', JSON.stringify(result.results, null, 2));
      }

      expect(result.verified).toBe(true);
      expect(result.results).toBeDefined();
      expect(result.results[0].verified).toBe(true);

      // Cleanup
      delete networkCache[ethrDID];
    });

    test('fails verification when credential is tampered', async () => {
      const tamperedCredential = {
        ...signedCredential,
        credentialSubject: {
          ...signedCredential.credentialSubject,
          alumniOf: 'Fake University',
        },
      };

      const result = await verifyCredential(tamperedCredential);

      expect(result.verified).toBe(false);
    });

    test('fails verification when public key is replaced with wrong key', async () => {
      // Generate a different keypair
      const wrongKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'wrong-key',
        controller: 'temp',
      });
      const wrongPublicKey = b58.encode(new Uint8Array(wrongKeypair.publicKeyBuffer));

      const tamperedCredential = {
        ...signedCredential,
        proof: {
          ...signedCredential.proof,
          publicKeyBase58: wrongPublicKey, // Wrong public key
        },
      };

      const result = await verifyCredential(tamperedCredential);

      // Should fail because:
      // 1. Address derived from wrong public key won't match DID address
      expect(result.verified).toBe(false);
    });
  });

  describe('Address Derivation Validation', () => {
    test('derived address from public key matches DID address', () => {
      const publicKeyBuffer = new Uint8Array(bbsKeypair.publicKeyBuffer);
      const derivedAddress = publicKeyToAddress(publicKeyBuffer);

      // Extract address from DID
      const didAddress = ethrDID.split(':').pop();

      expect(derivedAddress.toLowerCase()).toBe(didAddress.toLowerCase());
    });

    test('different public keys produce different addresses', () => {
      const keypair1 = Bls12381BBSKeyPairDock2023.generate({
        id: 'key1',
        controller: 'temp',
      });
      const keypair2 = Bls12381BBSKeyPairDock2023.generate({
        id: 'key2',
        controller: 'temp',
      });

      const address1 = publicKeyToAddress(new Uint8Array(keypair1.publicKeyBuffer));
      const address2 = publicKeyToAddress(new Uint8Array(keypair2.publicKeyBuffer));

      expect(address1).not.toBe(address2);
    });
  });

  describe('Multi-Network Support', () => {
    // Helper to create minimal DID document for purpose validation
    function setupMinimalDIDDoc(did) {
      const keyId = `${did}#keys-bbs`;
      const address = did.split(':').pop();
      networkCache[did] = {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/v2'],
        id: did,
        verificationMethod: [{
          id: `${did}#controller`,
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: did,
          blockchainAccountId: `eip155:1:${address}`,
        }],
        assertionMethod: [`${did}#controller`, keyId],
        authentication: [`${did}#controller`],
      };
    }

    test('works with mainnet ethr DIDs', async () => {
      const mainnetKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'mainnet-key',
        controller: 'temp',
      });
      const mainnetAddress = keypairToAddress(mainnetKeypair);
      const mainnetDID = addressToDID(mainnetAddress); // No network = mainnet

      // Set up minimal DID document for purpose validation
      setupMinimalDIDDoc(mainnetDID);

      const mainnetKeyDoc = {
        id: `${mainnetDID}#keys-bbs`,
        controller: mainnetDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: mainnetKeypair,
      };

      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential'],
        issuer: mainnetDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          alumniOf: 'Mainnet University',
        },
      };

      const signedVC = await issueCredential(mainnetKeyDoc, unsignedCredential);

      expect(signedVC.proof.publicKeyBase58).toBeDefined();
      expect(signedVC.issuer).toMatch(/^did:ethr:0x[0-9a-fA-F]{40}$/);

      const result = await verifyCredential(signedVC);
      expect(result.verified).toBe(true);

      // Cleanup
      delete networkCache[mainnetDID];
    });

    test('works with different network ethr DIDs', async () => {
      const networks = ['sepolia', 'polygon'];
      const createdDIDs = [];

      for (const network of networks) {
        const keypair = Bls12381BBSKeyPairDock2023.generate({
          id: `${network}-key`,
          controller: 'temp',
        });
        const address = keypairToAddress(keypair);
        const did = addressToDID(address, network);
        createdDIDs.push(did);

        // Set up minimal DID document for purpose validation
        setupMinimalDIDDoc(did);

        const networkKeyDoc = {
          id: `${did}#keys-bbs`,
          controller: did,
          type: Bls12381BBS23DockVerKeyName,
          keypair,
        };

        const unsignedCredential = {
          '@context': [
            CREDENTIALS_V1_CONTEXT,
            CREDENTIALS_EXAMPLES_CONTEXT,
            BBS_V1_CONTEXT,
          ],
          type: ['VerifiableCredential'],
          issuer: did,
          issuanceDate: new Date().toISOString(),
          credentialSubject: {
            id: 'did:example:holder',
            alumniOf: `${network} University`,
          },
        };

        // eslint-disable-next-line no-await-in-loop
        const signedVC = await issueCredential(networkKeyDoc, unsignedCredential);

        expect(signedVC.issuer).toContain(network);
        expect(signedVC.proof.publicKeyBase58).toBeDefined();

        // eslint-disable-next-line no-await-in-loop
        const result = await verifyCredential(signedVC);
        expect(result.verified).toBe(true);
      }

      // Cleanup
      createdDIDs.forEach((did) => delete networkCache[did]);
    }, 60000);
  });

  describe('Backward Compatibility', () => {
    test('non-ethr DIDs still work with standard verification', async () => {
      // Create a non-ethr DID credential
      const nonEthrDID = 'did:example:issuer123';

      // Create mock DID document for verification
      const publicKeyBase58 = b58.encode(new Uint8Array(bbsKeypair.publicKeyBuffer));
      const keyId = `${nonEthrDID}#keys-bbs`;

      networkCache[keyId] = {
        '@context': 'https://w3id.org/security/v2',
        id: keyId,
        type: Bls12381BBS23DockVerKeyName,
        controller: nonEthrDID,
        publicKeyBase58,
      };

      networkCache[nonEthrDID] = {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/v2'],
        id: nonEthrDID,
        verificationMethod: [{
          id: keyId,
          type: Bls12381BBS23DockVerKeyName,
          controller: nonEthrDID,
          publicKeyBase58,
        }],
        assertionMethod: [keyId],
      };

      const nonEthrKeyDoc = {
        id: keyId,
        controller: nonEthrDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: bbsKeypair,
      };

      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential'],
        issuer: nonEthrDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          alumniOf: 'Example University',
        },
      };

      const signedVC = await issueCredential(nonEthrKeyDoc, unsignedCredential);

      // Should still have publicKeyBase58 in proof
      expect(signedVC.proof.publicKeyBase58).toBeDefined();

      // Should verify using standard DID document resolution
      const result = await verifyCredential(signedVC);
      expect(result.verified).toBe(true);

      // Cleanup
      delete networkCache[keyId];
      delete networkCache[nonEthrDID];
    });
  });
});
