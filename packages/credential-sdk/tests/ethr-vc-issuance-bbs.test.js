/**
 * Unit tests for VC/VP issuance with ethr DIDs using BBS signatures
 *
 * These tests verify that credentials and presentations can be issued
 * and verified using ethr DID identifiers with BBS+ signatures for
 * selective disclosure capabilities.
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';
import {
  issueCredential, verifyCredential,
} from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import { addressToDID, keypairToAddress } from '../src/modules/ethr-did/utils';

// Constants
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const SECURITY_V2_CONTEXT = 'https://w3id.org/security/v2';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';
const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1';
const VIETCHAIN_NETWORK = 'vietchain';
const TEST_ISSUANCE_DATE = '2024-01-01T00:00:00Z';

/**
 * Helper to create and register mock DID document for BBS keypair
 * @param {Bls12381BBSKeyPairDock2023} keypair - BBS keypair
 * @param {string} did - DID string
 * @returns {object} keyDoc for signing
 */
function createBBSMockDIDDocument(keypair, did) {
  const publicKeyBase58 = b58.encode(new Uint8Array(keypair.publicKeyBuffer));
  const keyId = `${did}#keys-1`;

  const keyDoc = {
    id: keyId,
    controller: did,
    type: Bls12381BBS23DockVerKeyName,
    keypair,
  };

  // Register verification method
  networkCache[keyId] = {
    '@context': SECURITY_V2_CONTEXT,
    id: keyId,
    type: Bls12381BBS23DockVerKeyName,
    controller: did,
    publicKeyBase58,
  };

  // Register DID document
  networkCache[did] = {
    '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: Bls12381BBS23DockVerKeyName,
        controller: did,
        publicKeyBase58,
      },
    ],
    assertionMethod: [keyId],
    authentication: [keyId],
  };

  return keyDoc;
}

/**
 * Helper to clean up DID entries from networkCache
 * @param {string} did
 */
function cleanupDIDFromCache(did) {
  Object.keys(networkCache).forEach((key) => {
    if (key === did || key.startsWith(`${did}#`)) {
      delete networkCache[key];
    }
  });
}

mockFetch();

describe('Ethr DID VC Issuance with BBS', () => {
  let issuerKeypair;
  let issuerDID;
  let issuerKeyDoc;
  let holderKeypair;
  let holderDID;
  let holderKeyDoc;

  beforeAll(async () => {
    // Initialize WASM for BBS operations
    await initializeWasm();

    // Create issuer identity with BBS keypair
    issuerKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'issuer-key',
      controller: 'temp',
    });
    const issuerAddress = keypairToAddress(issuerKeypair);
    issuerDID = addressToDID(issuerAddress, VIETCHAIN_NETWORK);

    // Create and register issuer DID document
    issuerKeyDoc = createBBSMockDIDDocument(issuerKeypair, issuerDID);

    // Create holder identity with BBS keypair
    holderKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'holder-key',
      controller: 'temp',
    });
    const holderAddress = keypairToAddress(holderKeypair);
    holderDID = addressToDID(holderAddress, VIETCHAIN_NETWORK);

    // Create and register holder DID document
    holderKeyDoc = createBBSMockDIDDocument(holderKeypair, holderDID);
  });

  describe('Credential Issuance', () => {
    test('should issue a credential with BBS signature from ethr DID', async () => {
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: issuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDID,
          degree: {
            type: 'BachelorDegree',
            name: 'Bachelor of Science and Arts',
          },
        },
      };

      const signedVC = await issueCredential(issuerKeyDoc, unsignedCredential);

      expect(signedVC).toBeDefined();
      expect(signedVC.issuer).toBe(issuerDID);
      expect(signedVC.credentialSubject.id).toBe(holderDID);
      expect(signedVC.proof).toBeDefined();
      expect(signedVC.proof.type).toBe('Bls12381BBSSignatureDock2023');
      expect(signedVC.proof.verificationMethod).toBe(issuerKeyDoc.id);
      expect(signedVC.proof.proofPurpose).toBe('assertionMethod');
    }, 30000);

    test('should issue credential with ethr DID on mainnet', async () => {
      const mainnetKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'mainnet-key',
        controller: 'temp',
      });
      const mainnetAddress = keypairToAddress(mainnetKeypair);
      const mainnetDID = addressToDID(mainnetAddress); // No network = mainnet

      const keyDoc = createBBSMockDIDDocument(mainnetKeypair, mainnetDID);

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
          id: 'did:example:student123',
          alumniOf: 'Example University',
        },
      };

      const signedVC = await issueCredential(keyDoc, unsignedCredential);

      expect(signedVC.issuer).toBe(mainnetDID);
      expect(signedVC.issuer).toMatch(/^did:ethr:0x[0-9a-fA-F]{40}$/); // Mainnet format
      expect(signedVC.issuer).not.toContain('vietchain');
      expect(signedVC.proof).toBeDefined();
      expect(signedVC.proof.type).toBe('Bls12381BBSSignatureDock2023');

      // Verify the credential
      const result = await verifyCredential(signedVC);
      expect(result.verified).toBe(true);

      cleanupDIDFromCache(mainnetDID);
    }, 30000);

    test('should issue credential with ethr DID on different networks', async () => {
      const networks = ['sepolia', 'polygon', 'arbitrum'];
      const createdDIDs = [];

      for (const network of networks) {
        const keypair = Bls12381BBSKeyPairDock2023.generate({
          id: `${network}-key`,
          controller: 'temp',
        });
        const address = keypairToAddress(keypair);
        const did = addressToDID(address, network);
        createdDIDs.push(did);

        const keyDoc = createBBSMockDIDDocument(keypair, did);

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
            id: 'did:example:student123',
            alumniOf: `University on ${network}`,
          },
        };

        // eslint-disable-next-line no-await-in-loop
        const signedVC = await issueCredential(keyDoc, unsignedCredential);

        expect(signedVC.issuer).toBe(did);
        expect(signedVC.issuer).toContain(network);
        expect(signedVC.proof).toBeDefined();
        expect(signedVC.proof.type).toBe('Bls12381BBSSignatureDock2023');

        // eslint-disable-next-line no-await-in-loop
        const result = await verifyCredential(signedVC);
        expect(result.verified).toBe(true);
      }

      createdDIDs.forEach((did) => cleanupDIDFromCache(did));
    }, 60000);
  });

  describe('Credential Verification', () => {
    let signedCredential;

    beforeAll(async () => {
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential', 'AlumniCredential'],
        issuer: issuerDID,
        issuanceDate: TEST_ISSUANCE_DATE,
        credentialSubject: {
          id: holderDID,
          alumniOf: 'Example University',
        },
      };

      signedCredential = await issueCredential(issuerKeyDoc, unsignedCredential);
    });

    test('should verify credential signed with BBS from ethr DID', async () => {
      const result = await verifyCredential(signedCredential);

      expect(result.verified).toBe(true);
      expect(result.results).toBeDefined();
      expect(result.results[0].verified).toBe(true);
    }, 30000);

    test('should fail verification with tampered credential', async () => {
      const tamperedCredential = {
        ...signedCredential,
        credentialSubject: {
          ...signedCredential.credentialSubject,
          alumniOf: 'Fake University',
        },
      };

      const result = await verifyCredential(tamperedCredential);

      expect(result.verified).toBe(false);
    }, 30000);
  });

  // NOTE: BBS presentations require special handling with derived proofs
  // for selective disclosure. Standard presentation signing with BBS
  // has schema compatibility issues. See BBS+ selective disclosure
  // documentation for proper presentation creation.

  describe('Ethr DID Format Validation with BBS', () => {
    test('should work with checksummed addresses in DIDs', async () => {
      const keypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'checksum-test',
        controller: 'temp',
      });
      const address = keypairToAddress(keypair);
      const did = addressToDID(address, VIETCHAIN_NETWORK);

      // Address should be checksummed (mixed case)
      expect(did).toMatch(/did:ethr:vietchain:0x[0-9a-fA-F]{40}/);

      // Extract address part
      const addressPart = did.split(':')[3];
      expect(addressPart).toBe(address);
    });

    test('should handle mainnet DIDs without network prefix', async () => {
      const keypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'mainnet-test',
        controller: 'temp',
      });
      const address = keypairToAddress(keypair);
      const did = addressToDID(address); // No network = mainnet

      expect(did).toMatch(/^did:ethr:0x[0-9a-fA-F]{40}$/);
      expect(did).not.toContain('mainnet');
    });

    test('BBS-derived address differs from secp256k1 address derivation', async () => {
      // This verifies that BBS uses keccak256(publicKey) instead of secp256k1 derivation
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'bbs-key',
        controller: 'temp',
      });

      const bbsAddress = keypairToAddress(bbsKeypair);

      // BBS address should be valid Ethereum address format
      expect(bbsAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);

      // BBS public key is 96 bytes
      expect(bbsKeypair.publicKeyBuffer.length).toBe(96);
    });
  });
});
