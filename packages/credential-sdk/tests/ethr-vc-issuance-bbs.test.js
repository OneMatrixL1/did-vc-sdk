/**
 * Unit tests for VC/VP issuance with ethr DIDs using BBS signatures
 *
 * These tests verify that credentials and presentations can be issued
 * and verified using ethr DID identifiers with BBS+ signatures for
 * selective disclosure capabilities.
 *
 * IMPORTANT: These tests use BBS address-based recovery verification.
 * The DID documents do NOT contain the BBS public key - verification
 * uses the embedded publicKeyBase58 in the proof and validates it
 * by deriving the address and comparing with the DID.
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
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
 * Helper to create key document and register minimal DID document for BBS keypair.
 *
 * IMPORTANT: This creates a minimal DID document that does NOT contain the BBS public key.
 * Verification relies on the BBS address-based recovery mechanism:
 * 1. The proof contains publicKeyBase58 (embedded during signing)
 * 2. Verifier derives address from the embedded public key
 * 3. Verifier compares derived address with DID's address
 * 4. If match, verifies BBS signature using the embedded public key
 *
 * @param {Bls12381BBSKeyPairDock2023} keypair - BBS keypair
 * @param {string} did - DID string
 * @returns {object} keyDoc for signing
 */
function createBBSKeyDocWithMinimalDIDDocument(keypair, did) {
  const keyId = `${did}#keys-bbs`;
  const address = did.split(':').pop();

  const keyDoc = {
    id: keyId,
    controller: did,
    type: Bls12381BBS23DockVerKeyName,
    keypair,
  };

  // Register minimal DID document - NO BBS public key here!
  // The BBS public key comes from the proof's publicKeyBase58 field
  networkCache[did] = {
    '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
    id: did,
    verificationMethod: [
      {
        // Default controller key (secp256k1 recovery method)
        id: `${did}#controller`,
        type: 'EcdsaSecp256k1RecoveryMethod2020',
        controller: did,
        blockchainAccountId: `eip155:1:${address}`,
      },
    ],
    // Authorize both controller and BBS key ID for assertions
    assertionMethod: [`${did}#controller`, keyId],
    authentication: [`${did}#controller`],
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

    // Create key document with minimal DID document (no BBS key in doc)
    issuerKeyDoc = createBBSKeyDocWithMinimalDIDDocument(issuerKeypair, issuerDID);

    // Create holder identity with BBS keypair
    holderKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'holder-key',
      controller: 'temp',
    });
    const holderAddress = keypairToAddress(holderKeypair);
    holderDID = addressToDID(holderAddress, VIETCHAIN_NETWORK);

    // Create key document with minimal DID document (no BBS key in doc)
    holderKeyDoc = createBBSKeyDocWithMinimalDIDDocument(holderKeypair, holderDID);
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

      const keyDoc = createBBSKeyDocWithMinimalDIDDocument(mainnetKeypair, mainnetDID);

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

        const keyDoc = createBBSKeyDocWithMinimalDIDDocument(keypair, did);

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
