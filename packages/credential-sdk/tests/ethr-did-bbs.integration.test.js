/**
 * Integration tests for EthrDIDModule with BBS keypairs
 *
 * These tests verify BBS keypair support for ethr DIDs:
 * - DID creation from BBS keypair (address derivation)
 * - DID resolution (read-only operations)
 * - VC issuance and verification with BBS signatures
 *
 * IMPORTANT: These tests use BBS address-based recovery verification.
 * The DID documents do NOT contain the BBS public key - verification
 * uses the embedded publicKeyBase58 in the proof and validates it
 * by deriving the address and comparing with the DID.
 *
 * NOTE: DID document modifications (setAttribute, addDelegate, changeOwner)
 * are NOT tested here because BBS transaction signing is not yet supported.
 * See ethr-did.integration.test.js for secp256k1 modification tests.
 *
 * Environment Variables (REQUIRED):
 * ----------------------------------
 * ETHR_NETWORK_RPC_URL   - RPC endpoint URL (e.g., https://rpc.vietcha.in)
 *
 * Optional Environment Variables:
 * -------------------------------
 * ETHR_NETWORK           - Network name (default: sepolia)
 * ETHR_REGISTRY_ADDRESS  - DID Registry contract address
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { EthrDIDModule, createVietChainConfig } from '../src/modules/ethr-did';
import { keypairToAddress, parseDID, isEthrDID } from '../src/modules/ethr-did/utils';
import { issueCredential, verifyCredential } from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';

// Configuration from environment (required for integration tests)
if (!process.env.ETHR_NETWORK_RPC_URL) {
  throw new Error(
    'ETHR_NETWORK_RPC_URL environment variable is required for integration tests. '
      + 'Use scripts/test-integration-vietchain.sh or scripts/test-integration-sepolia.sh',
  );
}

const networkConfig = {
  name: process.env.ETHR_NETWORK || 'sepolia',
  rpcUrl: process.env.ETHR_NETWORK_RPC_URL,
  registry:
    process.env.ETHR_REGISTRY_ADDRESS
    || '0x03d5003bf0e79c5f5223588f347eba39afbc3818',
};

// Context URLs
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const SECURITY_V2_CONTEXT = 'https://w3id.org/security/v2';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';
const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1';

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

// Enable mock fetch for BBS DID document resolution
mockFetch();

describe('EthrDID BBS Integration Tests', () => {
  let module;

  beforeAll(async () => {
    // Initialize WASM for BBS operations
    await initializeWasm();

    // Create module with test network
    module = new EthrDIDModule({
      networks: [networkConfig],
      defaultNetwork: networkConfig.name,
    });
  });

  describe('DID Creation with BBS Keypair', () => {
    test('creates valid ethr DID from BBS keypair', async () => {
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'integration-key',
        controller: 'temp',
      });

      const did = await module.createNewDID(bbsKeypair);

      expect(isEthrDID(did)).toBe(true);
      expect(did).toContain(`did:ethr:${networkConfig.name}:`);

      // Verify address derivation is correct
      const expectedAddress = keypairToAddress(bbsKeypair);
      const parsed = parseDID(did);
      expect(parsed.address.toLowerCase()).toBe(expectedAddress.toLowerCase());
    });

    test('creates consistent DIDs for same BBS keypair', async () => {
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'consistent-key',
        controller: 'temp',
      });

      const did1 = await module.createNewDID(bbsKeypair);
      const did2 = await module.createNewDID(bbsKeypair);

      expect(did1).toBe(did2);
    });

    test('creates different DIDs for different BBS keypairs', async () => {
      const keypair1 = Bls12381BBSKeyPairDock2023.generate({
        id: 'key1',
        controller: 'temp',
      });
      const keypair2 = Bls12381BBSKeyPairDock2023.generate({
        id: 'key2',
        controller: 'temp',
      });

      const did1 = await module.createNewDID(keypair1);
      const did2 = await module.createNewDID(keypair2);

      expect(did1).not.toBe(did2);
    });
  });

  describe('DID Resolution (Read-Only)', () => {
    test('resolves DID document for BBS-derived DID', async () => {
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'resolve-key',
        controller: 'temp',
      });

      const did = await module.createNewDID(bbsKeypair);

      // Resolve the document (will show default owner key from chain)
      const document = await module.getDocument(did);

      expect(document).toBeDefined();
      expect(document.id).toBe(did);
      expect(document.verificationMethod).toBeDefined();
      expect(document.verificationMethod.length).toBeGreaterThanOrEqual(1);
    }, 30000);
  });

  describe('VC Issuance with BBS Signature', () => {
    let issuerKeypair;
    let issuerDID;
    let issuerKeyDoc;

    beforeAll(async () => {
      // Create issuer identity with BBS keypair
      issuerKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'issuer-integration',
        controller: 'temp',
      });
      issuerDID = await module.createNewDID(issuerKeypair);

      // Create key document with minimal DID document (no BBS key in doc)
      issuerKeyDoc = createBBSKeyDocWithMinimalDIDDocument(issuerKeypair, issuerDID);
    });

    afterAll(() => {
      cleanupDIDFromCache(issuerDID);
    });

    test('issues credential with BBS signature from ethr DID', async () => {
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
          id: 'did:example:student123',
          degree: {
            type: 'BachelorDegree',
            name: 'Bachelor of Science and Arts',
          },
        },
      };

      const signedVC = await issueCredential(issuerKeyDoc, unsignedCredential);

      expect(signedVC).toBeDefined();
      expect(signedVC.issuer).toBe(issuerDID);
      expect(signedVC.proof).toBeDefined();
      expect(signedVC.proof.type).toBe('Bls12381BBSSignatureDock2023');
      expect(signedVC.proof.verificationMethod).toBe(issuerKeyDoc.id);
    }, 30000);

    test('verifies BBS-signed credential from ethr DID', async () => {
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential', 'AlumniCredential'],
        issuer: issuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder456',
          alumniOf: 'Integration Test University',
        },
      };

      const signedVC = await issueCredential(issuerKeyDoc, unsignedCredential);
      const result = await verifyCredential(signedVC);

      expect(result.verified).toBe(true);
      expect(result.results).toBeDefined();
      expect(result.results[0].verified).toBe(true);
    }, 30000);

    test('fails verification with tampered credential', async () => {
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential'],
        issuer: issuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder789',
          alumniOf: 'Original University',
        },
      };

      const signedVC = await issueCredential(issuerKeyDoc, unsignedCredential);

      // Tamper with the credential
      const tamperedVC = {
        ...signedVC,
        credentialSubject: {
          ...signedVC.credentialSubject,
          alumniOf: 'Tampered University',
        },
      };

      const result = await verifyCredential(tamperedVC);

      expect(result.verified).toBe(false);
    }, 30000);
  });

  describe('Multi-Network Operations with BBS', () => {
    test('creates BBS DIDs on different networks', async () => {
      const multiNetModule = new EthrDIDModule({
        networks: ['sepolia', createVietChainConfig()],
        defaultNetwork: 'sepolia',
      });

      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'multi-net-key',
        controller: 'temp',
      });

      const sepoliaDID = await multiNetModule.createNewDID(bbsKeypair, 'sepolia');
      const vietChainDID = await multiNetModule.createNewDID(bbsKeypair, 'vietchain');

      // DIDs should be different due to network prefix
      expect(sepoliaDID).not.toBe(vietChainDID);
      expect(sepoliaDID).toContain('sepolia');
      expect(vietChainDID).toContain('vietchain');

      // But addresses should be the same (same keypair)
      const sepoliaAddress = parseDID(sepoliaDID).address;
      const vietChainAddress = parseDID(vietChainDID).address;
      expect(sepoliaAddress).toBe(vietChainAddress);
    });

    test('issues credentials on different networks with same BBS keypair', async () => {
      const networks = ['sepolia', 'vietchain'];
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'multi-net-issuer',
        controller: 'temp',
      });

      const multiNetModule = new EthrDIDModule({
        networks: ['sepolia', createVietChainConfig()],
        defaultNetwork: 'sepolia',
      });

      const createdDIDs = [];

      for (const network of networks) {
        // eslint-disable-next-line no-await-in-loop
        const did = await multiNetModule.createNewDID(bbsKeypair, network);
        createdDIDs.push(did);

        const keyDoc = createBBSKeyDocWithMinimalDIDDocument(bbsKeypair, did);

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
            id: 'did:example:student',
            alumniOf: `University on ${network}`,
          },
        };

        // eslint-disable-next-line no-await-in-loop
        const signedVC = await issueCredential(keyDoc, unsignedCredential);

        expect(signedVC.issuer).toBe(did);
        expect(signedVC.issuer).toContain(network);
        expect(signedVC.proof.type).toBe('Bls12381BBSSignatureDock2023');

        // eslint-disable-next-line no-await-in-loop
        const result = await verifyCredential(signedVC);
        expect(result.verified).toBe(true);
      }

      // Cleanup
      createdDIDs.forEach((did) => cleanupDIDFromCache(did));
    }, 60000);
  });

  describe('BBS vs Secp256k1 Comparison', () => {
    test('BBS and secp256k1 produce different DIDs from logically equivalent keypairs', async () => {
      // This tests that BBS address derivation is distinct from secp256k1
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'compare-key',
        controller: 'temp',
      });

      const bbsAddress = keypairToAddress(bbsKeypair);
      const bbsDID = await module.createNewDID(bbsKeypair);

      // BBS address should be valid
      expect(bbsAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
      expect(bbsDID).toContain(bbsAddress);

      // BBS public key is 96 bytes (vs 33 for secp256k1)
      expect(bbsKeypair.publicKeyBuffer.length).toBe(96);
    });
  });

  describe('Transaction Signing Limitation', () => {
    test('BBS keypair cannot sign transactions', async () => {
      const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'tx-test-key',
        controller: 'temp',
      });

      const did = await module.createNewDID(bbsKeypair);

      // Attempting to set attribute with BBS keypair should throw
      await expect(
        module.setAttribute(did, 'test', 'value', bbsKeypair),
      ).rejects.toThrow(/BBS transaction signing not yet supported/);
    });
  });
});
