/**
 * Unit tests for BBS key authorization logic in EthrDIDModule.getDocument()
 *
 * Tests that #keys-bbs (implicit BBS key) is:
 * - Added to assertionMethod when there's NO explicit BBS key registered
 * - NOT added when there IS an explicit BBS key in verificationMethod
 *
 * This follows EOA-like behavior: the implicit BBS key is always valid unless
 * explicitly overridden by registering a different BBS key on-chain.
 * Adding delegates or other on-chain data does NOT disable implicit BBS support.
 */

import { ETHR_BBS_KEY_ID } from '../src/modules/ethr-did/utils';

// Create a mock resolver function that we can control
const mockResolverResolve = jest.fn();

// Mock the did-resolver Resolver class
jest.mock('did-resolver', () => ({
  Resolver: jest.fn().mockImplementation(() => ({
    resolve: mockResolverResolve,
  })),
}));

// Mock ethr-did-resolver
jest.mock('ethr-did-resolver', () => ({
  getResolver: jest.fn().mockReturnValue({}),
}));

// Now import after mocking
import EthrDIDModule from '../src/modules/ethr-did/module';

describe('EthrDIDModule BBS Key Authorization', () => {
  let module;
  const testDID = 'did:ethr:testnet:0x1234567890123456789012345678901234567890';

  beforeEach(() => {
    module = new EthrDIDModule({
      networks: [{
        name: 'testnet',
        rpcUrl: 'https://rpc.example.com',
        registry: '0x0000000000000000000000000000000000000000',
      }],
      defaultNetwork: 'testnet',
    });

    mockResolverResolve.mockReset();
  });

  describe('No explicit BBS key (default document)', () => {
    test('adds #keys-bbs to assertionMethod when no explicit BBS key exists', async () => {
      // Simulate default document (no on-chain changes)
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [{
            id: `${testDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: testDID,
          }],
          authentication: [`${testDID}#controller`],
          assertionMethod: [`${testDID}#controller`],
        },
        didDocumentMetadata: {},
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
      });

      const document = await module.getDocument(testDID);

      expect(document.assertionMethod).toContain(`${testDID}#controller`);
      expect(document.assertionMethod).toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
      expect(document.assertionMethod).toHaveLength(2);
    });

    test('adds #keys-bbs when didDocumentMetadata is empty object', async () => {
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [{
            id: `${testDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: testDID,
          }],
          assertionMethod: [`${testDID}#controller`],
        },
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      expect(document.assertionMethod).toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
    });

    test('adds #keys-bbs when didDocumentMetadata is null', async () => {
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [{
            id: `${testDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: testDID,
          }],
          assertionMethod: [`${testDID}#controller`],
        },
        didDocumentMetadata: null,
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      expect(document.assertionMethod).toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
    });
  });

  describe('Has on-chain data but NO explicit BBS key', () => {
    test('STILL adds #keys-bbs when versionId exists but no explicit BBS key', async () => {
      // Simulate modified document (has on-chain changes like delegates)
      // But no explicit BBS key registered - should still allow implicit BBS
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [{
            id: `${testDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: testDID,
          }],
          authentication: [`${testDID}#controller`],
          assertionMethod: [`${testDID}#controller`],
        },
        didDocumentMetadata: {
          versionId: 12345, // Has on-chain data
          updated: '2024-01-15T10:30:00Z',
        },
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
      });

      const document = await module.getDocument(testDID);

      // Should STILL add implicit BBS key (EOA-like behavior)
      expect(document.assertionMethod).toContain(`${testDID}#controller`);
      expect(document.assertionMethod).toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
      expect(document.assertionMethod).toHaveLength(2);
    });

    test('adds #keys-bbs even with delegates in verificationMethod', async () => {
      // Simulate document with delegate added on-chain (but no BBS key)
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [
            {
              id: `${testDID}#controller`,
              type: 'EcdsaSecp256k1RecoveryMethod2020',
              controller: testDID,
            },
            {
              id: `${testDID}#delegate-1`,
              type: 'EcdsaSecp256k1VerificationKey2019',
              controller: testDID,
            },
          ],
          authentication: [`${testDID}#controller`],
          assertionMethod: [`${testDID}#controller`, `${testDID}#delegate-1`],
        },
        didDocumentMetadata: {
          versionId: 54321,
          updated: '2024-02-20T15:45:00Z',
        },
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      // Should add implicit BBS key alongside delegates
      expect(document.assertionMethod).toContain(`${testDID}#controller`);
      expect(document.assertionMethod).toContain(`${testDID}#delegate-1`);
      expect(document.assertionMethod).toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
      expect(document.assertionMethod).toHaveLength(3);
    });
  });

  describe('Has explicit BBS key registered', () => {
    test('does NOT add #keys-bbs when Bls12381BBSVerificationKeyDock2023 exists', async () => {
      // Simulate document with explicit BBS key registered on-chain
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [
            {
              id: `${testDID}#controller`,
              type: 'EcdsaSecp256k1RecoveryMethod2020',
              controller: testDID,
            },
            {
              id: `${testDID}#bbs-key-1`,
              type: 'Bls12381BBSVerificationKeyDock2023',
              controller: testDID,
              publicKeyBase58: 'somePublicKeyBase58',
            },
          ],
          authentication: [`${testDID}#controller`],
          assertionMethod: [`${testDID}#controller`, `${testDID}#bbs-key-1`],
        },
        didDocumentMetadata: {
          versionId: 99999,
        },
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      // Should NOT add implicit BBS key - explicit one takes precedence
      expect(document.assertionMethod).toContain(`${testDID}#controller`);
      expect(document.assertionMethod).toContain(`${testDID}#bbs-key-1`);
      expect(document.assertionMethod).not.toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
      expect(document.assertionMethod).toHaveLength(2);
    });

    test('does NOT add #keys-bbs when Bls12381G2VerificationKeyDock2022 exists', async () => {
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [
            {
              id: `${testDID}#controller`,
              type: 'EcdsaSecp256k1RecoveryMethod2020',
              controller: testDID,
            },
            {
              id: `${testDID}#bbs-key-2022`,
              type: 'Bls12381G2VerificationKeyDock2022',
              controller: testDID,
              publicKeyBase58: 'anotherPublicKey',
            },
          ],
          assertionMethod: [`${testDID}#controller`, `${testDID}#bbs-key-2022`],
        },
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      expect(document.assertionMethod).not.toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
    });

    test('does NOT add #keys-bbs when Bls12381PSVerificationKeyDock2023 exists', async () => {
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [
            {
              id: `${testDID}#controller`,
              type: 'EcdsaSecp256k1RecoveryMethod2020',
              controller: testDID,
            },
            {
              id: `${testDID}#ps-key`,
              type: 'Bls12381PSVerificationKeyDock2023',
              controller: testDID,
              publicKeyBase58: 'psPublicKey',
            },
          ],
          assertionMethod: [`${testDID}#controller`],
        },
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      expect(document.assertionMethod).not.toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
    });

    test('does NOT add #keys-bbs when Bls12381BBDT16VerificationKeyDock2024 exists', async () => {
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [
            {
              id: `${testDID}#controller`,
              type: 'EcdsaSecp256k1RecoveryMethod2020',
              controller: testDID,
            },
            {
              id: `${testDID}#bbdt16-key`,
              type: 'Bls12381BBDT16VerificationKeyDock2024',
              controller: testDID,
              publicKeyBase58: 'bbdt16PublicKey',
            },
          ],
          assertionMethod: [`${testDID}#controller`],
        },
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      expect(document.assertionMethod).not.toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
    });
  });

  describe('Edge cases', () => {
    test('does not duplicate #keys-bbs if already present', async () => {
      // Edge case: assertionMethod already contains #keys-bbs
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [{
            id: `${testDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: testDID,
          }],
          assertionMethod: [`${testDID}#controller`, `${testDID}${ETHR_BBS_KEY_ID}`],
        },
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      // Should not duplicate
      const bbsKeyCount = document.assertionMethod.filter(
        (id) => id === `${testDID}${ETHR_BBS_KEY_ID}`,
      ).length;
      expect(bbsKeyCount).toBe(1);
    });

    test('handles document without assertionMethod array', async () => {
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [{
            id: `${testDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: testDID,
          }],
          // No assertionMethod field
        },
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      // Should not throw, assertionMethod should remain undefined
      expect(document.assertionMethod).toBeUndefined();
    });

    test('handles document with empty verificationMethod array', async () => {
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          verificationMethod: [],
          assertionMethod: [`${testDID}#controller`],
        },
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      // No explicit BBS key, should add implicit
      expect(document.assertionMethod).toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
    });

    test('handles document with undefined verificationMethod', async () => {
      mockResolverResolve.mockResolvedValue({
        didDocument: {
          id: testDID,
          assertionMethod: [`${testDID}#controller`],
        },
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      // No verificationMethod, so no explicit BBS key, should add implicit
      expect(document.assertionMethod).toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
    });
  });
});
