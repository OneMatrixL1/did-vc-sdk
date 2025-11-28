/**
 * Unit tests for BBS key authorization logic in EthrDIDModule.getDocument()
 *
 * Tests that #keys-bbs is:
 * - Added to assertionMethod when there's NO on-chain data (default document)
 * - NOT added when there IS on-chain data (modified document)
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

  describe('No on-chain data (default document)', () => {
    test('adds #keys-bbs to assertionMethod when versionId is undefined', async () => {
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
        didDocumentMetadata: {}, // Empty - no versionId means no on-chain data
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

  describe('Has on-chain data (modified document)', () => {
    test('does NOT add #keys-bbs when versionId exists', async () => {
      // Simulate modified document (has on-chain changes)
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
          versionId: 12345, // Has versionId = has on-chain data
          updated: '2024-01-15T10:30:00Z',
        },
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
      });

      const document = await module.getDocument(testDID);

      expect(document.assertionMethod).toContain(`${testDID}#controller`);
      expect(document.assertionMethod).not.toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
      expect(document.assertionMethod).toHaveLength(1);
    });

    test('respects on-chain assertionMethod without adding #keys-bbs', async () => {
      // Simulate document with custom assertionMethod set on-chain
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

      // Should respect on-chain configuration
      expect(document.assertionMethod).toEqual([
        `${testDID}#controller`,
        `${testDID}#delegate-1`,
      ]);
      expect(document.assertionMethod).not.toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
    });

    test('does NOT add #keys-bbs even if versionId is 0 (falsy but defined)', async () => {
      // Edge case: versionId = 0 should still be considered as "has data"
      // because it's explicitly defined in the metadata
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
        didDocumentMetadata: {
          versionId: 0, // Explicitly set to 0
        },
        didResolutionMetadata: {},
      });

      const document = await module.getDocument(testDID);

      // versionId is defined (even if 0), so don't add #keys-bbs
      expect(document.assertionMethod).not.toContain(`${testDID}${ETHR_BBS_KEY_ID}`);
    });
  });

  describe('Edge cases', () => {
    test('does not duplicate #keys-bbs if already present in default doc', async () => {
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
  });
});
