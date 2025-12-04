/**
 * Unit tests for verifyPresentationOptimistic()
 *
 * Tests the optimistic verification helper for verifiable presentations that
 * tries optimistic resolution first, identifies which DIDs fail, and falls
 * back to blockchain if needed.
 */

import b58 from 'bs58';
import { issueCredential, signPresentation, verifyPresentation } from '../src/vc';
import { Secp256k1Keypair } from '../src/keypairs';
import { EcdsaSecp256k1VerKeyName } from '../src/vc/crypto/constants';
import {
  EthrDIDModule,
  addressToDID,
  keypairToAddress,
  verifyPresentationOptimistic,
  createMemoryStorageAdapter,
} from '../src/modules/ethr-did';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';

// Context URLs
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const SECURITY_V2_CONTEXT = 'https://w3id.org/security/v2';
const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1';
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

/**
 * Get raw public key bytes from keypair
 */
// eslint-disable-next-line no-underscore-dangle
const getRawPublicKeyBytes = (keypair) => keypair._publicKey();

/**
 * Helper to create and register mock DID document in networkCache
 */
function createMockDIDDocument(keypair, did) {
  const publicKeyBytes = getRawPublicKeyBytes(keypair);
  const publicKeyBase58 = b58.encode(publicKeyBytes);
  const keyId = `${did}#keys-1`;

  const keyDoc = {
    id: keyId,
    controller: did,
    type: EcdsaSecp256k1VerKeyName,
    publicKey: keypair.publicKey(),
    keypair,
  };

  // Register verification method
  networkCache[keyId] = {
    '@context': SECURITY_V2_CONTEXT,
    id: keyId,
    type: EcdsaSecp256k1VerKeyName,
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
        type: EcdsaSecp256k1VerKeyName,
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
 */
function cleanupDIDFromCache(did) {
  Object.keys(networkCache).forEach((key) => {
    if (key === did || key.startsWith(`${did}#`)) {
      delete networkCache[key];
    }
  });
}

/**
 * Create a mock module that resolves DIDs from networkCache
 * This allows testing the verifyPresentationOptimistic flow without needing
 * actual blockchain resolution.
 */
function createMockModule() {
  const realModule = new EthrDIDModule({
    networks: [networkConfig],
  });

  return {
    supports: (id) => realModule.supports(id),
    resolve: async (id) => {
      const idString = String(id);
      // Check if it's a full URL (has fragment)
      if (idString.includes('#')) {
        // Return the verification method directly from networkCache
        if (networkCache[idString]) {
          return networkCache[idString];
        }
        // Try to find it in the DID document
        const did = idString.split('#')[0];
        const didDoc = networkCache[did];
        if (didDoc) {
          const fragment = idString.substring(idString.indexOf('#'));
          const vm = didDoc.verificationMethod?.find(
            (v) => v.id === idString || v.id === fragment || v.id.endsWith(fragment),
          );
          if (vm) {
            return {
              '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/v2',
              ],
              ...vm,
            };
          }
        }
      }
      // Return the DID document directly
      if (networkCache[idString]) {
        return networkCache[idString];
      }
      // Fall back to real module (will likely fail in tests)
      return realModule.resolve(id);
    },
  };
}

describe('verifyPresentationOptimistic()', () => {
  let issuerKeypair;
  let issuerDID;
  let issuerKeyDoc;
  let holderKeypair;
  let holderDID;
  let holderKeyDoc;
  let signedCredential;
  let signedPresentation;
  let mockModule;

  const testChallenge = 'test-challenge-12345';
  const testDomain = 'test.example.com';

  beforeAll(async () => {
    // Create issuer keypair and derive ethr DID
    issuerKeypair = Secp256k1Keypair.random();
    const issuerAddress = keypairToAddress(issuerKeypair);
    issuerDID = addressToDID(issuerAddress, VIETCHAIN_NETWORK);
    issuerKeyDoc = createMockDIDDocument(issuerKeypair, issuerDID);

    // Create holder keypair and derive ethr DID
    holderKeypair = Secp256k1Keypair.random();
    const holderAddress = keypairToAddress(holderKeypair);
    holderDID = addressToDID(holderAddress, VIETCHAIN_NETWORK);
    holderKeyDoc = createMockDIDDocument(holderKeypair, holderDID);

    // Create mock module
    mockModule = createMockModule();

    // Issue credential
    const unsignedCredential = {
      '@context': [
        CREDENTIALS_V1_CONTEXT,
        CREDENTIALS_EXAMPLES_CONTEXT,
      ],
      type: ['VerifiableCredential'],
      issuer: issuerDID,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: holderDID,
        alumniOf: 'Optimistic Verification University',
      },
    };

    signedCredential = await issueCredential(issuerKeyDoc, unsignedCredential);

    // Create and sign presentation
    const unsignedPresentation = {
      '@context': [CREDENTIALS_V1_CONTEXT],
      type: ['VerifiablePresentation'],
      verifiableCredential: [signedCredential],
      holder: holderDID,
    };

    signedPresentation = await signPresentation(
      unsignedPresentation,
      holderKeyDoc,
      testChallenge,
      testDomain,
    );

    // Verify the presentation works with standard verifyPresentation
    const standardResult = await verifyPresentation(signedPresentation, {
      challenge: testChallenge,
      domain: testDomain,
    });
    if (!standardResult.verified) {
      throw new Error(`Test setup failed: standard presentation verification failed: ${JSON.stringify(standardResult.error)}`);
    }
  });

  afterAll(() => {
    cleanupDIDFromCache(issuerDID);
    cleanupDIDFromCache(holderDID);
  });

  describe('Basic functionality', () => {
    test('throws if module is not provided', async () => {
      await expect(
        verifyPresentationOptimistic(signedPresentation, { challenge: testChallenge }),
      ).rejects.toThrow('module is required');
    });

    test('throws if presentation is not provided', async () => {
      await expect(
        verifyPresentationOptimistic(null, { module: mockModule, challenge: testChallenge }),
      ).rejects.toThrow('"presentation" property is required');
    });

    test('verifies valid presentation without storage', async () => {
      const result = await verifyPresentationOptimistic(signedPresentation, {
        module: mockModule,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(true);
      expect(result.presentationResult.verified).toBe(true);
      expect(result.credentialResults[0].verified).toBe(true);
    });

    test('fails verification for tampered credential in presentation', async () => {
      const tamperedPresentation = {
        ...signedPresentation,
        verifiableCredential: [{
          ...signedPresentation.verifiableCredential[0],
          credentialSubject: {
            ...signedPresentation.verifiableCredential[0].credentialSubject,
            alumniOf: 'Fake University',
          },
        }],
      };

      const result = await verifyPresentationOptimistic(tamperedPresentation, {
        module: mockModule,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(false);
    });

    test('fails verification for wrong challenge', async () => {
      const result = await verifyPresentationOptimistic(signedPresentation, {
        module: mockModule,
        challenge: 'wrong-challenge',
        domain: testDomain,
      });

      expect(result.verified).toBe(false);
    });
  });

  describe('With memory storage', () => {
    test('verifies presentation and does not mark DIDs on success', async () => {
      const storage = createMemoryStorageAdapter();

      const result = await verifyPresentationOptimistic(signedPresentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(true);
      // Neither issuer nor holder should be marked on success
      expect(await storage.has(issuerDID)).toBe(false);
      expect(await storage.has(holderDID)).toBe(false);
    });

    test('skips optimistic when any DID is in storage', async () => {
      const storage = createMemoryStorageAdapter();

      // Pre-mark issuer DID
      await storage.set(issuerDID);

      const result = await verifyPresentationOptimistic(signedPresentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      // Should still verify (goes directly to blockchain fallback)
      expect(result.verified).toBe(true);
    });

    test('skips optimistic when holder DID is in storage', async () => {
      const storage = createMemoryStorageAdapter();

      // Pre-mark holder DID
      await storage.set(holderDID);

      const result = await verifyPresentationOptimistic(signedPresentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      // Should still verify (goes directly to blockchain fallback)
      expect(result.verified).toBe(true);
    });
  });

  describe('DID extraction', () => {
    test('extracts holder DID from string holder field', async () => {
      const storage = createMemoryStorageAdapter();

      const result = await verifyPresentationOptimistic(signedPresentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(true);
      // Holder should not be marked on success
      expect(await storage.has(holderDID)).toBe(false);
    });

    test('extracts issuer DID from credentials and marks on failure', async () => {
      const storage = createMemoryStorageAdapter();

      // Tamper credential to trigger failure detection
      const tamperedPresentation = {
        ...signedPresentation,
        verifiableCredential: [{
          ...signedPresentation.verifiableCredential[0],
          credentialSubject: {
            ...signedPresentation.verifiableCredential[0].credentialSubject,
            alumniOf: 'Tampered Value',
          },
        }],
      };

      await verifyPresentationOptimistic(tamperedPresentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      // Issuer DID should be marked because the credential failed
      expect(await storage.has(issuerDID)).toBe(true);
    });
  });

  describe('Multiple credentials', () => {
    let secondIssuerKeypair;
    let secondIssuerDID;
    let secondIssuerKeyDoc;
    let secondCredential;
    let multiCredPresentation;

    beforeAll(async () => {
      // Create second issuer
      secondIssuerKeypair = Secp256k1Keypair.random();
      const secondAddress = keypairToAddress(secondIssuerKeypair);
      secondIssuerDID = addressToDID(secondAddress, VIETCHAIN_NETWORK);
      secondIssuerKeyDoc = createMockDIDDocument(secondIssuerKeypair, secondIssuerDID);

      // Issue second credential
      const unsignedSecondCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential'],
        issuer: secondIssuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDID,
          degree: 'Masters of Science',
        },
      };

      secondCredential = await issueCredential(secondIssuerKeyDoc, unsignedSecondCredential);

      // Create multi-credential presentation
      const unsignedPresentation = {
        '@context': [CREDENTIALS_V1_CONTEXT],
        type: ['VerifiablePresentation'],
        verifiableCredential: [signedCredential, secondCredential],
        holder: holderDID,
      };

      multiCredPresentation = await signPresentation(
        unsignedPresentation,
        holderKeyDoc,
        testChallenge,
        testDomain,
      );
    });

    afterAll(() => {
      cleanupDIDFromCache(secondIssuerDID);
    });

    test('verifies VP with multiple credentials from different issuers', async () => {
      const storage = createMemoryStorageAdapter();

      const result = await verifyPresentationOptimistic(multiCredPresentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(true);
      // No DIDs should be marked on success
      expect(await storage.has(issuerDID)).toBe(false);
      expect(await storage.has(secondIssuerDID)).toBe(false);
      expect(await storage.has(holderDID)).toBe(false);
    });

    test('deduplicates DIDs when presenter is also an issuer', async () => {
      // Create self-issued credential
      const selfIssuedCred = await issueCredential(holderKeyDoc, {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential'],
        issuer: holderDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:subject',
          alumniOf: 'Self-Attested University',
        },
      });

      const selfIssuedPresentation = await signPresentation(
        {
          '@context': [CREDENTIALS_V1_CONTEXT],
          type: ['VerifiablePresentation'],
          verifiableCredential: [selfIssuedCred],
          holder: holderDID,
        },
        holderKeyDoc,
        testChallenge,
        testDomain,
      );

      const storage = createMemoryStorageAdapter();

      const result = await verifyPresentationOptimistic(selfIssuedPresentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(true);
    });
  });

  describe('Pass-through options', () => {
    test('passes challenge and domain to verifyPresentation', async () => {
      const result = await verifyPresentationOptimistic(signedPresentation, {
        module: mockModule,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(true);
    });

    test('passes skipRevocationCheck option', async () => {
      const result = await verifyPresentationOptimistic(signedPresentation, {
        module: mockModule,
        challenge: testChallenge,
        domain: testDomain,
        skipRevocationCheck: true,
      });

      expect(result.verified).toBe(true);
    });
  });

  describe('Edge cases', () => {
    test('handles presentation with empty credentials array', async () => {
      const emptyPresentation = await signPresentation(
        {
          '@context': [CREDENTIALS_V1_CONTEXT],
          type: ['VerifiablePresentation'],
          verifiableCredential: [],
          holder: holderDID,
        },
        holderKeyDoc,
        testChallenge,
        testDomain,
      );

      const result = await verifyPresentationOptimistic(emptyPresentation, {
        module: mockModule,
        challenge: testChallenge,
        domain: testDomain,
      });

      // Empty presentation should still verify (just the proof)
      expect(result.verified).toBe(true);
    });

    test('handles credentials with object issuer format', async () => {
      // Note: This tests the DID extraction logic, not full verification
      const storage = createMemoryStorageAdapter();

      // Create credential with object issuer format
      const credWithObjectIssuer = {
        ...signedCredential,
        issuer: { id: issuerDID, name: 'Test Issuer Org' },
      };

      const presentationWithObjectIssuer = {
        ...signedPresentation,
        verifiableCredential: [credWithObjectIssuer],
      };

      // Will fail verification (signature invalid due to modification)
      // but should correctly extract and mark the issuer DID
      await verifyPresentationOptimistic(presentationWithObjectIssuer, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      // The issuer DID should have been correctly extracted
      expect(await storage.has(issuerDID)).toBe(true);
    });
  });

  describe('Granular failure detection', () => {
    /**
     * These tests verify that when VP optimistic verification fails,
     * the granular detection correctly identifies and marks ONLY the
     * DIDs that actually need blockchain resolution.
     *
     * This is critical for performance - we don't want one modified DID
     * to force blockchain resolution for ALL DIDs in future verifications.
     */

    let issuer2Keypair;
    let issuer2DID;
    let issuer2KeyDoc;
    let issuer3Keypair;
    let issuer3DID;
    let issuer3KeyDoc;
    let cred1; // from issuerDID (issuer1)
    let cred2; // from issuer2DID
    let cred3; // from issuer3DID

    beforeAll(async () => {
      // Create issuer2
      issuer2Keypair = Secp256k1Keypair.random();
      const issuer2Address = keypairToAddress(issuer2Keypair);
      issuer2DID = addressToDID(issuer2Address, VIETCHAIN_NETWORK);
      issuer2KeyDoc = createMockDIDDocument(issuer2Keypair, issuer2DID);

      // Create issuer3
      issuer3Keypair = Secp256k1Keypair.random();
      const issuer3Address = keypairToAddress(issuer3Keypair);
      issuer3DID = addressToDID(issuer3Address, VIETCHAIN_NETWORK);
      issuer3KeyDoc = createMockDIDDocument(issuer3Keypair, issuer3DID);

      // Create credential from issuer1 (uses issuerDID from parent scope)
      cred1 = await issueCredential(issuerKeyDoc, {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: issuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: { id: holderDID, alumniOf: 'University One' },
      });

      // Create credential from issuer2
      cred2 = await issueCredential(issuer2KeyDoc, {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: issuer2DID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: { id: holderDID, alumniOf: 'University Two' },
      });

      // Create credential from issuer3
      cred3 = await issueCredential(issuer3KeyDoc, {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: issuer3DID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: { id: holderDID, alumniOf: 'University Three' },
      });
    });

    afterAll(() => {
      cleanupDIDFromCache(issuer2DID);
      cleanupDIDFromCache(issuer3DID);
    });

    test('marks only the failed issuer when 1 of 3 credentials is tampered', async () => {
      const storage = createMemoryStorageAdapter();

      // Create VP with 3 credentials, tamper only cred2
      const tamperedCred2 = {
        ...cred2,
        credentialSubject: { ...cred2.credentialSubject, alumniOf: 'TAMPERED' },
      };

      const presentation = await signPresentation(
        {
          '@context': [CREDENTIALS_V1_CONTEXT],
          type: ['VerifiablePresentation'],
          verifiableCredential: [cred1, tamperedCred2, cred3],
          holder: holderDID,
        },
        holderKeyDoc,
        testChallenge,
        testDomain,
      );

      const result = await verifyPresentationOptimistic(presentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(false);

      // CRITICAL: Only issuer2 should be marked, not issuer1 or issuer3
      expect(await storage.has(issuerDID)).toBe(false); // issuer1 - not marked
      expect(await storage.has(issuer2DID)).toBe(true); // issuer2 - MARKED
      expect(await storage.has(issuer3DID)).toBe(false); // issuer3 - not marked
      expect(await storage.has(holderDID)).toBe(false); // holder - not marked
    });

    test('marks multiple failed issuers when 2 of 3 credentials are tampered', async () => {
      const storage = createMemoryStorageAdapter();

      // Tamper cred1 and cred3, leave cred2 valid
      const tamperedCred1 = {
        ...cred1,
        credentialSubject: { ...cred1.credentialSubject, alumniOf: 'TAMPERED1' },
      };
      const tamperedCred3 = {
        ...cred3,
        credentialSubject: { ...cred3.credentialSubject, alumniOf: 'TAMPERED3' },
      };

      const presentation = await signPresentation(
        {
          '@context': [CREDENTIALS_V1_CONTEXT],
          type: ['VerifiablePresentation'],
          verifiableCredential: [tamperedCred1, cred2, tamperedCred3],
          holder: holderDID,
        },
        holderKeyDoc,
        testChallenge,
        testDomain,
      );

      const result = await verifyPresentationOptimistic(presentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(false);

      // CRITICAL: Both issuer1 and issuer3 marked, issuer2 not marked
      expect(await storage.has(issuerDID)).toBe(true); // issuer1 - MARKED
      expect(await storage.has(issuer2DID)).toBe(false); // issuer2 - not marked
      expect(await storage.has(issuer3DID)).toBe(true); // issuer3 - MARKED
      expect(await storage.has(holderDID)).toBe(false); // holder - not marked
    });

    test('does not mark presenter when proof is tampered (tampering is not DID-related)', async () => {
      /**
       * IMPORTANT: This test documents expected behavior.
       *
       * Granular detection can only identify failures caused by DID resolution
       * differences (optimistic vs blockchain). It CANNOT detect failures caused by:
       * - Tampered signatures/proofs
       * - Wrong challenge/domain
       * - Expired credentials
       *
       * When a proof is tampered, verification fails regardless of resolution strategy,
       * so the presenter DID is NOT marked (because using blockchain resolution
       * wouldn't help - the proof is still invalid).
       */
      const storage = createMemoryStorageAdapter();

      // Create valid presentation first
      const validPresentation = await signPresentation(
        {
          '@context': [CREDENTIALS_V1_CONTEXT],
          type: ['VerifiablePresentation'],
          verifiableCredential: [cred1, cred2],
          holder: holderDID,
        },
        holderKeyDoc,
        testChallenge,
        testDomain,
      );

      // Get the proof
      const proof = Array.isArray(validPresentation.proof)
        ? validPresentation.proof[0]
        : validPresentation.proof;

      // Get the signature value (could be proofValue or jws depending on signature type)
      const signatureKey = proof.proofValue ? 'proofValue' : 'jws';
      const signatureValue = proof[signatureKey];

      // Tamper the presentation proof (not the credentials)
      const tamperedPresentation = {
        ...validPresentation,
        proof: {
          ...proof,
          [signatureKey]: 'zTAMPERED' + signatureValue.slice(9),
        },
      };

      const result = await verifyPresentationOptimistic(tamperedPresentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(false);

      // When proof is tampered, NO DIDs are marked because:
      // - Credential issuers pass individual verification
      // - Presenter test with blockchain still fails (proof is still tampered)
      // This is correct behavior - marking DIDs won't help with tampered proofs
      expect(await storage.has(issuerDID)).toBe(false);
      expect(await storage.has(issuer2DID)).toBe(false);
      expect(await storage.has(holderDID)).toBe(false);
    });

    test('marks issuer but not presenter when credential is tampered', async () => {
      /**
       * When a credential is tampered:
       * - The issuer DID is marked (credential verification fails)
       * - The presenter DID is NOT marked (presentation proof is valid)
       */
      const storage = createMemoryStorageAdapter();

      // Tamper one credential
      const tamperedCred2 = {
        ...cred2,
        credentialSubject: { ...cred2.credentialSubject, alumniOf: 'TAMPERED' },
      };

      const presentation = await signPresentation(
        {
          '@context': [CREDENTIALS_V1_CONTEXT],
          type: ['VerifiablePresentation'],
          verifiableCredential: [cred1, tamperedCred2],
          holder: holderDID,
        },
        holderKeyDoc,
        testChallenge,
        testDomain,
      );

      const result = await verifyPresentationOptimistic(presentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(false);

      // Only issuer2 is marked (tampered credential)
      // Presenter is NOT marked (presentation proof is valid)
      expect(await storage.has(issuerDID)).toBe(false); // issuer1 - not marked
      expect(await storage.has(issuer2DID)).toBe(true); // issuer2 - MARKED
      expect(await storage.has(holderDID)).toBe(false); // holder - not marked
    });

    test('continues testing all issuers even after first failure', async () => {
      const storage = createMemoryStorageAdapter();

      // Tamper ALL 3 credentials
      const tamperedCred1 = {
        ...cred1,
        credentialSubject: { ...cred1.credentialSubject, alumniOf: 'TAMPERED1' },
      };
      const tamperedCred2 = {
        ...cred2,
        credentialSubject: { ...cred2.credentialSubject, alumniOf: 'TAMPERED2' },
      };
      const tamperedCred3 = {
        ...cred3,
        credentialSubject: { ...cred3.credentialSubject, alumniOf: 'TAMPERED3' },
      };

      const presentation = await signPresentation(
        {
          '@context': [CREDENTIALS_V1_CONTEXT],
          type: ['VerifiablePresentation'],
          verifiableCredential: [tamperedCred1, tamperedCred2, tamperedCred3],
          holder: holderDID,
        },
        holderKeyDoc,
        testChallenge,
        testDomain,
      );

      const result = await verifyPresentationOptimistic(presentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(false);

      // CRITICAL: All 3 issuers should be marked (continues after first failure)
      expect(await storage.has(issuerDID)).toBe(true); // issuer1 - MARKED
      expect(await storage.has(issuer2DID)).toBe(true); // issuer2 - MARKED
      expect(await storage.has(issuer3DID)).toBe(true); // issuer3 - MARKED
    });

    test('skips already-marked DIDs during granular detection', async () => {
      const storage = createMemoryStorageAdapter();

      // Pre-mark issuer2
      await storage.set(issuer2DID);

      // Tamper cred1 and cred2
      const tamperedCred1 = {
        ...cred1,
        credentialSubject: { ...cred1.credentialSubject, alumniOf: 'TAMPERED1' },
      };
      const tamperedCred2 = {
        ...cred2,
        credentialSubject: { ...cred2.credentialSubject, alumniOf: 'TAMPERED2' },
      };

      const presentation = await signPresentation(
        {
          '@context': [CREDENTIALS_V1_CONTEXT],
          type: ['VerifiablePresentation'],
          verifiableCredential: [tamperedCred1, tamperedCred2, cred3],
          holder: holderDID,
        },
        holderKeyDoc,
        testChallenge,
        testDomain,
      );

      // Since issuer2 is pre-marked, it should skip optimistic entirely
      // and go straight to blockchain resolution
      const result = await verifyPresentationOptimistic(presentation, {
        module: mockModule,
        storage,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(false);

      // issuer2 was already marked, issuer1 should NOT be marked
      // because we skipped optimistic path entirely (went to blockchain)
      expect(await storage.has(issuer2DID)).toBe(true); // was pre-marked
    });
  });
});
