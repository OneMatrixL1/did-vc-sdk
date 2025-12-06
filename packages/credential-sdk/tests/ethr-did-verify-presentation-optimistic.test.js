/**
 * Unit tests for verifyPresentationOptimistic()
 *
 * Tests the optimistic verification helper for verifiable presentations that
 * tries optimistic resolution first, then falls back to blockchain if needed.
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

    test('verifies valid presentation', async () => {
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
      const result = await verifyPresentationOptimistic(multiCredPresentation, {
        module: mockModule,
        challenge: testChallenge,
        domain: testDomain,
      });

      expect(result.verified).toBe(true);
    });

    test('handles self-issued credential', async () => {
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

      const result = await verifyPresentationOptimistic(selfIssuedPresentation, {
        module: mockModule,
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
  });
});
