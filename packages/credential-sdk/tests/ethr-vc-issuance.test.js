/**
 * Unit tests for VC/VP issuance with ethr DIDs
 *
 * These tests verify that credentials and presentations can be issued
 * and verified using ethr DID identifiers without requiring network connectivity.
 */

// Mock fetch for document loader
import b58 from 'bs58';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';
import {
  issueCredential, verifyCredential, signPresentation, verifyPresentation,
} from '../src/vc';
import { Secp256k1Keypair } from '../src/keypairs';
import { addressToDID, keypairToAddress } from '../src/modules/ethr-did/utils';
import { EcdsaSecp256k1VerKeyName } from '../src/vc/crypto/constants';

// Constants to avoid duplicate string literals
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const SECURITY_V2_CONTEXT = 'https://w3id.org/security/v2';
const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1';
const VIETCHAIN_NETWORK = 'vietchain';
const TEST_ISSUANCE_DATE = '2024-01-01T00:00:00Z';
const TEST_DOMAIN = 'example.com';

/**
 * Get raw public key bytes from keypair
 * @param {Secp256k1Keypair} keypair
 * @returns {Uint8Array}
 */
// eslint-disable-next-line no-underscore-dangle
const getRawPublicKeyBytes = (keypair) => keypair._publicKey();

/**
 * Helper to create and register mock DID document in networkCache
 * @param {Secp256k1Keypair} keypair
 * @param {string} did
 * @returns {object} keyDoc for signing
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
 * @param {string} did
 */
function cleanupDIDFromCache(did) {
  // Find and delete all keys that start with this DID
  Object.keys(networkCache).forEach((key) => {
    if (key === did || key.startsWith(`${did}#`)) {
      delete networkCache[key];
    }
  });
}

/**
 * Helper to add a delegate to an existing DID document in networkCache
 * Creates a fresh copy to avoid mutation side effects
 * @param {string} controllerDID - The DID that controls the delegate
 * @param {Secp256k1Keypair} delegateKeypair - The delegate's keypair
 * @param {string} delegateKeyId - The key ID for the delegate (e.g., 'did:ethr:...#delegate-1')
 * @returns {object} delegateKeyDoc for signing
 */
function addDelegateToCache(controllerDID, delegateKeypair, delegateKeyId) {
  const delegatePublicKeyBytes = getRawPublicKeyBytes(delegateKeypair);
  const delegatePublicKeyBase58 = b58.encode(delegatePublicKeyBytes);

  const delegateKeyDoc = {
    id: delegateKeyId,
    controller: controllerDID,
    type: EcdsaSecp256k1VerKeyName,
    publicKey: delegateKeypair.publicKey(),
    keypair: delegateKeypair,
  };

  // Register delegate verification method
  networkCache[delegateKeyId] = {
    '@context': SECURITY_V2_CONTEXT,
    id: delegateKeyId,
    type: EcdsaSecp256k1VerKeyName,
    controller: controllerDID,
    publicKeyBase58: delegatePublicKeyBase58,
  };

  // Get existing DID document and create a fresh copy with delegate added
  const existingDoc = networkCache[controllerDID];
  if (existingDoc) {
    networkCache[controllerDID] = {
      ...existingDoc,
      verificationMethod: [
        ...existingDoc.verificationMethod,
        {
          id: delegateKeyId,
          type: EcdsaSecp256k1VerKeyName,
          controller: controllerDID,
          publicKeyBase58: delegatePublicKeyBase58,
        },
      ],
      assertionMethod: [...existingDoc.assertionMethod, delegateKeyId],
      authentication: [...existingDoc.authentication, delegateKeyId],
    };
  }

  return delegateKeyDoc;
}

mockFetch();

describe('Ethr DID VC Issuance', () => {
  let issuerKeypair;
  let issuerDID;
  let issuerKeyDoc;
  let holderKeypair;
  let holderDID;
  let holderKeyDoc;

  beforeAll(() => {
    // Create issuer identity
    issuerKeypair = new Secp256k1Keypair(
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    );
    const issuerAddress = keypairToAddress(issuerKeypair);
    issuerDID = addressToDID(issuerAddress, VIETCHAIN_NETWORK);

    // Create issuer key document for signing
    const issuerPublicKey = issuerKeypair.publicKey();
    // Use getRawPublicKeyBytes to get raw bytes (publicKey() wraps it in PublicKeySecp256k1)
    const issuerPublicKeyBytes = getRawPublicKeyBytes(issuerKeypair);
    const issuerPublicKeyBase58 = b58.encode(issuerPublicKeyBytes);

    issuerKeyDoc = {
      id: `${issuerDID}#keys-1`,
      controller: issuerDID,
      type: EcdsaSecp256k1VerKeyName,
      publicKey: issuerPublicKey,
      keypair: issuerKeypair,
    };

    // Mock DID document resolution for issuer
    networkCache[issuerKeyDoc.id] = {
      '@context': SECURITY_V2_CONTEXT,
      id: issuerKeyDoc.id,
      type: EcdsaSecp256k1VerKeyName,
      controller: issuerDID,
      publicKeyBase58: issuerPublicKeyBase58,
    };
    networkCache[issuerDID] = {
      '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
      id: issuerDID,
      verificationMethod: [
        {
          id: issuerKeyDoc.id,
          type: EcdsaSecp256k1VerKeyName,
          controller: issuerDID,
          publicKeyBase58: issuerPublicKeyBase58,
        },
      ],
      assertionMethod: [issuerKeyDoc.id],
      authentication: [issuerKeyDoc.id],
    };

    // Create holder identity
    holderKeypair = new Secp256k1Keypair(
      'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
    );
    const holderAddress = keypairToAddress(holderKeypair);
    holderDID = addressToDID(holderAddress, VIETCHAIN_NETWORK);

    // Create holder key document for signing
    const holderPublicKey = holderKeypair.publicKey();
    const holderPublicKeyBytes = getRawPublicKeyBytes(holderKeypair);
    const holderPublicKeyBase58 = b58.encode(holderPublicKeyBytes);

    holderKeyDoc = {
      id: `${holderDID}#keys-1`,
      controller: holderDID,
      type: EcdsaSecp256k1VerKeyName,
      publicKey: holderPublicKey,
      keypair: holderKeypair,
    };

    // Mock DID document resolution for holder
    networkCache[holderKeyDoc.id] = {
      '@context': SECURITY_V2_CONTEXT,
      id: holderKeyDoc.id,
      type: EcdsaSecp256k1VerKeyName,
      controller: holderDID,
      publicKeyBase58: holderPublicKeyBase58,
    };
    networkCache[holderDID] = {
      '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
      id: holderDID,
      verificationMethod: [
        {
          id: holderKeyDoc.id,
          type: EcdsaSecp256k1VerKeyName,
          controller: holderDID,
          publicKeyBase58: holderPublicKeyBase58,
        },
      ],
      assertionMethod: [holderKeyDoc.id],
      authentication: [holderKeyDoc.id],
    };
  });

  describe('Credential Issuance', () => {
    test('should issue a credential with ethr DID as issuer', async () => {
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
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
      expect(signedVC.proof.type).toBe('EcdsaSecp256k1Signature2019');
      expect(signedVC.proof.verificationMethod).toBe(issuerKeyDoc.id);
      expect(signedVC.proof.proofPurpose).toBe('assertionMethod');
    }, 30000);

    test('should issue credential with ethr DID on mainnet', async () => {
      const mainnetKeypair = Secp256k1Keypair.random();
      const mainnetAddress = keypairToAddress(mainnetKeypair);
      const mainnetDID = addressToDID(mainnetAddress); // No network = mainnet

      // Register mock DID document for verification
      const keyDoc = createMockDIDDocument(mainnetKeypair, mainnetDID);

      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential'],
        issuer: mainnetDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:student123',
          alumniOf: 'Example University', // Use field from examples context
        },
      };

      const signedVC = await issueCredential(keyDoc, unsignedCredential);

      expect(signedVC.issuer).toBe(mainnetDID);
      expect(signedVC.issuer).toMatch(/^did:ethr:0x[0-9a-fA-F]{40}$/); // Mainnet format
      expect(signedVC.issuer).not.toContain('vietchain');
      expect(signedVC.proof).toBeDefined();

      // Verify the credential can be verified
      const result = await verifyCredential(signedVC);
      expect(result.verified).toBe(true);

      // Cleanup
      cleanupDIDFromCache(mainnetDID);
    }, 30000);

    test('should issue credential with ethr DID on different networks', async () => {
      const networks = ['sepolia', 'polygon', 'arbitrum'];
      const createdDIDs = [];

      for (const network of networks) {
        const keypair = Secp256k1Keypair.random();
        const address = keypairToAddress(keypair);
        const did = addressToDID(address, network);
        createdDIDs.push(did);

        // Register mock DID document for verification
        const keyDoc = createMockDIDDocument(keypair, did);

        const unsignedCredential = {
          '@context': [
            CREDENTIALS_V1_CONTEXT,
            CREDENTIALS_EXAMPLES_CONTEXT,
          ],
          type: ['VerifiableCredential'],
          issuer: did,
          issuanceDate: new Date().toISOString(),
          credentialSubject: {
            id: 'did:example:student123',
            alumniOf: `University on ${network}`, // Use supported field
          },
        };

        // eslint-disable-next-line no-await-in-loop
        const signedVC = await issueCredential(keyDoc, unsignedCredential);

        expect(signedVC.issuer).toBe(did);
        expect(signedVC.issuer).toContain(network);
        expect(signedVC.proof).toBeDefined();

        // Verify the credential can be verified
        // eslint-disable-next-line no-await-in-loop
        const result = await verifyCredential(signedVC);
        expect(result.verified).toBe(true);
      }

      // Cleanup all created DIDs
      createdDIDs.forEach((did) => cleanupDIDFromCache(did));
    }, 30000);
  });

  describe('Credential Verification', () => {
    let signedCredential;

    beforeAll(async () => {
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
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

    test('should verify credential signed with ethr DID', async () => {
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
          alumniOf: 'Fake University', // Tampered data
        },
      };

      const result = await verifyCredential(tamperedCredential);

      expect(result.verified).toBe(false);
    }, 30000);
  });

  describe('Presentation Issuance', () => {
    let verifiableCredential;

    beforeAll(async () => {
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: issuerDID,
        issuanceDate: TEST_ISSUANCE_DATE,
        credentialSubject: {
          id: holderDID,
          degree: {
            type: 'BachelorDegree',
            name: 'Bachelor of Computer Science',
          },
        },
      };

      verifiableCredential = await issueCredential(issuerKeyDoc, unsignedCredential);
    });

    test('should create presentation with ethr DID as holder', async () => {
      const unsignedPresentation = {
        '@context': [CREDENTIALS_V1_CONTEXT],
        type: ['VerifiablePresentation'],
        verifiableCredential: [verifiableCredential],
        holder: holderDID,
      };

      const signedVP = await signPresentation(
        unsignedPresentation,
        holderKeyDoc,
        'some-challenge-123',
        TEST_DOMAIN,
      );

      expect(signedVP).toBeDefined();
      expect(signedVP.holder).toBe(holderDID);
      expect(signedVP.verifiableCredential).toHaveLength(1);
      expect(signedVP.proof).toBeDefined();
      expect(signedVP.proof.type).toBe('EcdsaSecp256k1Signature2019');
      expect(signedVP.proof.verificationMethod).toBe(holderKeyDoc.id);
      expect(signedVP.proof.proofPurpose).toBe('authentication');
      expect(signedVP.proof.challenge).toBe('some-challenge-123');
      expect(signedVP.proof.domain).toBe(TEST_DOMAIN);
    }, 30000);

    test('should verify presentation signed with ethr DID', async () => {
      const unsignedPresentation = {
        '@context': [CREDENTIALS_V1_CONTEXT],
        type: ['VerifiablePresentation'],
        verifiableCredential: [verifiableCredential],
        holder: holderDID,
      };

      const signedVP = await signPresentation(
        unsignedPresentation,
        holderKeyDoc,
        'challenge-456',
        'verifier.example.com',
      );

      const result = await verifyPresentation(signedVP, {
        challenge: 'challenge-456',
        domain: 'verifier.example.com',
      });

      expect(result.verified).toBe(true);
      expect(result.presentationResult.verified).toBe(true);
    }, 30000);

    test('should fail verification with wrong challenge', async () => {
      const unsignedPresentation = {
        '@context': [CREDENTIALS_V1_CONTEXT],
        type: ['VerifiablePresentation'],
        verifiableCredential: [verifiableCredential],
        holder: holderDID,
      };

      const signedVP = await signPresentation(
        unsignedPresentation,
        holderKeyDoc,
        'correct-challenge',
        TEST_DOMAIN,
      );

      const result = await verifyPresentation(signedVP, {
        challenge: 'wrong-challenge', // Wrong challenge
        domain: TEST_DOMAIN,
      });

      expect(result.verified).toBe(false);
    }, 30000);
  });

  describe('Multiple Credentials in Presentation', () => {
    test('should create presentation with multiple credentials from ethr DID issuer', async () => {
      // Issue multiple credentials
      const credential1 = await issueCredential(issuerKeyDoc, {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential', 'AlumniCredential'],
        issuer: issuerDID,
        issuanceDate: TEST_ISSUANCE_DATE,
        credentialSubject: {
          id: holderDID,
          alumniOf: 'JavaScript University',
        },
      });

      const credential2 = await issueCredential(issuerKeyDoc, {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential', 'AlumniCredential'],
        issuer: issuerDID,
        issuanceDate: TEST_ISSUANCE_DATE,
        credentialSubject: {
          id: holderDID,
          alumniOf: 'Rust University',
        },
      });

      const unsignedPresentation = {
        '@context': [CREDENTIALS_V1_CONTEXT],
        type: ['VerifiablePresentation'],
        verifiableCredential: [credential1, credential2],
        holder: holderDID,
      };

      const signedVP = await signPresentation(
        unsignedPresentation,
        holderKeyDoc,
        'multi-cred-challenge',
        TEST_DOMAIN,
      );

      expect(signedVP.verifiableCredential).toHaveLength(2);
      expect(signedVP.verifiableCredential[0].credentialSubject.alumniOf).toBe('JavaScript University');
      expect(signedVP.verifiableCredential[1].credentialSubject.alumniOf).toBe('Rust University');
      expect(signedVP.proof).toBeDefined();

      const result = await verifyPresentation(signedVP, {
        challenge: 'multi-cred-challenge',
        domain: TEST_DOMAIN,
      });

      expect(result.verified).toBe(true);
    }, 30000);
  });

  describe('Issuing with Delegate Keys', () => {
    test('should issue credential with delegate key', async () => {
      // Create a fresh issuer for this test
      const delegateTestIssuerKeypair = new Secp256k1Keypair(
        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      );
      const delegateTestIssuerAddress = keypairToAddress(delegateTestIssuerKeypair);
      const delegateTestIssuerDID = addressToDID(delegateTestIssuerAddress, VIETCHAIN_NETWORK);

      // Create issuer DID document using helper
      createMockDIDDocument(delegateTestIssuerKeypair, delegateTestIssuerDID);

      // Create and add delegate using helper (creates fresh copy, no mutation)
      const delegateKeypair = new Secp256k1Keypair(
        'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
      );
      const delegateKeyId = `${delegateTestIssuerDID}#delegate-keys-1`;
      const delegateKeyDoc = addDelegateToCache(delegateTestIssuerDID, delegateKeypair, delegateKeyId);

      // Issue credential using the delegate key
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential', 'AlumniCredential'],
        issuer: delegateTestIssuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDID,
          alumniOf: 'Delegate University',
        },
      };

      const signedVC = await issueCredential(delegateKeyDoc, unsignedCredential);

      expect(signedVC).toBeDefined();
      expect(signedVC.issuer).toBe(delegateTestIssuerDID);
      expect(signedVC.proof).toBeDefined();
      expect(signedVC.proof.type).toBe('EcdsaSecp256k1Signature2019');
      expect(signedVC.proof.verificationMethod).toBe(delegateKeyDoc.id);

      // Verify the credential
      const result = await verifyCredential(signedVC);
      expect(result.verified).toBe(true);

      // Cleanup
      cleanupDIDFromCache(delegateTestIssuerDID);
    }, 30000);

    test('should issue credential with multiple delegates', async () => {
      // Create a fresh issuer for this test
      const multiDelegateIssuerKeypair = new Secp256k1Keypair(
        'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      );
      const multiDelegateIssuerAddress = keypairToAddress(multiDelegateIssuerKeypair);
      const multiDelegateIssuerDID = addressToDID(multiDelegateIssuerAddress, VIETCHAIN_NETWORK);

      // Create issuer DID document using helper
      createMockDIDDocument(multiDelegateIssuerKeypair, multiDelegateIssuerDID);

      // Create and add delegates using helper (creates fresh copies, no mutation)
      const delegate1Keypair = new Secp256k1Keypair(
        '1111111111111111111111111111111111111111111111111111111111111111',
      );
      const delegate2Keypair = new Secp256k1Keypair(
        '2222222222222222222222222222222222222222222222222222222222222222',
      );

      const delegate1KeyDoc = addDelegateToCache(
        multiDelegateIssuerDID,
        delegate1Keypair,
        `${multiDelegateIssuerDID}#delegate1`,
      );
      const delegate2KeyDoc = addDelegateToCache(
        multiDelegateIssuerDID,
        delegate2Keypair,
        `${multiDelegateIssuerDID}#delegate2`,
      );

      // Issue credentials with different delegates
      const cred1 = await issueCredential(delegate1KeyDoc, {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential'],
        issuer: multiDelegateIssuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDID,
          alumniOf: 'University A',
        },
      });

      const cred2 = await issueCredential(delegate2KeyDoc, {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential'],
        issuer: multiDelegateIssuerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDID,
          alumniOf: 'University B',
        },
      });

      // Both should be issued by the same DID but signed with different keys
      expect(cred1.issuer).toBe(multiDelegateIssuerDID);
      expect(cred2.issuer).toBe(multiDelegateIssuerDID);
      expect(cred1.proof.verificationMethod).toBe(delegate1KeyDoc.id);
      expect(cred2.proof.verificationMethod).toBe(delegate2KeyDoc.id);
      expect(cred1.proof.verificationMethod).not.toBe(cred2.proof.verificationMethod);

      // Both should verify successfully
      const result1 = await verifyCredential(cred1);
      const result2 = await verifyCredential(cred2);
      expect(result1.verified).toBe(true);
      expect(result2.verified).toBe(true);

      // Cleanup
      cleanupDIDFromCache(multiDelegateIssuerDID);
    }, 30000);
  });

  describe('Key Rotation and Ownership Transfer', () => {
    test('should issue credential after complete ownership transfer to new private key', async () => {
      // Create a completely fresh DID for this test to avoid caching issues
      // This simulates the state AFTER an ownership transfer has occurred
      const transferTestKeypair = new Secp256k1Keypair(
        'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
      );
      const transferTestAddress = keypairToAddress(transferTestKeypair);
      const transferTestDID = addressToDID(transferTestAddress, VIETCHAIN_NETWORK);
      const transferTestPublicKeyBytes = getRawPublicKeyBytes(transferTestKeypair);
      const transferTestPublicKeyBase58 = b58.encode(transferTestPublicKeyBytes);

      const newOwnerKeyDoc = {
        id: `${transferTestDID}#keys-new-owner`,
        controller: transferTestDID,
        type: EcdsaSecp256k1VerKeyName,
        publicKey: transferTestKeypair.publicKey(),
        keypair: transferTestKeypair,
      };

      // Mock DID document with new owner (after transfer)
      // Old owner's key is NOT in this document
      networkCache[newOwnerKeyDoc.id] = {
        '@context': SECURITY_V2_CONTEXT,
        id: newOwnerKeyDoc.id,
        type: EcdsaSecp256k1VerKeyName,
        controller: transferTestDID,
        publicKeyBase58: transferTestPublicKeyBase58,
      };
      networkCache[transferTestDID] = {
        '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
        id: transferTestDID,
        verificationMethod: [
          {
            id: newOwnerKeyDoc.id,
            type: EcdsaSecp256k1VerKeyName,
            controller: transferTestDID,
            publicKeyBase58: transferTestPublicKeyBase58,
          },
        ],
        assertionMethod: [newOwnerKeyDoc.id],
        authentication: [newOwnerKeyDoc.id],
      };

      // Issue credential with new owner's key (after ownership transfer)
      const credentialAfterTransfer = await issueCredential(newOwnerKeyDoc, {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: transferTestDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDID,
          degree: {
            type: 'DoctorateDegree',
            name: 'PhD in Computer Science',
          },
        },
      });

      expect(credentialAfterTransfer.issuer).toBe(transferTestDID);
      expect(credentialAfterTransfer.proof.verificationMethod).toBe(newOwnerKeyDoc.id);

      // Verify credential signed with new owner works
      const resultAfter = await verifyCredential(credentialAfterTransfer);
      if (!resultAfter.verified) {
        console.log('New owner verification failed:', JSON.stringify(resultAfter.error, null, 2));
      }
      expect(resultAfter.verified).toBe(true);

      // Test that a different keypair (simulating old owner) cannot be used
      const oldOwnerKeypair = new Secp256k1Keypair(
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      );
      const oldOwnerKeyDoc = {
        id: `${transferTestDID}#keys-old-owner`,
        controller: transferTestDID,
        type: EcdsaSecp256k1VerKeyName,
        publicKey: oldOwnerKeypair.publicKey(),
        keypair: oldOwnerKeypair,
      };

      // Issue credential with old owner's key (not in DID document)
      const credentialWithOldKey = await issueCredential(oldOwnerKeyDoc, {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential', 'AlumniCredential'],
        issuer: transferTestDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDID,
          alumniOf: 'Old Owner University',
        },
      });

      // Verification should fail because old key is not in DID document
      const resultOldKey = await verifyCredential(credentialWithOldKey);
      expect(resultOldKey.verified).toBe(false);
      expect(resultOldKey.error).toBeDefined();

      // Cleanup
      cleanupDIDFromCache(transferTestDID);
    }, 30000);

    test('should fail to sign with old owner key after ownership transfer', async () => {
      // Create initial owner
      const oldOwnerKeypair = new Secp256k1Keypair(
        '9999999999999999999999999999999999999999999999999999999999999999',
      );
      const oldOwnerAddress = keypairToAddress(oldOwnerKeypair);
      const rotationDID = addressToDID(oldOwnerAddress, VIETCHAIN_NETWORK);

      const oldOwnerKeyDoc = {
        id: `${rotationDID}#keys-1`,
        controller: rotationDID,
        type: EcdsaSecp256k1VerKeyName,
        publicKey: oldOwnerKeypair.publicKey(),
        keypair: oldOwnerKeypair,
      };

      // Create new owner
      const newOwnerKeypair = new Secp256k1Keypair(
        '8888888888888888888888888888888888888888888888888888888888888888',
      );
      const newOwnerPublicKeyBytes = getRawPublicKeyBytes(newOwnerKeypair);
      const newOwnerPublicKeyBase58 = b58.encode(newOwnerPublicKeyBytes);

      const newOwnerKeyDoc = {
        id: `${rotationDID}#keys-2`,
        controller: rotationDID,
        type: EcdsaSecp256k1VerKeyName,
        publicKey: newOwnerKeypair.publicKey(),
        keypair: newOwnerKeypair,
      };

      // Mock DID document with ONLY new owner (simulating ownership transfer)
      networkCache[newOwnerKeyDoc.id] = {
        '@context': SECURITY_V2_CONTEXT,
        id: newOwnerKeyDoc.id,
        type: EcdsaSecp256k1VerKeyName,
        controller: rotationDID,
        publicKeyBase58: newOwnerPublicKeyBase58,
      };
      networkCache[rotationDID] = {
        '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
        id: rotationDID,
        verificationMethod: [
          {
            id: newOwnerKeyDoc.id,
            type: EcdsaSecp256k1VerKeyName,
            controller: rotationDID,
            publicKeyBase58: newOwnerPublicKeyBase58,
          },
        ],
        assertionMethod: [newOwnerKeyDoc.id],
        authentication: [newOwnerKeyDoc.id],
      };

      // Try to issue credential with old owner's key (should create credential but fail verification)
      const signedVC = await issueCredential(oldOwnerKeyDoc, {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
        ],
        type: ['VerifiableCredential', 'AlumniCredential'],
        issuer: rotationDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDID,
          alumniOf: 'Invalid University',
        },
      });

      // Credential is created, but verification should fail
      expect(signedVC).toBeDefined();
      expect(signedVC.proof.verificationMethod).toBe(oldOwnerKeyDoc.id);

      // Verification should fail because old key is not in DID document
      const result = await verifyCredential(signedVC);
      expect(result.verified).toBe(false);
      // The error should indicate that the verification method is not found
      expect(result.error).toBeDefined();

      // Cleanup
      cleanupDIDFromCache(rotationDID);
    }, 30000);
  });

  describe('Ethr DID Format Validation', () => {
    test('should work with checksummed addresses in DIDs', () => {
      const keypair = Secp256k1Keypair.random();
      const address = keypairToAddress(keypair);
      const did = addressToDID(address, VIETCHAIN_NETWORK);

      // Address should be checksummed (mixed case)
      expect(did).toMatch(/did:ethr:vietchain:0x[0-9a-fA-F]{40}/);

      // Extract address part
      const addressPart = did.split(':')[3];
      expect(addressPart).toBe(address); // Should match checksummed address
    });

    test('should handle mainnet DIDs without network prefix', () => {
      const keypair = Secp256k1Keypair.random();
      const address = keypairToAddress(keypair);
      const did = addressToDID(address); // No network = mainnet

      expect(did).toMatch(/^did:ethr:0x[0-9a-fA-F]{40}$/);
      expect(did).not.toContain('mainnet');
    });
  });
});
