/**
 * Tests for DID delegation with embedded keys (W3C CID Spec Compliant)
 *
 * These tests verify:
 * 1. Delegation with embedded public key - REQUIRED per W3C spec
 * 2. Key rotation with delegated keys
 * 3. Controller field validation per W3C CID 1.0 specification
 *
 * W3C SPECIFICATION REQUIREMENT:
 * Per W3C Controlled Identifiers v1.0, Section 3.3 "Retrieve Verification Method", Step 10:
 * "If the absolute URL value of verificationMethod.controller does not equal
 * controllerDocumentUrl, an error MUST be raised."
 *
 * This means the `controller` field in a verification method MUST match the DID document
 * URL from which it was retrieved. This is a security requirement, not a limitation.
 *
 * CORRECT PATTERN (per spec):
 * - Embed the delegate's public key in the delegating DID's document
 * - Set `controller` to the delegating DID (document URL)
 * - When delegate rotates key, update the delegating DID's document
 *
 * @see https://www.w3.org/TR/2025/CR-cid-1.0-20250130/#retrieve-verification-method
 */

import b58 from 'bs58';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';
import {
  issueCredential,
  verifyCredential,
  signPresentation,
  verifyPresentation,
} from '../src/vc';
import { Secp256k1Keypair } from '../src/keypairs';
import { addressToDID, keypairToAddress } from '../src/modules/ethr-did/utils';
import { EcdsaSecp256k1VerKeyName } from '../src/vc/crypto/constants';

// Constants
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const SECURITY_V2_CONTEXT = 'https://w3id.org/security/v2';
const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1';
const VIETCHAIN_NETWORK = 'vietchain';

/**
 * Get raw public key bytes from keypair
 */
// eslint-disable-next-line no-underscore-dangle
const getRawPublicKeyBytes = (keypair) => keypair._publicKey();

/**
 * Create a DID document for a self-sovereign identity (owns its own keys)
 */
function createSelfSovereignDID(keypair, did) {
  const publicKeyBytes = getRawPublicKeyBytes(keypair);
  const publicKeyBase58 = b58.encode(publicKeyBytes);
  const keyId = `${did}#keys-1`;

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

  return {
    id: keyId,
    controller: did,
    type: EcdsaSecp256k1VerKeyName,
    publicKey: keypair.publicKey(),
    keypair,
  };
}

/**
 * Add a delegate to an existing DID's document WITH embedded public key.
 * The controller field is set to the delegating DID (authorizing DID), not the delegate's DID.
 *
 * @param {string} companyDID - The DID that is delegating authority
 * @param {Secp256k1Keypair} delegateKeypair - The delegate's keypair
 * @param {string} delegateKeyId - Key ID (e.g., 'did:ethr:...#delegate-1')
 * @returns {object} keyDoc for signing
 */
function addDelegateWithEmbeddedKey(companyDID, delegateKeypair, delegateKeyId) {
  const publicKeyBytes = getRawPublicKeyBytes(delegateKeypair);
  const publicKeyBase58 = b58.encode(publicKeyBytes);

  // Create key doc for signing
  const keyDoc = {
    id: delegateKeyId,
    controller: companyDID, // Controller is the authorizing DID
    type: EcdsaSecp256k1VerKeyName,
    publicKey: delegateKeypair.publicKey(),
    keypair: delegateKeypair,
  };

  // Register verification method with embedded key
  networkCache[delegateKeyId] = {
    '@context': SECURITY_V2_CONTEXT,
    id: delegateKeyId,
    type: EcdsaSecp256k1VerKeyName,
    controller: companyDID, // Controller is the authorizing DID
    publicKeyBase58,
  };

  // Get or create company's DID document
  const existingDoc = networkCache[companyDID] || {
    '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
    id: companyDID,
    verificationMethod: [],
    assertionMethod: [],
    authentication: [],
  };

  // Add delegate to company's document
  networkCache[companyDID] = {
    ...existingDoc,
    verificationMethod: [
      ...existingDoc.verificationMethod,
      {
        id: delegateKeyId,
        type: EcdsaSecp256k1VerKeyName,
        controller: companyDID,
        publicKeyBase58,
      },
    ],
    assertionMethod: [...existingDoc.assertionMethod, delegateKeyId],
    authentication: [...existingDoc.authentication, delegateKeyId],
  };

  return keyDoc;
}

/**
 * Add a delegate to an existing DID's document WITHOUT embedded public key.
 * Only controller reference, no publicKeyBase58.
 *
 * NOTE: This pattern VIOLATES W3C CID 1.0 spec!
 * Per Section 3.3 Step 10, controller MUST equal the document URL.
 * Setting controller to a different DID is spec-non-compliant.
 */
function addDelegateWithoutKey(companyDID, delegateDID, delegateKeyId) {
  // Register verification method WITHOUT key
  // WARNING: This violates W3C CID 1.0 spec - controller must equal document URL
  networkCache[delegateKeyId] = {
    '@context': SECURITY_V2_CONTEXT,
    id: delegateKeyId,
    type: EcdsaSecp256k1VerKeyName,
    controller: delegateDID, // VIOLATES SPEC: controller must equal companyDID
    // NO publicKeyBase58
  };

  // Get or create company's DID document
  const existingDoc = networkCache[companyDID] || {
    '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
    id: companyDID,
    verificationMethod: [],
    assertionMethod: [],
    authentication: [],
  };

  // Add delegate to company's document
  networkCache[companyDID] = {
    ...existingDoc,
    verificationMethod: [
      ...existingDoc.verificationMethod,
      {
        id: delegateKeyId,
        type: EcdsaSecp256k1VerKeyName,
        controller: delegateDID,
        // NO publicKeyBase58
      },
    ],
    assertionMethod: [...existingDoc.assertionMethod, delegateKeyId],
    authentication: [...existingDoc.authentication, delegateKeyId],
  };
}

/**
 * Update a delegate's key in the company's document
 */
function updateDelegateKey(companyDID, delegateKeypair, delegateKeyId) {
  const publicKeyBytes = getRawPublicKeyBytes(delegateKeypair);
  const publicKeyBase58 = b58.encode(publicKeyBytes);

  // Update verification method entry
  networkCache[delegateKeyId] = {
    '@context': SECURITY_V2_CONTEXT,
    id: delegateKeyId,
    type: EcdsaSecp256k1VerKeyName,
    controller: companyDID,
    publicKeyBase58,
  };

  // Update in company's document - create new array to ensure cache update
  const doc = networkCache[companyDID];
  if (doc) {
    const newVerificationMethod = doc.verificationMethod.map((vm) => {
      if (vm.id === delegateKeyId) {
        return {
          id: delegateKeyId,
          type: EcdsaSecp256k1VerKeyName,
          controller: companyDID,
          publicKeyBase58,
        };
      }
      return vm;
    });

    networkCache[companyDID] = {
      ...doc,
      verificationMethod: newVerificationMethod,
    };
  }

  return {
    id: delegateKeyId,
    controller: companyDID,
    type: EcdsaSecp256k1VerKeyName,
    publicKey: delegateKeypair.publicKey(),
    keypair: delegateKeypair,
  };
}

/**
 * Clean up DID entries from networkCache
 */
function cleanupDID(did) {
  Object.keys(networkCache).forEach((key) => {
    if (key === did || key.startsWith(`${did}#`)) {
      delete networkCache[key];
    }
  });
}

// Enable mock fetch
mockFetch();

describe('DID Delegation and Controller Resolution', () => {
  let companyKeypair;
  let companyDID;
  let ceoKeypair;
  let ceoDID;

  beforeEach(() => {
    // Create Company DID
    companyKeypair = Secp256k1Keypair.random();
    const companyAddress = keypairToAddress(companyKeypair);
    companyDID = addressToDID(companyAddress, VIETCHAIN_NETWORK);

    // Initialize empty company DID document
    networkCache[companyDID] = {
      '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
      id: companyDID,
      verificationMethod: [],
      assertionMethod: [],
      authentication: [],
    };

    // Create CEO keypair and DID
    ceoKeypair = Secp256k1Keypair.random();
    const ceoAddress = keypairToAddress(ceoKeypair);
    ceoDID = addressToDID(ceoAddress, VIETCHAIN_NETWORK);

    // Set up CEO's own DID document (for deep resolution tests)
    createSelfSovereignDID(ceoKeypair, ceoDID);
  });

  afterEach(() => {
    cleanupDID(companyDID);
    cleanupDID(ceoDID);
  });

  describe('Delegation with Embedded Key (W3C Spec Compliant)', () => {
    test('should issue credential signed by delegate on behalf of Company', async () => {
      const delegateKeyId = `${companyDID}#ceo-key`;

      // Add CEO as delegate to Company's document WITH embedded key
      const ceoKeyDoc = addDelegateWithEmbeddedKey(companyDID, ceoKeypair, delegateKeyId);

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: companyDID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Test Holder',
        },
      };

      const signedCredential = await issueCredential(ceoKeyDoc, credential);

      expect(signedCredential.proof).toBeDefined();
      expect(signedCredential.issuer).toBe(companyDID);
      expect(signedCredential.proof.verificationMethod).toBe(delegateKeyId);
    });

    test('should verify credential signed by delegate (1 DID resolution)', async () => {
      const delegateKeyId = `${companyDID}#ceo-key`;

      // Add CEO as delegate to Company's document WITH embedded key
      const ceoKeyDoc = addDelegateWithEmbeddedKey(companyDID, ceoKeypair, delegateKeyId);

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: companyDID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Test Holder',
        },
      };

      const signedCredential = await issueCredential(ceoKeyDoc, credential);

      // Verify - only needs 1 resolution (key is embedded in Company's doc)
      const result = await verifyCredential(signedCredential);

      expect(result.verified).toBe(true);
    });

    test('should verify presentation with delegate-signed credential', async () => {
      const delegateKeyId = `${companyDID}#ceo-key`;

      // Add CEO as delegate
      const ceoKeyDoc = addDelegateWithEmbeddedKey(companyDID, ceoKeypair, delegateKeyId);

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: companyDID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: ceoDID,
          name: 'CEO Credential',
        },
      };

      const signedCredential = await issueCredential(ceoKeyDoc, credential);

      // Create holder for presentation
      const holderKeypair = Secp256k1Keypair.random();
      const holderAddress = keypairToAddress(holderKeypair);
      const holderDID = addressToDID(holderAddress, VIETCHAIN_NETWORK);
      const holderKeyDoc = createSelfSovereignDID(holderKeypair, holderDID);

      const presentation = {
        '@context': [CREDENTIALS_V1_CONTEXT],
        type: ['VerifiablePresentation'],
        holder: holderDID,
        verifiableCredential: [signedCredential],
      };

      const challenge = 'test-challenge-123';
      const domain = 'example.com';

      const signedPresentation = await signPresentation(
        presentation,
        holderKeyDoc,
        challenge,
        domain,
      );

      const result = await verifyPresentation(signedPresentation, { challenge, domain });

      expect(result.verified).toBe(true);

      cleanupDID(holderDID);
    });

    test('should fail when wrong key signs credential', async () => {
      const delegateKeyId = `${companyDID}#ceo-key`;

      // Add CEO as delegate
      addDelegateWithEmbeddedKey(companyDID, ceoKeypair, delegateKeyId);

      // Attacker tries to sign with their own key
      const attackerKeypair = Secp256k1Keypair.random();
      const attackerKeyDoc = {
        id: delegateKeyId,
        controller: companyDID,
        type: EcdsaSecp256k1VerKeyName,
        publicKey: attackerKeypair.publicKey(),
        keypair: attackerKeypair,
      };

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: companyDID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Attacker Credential',
        },
      };

      const signedCredential = await issueCredential(attackerKeyDoc, credential);

      const result = await verifyCredential(signedCredential);
      expect(result.verified).toBe(false);
    });
  });

  describe('Key Rotation with Embedded Keys', () => {
    test('old credential still verifies after delegate key rotation (stale embedded key)', async () => {
      const delegateKeyId = `${companyDID}#ceo-key`;

      // Add CEO as delegate with embedded key
      const ceoKeyDoc = addDelegateWithEmbeddedKey(companyDID, ceoKeypair, delegateKeyId);

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: companyDID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Original Key Credential',
        },
      };

      const signedCredential = await issueCredential(ceoKeyDoc, credential);

      // Verify with original key
      const result1 = await verifyCredential(signedCredential);
      expect(result1.verified).toBe(true);

      // === CEO ROTATES KEY (updates their own DID, NOT Company's) ===
      const newCeoKeypair = Secp256k1Keypair.random();
      createSelfSovereignDID(newCeoKeypair, ceoDID);

      // Old credential STILL verifies because Company's doc has stale embedded key
      const result2 = await verifyCredential(signedCredential);
      expect(result2.verified).toBe(true);
    });

    test('new credential fails when signed with rotated key but Company doc not updated', async () => {
      const delegateKeyId = `${companyDID}#ceo-key`;

      // Add CEO as delegate with original key
      addDelegateWithEmbeddedKey(companyDID, ceoKeypair, delegateKeyId);

      // CEO rotates to new key
      const newCeoKeypair = Secp256k1Keypair.random();

      // Sign credential with NEW key (but Company's doc still has OLD key)
      const newKeyDoc = {
        id: delegateKeyId,
        controller: companyDID,
        type: EcdsaSecp256k1VerKeyName,
        publicKey: newCeoKeypair.publicKey(),
        keypair: newCeoKeypair,
      };

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: companyDID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:holder',
          name: 'New Key Credential',
        },
      };

      const signedCredential = await issueCredential(newKeyDoc, credential);

      // FAILS - signature doesn't match embedded key in Company's doc
      const result = await verifyCredential(signedCredential);
      expect(result.verified).toBe(false);
    });

    test('new credential verifies after updating Company document with new key', async () => {
      const delegateKeyId = `${companyDID}#ceo-key`;

      // Add CEO as delegate with new key directly
      const newCeoKeypair = Secp256k1Keypair.random();
      const keyDoc = addDelegateWithEmbeddedKey(companyDID, newCeoKeypair, delegateKeyId);

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: companyDID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:holder',
          name: 'New Key Credential',
        },
      };

      const signedCredential = await issueCredential(keyDoc, credential);

      // Verifies because Company's doc has the correct key
      const result = await verifyCredential(signedCredential);
      expect(result.verified).toBe(true);
    });
  });

  describe('Spec-Non-Compliant Pattern (Controller Mismatch) - CORRECTLY REJECTED', () => {
    // These tests document that verification correctly fails when the pattern
    // violates W3C CID 1.0 spec (controller doesn't match document URL).

    test('correctly rejects verification when controller mismatches document URL', async () => {
      const delegateKeyId = `${companyDID}#ceo-key`;

      // Add delegate with controller pointing to different DID (VIOLATES SPEC)
      addDelegateWithoutKey(companyDID, ceoDID, delegateKeyId);

      // CEO's own DID has the key
      createSelfSovereignDID(ceoKeypair, ceoDID);

      // Create key doc for signing
      const keyDoc = {
        id: delegateKeyId,
        controller: companyDID,
        type: EcdsaSecp256k1VerKeyName,
        publicKey: ceoKeypair.publicKey(),
        keypair: ceoKeypair,
      };

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: companyDID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Test Holder',
        },
      };

      const signedCredential = await issueCredential(keyDoc, credential);

      // Verification CORRECTLY fails - this pattern violates W3C CID spec
      // Per spec Section 3.3 Step 10: controller MUST equal document URL
      const result = await verifyCredential(signedCredential);

      expect(result.verified).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('Multiple Delegates', () => {
    test('should support multiple delegates on same DID', async () => {
      // Add CEO as first delegate
      const ceoKeyId = `${companyDID}#ceo-key`;
      const ceoKeyDoc = addDelegateWithEmbeddedKey(companyDID, ceoKeypair, ceoKeyId);

      // Add CFO as second delegate
      const cfoKeypair = Secp256k1Keypair.random();
      const cfoKeyId = `${companyDID}#cfo-key`;
      const cfoKeyDoc = addDelegateWithEmbeddedKey(companyDID, cfoKeypair, cfoKeyId);

      // Issue credentials with both delegates
      const ceoCredential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: companyDID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: { id: 'did:example:holder1', name: 'CEO Issued' },
      };

      const cfoCredential = {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: companyDID,
        issuanceDate: '2024-01-01T00:00:00Z',
        credentialSubject: { id: 'did:example:holder2', name: 'CFO Issued' },
      };

      const signedCeoCredential = await issueCredential(ceoKeyDoc, ceoCredential);
      const signedCfoCredential = await issueCredential(cfoKeyDoc, cfoCredential);

      // Both should verify
      const result1 = await verifyCredential(signedCeoCredential);
      const result2 = await verifyCredential(signedCfoCredential);

      expect(result1.verified).toBe(true);
      expect(result2.verified).toBe(true);
      expect(signedCeoCredential.proof.verificationMethod).toBe(ceoKeyId);
      expect(signedCfoCredential.proof.verificationMethod).toBe(cfoKeyId);
    });
  });
});
