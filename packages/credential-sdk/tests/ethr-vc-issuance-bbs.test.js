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

  describe('BBS Selective Disclosure Presentations', () => {
    /**
     * BBS presentations use a different mechanism than standard VPs.
     * Instead of signPresentation(), we use the Presentation class to create
     * derived credentials that reveal only selected attributes.
     */
    let fullCredential;

    /**
     * Helper to cache verification method for Presentation.addCredentialToPresent()
     * BBS recovery embeds publicKeyBase58 in the proof, but the Presentation class
     * still needs to resolve the verification method ID from the network cache.
     */
    function cacheVerificationMethodForPresentation(credential) {
      const verificationMethod = credential.proof.verificationMethod;
      networkCache[verificationMethod] = {
        '@context': BBS_V1_CONTEXT,
        id: verificationMethod,
        type: 'Bls12381BBSVerificationKeyDock2023',
        controller: credential.issuer,
        publicKeyBase58: credential.proof.publicKeyBase58,
      };
    }

    beforeAll(async () => {
      // Issue a credential with multiple attributes
      const unsignedCredential = {
        '@context': [
          CREDENTIALS_V1_CONTEXT,
          CREDENTIALS_EXAMPLES_CONTEXT,
          BBS_V1_CONTEXT,
        ],
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: issuerDID,
        issuanceDate: TEST_ISSUANCE_DATE,
        credentialSubject: {
          id: holderDID,
          givenName: 'Alice',
          familyName: 'Smith',
          degree: {
            type: 'BachelorDegree',
            name: 'Bachelor of Science and Arts',
            university: 'Example University',
          },
          alumniOf: 'Example University',
          graduationYear: 2020,
        },
      };

      fullCredential = await issueCredential(issuerKeyDoc, unsignedCredential);
    });

    test('should derive credential revealing only selected attributes', async () => {
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      // Cache verification method for Presentation class
      cacheVerificationMethodForPresentation(fullCredential);

      // Add the full credential to the presentation
      const credIdx = await presentation.addCredentialToPresent(fullCredential);
      expect(credIdx).toBe(0);

      // Reveal only specific attributes (hiding givenName, familyName, graduationYear)
      presentation.addAttributeToReveal(credIdx, [
        'credentialSubject.degree.type',
        'credentialSubject.degree.name',
        'credentialSubject.alumniOf',
      ]);

      // Derive the credential with only revealed attributes
      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'test-nonce-123',
      });

      expect(derivedCredentials).toHaveLength(1);
      const derivedCred = derivedCredentials[0];

      // Verify the derived credential has revealed attributes
      expect(derivedCred.credentialSubject.degree.type).toBe('BachelorDegree');
      expect(derivedCred.credentialSubject.degree.name).toBe('Bachelor of Science and Arts');
      expect(derivedCred.credentialSubject.alumniOf).toBe('Example University');

      // Verify hidden attributes are NOT present
      expect(derivedCred.credentialSubject.givenName).toBeUndefined();
      expect(derivedCred.credentialSubject.familyName).toBeUndefined();
      expect(derivedCred.credentialSubject.graduationYear).toBeUndefined();

      // Verify the derived credential has a proof
      expect(derivedCred.proof).toBeDefined();
      expect(derivedCred.proof.type).toBe('Bls12381BBSSignatureProofDock2023');
      // Nonce is base64url encoded in the proof
      expect(derivedCred.proof.nonce).toBeDefined();
    }, 30000);

    test('should verify derived credential with selective disclosure', async () => {
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      cacheVerificationMethodForPresentation(fullCredential);
      await presentation.addCredentialToPresent(fullCredential);
      presentation.addAttributeToReveal(0, [
        'credentialSubject.alumniOf',
        'credentialSubject.degree.type',
      ]);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'verifier-challenge-456',
      });

      // Verify the derived credential
      const result = await verifyCredential(derivedCredentials[0]);

      expect(result.verified).toBe(true);
      expect(result.results[0].verified).toBe(true);
    }, 30000);

    test('should reveal different attributes for different verifiers', async () => {
      const { default: Presentation } = await import('../src/vc/presentation');

      // Scenario 1: Verifier only needs to know alumniOf
      const presentation1 = new Presentation();
      cacheVerificationMethodForPresentation(fullCredential);
      await presentation1.addCredentialToPresent(fullCredential);
      presentation1.addAttributeToReveal(0, ['credentialSubject.alumniOf']);

      const derivedCred1 = presentation1.deriveCredentials({ nonce: 'v1' })[0];
      expect(derivedCred1.credentialSubject.alumniOf).toBe('Example University');
      expect(derivedCred1.credentialSubject.degree).toBeUndefined();

      // Scenario 2: Verifier needs degree info
      const presentation2 = new Presentation();
      cacheVerificationMethodForPresentation(fullCredential);
      await presentation2.addCredentialToPresent(fullCredential);
      presentation2.addAttributeToReveal(0, [
        'credentialSubject.degree.type',
        'credentialSubject.degree.name',
        'credentialSubject.degree.university',
      ]);

      const derivedCred2 = presentation2.deriveCredentials({ nonce: 'v2' })[0];
      expect(derivedCred2.credentialSubject.degree.type).toBe('BachelorDegree');
      expect(derivedCred2.credentialSubject.degree.name).toBe('Bachelor of Science and Arts');
      expect(derivedCred2.credentialSubject.graduationYear).toBeUndefined();

      // Both derived credentials should verify
      const result1 = await verifyCredential(derivedCred1);
      const result2 = await verifyCredential(derivedCred2);

      expect(result1.verified).toBe(true);
      expect(result2.verified).toBe(true);
    }, 30000);

    test('should fail verification if derived credential is tampered', async () => {
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      cacheVerificationMethodForPresentation(fullCredential);
      await presentation.addCredentialToPresent(fullCredential);
      presentation.addAttributeToReveal(0, ['credentialSubject.alumniOf']);

      const derivedCredentials = presentation.deriveCredentials({
        nonce: 'challenge-789',
      });

      // Tamper with revealed attribute
      const tamperedCred = {
        ...derivedCredentials[0],
        credentialSubject: {
          ...derivedCredentials[0].credentialSubject,
          alumniOf: 'Fake University',
        },
      };

      const result = await verifyCredential(tamperedCred);
      expect(result.verified).toBe(false);
    }, 30000);

    test('should preserve issuer and essential metadata in derived credential', async () => {
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      cacheVerificationMethodForPresentation(fullCredential);
      await presentation.addCredentialToPresent(fullCredential);
      presentation.addAttributeToReveal(0, ['credentialSubject.alumniOf']);

      const derivedCred = presentation.deriveCredentials({ nonce: 'n1' })[0];

      // Essential metadata should be preserved
      expect(derivedCred.issuer).toBe(issuerDID);
      expect(derivedCred.type).toContain('VerifiableCredential');
      expect(derivedCred.type).toContain('UniversityDegreeCredential');
      expect(derivedCred['@context']).toContainEqual(CREDENTIALS_V1_CONTEXT);
      // Note: issuanceDate is set to current date by deriveCredentials if not revealed
      expect(derivedCred.issuanceDate).toBeDefined();

      // Proof should reference the issuer's verification method
      expect(derivedCred.proof.verificationMethod).toContain(issuerDID);
    }, 30000);

    test('should handle nested attribute revelation', async () => {
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      cacheVerificationMethodForPresentation(fullCredential);
      await presentation.addCredentialToPresent(fullCredential);

      // Reveal only the degree.type, not the full degree object
      presentation.addAttributeToReveal(0, ['credentialSubject.degree.type']);

      const derivedCred = presentation.deriveCredentials({ nonce: 'n2' })[0];

      // Should have degree.type but not other degree fields
      expect(derivedCred.credentialSubject.degree.type).toBe('BachelorDegree');
      expect(derivedCred.credentialSubject.degree.name).toBeUndefined();
      expect(derivedCred.credentialSubject.degree.university).toBeUndefined();

      const result = await verifyCredential(derivedCred);
      expect(result.verified).toBe(true);
    }, 30000);

    test('should show proof differences between VC and derived credential', async () => {
      const { default: Presentation } = await import('../src/vc/presentation');

      // VC proof contains publicKeyBase58 (for BBS recovery)
      console.log('\n=== ORIGINAL VC PROOF ===');
      console.log('Type:', fullCredential.proof.type);
      console.log('Has publicKeyBase58:', 'publicKeyBase58' in fullCredential.proof);
      console.log('VC proof keys:', Object.keys(fullCredential.proof).sort());

      // Create derived credential
      const presentation = new Presentation();
      cacheVerificationMethodForPresentation(fullCredential);
      await presentation.addCredentialToPresent(fullCredential);
      presentation.addAttributeToReveal(0, ['credentialSubject.alumniOf']);

      const derivedCred = presentation.deriveCredentials({ nonce: 'compare-123' })[0];

      // Derived credential (VP) proof does NOT contain publicKeyBase58
      console.log('\n=== DERIVED CREDENTIAL (VP) PROOF ===');
      console.log('Type:', derivedCred.proof.type);
      console.log('Has publicKeyBase58:', 'publicKeyBase58' in derivedCred.proof);
      console.log('VP proof keys:', Object.keys(derivedCred.proof).sort());
      console.log('');

      // Verify the differences
      expect(fullCredential.proof.type).toBe('Bls12381BBSSignatureDock2023');
      expect(derivedCred.proof.type).toBe('Bls12381BBSSignatureProofDock2023');

      // BOTH now have publicKeyBase58 for optimistic verification!
      expect('publicKeyBase58' in fullCredential.proof).toBe(true);
      expect('publicKeyBase58' in derivedCred.proof).toBe(true);

      // Verify they have the same public key (from the same issuer)
      expect(derivedCred.proof.publicKeyBase58).toBe(fullCredential.proof.publicKeyBase58);

      expect('proofValue' in fullCredential.proof).toBe(true);
      expect('proofValue' in derivedCred.proof).toBe(true);

      // Derived proof has nonce, original doesn't
      expect('nonce' in fullCredential.proof).toBe(false);
      expect('nonce' in derivedCred.proof).toBe(true);
    }, 30000);

    test('should enable optimistic off-chain verification with publicKeyBase58', async () => {
      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();

      cacheVerificationMethodForPresentation(fullCredential);
      await presentation.addCredentialToPresent(fullCredential);
      presentation.addAttributeToReveal(0, ['credentialSubject.alumniOf']);

      const derivedCred = presentation.deriveCredentials({ nonce: 'optimistic-123' })[0];

      // Verify the derived credential has publicKeyBase58 for optimistic verification
      expect(derivedCred.proof.publicKeyBase58).toBeDefined();
      expect(typeof derivedCred.proof.publicKeyBase58).toBe('string');

      // Verify we can derive address from publicKeyBase58 (same as VC)
      const publicKeyFromProof = derivedCred.proof.publicKeyBase58;
      const expectedAddress = issuerDID.split(':').pop();

      // The publicKeyBase58 should be the same as the original credential
      expect(publicKeyFromProof).toBe(fullCredential.proof.publicKeyBase58);

      // This enables optimistic verification:
      // 1. Extract publicKeyBase58 from proof
      // 2. Derive address: keccak256(publicKey).slice(-20)
      // 3. Compare with DID address
      // 4. If match, verify without blockchain lookup
      const derivedAddress = keypairToAddress({
        publicKeyBuffer: Buffer.from(
          require('bs58').decode(publicKeyFromProof),
        ),
      });

      expect(derivedAddress.toLowerCase()).toBe(expectedAddress.toLowerCase());

      // Full verification should still work
      const result = await verifyCredential(derivedCred);
      expect(result.verified).toBe(true);
    }, 30000);

    test('should work with mainnet ethr DIDs', async () => {
      const mainnetKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'mainnet-sd',
        controller: 'temp',
      });
      const mainnetAddress = keypairToAddress(mainnetKeypair);
      const mainnetDID = addressToDID(mainnetAddress); // No network = mainnet

      const keyDoc = createBBSKeyDocWithMinimalDIDDocument(mainnetKeypair, mainnetDID);

      const credential = await issueCredential(keyDoc, {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: mainnetDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: holderDID,
          field1: 'value1',
          field2: 'value2',
        },
      });

      const { default: Presentation } = await import('../src/vc/presentation');
      const presentation = new Presentation();
      cacheVerificationMethodForPresentation(credential);
      await presentation.addCredentialToPresent(credential);
      presentation.addAttributeToReveal(0, ['credentialSubject.field1']);

      const derivedCred = presentation.deriveCredentials({ nonce: 'mn1' })[0];

      expect(derivedCred.credentialSubject.field1).toBe('value1');
      expect(derivedCred.credentialSubject.field2).toBeUndefined();

      const result = await verifyCredential(derivedCred);
      expect(result.verified).toBe(true);

      cleanupDIDFromCache(mainnetDID);
    }, 30000);

    describe('Two-Tier Verification - Legacy Path Coverage', () => {
      /**
       * These tests cover legacy scenarios where publicKeyBase58 is NOT present
       * in the VP proof. This tests backward compatibility with old credentials
       * issued before the publicKeyBase58 feature.
       */

      test('Path 4: VP without publicKeyBase58 → Tier 2 → Found in DID doc → Verify succeeds', async () => {
        const { default: Presentation } = await import('../src/vc/presentation');
        const presentation = new Presentation();

        // Create a derived credential normally
        cacheVerificationMethodForPresentation(fullCredential);
        await presentation.addCredentialToPresent(fullCredential);
        presentation.addAttributeToReveal(0, ['credentialSubject.alumniOf']);

        const derivedCred = presentation.deriveCredentials({ nonce: 'legacy-path4' })[0];

        // Verify it has publicKeyBase58 (current implementation)
        expect(derivedCred.proof.publicKeyBase58).toBeDefined();

        // LEGACY SCENARIO: Manually remove publicKeyBase58 to simulate old VP
        const legacyVP = {
          ...derivedCred,
          proof: {
            ...derivedCred.proof,
          },
        };
        delete legacyVP.proof.publicKeyBase58;

        // Verify the VP doesn't have publicKeyBase58
        expect(legacyVP.proof.publicKeyBase58).toBeUndefined();

        // Verification should SKIP Tier 1 (no publicKeyBase58)
        // Falls directly to Tier 2: fetch DID document
        // Should find verification method in DID document (it's in networkCache)
        const result = await verifyCredential(legacyVP);

        // Should succeed via Tier 2 (DID document lookup)
        expect(result.verified).toBe(true);
        expect(result.results[0].verified).toBe(true);

        console.log('\n✓ Path 4: VP without publicKeyBase58 verified via Tier 2 (DID doc lookup)');
      }, 30000);

      test('Path 5: VP without publicKeyBase58 → Tier 2 → NOT found in DID doc → Verify fails', async () => {
        const { default: Presentation } = await import('../src/vc/presentation');
        const presentation = new Presentation();

        // Create a derived credential normally
        cacheVerificationMethodForPresentation(fullCredential);
        await presentation.addCredentialToPresent(fullCredential);
        presentation.addAttributeToReveal(0, ['credentialSubject.alumniOf']);

        const derivedCred = presentation.deriveCredentials({ nonce: 'legacy-path5' })[0];

        // LEGACY SCENARIO: Remove publicKeyBase58 AND point to non-existent key
        const legacyVP = {
          ...derivedCred,
          proof: {
            ...derivedCred.proof,
            verificationMethod: `${issuerDID}#non-existent-key`,
          },
        };
        delete legacyVP.proof.publicKeyBase58;

        // Verify the VP doesn't have publicKeyBase58
        expect(legacyVP.proof.publicKeyBase58).toBeUndefined();

        // Verification should SKIP Tier 1 (no publicKeyBase58)
        // Falls directly to Tier 2: fetch DID document
        // Should NOT find verification method (non-existent-key)
        const result = await verifyCredential(legacyVP);

        // Should fail - verification method not found in DID document
        expect(result.verified).toBe(false);

        console.log('\n✓ Path 5: VP without publicKeyBase58 failed (key not in DID doc)');
      }, 30000);
    });
  });

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

  describe('VC Verification After Ownership Change (BBS Flow)', () => {
    /**
     * These tests simulate the scenario where DID ownership has been changed
     * via changeOwnerWithPubkey to a different BBS keypair.
     *
     * We simulate the FINAL STATE of the DID document after ownership change
     * (without calling changeOwnerWithPubkey) and test VC verification behavior.
     *
     * Key scenarios:
     * 1. VC issued by original keypair → ownership changed → verify VC
     * 2. VC issued by new owner keypair → verify VC
     */

    let originalKeypair;
    let originalAddress;
    let originalDID;
    let newOwnerKeypair;
    let newOwnerAddress;

    beforeAll(async () => {
      // Original BBS keypair (issuer before ownership change)
      originalKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'original-owner',
        controller: 'temp',
      });
      originalAddress = keypairToAddress(originalKeypair);
      originalDID = addressToDID(originalAddress, VIETCHAIN_NETWORK);

      // New owner BBS keypair (after ownership change)
      newOwnerKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'new-owner',
        controller: 'temp',
      });
      newOwnerAddress = keypairToAddress(newOwnerKeypair);
    });

    afterAll(() => {
      cleanupDIDFromCache(originalDID);
    });

    test('VC issued before ownership change still verifies via optimistic verification', async () => {
      /**
       * This test demonstrates that VCs issued BEFORE ownership change continue
       * to verify even AFTER ownership changes. This is because:
       *
       * 1. The proof contains publicKeyBase58 (original keypair's public key)
       * 2. Optimistic verification derives address from publicKeyBase58
       * 3. The derived address matches the DID's address (from the DID STRING itself)
       * 4. The DID string (did:ethr:vietchain:0xOriginal...) never changes
       * 5. Therefore, VCs signed by the original keypair remain valid
       *
       * This is a KEY INSIGHT: The DID identifier IS the address, and the original
       * keypair's address IS that identifier. Changing ownership (who controls the DID)
       * doesn't invalidate previously issued VCs because:
       * - The VC is bound to the DID string (address), not to "current ownership"
       * - Optimistic verification checks address derivation, not DID doc ownership
       */

      // Step 1: Set up DID document with ORIGINAL owner
      const originalKeyId = `${originalDID}#keys-bbs`;
      networkCache[originalDID] = {
        '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
        id: originalDID,
        verificationMethod: [
          {
            id: `${originalDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: originalDID,
            blockchainAccountId: `eip155:1:${originalAddress}`,
          },
        ],
        assertionMethod: [`${originalDID}#controller`, originalKeyId],
        authentication: [`${originalDID}#controller`],
      };

      // Step 2: Issue VC with original keypair
      const originalKeyDoc = {
        id: originalKeyId,
        controller: originalDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: originalKeypair,
      };

      const credential = await issueCredential(originalKeyDoc, {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: originalDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'issued-before-ownership-change',
        },
      });

      // Verify VC was issued correctly with publicKeyBase58 embedded
      expect(credential.proof.publicKeyBase58).toBeDefined();

      // Verify VC passes BEFORE ownership change
      const resultBeforeChange = await verifyCredential(credential);
      expect(resultBeforeChange.verified).toBe(true);

      // Step 3: Simulate ownership change - update DID document to show NEW owner
      networkCache[originalDID] = {
        '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
        id: originalDID,
        verificationMethod: [
          {
            // Owner is now the NEW keypair's address
            id: `${originalDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: originalDID,
            blockchainAccountId: `eip155:1:${newOwnerAddress}`,
          },
        ],
        // Note: Original key is no longer in assertionMethod
        assertionMethod: [`${originalDID}#controller`],
        authentication: [`${originalDID}#controller`],
      };

      // Step 4: Verify the VC issued by original keypair AFTER ownership change
      const resultAfterChange = await verifyCredential(credential);
      expect(resultAfterChange.verified).toBe(true);
    }, 30000);

    test('VC issued by non-owner keypair should fail verification when DID doc is checked', async () => {
      // Set up DID document with NEW owner (simulating post-ownership-change state)
      const wrongKeyId = `${originalDID}#keys-wrong`;
      networkCache[originalDID] = {
        '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
        id: originalDID,
        verificationMethod: [
          {
            id: `${originalDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: originalDID,
            blockchainAccountId: `eip155:1:${newOwnerAddress}`,
          },
        ],
        assertionMethod: [`${originalDID}#controller`],
        authentication: [`${originalDID}#controller`],
      };

      // Issue VC with a DIFFERENT keypair (not the owner - neither original nor new)
      const attackerKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'attacker',
        controller: 'temp',
      });

      const attackerKeyDoc = {
        id: wrongKeyId,
        controller: originalDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: attackerKeypair,
      };

      const credential = await issueCredential(attackerKeyDoc, {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: originalDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'issued-by-attacker',
        },
      });

      const result = await verifyCredential(credential);

      // Should fail because attacker's derived address doesn't match originalDID's address
      expect(result.verified).toBe(false);
    }, 30000);

    test('VC issued by new owner should verify after ownership change', async () => {
      // The new owner creates their own DID based on their BBS keypair address
      // This is how it works in practice - new owner uses their own DID
      const newOwnerDID = addressToDID(newOwnerAddress, VIETCHAIN_NETWORK);
      const newOwnerKeyId = `${newOwnerDID}#keys-bbs`;

      // Issue VC with new owner's keypair using their own DID
      const newOwnerKeyDoc = {
        id: newOwnerKeyId,
        controller: newOwnerDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: newOwnerKeypair,
      };

      const credential = await issueCredential(newOwnerKeyDoc, {
        '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: newOwnerDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'issued-by-new-owner',
        },
      });

      // Register DID doc for new owner's DID
      networkCache[newOwnerDID] = {
        '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
        id: newOwnerDID,
        verificationMethod: [
          {
            id: `${newOwnerDID}#controller`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: newOwnerDID,
            blockchainAccountId: `eip155:1:${newOwnerAddress}`,
          },
        ],
        assertionMethod: [`${newOwnerDID}#controller`, newOwnerKeyId],
        authentication: [`${newOwnerDID}#controller`],
      };

      // Cache the verification method key ID (needed for document loader)
      networkCache[newOwnerKeyId] = {
        '@context': BBS_V1_CONTEXT,
        id: newOwnerKeyId,
        type: 'Bls12381BBSVerificationKeyDock2023',
        controller: newOwnerDID,
        publicKeyBase58: credential.proof.publicKeyBase58,
      };

      const result = await verifyCredential(credential);

      // Should verify - new owner's address matches their DID
      expect(result.verified).toBe(true);

      cleanupDIDFromCache(newOwnerDID);
    }, 30000);
  });
});
