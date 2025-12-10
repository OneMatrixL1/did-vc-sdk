/**
 * TESTCASE 3: Cross-System Customer Tier Verification with BBS Signatures
 *
 * Real-world Flow:
 * 1. System A (e-commerce) issues VIP tier credential to user with BBS signature
 * 2. User creates Verifiable Presentation containing the VC
 * 3. User signs VP with their own key (proves ownership)
 * 4. System B (partner service) verifies VP (includes VC verification)
 * 5. System B grants access based on tier
 *
 * Security Features:
 * - BBS signatures for privacy-preserving credentials
 * - VP proves user owns the credential
 * - Challenge-response prevents replay attacks
 * - Tamper detection on both VP and VC
 * - Expiration validation
 *
 * Run: npm test -- testcase3
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';
import {
    issueCredential,
} from '../src/vc';
import { signPresentation, verifyPresentation } from '../src/vc/presentations';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import { addressToDID, keypairToAddress } from '../src/modules/ethr-did/utils';
import customerTierContext from './testcase3/customer-tier-context.json';

// Setup mock to avoid network calls
mockFetch();

// Constants
const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';
const BBS_V1 = 'https://ld.truvera.io/security/bbs/v1';
const DID_V1 = 'https://www.w3.org/ns/did/v1';
const SECURITY_V2 = 'https://w3id.org/security/v2';
const VIETCHAIN_NETWORK = 'vietchain';

// Custom context - will be hosted on GitHub after push
const CUSTOMER_TIER_CONTEXT = 'https://raw.githubusercontent.com/OneMatrixL1/did-vc-sdk/testcase3/packages/credential-sdk/tests/testcase3/customer-tier-context.json';

// Cache the context locally for testing (before pushing to GitHub)
networkCache[CUSTOMER_TIER_CONTEXT] = customerTierContext;

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
        '@context': [DID_V1, SECURITY_V2],
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

describe('TESTCASE 3: Cross-System Customer Tier Verification', () => {
    // Entities
    let systemADID, systemAKeyDoc;
    let userDID, userKeyDoc;

    // Credentials
    let vip1Credential;

    beforeAll(async () => {
        // Initialize WASM for BBS operations
        await initializeWasm();

        // ========== Setup System A (Issuer) with BBS ==========
        const systemAKeypair = Bls12381BBSKeyPairDock2023.generate({
            id: 'system-a-key',
            controller: 'temp',
        });
        systemADID = addressToDID(keypairToAddress(systemAKeypair), VIETCHAIN_NETWORK);
        systemAKeyDoc = createBBSKeyDocWithMinimalDIDDocument(systemAKeypair, systemADID);

        expect(systemADID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);

        // ========== Setup User (Holder) with BBS ==========
        const userKeypair = Bls12381BBSKeyPairDock2023.generate({
            id: 'user-key',
            controller: 'temp',
        });
        userDID = addressToDID(keypairToAddress(userKeypair), VIETCHAIN_NETWORK);
        userKeyDoc = createBBSKeyDocWithMinimalDIDDocument(userKeypair, userDID);

        expect(userDID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);
        expect(userDID).not.toBe(systemADID);
    });

    describe('Scenario 1: System A issues customer tier credential', () => {
        test('System A issues VIP1 credential to user with BBS signature', async () => {
            // Build unsigned credential using custom context
            const unsignedCredential = {
                '@context': [
                    CREDENTIALS_V1,
                    BBS_V1,
                    CUSTOMER_TIER_CONTEXT,
                ],
                type: ['VerifiableCredential', 'CustomerTierCredential'],
                issuer: systemADID,
                issuanceDate: '2024-01-01T00:00:00Z',
                credentialSubject: {
                    id: userDID,
                    customerTier: {
                        tier: 'VIP1',
                        tierName: 'VIP1 - Premium Customer',
                        tierDescription: 'Top tier customer from System A E-commerce',
                        totalSpent: '$250,000',
                        memberSince: '2020-03-15',
                        accountId: 'SYSCUST-12345',
                    },
                },
            };

            // Issue credential using SDK with BBS
            vip1Credential = await issueCredential(systemAKeyDoc, unsignedCredential);

            // Validate
            expect(vip1Credential).toBeDefined();
            expect(vip1Credential.issuer).toBe(systemADID);
            expect(vip1Credential.credentialSubject.id).toBe(userDID);
            expect(vip1Credential.credentialSubject.customerTier.tier).toBe('VIP1');
            expect(vip1Credential.proof).toBeDefined();
            expect(vip1Credential.proof.type).toBe('Bls12381BBSSignatureDock2023');
        }, 30000);
    });

    describe('Scenario 2: User presents credential to System B via VP', () => {
        test('User creates and signs Verifiable Presentation with BBS', async () => {
            // System B generates challenge (prevents replay attack)
            const challenge = `system-b-challenge-${Date.now()}`;
            const domain = 'systemb.example.com';

            // User creates VP containing the VC
            const unsignedPresentation = {
                '@context': [CREDENTIALS_V1, BBS_V1],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vip1Credential],
                holder: userDID,
            };

            // User signs VP with their BBS key (proves ownership)
            const signedVP = await signPresentation(
                unsignedPresentation,
                userKeyDoc,
                challenge,
                domain,
            );

            // Validate VP structure
            expect(signedVP).toBeDefined();
            expect(signedVP.holder).toBe(userDID);
            expect(signedVP.verifiableCredential).toHaveLength(1);
            expect(signedVP.proof).toBeDefined();
            expect(signedVP.proof.type).toBe('Bls12381BBSSignatureDock2023');
            expect(signedVP.proof.challenge).toBe(challenge);
            expect(signedVP.proof.domain).toBe(domain);
            expect(signedVP.proof.proofPurpose).toBe('authentication');

            const result = await verifyPresentation(signedVP, {
                challenge,
                domain,
            });

            // Validate verification result
            expect(result.verified).toBe(true);
            expect(result.presentationResult.verified).toBe(true);
            expect(result.credentialResults).toBeDefined();
            expect(result.credentialResults[0].verified).toBe(true);
        }, 30000);

        test('SECURITY: System B rejects tampered credential in VP', async () => {
            const challenge = `security-test-${Date.now()}`;
            const domain = 'systemb.example.com';

            // Tamper with credential
            const tamperedVC = {
                ...vip1Credential,
                credentialSubject: {
                    ...vip1Credential.credentialSubject,
                    customerTier: {
                        ...vip1Credential.credentialSubject.customerTier,
                        tier: 'VIP3', // TAMPERED!
                        tierName: 'VIP3 - TAMPERED!',
                    },
                },
            };

            // Create VP with tampered VC
            const tamperedPresentation = {
                '@context': [CREDENTIALS_V1, BBS_V1],
                type: ['VerifiablePresentation'],
                verifiableCredential: [tamperedVC],
                holder: userDID,
            };

            const signedVP = await signPresentation(
                tamperedPresentation,
                userKeyDoc,
                challenge,
                domain,
            );

            const result = await verifyPresentation(signedVP, {
                challenge,
                domain,
            });

            // Must fail because VC signature is invalid
            expect(result.verified).toBe(false);
            expect(result.credentialResults[0].verified).toBe(false);
        }, 30000);

        test('SECURITY: System B rejects wrong challenge', async () => {
            const correctChallenge = `correct-${Date.now()}`;
            const wrongChallenge = `wrong-${Date.now()}`;
            const domain = 'systemb.example.com';

            // Create VP with correct challenge
            const presentation = {
                '@context': [CREDENTIALS_V1, BBS_V1],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vip1Credential],
                holder: userDID,
            };

            const signedVP = await signPresentation(
                presentation,
                userKeyDoc,
                correctChallenge,
                domain,
            );

            // Try to verify with wrong challenge
            const result = await verifyPresentation(signedVP, {
                challenge: wrongChallenge,
                domain,
            });

            // Must fail
            expect(result.verified).toBe(false);
        }, 30000);

        test('SECURITY: System B rejects expired credential', async () => {
            // Issue expired credential
            const expiredCredential = await issueCredential(systemAKeyDoc, {
                '@context': [
                    CREDENTIALS_V1,
                    BBS_V1,
                    CUSTOMER_TIER_CONTEXT,
                ],
                type: ['VerifiableCredential', 'CustomerTierCredential'],
                issuer: systemADID,
                issuanceDate: '2023-01-01T00:00:00Z',
                expirationDate: '2023-12-31T23:59:59Z', // Expired
                credentialSubject: {
                    id: userDID,
                    customerTier: {
                        tier: 'VIP1',
                        tierName: 'VIP1 - Expired',
                        tierDescription: 'Expired customer tier',
                    },
                },
            });

            const challenge = `expired-test-${Date.now()}`;
            const domain = 'systemb.example.com';

            // Create VP with expired VC
            const presentation = {
                '@context': [CREDENTIALS_V1, BBS_V1],
                type: ['VerifiablePresentation'],
                verifiableCredential: [expiredCredential],
                holder: userDID,
            };

            const signedVP = await signPresentation(
                presentation,
                userKeyDoc,
                challenge,
                domain,
            );

            const result = await verifyPresentation(signedVP, {
                challenge,
                domain,
            });

            // Must fail due to expiration
            expect(result.verified).toBe(false);
            expect(result.credentialResults[0].verified).toBe(false);
            expect(result.credentialResults[0].error).toBeDefined();
            expect(result.credentialResults[0].error.message).toMatch(/expired/i);
        }, 30000);
    });
});
