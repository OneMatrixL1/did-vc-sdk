/**
 * TESTCASE 3: Cross-System Customer Tier Verification
 *
 * Real-world Flow:
 * 1. System A (e-commerce) issues VIP tier credential to user
 * 2. User creates Verifiable Presentation containing the VC
 * 3. User signs VP with their own key (proves ownership)
 * 4. System B (partner service) verifies VP (includes VC verification)
 * 5. System B grants access based on tier
 *
 * Security Features:
 * - VP proves user owns the credential
 * - Challenge-response prevents replay attacks
 * - Tamper detection on both VP and VC
 * - Expiration validation
 *
 * Run: npm test -- testcase3
 */

import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';
import b58 from 'bs58';
import {
    issueCredential,
} from '../src/vc';
import { signPresentation, verifyPresentation } from '../src/vc/presentations';
import { Secp256k1Keypair } from '../src/keypairs';
import { addressToDID, keypairToAddress } from '../src/modules/ethr-did/utils';
import { EcdsaSecp256k1VerKeyName } from '../src/vc/crypto/constants';

// Setup mock to avoid network calls
mockFetch();

// Constants
const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES = 'https://www.w3.org/2018/credentials/examples/v1';
const DID_V1 = 'https://www.w3.org/ns/did/v1';
const SECURITY_V2 = 'https://w3id.org/security/v2';
const VIETCHAIN_NETWORK = 'vietchain';

/**
 * Get raw public key bytes from Secp256k1Keypair
 */
function getRawPublicKeyBytes(keypair) {
    const pk = keypair.publicKey();
    return pk.value;
}

/**
 * Create key document and register DID document in networkCache
 * Following SDK pattern from ethr-vc-issuance-secp256k1.test.js
 */
function createKeyDocAndRegisterDID(keypair, did) {
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

    // Register key
    networkCache[keyId] = {
        '@context': SECURITY_V2,
        id: keyId,
        type: EcdsaSecp256k1VerKeyName,
        controller: did,
        publicKeyBase58,
    };

    // Register DID document
    networkCache[did] = {
        '@context': [DID_V1, SECURITY_V2],
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

describe('TESTCASE 3: Cross-System Customer Tier Verification', () => {
    // Entities
    let systemADID, systemAKeyDoc;
    let userDID, userKeyDoc;

    // Credentials
    let vip1Credential;

    beforeAll(() => {
        console.log('\n' + '='.repeat(70));
        console.log('🚀 TESTCASE 3: Cross-System Customer Tier Verification');
        console.log('='.repeat(70) + '\n');

        // ========== Setup System A (Issuer) ==========
        const systemAKeypair = Secp256k1Keypair.random();
        systemADID = addressToDID(keypairToAddress(systemAKeypair), VIETCHAIN_NETWORK);
        systemAKeyDoc = createKeyDocAndRegisterDID(systemAKeypair, systemADID);

        expect(systemADID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);

        // ========== Setup User (Holder) ==========
        const userKeypair = Secp256k1Keypair.random();
        userDID = addressToDID(keypairToAddress(userKeypair), VIETCHAIN_NETWORK);
        userKeyDoc = createKeyDocAndRegisterDID(userKeypair, userDID);

        expect(userDID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);
        expect(userDID).not.toBe(systemADID);

        console.log('✅ Setup complete:');
        console.log(`   System A DID: ${systemADID}`);
        console.log(`   User DID: ${userDID}\n`);
    });

    describe('Scenario 1: System A issues customer tier credential', () => {
        test('System A issues VIP1 credential to user', async () => {
            console.log('='.repeat(70));
            console.log('🏪 SCENARIO 1: System A - E-commerce Platform');
            console.log('='.repeat(70) + '\n');

            console.log('📝 User logs into System A');
            console.log('🔍 Checking purchase history:');
            console.log('   - Total spent: $250,000');
            console.log('   - Member since: 2020-03-15');
            console.log('💎 → Qualifies for VIP1 tier!\n');

            // Build unsigned credential
            const unsignedCredential = {
                '@context': [
                    CREDENTIALS_V1,
                    CREDENTIALS_EXAMPLES,
                ],
                type: ['VerifiableCredential', 'CustomerTierCredential'],
                issuer: systemADID,
                issuanceDate: '2024-01-01T00:00:00Z',
                credentialSubject: {
                    id: userDID,
                    alumniOf: 'VIP1 Tier - System A E-commerce',
                },
            };

            console.log('🔐 System A issuing credential...');

            // Issue credential using SDK
            vip1Credential = await issueCredential(systemAKeyDoc, unsignedCredential);

            // Validate
            expect(vip1Credential).toBeDefined();
            expect(vip1Credential.issuer).toBe(systemADID);
            expect(vip1Credential.credentialSubject.id).toBe(userDID);
            expect(vip1Credential.proof).toBeDefined();
            expect(vip1Credential.proof.type).toBe('EcdsaSecp256k1Signature2019');

            console.log('✅ Credential issued successfully!\n');
            console.log('📄 Credential details:');
            console.log(`   Issuer: ${vip1Credential.issuer}`);
            console.log(`   Subject: ${vip1Credential.credentialSubject.id}`);
            console.log(`   Tier: ${vip1Credential.credentialSubject.alumniOf}`);
            console.log(`   Signature: ${vip1Credential.proof.type}\n`);

            console.log('💾 User saved credential to digital wallet\n');
        }, 30000);
    });

    describe('Scenario 2: User presents credential to System B via VP', () => {
        test('User creates and signs Verifiable Presentation', async () => {
            console.log('='.repeat(70));
            console.log('🏢 SCENARIO 2: User presents to System B');
            console.log('='.repeat(70) + '\n');

            console.log('👤 User accessing System B...');
            console.log('🎫 System B requests proof of VIP tier\n');

            // System B generates challenge (prevents replay attack)
            const challenge = `system-b-challenge-${Date.now()}`;
            const domain = 'systemb.example.com';

            console.log('🔐 System B sends challenge:');
            console.log(`   Challenge: ${challenge.substring(0, 40)}...`);
            console.log(`   Domain: ${domain}\n`);

            // User creates VP containing the VC
            const unsignedPresentation = {
                '@context': [CREDENTIALS_V1],
                type: ['VerifiablePresentation'],
                verifiableCredential: [vip1Credential],
                holder: userDID,
            };

            console.log('📝 User creating Verifiable Presentation...');

            // User signs VP with their key (proves ownership)
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
            expect(signedVP.proof.type).toBe('EcdsaSecp256k1Signature2019');
            expect(signedVP.proof.challenge).toBe(challenge);
            expect(signedVP.proof.domain).toBe(domain);
            expect(signedVP.proof.proofPurpose).toBe('authentication');

            console.log('✅ VP created and signed!\n');
            console.log('📄 Presentation details:');
            console.log(`   Holder: ${signedVP.holder}`);
            console.log(`   VCs included: ${signedVP.verifiableCredential.length}`);
            console.log(`   Signature: ${signedVP.proof.type}`);
            console.log(`   Purpose: ${signedVP.proof.proofPurpose}\n`);

            console.log('📤 User sending VP to System B...\n');

            // System B verifies VP (including VC inside)
            console.log('🔍 System B verifying presentation...');
            console.log('   ⏳ Checking VP signature (proof of ownership)');
            console.log('   ⏳ Verifying challenge matches');
            console.log('   ⏳ Verifying VC inside (issuer, signature)');
            console.log('   ⏳ Checking expiration\n');

            const result = await verifyPresentation(signedVP, {
                challenge,
                domain,
            });

            // Validate verification result
            expect(result.verified).toBe(true);
            expect(result.presentationResult.verified).toBe(true);
            expect(result.credentialResults).toBeDefined();
            expect(result.credentialResults[0].verified).toBe(true);

            console.log('✅ VERIFICATION SUCCESSFUL!\n');
            console.log('📊 Verified information:');
            console.log(`   VP Holder: ${signedVP.holder}`);
            console.log(`   VC Issuer: ${vip1Credential.issuer} (System A)`);
            console.log(`   Tier: ${vip1Credential.credentialSubject.alumniOf}\n`);

            console.log('🎉 ACCESS GRANTED!');
            console.log('   ✓ User proves ownership via VP signature');
            console.log('   ✓ VC verified from System A');
            console.log('   ✓ VIP1 tier confirmed');
            console.log('   ✓ Unlocking premium features\n');
        }, 30000);

        test('SECURITY: System B rejects tampered credential in VP', async () => {
            console.log('='.repeat(70));
            console.log('🔒 SECURITY TEST: Tamper Detection');
            console.log('='.repeat(70) + '\n');

            console.log('⚠️  Simulating attack: Modifying VC tier inside VP\n');

            const challenge = `security-test-${Date.now()}`;
            const domain = 'systemb.example.com';

            // Tamper with credential
            const tamperedVC = {
                ...vip1Credential,
                credentialSubject: {
                    ...vip1Credential.credentialSubject,
                    alumniOf: 'VIP3 Tier - TAMPERED!', // MODIFIED!
                },
            };

            // Create VP with tampered VC
            const tamperedPresentation = {
                '@context': [CREDENTIALS_V1],
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

            console.log('🔍 System B verifying...\n');

            const result = await verifyPresentation(signedVP, {
                challenge,
                domain,
            });

            // Must fail because VC signature is invalid
            expect(result.verified).toBe(false);
            expect(result.credentialResults[0].verified).toBe(false);

            console.log('✅ ATTACK BLOCKED!');
            console.log('   VC signature verification failed');
            console.log('   → Access denied\n');
        }, 30000);

        test('SECURITY: System B rejects wrong challenge', async () => {
            console.log('='.repeat(70));
            console.log('🔒 SECURITY TEST: Challenge Mismatch');
            console.log('='.repeat(70) + '\n');

            console.log('⚠️  Simulating replay attack: Wrong challenge\n');

            const correctChallenge = `correct-${Date.now()}`;
            const wrongChallenge = `wrong-${Date.now()}`;
            const domain = 'systemb.example.com';

            // Create VP with correct challenge
            const presentation = {
                '@context': [CREDENTIALS_V1],
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

            console.log('🔍 Attacker tries to verify with wrong challenge...\n');

            // Try to verify with wrong challenge
            const result = await verifyPresentation(signedVP, {
                challenge: wrongChallenge,
                domain,
            });

            // Must fail
            expect(result.verified).toBe(false);

            console.log('✅ REPLAY ATTACK BLOCKED!');
            console.log('   Challenge mismatch detected');
            console.log('   → Access denied\n');
        }, 30000);

        test('SECURITY: System B rejects expired credential', async () => {
            console.log('='.repeat(70));
            console.log('🔒 SECURITY TEST: Expiration Validation');
            console.log('='.repeat(70) + '\n');

            console.log('⏰ Creating credential with past expiration\n');

            // Issue expired credential
            const expiredCredential = await issueCredential(systemAKeyDoc, {
                '@context': [
                    CREDENTIALS_V1,
                    CREDENTIALS_EXAMPLES,
                ],
                type: ['VerifiableCredential', 'CustomerTierCredential'],
                issuer: systemADID,
                issuanceDate: '2023-01-01T00:00:00Z',
                expirationDate: '2023-12-31T23:59:59Z', // Expired
                credentialSubject: {
                    id: userDID,
                    alumniOf: 'VIP1 Tier - Expired',
                },
            });

            const challenge = `expired-test-${Date.now()}`;
            const domain = 'systemb.example.com';

            // Create VP with expired VC
            const presentation = {
                '@context': [CREDENTIALS_V1],
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

            console.log('🔍 System B verifying expired credential...\n');

            const result = await verifyPresentation(signedVP, {
                challenge,
                domain,
            });

            // Must fail due to expiration
            expect(result.verified).toBe(false);
            expect(result.credentialResults[0].verified).toBe(false);
            expect(result.credentialResults[0].error).toBeDefined();
            expect(result.credentialResults[0].error.message).toMatch(/expired/i);

            console.log('✅ EXPIRED CREDENTIAL REJECTED!');
            console.log(`   Error: ${result.credentialResults[0].error.message}`);
            console.log('   → Access denied\n');
        }, 30000);
    });
});
