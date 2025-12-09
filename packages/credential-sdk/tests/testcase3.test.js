/**
 * TESTCASE 3: Cross-System Customer Tier Verification
 *
 * Use Case Flow:
 * 1. System A (e-commerce) issues VIP tier credential to user using ethr-did + BBS
 * 2. User presents credential to System B (partner service)
 * 3. System B verifies credential and grants access based on tier
 *
 * Security Features:
 * - BBS signatures for privacy
 * - Tamper detection
 * - Expiration validation
 * - DID authentication
 *
 * Run: npm test -- testcase3
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';
import {
    issueCredential,
    verifyCredential,
} from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import { addressToDID, keypairToAddress } from '../src/modules/ethr-did/utils';

// Setup mock to avoid network calls
mockFetch();

// Constants
const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';
const BBS_V1 = 'https://ld.truvera.io/security/bbs/v1';
const DID_V1 = 'https://www.w3.org/ns/did/v1';
const SECURITY_V2 = 'https://w3id.org/security/v2';
const CUSTOMER_TIER_CONTEXT = 'https://example.com/contexts/customer-tier/v1';

/**
 * Register DID document in mock registry
 * @param {Object} keypair - BBS keypair
 * @param {string} did - DID string
 * @returns {Object} Key document for signing
 */
function registerDID(keypair, did) {
    const keyId = `${did}#keys-bbs`;
    const address = did.split(':').pop();

    // Register DID document (simulates blockchain registry)
    networkCache[did] = {
        '@context': [DID_V1, SECURITY_V2],
        id: did,
        verificationMethod: [
            {
                id: `${did}#controller`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1:${address}`,
            },
        ],
        assertionMethod: [`${did}#controller`, keyId],
        authentication: [`${did}#controller`, keyId],
    };

    return {
        id: keyId,
        controller: did,
        type: Bls12381BBS23DockVerKeyName,
        keypair,
    };
}

/**
 * Create customer tier credential with full validation
 */
function createCustomerTierCredential(issuerDID, subjectDID, tier, options = {}) {
    const {
        accountId = 'SYSCUST-12345',
        totalSpent = '$250,000',
        memberSince = '2020-03-15',
        issuanceDate = new Date('2024-01-01').toISOString(),
        expirationDate = null,
    } = options;

    // Validate inputs
    if (!issuerDID || !issuerDID.startsWith('did:')) {
        throw new Error('Invalid issuer DID');
    }

    if (!subjectDID || !subjectDID.startsWith('did:')) {
        throw new Error('Invalid subject DID');
    }

    if (!['VIP1', 'VIP2', 'VIP3', 'STANDARD'].includes(tier)) {
        throw new Error(`Invalid tier: ${tier}. Must be VIP1, VIP2, VIP3, or STANDARD`);
    }

    const credential = {
        '@context': [
            CREDENTIALS_V1,
            BBS_V1,
            {
                CustomerTierCredential: `${CUSTOMER_TIER_CONTEXT}#CustomerTierCredential`,
                customerTier: {
                    '@id': `${CUSTOMER_TIER_CONTEXT}#customerTier`,
                    '@type': '@id',
                },
                tierLevel: `${CUSTOMER_TIER_CONTEXT}#tierLevel`,
                accountId: `${CUSTOMER_TIER_CONTEXT}#accountId`,
                totalSpent: `${CUSTOMER_TIER_CONTEXT}#totalSpent`,
                memberSince: `${CUSTOMER_TIER_CONTEXT}#memberSince`,
            },
        ],
        type: ['VerifiableCredential', 'CustomerTierCredential'],
        issuer: issuerDID,
        issuanceDate,
        credentialSubject: {
            id: subjectDID,
            customerTier: {
                tierLevel: tier,
                accountId,
                totalSpent,
                memberSince,
            },
        },
    };

    // Add expiration date if provided
    if (expirationDate) {
        credential.expirationDate = expirationDate;
    }

    return credential;
}

describe('TESTCASE 3: Cross-System Customer Tier Verification', () => {
    // Entities
    let systemADID, systemAKeyDoc, systemAKeypair;
    let userDID, userKeyDoc, userKeypair;
    let systemBDID, systemBKeyDoc, systemBKeypair;

    // Credentials
    let vip1Credential;

    beforeAll(async () => {
        // Initialize BBS cryptography
        await initializeWasm();

        console.log('\n' + '='.repeat(70));
        console.log('🚀 TESTCASE 3: Cross-System Customer Tier Verification');
        console.log('='.repeat(70) + '\n');

        // ========== Setup System A (Issuer) ==========
        systemAKeypair = Bls12381BBSKeyPairDock2023.generate({
            id: 'system-a-issuer',
            controller: 'temp',
        });
        systemADID = addressToDID(keypairToAddress(systemAKeypair), 'vietchain');
        systemAKeyDoc = registerDID(systemAKeypair, systemADID);

        // Validate System A setup
        expect(systemADID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);
        expect(systemAKeyDoc.id).toBe(`${systemADID}#keys-bbs`);
        expect(systemAKeyDoc.type).toBe(Bls12381BBS23DockVerKeyName);

        // ========== Setup User ==========
        userKeypair = Bls12381BBSKeyPairDock2023.generate({
            id: 'user-key',
            controller: 'temp',
        });
        userDID = addressToDID(keypairToAddress(userKeypair), 'vietchain');
        userKeyDoc = registerDID(userKeypair, userDID);

        // Validate User setup
        expect(userDID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);
        expect(userDID).not.toBe(systemADID); // User and System A must be different

        // ========== Setup System B (Verifier) ==========
        systemBKeypair = Bls12381BBSKeyPairDock2023.generate({
            id: 'system-b-verifier',
            controller: 'temp',
        });
        systemBDID = addressToDID(keypairToAddress(systemBKeypair), 'vietchain');
        systemBKeyDoc = registerDID(systemBKeypair, systemBDID);

        // Validate System B setup
        expect(systemBDID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);
        expect(systemBDID).not.toBe(systemADID);
        expect(systemBDID).not.toBe(userDID);

        console.log('✅ Setup complete:');
        console.log(`   System A DID: ${systemADID}`);
        console.log(`   User DID: ${userDID}`);
        console.log(`   System B DID: ${systemBDID}\n`);
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
            console.log('   - Orders: 127');
            console.log('💎 → Qualifies for VIP1 tier!\n');

            // Create credential
            const unsignedCredential = createCustomerTierCredential(
                systemADID,
                userDID,
                'VIP1',
                {
                    accountId: 'SYSCUST-12345',
                    totalSpent: '$250,000',
                    memberSince: '2020-03-15',
                },
            );

            // Validate credential structure before signing
            expect(unsignedCredential.issuer).toBe(systemADID);
            expect(unsignedCredential.credentialSubject.id).toBe(userDID);
            expect(unsignedCredential.credentialSubject.customerTier.tierLevel).toBe('VIP1');

            console.log('🔐 System A issuing credential with BBS signature...');

            // Issue credential
            vip1Credential = await issueCredential(systemAKeyDoc, unsignedCredential);

            // Validate issued credential
            expect(vip1Credential).toBeDefined();
            expect(vip1Credential.proof).toBeDefined();
            expect(vip1Credential.proof.type).toBe('Bls12381BBSSignatureDock2023');
            expect(vip1Credential.proof.verificationMethod).toBe(systemAKeyDoc.id);
            expect(vip1Credential.proof.proofPurpose).toBe('assertionMethod');
            expect(vip1Credential.proof.created).toBeDefined();

            console.log('✅ Credential issued successfully!\n');
            console.log('📄 Credential details:');
            console.log(`   Issuer: ${vip1Credential.issuer}`);
            console.log(`   Subject: ${vip1Credential.credentialSubject.id}`);
            console.log(`   Tier: ${vip1Credential.credentialSubject.customerTier.tierLevel}`);
            console.log(`   Account: ${vip1Credential.credentialSubject.customerTier.accountId}`);
            console.log(`   Total Spent: ${vip1Credential.credentialSubject.customerTier.totalSpent}`);
            console.log(`   Member Since: ${vip1Credential.credentialSubject.customerTier.memberSince}`);
            console.log(`   Signature: ${vip1Credential.proof.type}`);
            console.log(`   Created: ${vip1Credential.proof.created}\n`);

            console.log('💾 User saved credential to digital wallet\n');
        }, 30000);

        test('User verifies credential received from System A', async () => {
            console.log('🔍 User verifying credential...\n');

            const result = await verifyCredential(vip1Credential);

            // Validate verification result
            expect(result.verified).toBe(true);
            expect(result.results).toBeDefined();
            expect(result.results.length).toBeGreaterThan(0);
            expect(result.results[0].verified).toBe(true);

            console.log('✅ User verification successful!\n');
        }, 30000);
    });

    describe('Scenario 2: User presents credential to System B', () => {
        test('System B verifies credential from System A', async () => {
            console.log('='.repeat(70));
            console.log('🏢 SCENARIO 2: System B - Partner Premium Service');
            console.log('='.repeat(70) + '\n');

            console.log('👤 User accessing System B...');
            console.log('🎫 User presents VIP credential from System A\n');

            console.log('🔍 System B verifying credential...');
            console.log('   ⏳ Checking BBS signature');
            console.log('   ⏳ Verifying issuer (System A DID)');
            console.log('   ⏳ Checking expiration date');
            console.log('   ⏳ Validating credential structure\n');

            // System B verifies credential
            const verificationResult = await verifyCredential(vip1Credential);

            // Detailed validation
            expect(verificationResult.verified).toBe(true);
            expect(verificationResult.results).toBeDefined();

            // Check credential data
            expect(vip1Credential.issuer).toBe(systemADID);
            expect(vip1Credential.credentialSubject.id).toBe(userDID);

            const { customerTier } = vip1Credential.credentialSubject;

            expect(customerTier.tierLevel).toBe('VIP1');
            expect(customerTier.accountId).toBe('SYSCUST-12345');

            console.log('✅ VERIFICATION SUCCESSFUL!\n');
            console.log('📊 Verified information:');
            console.log(`   Issuer: ${vip1Credential.issuer} (System A)`);
            console.log(`   Subject: ${vip1Credential.credentialSubject.id} (User)`);
            console.log(`   Tier Level: ${customerTier.tierLevel}`);
            console.log(`   Account ID: ${customerTier.accountId}`);
            console.log(`   Total Spent: ${customerTier.totalSpent}`);
            console.log(`   Member Since: ${customerTier.memberSince}\n`);

            console.log('🎉 ACCESS GRANTED!');
            console.log('   ✓ User VIP1 status verified on System A');
            console.log('   ✓ Unlocking premium features on System B');
            console.log('   ✓ Applying 20% discount');
            console.log('   ✓ Activating priority customer support\n');
        }, 30000);

        test('SECURITY: System B rejects tampered credential', async () => {
            console.log('='.repeat(70));
            console.log('🔒 SECURITY TEST: Tamper Detection');
            console.log('='.repeat(70) + '\n');

            console.log('⚠️  Simulating attack: Changing tier VIP1 → VIP3\n');

            // Attacker modifies credential
            const tamperedCredential = {
                ...vip1Credential,
                credentialSubject: {
                    ...vip1Credential.credentialSubject,
                    customerTier: {
                        ...vip1Credential.credentialSubject.customerTier,
                        tierLevel: 'VIP3', // MODIFIED!
                    },
                },
            };

            console.log('🔍 System B verifying tampered credential...\n');

            const result = await verifyCredential(tamperedCredential);

            // Must fail verification
            expect(result.verified).toBe(false);

            console.log('✅ ATTACK BLOCKED!');
            console.log('   System B detected credential tampering');
            console.log('   BBS signature verification failed');
            console.log('   → Access denied\n');
        }, 30000);

        test('SECURITY: System B rejects expired credential', async () => {
            console.log('='.repeat(70));
            console.log('🔒 SECURITY TEST: Expiration Validation');
            console.log('='.repeat(70) + '\n');

            console.log('⏰ Creating credential with past expiration date\n');

            // Create expired credential
            const expiredCredential = createCustomerTierCredential(
                systemADID,
                userDID,
                'VIP1',
                {
                    issuanceDate: new Date('2023-01-01').toISOString(),
                    expirationDate: new Date('2023-12-31').toISOString(), // Expired
                },
            );

            // Sign expired credential
            const signedExpired = await issueCredential(systemAKeyDoc, expiredCredential);

            console.log('🔍 System B verifying expired credential...\n');

            const result = await verifyCredential(signedExpired);

            // Must fail due to expiration
            expect(result.verified).toBe(false);
            expect(result.error).toBeDefined();
            expect(result.error.message).toMatch(/expired/i);

            console.log('✅ EXPIRED CREDENTIAL REJECTED!');
            console.log(`   Error: ${result.error.message}`);
            console.log('   → Access denied\n');
        }, 30000);
    });


    describe('Summary', () => {
        test('Test case summary', () => {
            console.log('='.repeat(70));
            console.log('📝 TESTCASE 3 SUMMARY');
            console.log('='.repeat(70) + '\n');

            console.log('✅ Features tested:');
            console.log('   1. ✓ System A issued VIP1 credential with BBS');
            console.log('   2. ✓ User verified received credential');
            console.log('   3. ✓ System B verified credential from System A');
            console.log('   4. ✓ Detected and rejected tampered credential');
            console.log('   5. ✓ Detected and rejected expired credential\n');

            console.log('🔐 Security:');
            console.log('   • BBS Signatures for privacy');
            console.log('   • Tamper detection working correctly');
            console.log('   • Expiration date validated');
            console.log('   • DID-based authentication\n');

            console.log('💡 Use Case:');
            console.log('   Cross-platform loyalty program with cryptographic proof');
            console.log('   User can prove VIP status from one platform');
            console.log('   to another without sharing raw data\n');

            console.log('🔧 Technology Stack:');
            console.log('   • ethr-did (Ethereum-based DIDs)');
            console.log('   • BBS Signatures (Privacy-preserving)');
            console.log('   • W3C Verifiable Credentials\n');
        });
    });
});
