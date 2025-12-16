/**
 * TESTCASE 1: Basic Verifiable Credential with BBS Selective Disclosure
 *
 * Scenario:
 * - Issuer issues a basic verifiable credential to User using BBS signature
 * - User (Holder) creates derived credential revealing specific attributes
 * - Verifier verifies the derived credential using Optimistic verification
 *
 * This test uses:
 * - BBS signatures for Issuer
 * - BBS Selective Disclosure for User presentation
 * - Optimistic verification (no blockchain RPC, real HTTP for contexts)
 *
 * Run: npm test -- testcase1
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import {
    issueCredential,
    VerifiablePresentation,
} from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName, EcdsaSecp256k1RecoveryMethod2020Name } from '../src/vc/crypto/constants';
import { Secp256k1Keypair } from '../src/keypairs';
import {
    EthrDIDModule,
    addressToDID,
    keypairToAddress,
    verifyPresentationOptimistic,
} from '../src/modules/ethr-did';

// Constants
const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';
const BBS_V1 = 'https://ld.truvera.io/security/bbs23/v1';
const VIETCHAIN_NETWORK = 'vietchain';
const VIETCHAIN_CHAIN_ID = 84005;

// Network configuration
const networkConfig = {
    name: VIETCHAIN_NETWORK,
    rpcUrl: 'https://rpc.vietcha.in',
    registry: '0xF0889fb2473F91c068178870ae2e1A0408059A03',
    chainId: VIETCHAIN_CHAIN_ID,
};

// Custom context URL
const CUSTOM_CONTEXT = 'https://raw.githubusercontent.com/OneMatrixL1/did-vc-sdk/testcase1/packages/credential-sdk/tests/testcase1/example-context.json';

describe('TESTCASE 1: Basic Verifiable Credential', () => {
    // Issuer - BBS keypair
    let issuerKeypair;
    let issuerDID;
    let issuerKeyDoc;

    // User (Holder) - Secp256k1 keypair
    let userKeypair;
    let userDID;
    let userKeyDoc;

    // Verifier
    let verifierModule;

    // Credential
    let credential;

    beforeAll(async () => {
        await initializeWasm();

        // ========== Issuer with BBS ==========
        issuerKeypair = Bls12381BBSKeyPairDock2023.generate({
            id: 'issuer-key',
            controller: 'temp',
        });

        issuerDID = addressToDID(keypairToAddress(issuerKeypair), VIETCHAIN_NETWORK);

        issuerKeyDoc = {
            id: `${issuerDID}#keys-bbs`,
            controller: issuerDID,
            type: Bls12381BBS23DockVerKeyName,
            keypair: issuerKeypair,
        };

        // ========== User (Holder) with Secp256k1 ==========
        userKeypair = Secp256k1Keypair.random();
        userDID = addressToDID(keypairToAddress(userKeypair), VIETCHAIN_NETWORK);

        // Create userKeyDoc for VP signing
        const userPublicKeyBytes = userKeypair._publicKey();
        const userPublicKeyBase58 = b58.encode(userPublicKeyBytes);

        userKeyDoc = {
            id: `${userDID}#controller`,
            controller: userDID,
            type: EcdsaSecp256k1RecoveryMethod2020Name,
            keypair: userKeypair,
            publicKeyBase58: userPublicKeyBase58,
        };

        // ========== Verifier ==========
        verifierModule = new EthrDIDModule({
            networks: [networkConfig],
        });
    }, 30000);

    describe('Scenario 1: Issuer issues credential', () => {
        test('Issuer issues passport credential to user with BBS signature', async () => {
            const unsignedCredential = {
                '@context': [CREDENTIALS_V1, BBS_V1, CUSTOM_CONTEXT],
                type: ['VerifiableCredential', 'ExampleCredential'],
                id: 'urn:uuid:cred-example-12345',
                issuer: issuerDID,
                issuanceDate: new Date().toISOString(),
                credentialSubject: {
                    id: userDID,
                    firstName: 'John',
                    lastName: 'Doe',
                    birthDate: '1990-01-15',
                    birthPlace: 'New York, USA',
                    sex: 'Male',
                    nationality: 'American',
                    citizenship: 'USA',
                    passportNumber: 'P123456789',
                    passportIssueDate: '2020-01-01',
                    passportExpiryDate: '2030-01-01',
                    passportIssuingCountry: 'USA',
                    permanentAddress: '123 Main St, New York, NY 10001',
                },
            };

            credential = await issueCredential(issuerKeyDoc, unsignedCredential);

            expect(credential).toBeDefined();
            expect(credential.issuer).toBe(issuerDID);
            expect(credential.credentialSubject.firstName).toBe('John');
            expect(credential.proof.type).toBe('Bls12381BBSSignatureDock2023');
        }, 30000);
    });

    describe('Scenario 2: User presents VP to Verifier', () => {
        test('User creates VP with selective disclosure (reveal 4 fields)', async () => {
            // 1. User prepares selective disclosure
            const { default: Presentation } = await import('../src/vc/presentation');
            const bbsPresentation = new Presentation();

            await bbsPresentation.addCredentialToPresent(credential);

            // 2. Reveal only 4 fields (hide sensitive: passport, address)
            bbsPresentation.addAttributeToReveal(0, [
                'credentialSubject.id',
                'credentialSubject.firstName',
                'credentialSubject.lastName',
                'credentialSubject.nationality',
            ]);

            // 3. Derive credential (BBS ZK proof)
            const derivedCredentials = bbsPresentation.deriveCredentials({
                nonce: 'nonce-123',
            });

            expect(derivedCredentials.length).toBe(1);
            const derivedCred = derivedCredentials[0];

            // 4. Validate revealed fields
            expect(derivedCred.credentialSubject.firstName).toBe('John');
            expect(derivedCred.credentialSubject.lastName).toBe('Doe');
            expect(derivedCred.credentialSubject.nationality).toBe('American');

            // Hidden fields
            expect(derivedCred.credentialSubject.passportNumber).toBeUndefined();
            expect(derivedCred.credentialSubject.permanentAddress).toBeUndefined();

            // 5. Wrap derived credential in VP
            const challenge = 'challenge-from-verifier-123';
            const domain = 'https://verifier.example.com';

            const vp = new VerifiablePresentation('urn:uuid:vp-basic-123');
            vp.addContext(BBS_V1);
            vp.addContext(CUSTOM_CONTEXT);
            vp.setHolder(userDID);
            vp.addCredential(derivedCred);

            // 6. User signs VP with Secp256k1 key
            await vp.sign(userKeyDoc, challenge, domain);

            // 7. Verifier verifies VP
            const result = await verifyPresentationOptimistic(vp.toJSON(), {
                module: verifierModule,
                challenge,
                domain,
            });

            expect(result.verified).toBe(true);
        }, 30000);

        test('SECURITY: VP with tampered credential is rejected', async () => {
            const { default: Presentation } = await import('../src/vc/presentation');
            const presentation = new Presentation();

            await presentation.addCredentialToPresent(credential);
            presentation.addAttributeToReveal(0, ['credentialSubject.firstName']);

            const derivedCredentials = presentation.deriveCredentials({
                nonce: 'nonce-tamper',
            });

            // Tamper firstName
            const tamperedCred = {
                ...derivedCredentials[0],
                credentialSubject: {
                    ...derivedCredentials[0].credentialSubject,
                    firstName: 'Hacker',  // TAMPERED!
                },
            };

            // Wrap in VP
            const challenge = 'challenge-tamper';
            const domain = 'https://verifier.example.com';

            const vp = new VerifiablePresentation('urn:uuid:vp-tampered');
            vp.addContext(BBS_V1);
            vp.addContext(CUSTOM_CONTEXT);
            vp.setHolder(userDID);
            vp.addCredential(tamperedCred);

            await vp.sign(userKeyDoc, challenge, domain);

            // Verification fails - BBS proof doesn't match
            const result = await verifyPresentationOptimistic(vp.toJSON(), {
                module: verifierModule,
                challenge,
                domain,
            });

            expect(result.verified).toBe(false);
        }, 30000);

        test('🚨 ATTACK: Attacker steals credential - SDK does NOT auto-check holder', async () => {
            // 1. User creates valid derived credential
            const { default: Presentation } = await import('../src/vc/presentation');
            const userPresentation = new Presentation();
            await userPresentation.addCredentialToPresent(credential);
            userPresentation.addAttributeToReveal(0, [
                'credentialSubject.id',
                'credentialSubject.firstName',
            ]);

            const derivedCredentials = userPresentation.deriveCredentials({
                nonce: 'nonce-stolen',
            });

            const stolenCred = derivedCredentials[0];

            // 2. Attacker creates their own keypair
            const attackerKeypair = Secp256k1Keypair.random();
            const attackerDID = addressToDID(keypairToAddress(attackerKeypair), VIETCHAIN_NETWORK);

            const attackerKeyDoc = {
                id: `${attackerDID}#controller`,
                controller: attackerDID,
                type: EcdsaSecp256k1RecoveryMethod2020Name,
                keypair: attackerKeypair,
                publicKeyBase58: b58.encode(attackerKeypair._publicKey()),
            };

            // 3. Attacker creates VP with stolen credential
            const challenge = 'challenge-attack';
            const domain = 'https://verifier.example.com';

            const attackerVP = new VerifiablePresentation('urn:uuid:vp-attacker');
            attackerVP.addContext(BBS_V1);
            attackerVP.addContext(CUSTOM_CONTEXT);
            attackerVP.setHolder(attackerDID);  // Attacker's DID
            attackerVP.addCredential(stolenCred);  // Stolen credential

            await attackerVP.sign(attackerKeyDoc, challenge, domain);

            // SDK verification PASSES
            const result = await verifyPresentationOptimistic(attackerVP.toJSON(), {
                module: verifierModule,
                challenge,
                domain,
            });

            expect(result.verified).toBe(true);

            // VP holder is ATTACKER but credential subject is USER
            expect(attackerVP.holder).toBe(attackerDID);
            expect(stolenCred.credentialSubject.id).toBe(userDID);
            expect(attackerVP.holder).not.toBe(stolenCred.credentialSubject.id);
        }, 30000);

        test('✅ SECURE: Manual holder check prevents stolen credential attack', async () => {
            function verifyHolderBinding(vpJson) {
                const holder = vpJson.holder;
                const creds = vpJson.verifiableCredential || [];

                for (const cred of creds) {
                    const subjectId = cred.credentialSubject?.id;

                    if (subjectId && subjectId !== holder) {
                        throw new Error(
                            `Holder binding mismatch: VP holder is ${holder}, ` +
                            `but credential subject is ${subjectId}`
                        );
                    }
                }

                return true;
            }

            // Attacker's VP
            const { default: Presentation } = await import('../src/vc/presentation');
            const userPresentation = new Presentation();
            await userPresentation.addCredentialToPresent(credential);
            userPresentation.addAttributeToReveal(0, ['credentialSubject.id', 'credentialSubject.firstName']);

            const derivedCredentials = userPresentation.deriveCredentials({ nonce: 'nonce-secure' });
            const stolenCred = derivedCredentials[0];

            const attackerKeypair = Secp256k1Keypair.random();
            const attackerDID = addressToDID(keypairToAddress(attackerKeypair), VIETCHAIN_NETWORK);

            const attackerKeyDoc = {
                id: `${attackerDID}#controller`,
                controller: attackerDID,
                type: EcdsaSecp256k1RecoveryMethod2020Name,
                keypair: attackerKeypair,
                publicKeyBase58: b58.encode(attackerKeypair._publicKey()),
            };

            const attackerVP = new VerifiablePresentation('urn:uuid:vp-attacker-2');
            attackerVP.addContext(BBS_V1);
            attackerVP.addContext(CUSTOM_CONTEXT);
            attackerVP.setHolder(attackerDID);
            attackerVP.addCredential(stolenCred);

            await attackerVP.sign(attackerKeyDoc, 'challenge-secure', 'https://verifier.example.com');

            const vpJson = attackerVP.toJSON();

            // SDK verification passes
            const result = await verifyPresentationOptimistic(vpJson, {
                module: verifierModule,
                challenge: 'challenge-secure',
                domain: 'https://verifier.example.com',
            });

            expect(result.verified).toBe(true);

            // BUT manual holder check FAILS!
            expect(() => verifyHolderBinding(vpJson)).toThrow('Holder binding mismatch');
        }, 30000);
    });
});
