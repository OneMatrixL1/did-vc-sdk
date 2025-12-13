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
import {
    issueCredential,
} from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import {
    EthrDIDModule,
    addressToDID,
    keypairToAddress,
    verifyCredentialOptimistic,
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
    // Issuer
    let issuerKeypair;
    let issuerDID;
    let issuerKeyDoc;

    // User (Holder)
    let userKeypair;
    let userDID;

    // Verifier - uses EthrDIDModule
    let verifierModule;

    // Credentials
    let credential;

    beforeAll(async () => {
        // Initialize WASM for BBS operations
        await initializeWasm();

        // ========== Setup Issuer with BBS ==========
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

        expect(issuerDID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);

        // ========== Setup User (Holder) with BBS ==========
        userKeypair = Bls12381BBSKeyPairDock2023.generate({
            id: 'user-key',
            controller: 'temp',
        });

        userDID = addressToDID(keypairToAddress(userKeypair), VIETCHAIN_NETWORK);

        // ========== Setup Verifier ==========
        verifierModule = new EthrDIDModule({
            networks: [networkConfig],
        });
    }, 30000);

    describe('Scenario 1: Issuer issues credential', () => {
        test('Issuer issues credential to user with BBS signature', async () => {
            const unsignedCredential = {
                '@context': [
                    CREDENTIALS_V1,
                    BBS_V1,
                    CUSTOM_CONTEXT,
                ],
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
            expect(credential.credentialSubject.lastName).toBe('Doe');
            expect(credential.credentialSubject.passportNumber).toBe('P123456789');
            expect(credential.proof).toBeDefined();
            expect(credential.proof.type).toBe('Bls12381BBSSignatureDock2023');
            expect(credential.proof.publicKeyBase58).toBeDefined();
        }, 30000);
    });

    describe('Scenario 2: User presents credential to Verifier', () => {
        test('User creates derived credential revealing specific attributes', async () => {
            // 1. User prepares Presentation with Selective Disclosure
            const { default: Presentation } = await import('../src/vc/presentation');
            const presentation = new Presentation();

            // 2. Add credential and select attributes to reveal
            await presentation.addCredentialToPresent(credential);

            // Reveal specific fields (selective disclosure)
            presentation.addAttributeToReveal(0, [
                'credentialSubject.id',
                'credentialSubject.firstName',
                'credentialSubject.lastName',
                'credentialSubject.birthDate',
                'credentialSubject.nationality',
                // Note: passportNumber and other sensitive fields are NOT revealed
            ]);

            // 3. Derive credentials (this generates the ZK proof)
            const derivedCredentials = presentation.deriveCredentials({
                nonce: 'nonce-123',
            });

            expect(derivedCredentials.length).toBe(1);
            const derivedCred = derivedCredentials[0];

            // 4. Verifier verifies the derived credential using Optimistic verification
            const result = await verifyCredentialOptimistic(derivedCred, {
                module: verifierModule,
            });

            expect(result.verified).toBe(true);
            expect(result.results[0].verified).toBe(true);

            // Validate revealed data is present
            expect(derivedCred.credentialSubject.firstName).toBe('John');
            expect(derivedCred.credentialSubject.lastName).toBe('Doe');
            expect(derivedCred.credentialSubject.birthDate).toBe('1990-01-15');
            expect(derivedCred.credentialSubject.nationality).toBe('American');

            // Validate sensitive fields are NOT revealed (selective disclosure)
            expect(derivedCred.credentialSubject.passportNumber).toBeUndefined();
            expect(derivedCred.credentialSubject.permanentAddress).toBeUndefined();
        }, 30000);

        test('SECURITY: Verifier rejects derived credential with tampered values', async () => {
            const { default: Presentation } = await import('../src/vc/presentation');
            const presentation = new Presentation();

            await presentation.addCredentialToPresent(credential);
            presentation.addAttributeToReveal(0, ['credentialSubject.firstName']);

            const derivedCredentials = presentation.deriveCredentials({
                nonce: 'nonce-bad',
            });

            // Tamper with the derived credential
            const tamperedCred = {
                ...derivedCredentials[0],
                credentialSubject: {
                    ...derivedCredentials[0].credentialSubject,
                    firstName: 'Hacker', // TAMPERED!
                },
            };

            const result = await verifyCredentialOptimistic(tamperedCred, {
                module: verifierModule,
            });

            expect(result.verified).toBe(false);
        }, 30000);
    });
});
