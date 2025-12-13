/**
 * TESTCASE 2: KYC Credential with Age and Location Predicates
 *
 * Scenario:
 * - System A issues KYC credential to User with BBS signature
 * - User creates derived credential proving age > 18 and birthPlace = "Hanoi"
 * - System B verifies the derived credential without seeing actual birthDate
 *
 * This test uses:
 * - BBS signatures with predicate proofs
 * - Age verification without revealing exact birth date
 * - Location verification with selective disclosure
 * - Optimistic verification (no blockchain RPC, real HTTP for contexts)
 *
 * Run: npm test -- testcase2
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

const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';
const BBS_V1 = 'https://ld.truvera.io/security/bbs23/v1';
const VIETCHAIN_NETWORK = 'vietchain';
const VIETCHAIN_CHAIN_ID = 84005;

const networkConfig = {
    name: VIETCHAIN_NETWORK,
    rpcUrl: 'https://rpc.vietcha.in',
    registry: '0xF0889fb2473F91c068178870ae2e1A0408059A03',
    chainId: VIETCHAIN_CHAIN_ID,
};

const KYC_CONTEXT = 'https://raw.githubusercontent.com/OneMatrixL1/did-vc-sdk/testcase2/packages/credential-sdk/tests/testcase2/kyc-context.json';

describe('TESTCASE 2: KYC Credential Verification', () => {
    let systemAKeypair;
    let systemADID;
    let systemAKeyDoc;

    let userKeypair;
    let userDID;

    let systemBModule;

    let kycCredential;

    beforeAll(async () => {
        await initializeWasm();

        systemAKeypair = Bls12381BBSKeyPairDock2023.generate({
            id: 'system-a-key',
            controller: 'temp',
        });

        systemADID = addressToDID(keypairToAddress(systemAKeypair), VIETCHAIN_NETWORK);

        systemAKeyDoc = {
            id: `${systemADID}#keys-bbs`,
            controller: systemADID,
            type: Bls12381BBS23DockVerKeyName,
            keypair: systemAKeypair,
        };

        expect(systemADID).toMatch(/^did:ethr:vietchain:0x[0-9a-fA-F]{40}$/);

        userKeypair = Bls12381BBSKeyPairDock2023.generate({
            id: 'user-key',
            controller: 'temp',
        });

        userDID = addressToDID(keypairToAddress(userKeypair), VIETCHAIN_NETWORK);

        systemBModule = new EthrDIDModule({
            networks: [networkConfig],
        });
    }, 30000);

    describe('Scenario 1: System A issues KYC credential', () => {
        test('System A issues KYC credential to user with BBS signature', async () => {
            const birthDate = new Date('2000-05-15');

            const unsignedCredential = {
                '@context': [
                    CREDENTIALS_V1,
                    BBS_V1,
                    KYC_CONTEXT,
                ],
                type: ['VerifiableCredential', 'KYCCredential'],
                id: 'urn:uuid:kyc-cred-12345',
                issuer: systemADID,
                issuanceDate: new Date().toISOString(),
                credentialSubject: {
                    id: userDID,
                    fullName: 'Nguyen Van A',
                    birthDate: birthDate.toISOString(),
                    birthPlace: 'Hanoi',
                    nationality: 'Vietnamese',
                    idNumber: 'CCCD123456789',
                },
            };

            kycCredential = await issueCredential(systemAKeyDoc, unsignedCredential);

            expect(kycCredential).toBeDefined();
            expect(kycCredential.issuer).toBe(systemADID);
            expect(kycCredential.credentialSubject.fullName).toBe('Nguyen Van A');
            expect(kycCredential.credentialSubject.birthPlace).toBe('Hanoi');
            expect(kycCredential.proof).toBeDefined();
            expect(kycCredential.proof.type).toBe('Bls12381BBSSignatureDock2023');
            expect(kycCredential.proof.publicKeyBase58).toBeDefined();
        }, 30000);
    });

    describe('Scenario 2: User proves age > 18 and birthPlace = Hanoi to System B', () => {
        test('User creates derived credential revealing birthPlace and proving age > 18', async () => {
            const { default: Presentation } = await import('../src/vc/presentation');
            const presentation = new Presentation();

            await presentation.addCredentialToPresent(kycCredential);

            presentation.addAttributeToReveal(0, [
                'credentialSubject.id',
                'credentialSubject.birthPlace',
                'credentialSubject.nationality',
            ]);

            const currentYear = new Date().getFullYear();
            const eighteenYearsAgo = new Date(currentYear - 18, 0, 1);

            const bounds = {
                birthDate: {
                    max: eighteenYearsAgo.toISOString(),
                },
            };

            const derivedCredentials = presentation.deriveCredentials({
                nonce: 'nonce-kyc-123',
                bounds,
            });

            expect(derivedCredentials.length).toBe(1);
            const derivedCred = derivedCredentials[0];

            const result = await verifyCredentialOptimistic(derivedCred, {
                module: systemBModule,
            });

            expect(result.verified).toBe(true);
            expect(result.results[0].verified).toBe(true);

            expect(derivedCred.credentialSubject.birthPlace).toBe('Hanoi');
            expect(derivedCred.credentialSubject.nationality).toBe('Vietnamese');

            expect(derivedCred.credentialSubject.birthDate).toBeUndefined();
            expect(derivedCred.credentialSubject.fullName).toBeUndefined();
            expect(derivedCred.credentialSubject.idNumber).toBeUndefined();
        }, 30000);

        test('SECURITY: System B rejects derived credential with tampered birthPlace', async () => {
            const { default: Presentation } = await import('../src/vc/presentation');
            const presentation = new Presentation();

            await presentation.addCredentialToPresent(kycCredential);
            presentation.addAttributeToReveal(0, ['credentialSubject.birthPlace']);

            const derivedCredentials = presentation.deriveCredentials({
                nonce: 'nonce-tamper',
            });

            const tamperedCred = {
                ...derivedCredentials[0],
                credentialSubject: {
                    ...derivedCredentials[0].credentialSubject,
                    birthPlace: 'Ho Chi Minh',
                },
            };

            const result = await verifyCredentialOptimistic(tamperedCred, {
                module: systemBModule,
            });

            expect(result.verified).toBe(false);
        }, 30000);

        test('User proves only birthPlace without age predicate', async () => {
            const { default: Presentation } = await import('../src/vc/presentation');
            const presentation = new Presentation();

            await presentation.addCredentialToPresent(kycCredential);

            presentation.addAttributeToReveal(0, [
                'credentialSubject.id',
                'credentialSubject.birthPlace',
            ]);

            const derivedCredentials = presentation.deriveCredentials({
                nonce: 'nonce-location-only',
            });

            expect(derivedCredentials.length).toBe(1);
            const derivedCred = derivedCredentials[0];

            const result = await verifyCredentialOptimistic(derivedCred, {
                module: systemBModule,
            });

            expect(result.verified).toBe(true);

            expect(derivedCred.credentialSubject.birthPlace).toBe('Hanoi');
            expect(derivedCred.credentialSubject.birthDate).toBeUndefined();
            expect(derivedCred.credentialSubject.fullName).toBeUndefined();
            expect(derivedCred.credentialSubject.idNumber).toBeUndefined();
            expect(derivedCred.credentialSubject.nationality).toBeUndefined();
        }, 30000);
    });
});
