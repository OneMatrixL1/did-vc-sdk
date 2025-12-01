
import { EthrDIDModule, createVietChainConfig } from '../src/modules/ethr-did';
import { ETHR_BBS_KEY_ID } from '../src/modules/ethr-did/utils';

// Mock network cache to avoid real network calls
jest.mock('../src/modules/ethr-did/config', () => ({
    validateModuleConfig: jest.fn(),
    normalizeNetworkConfig: (config) => config,
}));

describe('Ethr DID BBS "Graduation" Logic', () => {
    let module;
    const did = 'did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61';
    const implicitKeyId = `${did}${ETHR_BBS_KEY_ID}`;

    beforeEach(() => {
        module = new EthrDIDModule({
            networks: [{ name: 'vietchain', rpcUrl: 'http://localhost:8545' }],
            defaultNetwork: 'vietchain',
        });
    });

    test('Scenario 1: Default State (No on-chain data)', async () => {
        // Mock resolver to return a clean DID document
        const mockResolve = jest.spyOn(module.resolver, 'resolve').mockResolvedValue({
            didDocument: {
                id: did,
                verificationMethod: [],
                assertionMethod: [`${did}#controller`],
            },
            didDocumentMetadata: {
                // No versionId implies no on-chain data
            },
        });

        const doc = await module.getDocument(did);

        // Implicit key SHOULD be added
        expect(doc.assertionMethod).toContain(implicitKeyId);
    });

    test('Scenario 2: Graduated State (Has on-chain data, but NO explicit BBS key)', async () => {
        // Mock resolver to return a DID document with on-chain history (versionId set)
        // e.g. someone added a secp256k1 delegate
        const mockResolve = jest.spyOn(module.resolver, 'resolve').mockResolvedValue({
            didDocument: {
                id: did,
                verificationMethod: [{
                    id: `${did}#delegate-1`,
                    type: 'EcdsaSecp256k1RecoveryMethod2020',
                    controller: did,
                }],
                assertionMethod: [`${did}#controller`, `${did}#delegate-1`],
            },
            didDocumentMetadata: {
                versionId: '123', // Simulates on-chain data
            },
        });

        const doc = await module.getDocument(did);

        // Implicit key SHOULD STILL be added (The Fix)
        // In the old logic, presence of versionId would prevent this.
        expect(doc.assertionMethod).toContain(implicitKeyId);
    });

    test('Scenario 3: Explicit State (Has explicit BBS key)', async () => {
        // Mock resolver to return a DID document with an explicit BBS key
        const mockResolve = jest.spyOn(module.resolver, 'resolve').mockResolvedValue({
            didDocument: {
                id: did,
                verificationMethod: [{
                    id: `${did}#my-explicit-bbs-key`,
                    type: 'Bls12381BBSVerificationKeyDock2023', // Explicit BBS type
                    controller: did,
                }],
                assertionMethod: [`${did}#controller`, `${did}#my-explicit-bbs-key`],
            },
            didDocumentMetadata: {
                versionId: '124',
            },
        });

        const doc = await module.getDocument(did);

        // Implicit key SHOULD NOT be added because explicit one exists
        expect(doc.assertionMethod).not.toContain(implicitKeyId);
        expect(doc.assertionMethod).toContain(`${did}#my-explicit-bbs-key`);
    });
});
