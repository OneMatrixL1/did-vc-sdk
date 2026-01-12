import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { DIDServiceClient } from '../src/api-client';
import { verifyBLSSignature, publicKeyToAddress, createChangeOwnerWithPubkeyHash, DEFAULT_CHAIN_ID, DEFAULT_REGISTRY_ADDRESS } from '../src/modules/ethr-did/utils';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';

describe('DIDServiceClient Mock History Verification', () => {
    beforeAll(async () => {
        await initializeWasm();
    });

    test('generates valid signatures for each transition', async () => {
        const client = new DIDServiceClient();
        const identityAddress = '0x1234567890123456789012345678901234567890';
        const did = `did:ethr:${identityAddress}`;
        const history = await client.getDIDOwnerHistory(did);
        console.log(history);

        const DEFAULT_CHAIN_ID = 1337;
        const DEFAULT_REGISTRY_ADDRESS = '0x8697547b3b82327B70A90C6248662EC083ad5A62';

        for (const [i, record] of history.entries()) {
            // Verify ownership continuity: newOwner[i-1] === oldOwner[i]
            if (i > 0) {
                const prevRecord = history[i - 1];
                expect(record.message.oldOwner).toBe(prevRecord.message.newOwner);
            }

            // Re-calculate hash using the shared utility
            const hash = createChangeOwnerWithPubkeyHash(
                record.message.identity,
                record.message.oldOwner,
                record.message.newOwner,
                DEFAULT_CHAIN_ID,
                DEFAULT_REGISTRY_ADDRESS
            );

            // Convert hex strings to Uint8Array
            const publicKeyBytes = Buffer.from(record.publicKey.slice(2), 'hex');
            const signatureBytes = Buffer.from(record.signature.slice(2), 'hex');

            // Verify that the old owner address in the message matches the provided public key
            const derivedAddress = publicKeyToAddress(publicKeyBytes);
            expect(derivedAddress).toBe(record.message.oldOwner);

            const isValid = verifyBLSSignature(signatureBytes, hash, publicKeyBytes);
            expect(isValid).toBe(true);
        }
    });
});
