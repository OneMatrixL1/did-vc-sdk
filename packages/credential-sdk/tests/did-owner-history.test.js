import 'dotenv/config';
import { JsonRpcProvider } from 'ethers';
import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { DIDServiceClient } from '../src/api-client';
import { EthrDIDModule } from '../src/modules/ethr-did';
import { Secp256k1Keypair } from '../src/keypairs';
import { verifyBLSSignature, publicKeyToAddress, createChangeOwnerWithPubkeyHash, DEFAULT_CHAIN_ID, DEFAULT_REGISTRY_ADDRESS, keypairToAddress } from '../src/modules/ethr-did/utils';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { getUncompressedG2PublicKey } from '../src/modules/ethr-did/bbs-uncompressed';

// Configuration from environment (required for integration tests)
const networkConfig = {
    name: process.env.ETHR_NETWORK || 'vietchain',
    rpcUrl: process.env.ETHR_NETWORK_RPC_URL,
    registry:
        process.env.ETHR_REGISTRY_ADDRESS
        || '0x8697547b3b82327B70A90C6248662EC083ad5A62', // VietChain default
};

/**
 * Usage:
 * ------
 * ETHR_PRIVATE_KEY=0x... \
 * ETHR_NETWORK_RPC_URL=https://rpc.vietcha.in \
 * ETHR_REGISTRY_ADDRESS=0x8697547b3b82327B70A90C6248662EC083ad5A62 \
 * yarn jest tests/did-owner-history.test.js
 */
describe('DIDServiceClient Owner History Verification', () => {
    let module = new EthrDIDModule({
        networks: [networkConfig],
        defaultNetwork: networkConfig.name,
    });
    let gasPayerKeypair;
    let did;
    let initialBBSKeypair;

    beforeAll(async () => {
        await initializeWasm();

        // Create module with test network
        if (process.env.ETHR_PRIVATE_KEY) {
            // Load gas payer keypair from environment
            const privateKeyBytes = Buffer.from(
                process.env.ETHR_PRIVATE_KEY.replace('0x', ''),
                'hex',
            );
            gasPayerKeypair = new Secp256k1Keypair(privateKeyBytes, 'private');

            initialBBSKeypair = Bls12381BBSKeyPairDock2023.generate({ id: 'initial-owner' });
            did = await module.createNewDID(initialBBSKeypair);
            console.log(`Created DID for integration test: ${did}`);
        }
    });

    test('generates valid signatures for each transition (Mock Fallback)', async () => {
        const client = new DIDServiceClient();
        const identityAddress = '0x28FB2e9be9838a7eF5Dcb0D90c6E7a98124360EE';
        const did = `did:ethr:${identityAddress}`;
        const history = await client.getDIDOwnerHistory(did);
        console.log("history off chain: ", history);

        expect(history.length).toBeGreaterThan(0);

        for (const [i, record] of history.entries()) {
            if (i > 0) {
                const prevRecord = history[i - 1];
                expect(record.message.oldOwner).toBe(prevRecord.message.newOwner);
            }

            const hash = createChangeOwnerWithPubkeyHash(
                record.message.identity,
                record.message.oldOwner,
                record.message.newOwner,
                DEFAULT_CHAIN_ID,
                DEFAULT_REGISTRY_ADDRESS
            );

            const publicKeyBytes = Buffer.from(record.publicKey.slice(2), 'hex');
            const signatureBytes = Buffer.from(record.signature.slice(2), 'hex');

            const derivedAddress = publicKeyToAddress(publicKeyBytes);
            expect(derivedAddress).toBe(record.message.oldOwner);

            const isValid = verifyBLSSignature(signatureBytes, hash, publicKeyBytes);
            expect(isValid).toBe(true);
        }
    });

    test('initializes with provider and verifies 3 on-chain transitions', async () => {
        if (!networkConfig.rpcUrl || !process.env.ETHR_PRIVATE_KEY) {
            console.warn('Skipping on-chain test: ETHR_NETWORK_RPC_URL or ETHR_PRIVATE_KEY not set');
            return;
        }

        const provider = new JsonRpcProvider(networkConfig.rpcUrl);
        const client = new DIDServiceClient(undefined, {
            provider,
            registry: networkConfig.registry
        });

        const expectedHistory = [];
        let currentBBSKeypair = initialBBSKeypair;

        // Perform 3 transitions
        for (let i = 1; i <= 3; i++) {
            const nextBBSKeypair = Bls12381BBSKeyPairDock2023.generate({ id: `owner-${i}` });
            const nextOwnerAddress = keypairToAddress(nextBBSKeypair);

            console.log(`Transition ${i}: changing owner to ${nextOwnerAddress}`);

            const receipt = await module.changeOwnerWithPubkey(
                did,
                nextOwnerAddress,
                currentBBSKeypair,
                gasPayerKeypair,
            );
            expect(receipt.status).toBe(1);

            const uncompressedPubkey = getUncompressedG2PublicKey(currentBBSKeypair.publicKeyBuffer);
            expectedHistory.push({
                oldOwner: keypairToAddress(currentBBSKeypair),
                newOwner: nextOwnerAddress,
                publicKey: `0x${Buffer.from(uncompressedPubkey).toString('hex')}`
            });

            currentBBSKeypair = nextBBSKeypair;
        }

        // Fetch history using the client
        const history = await client.getDIDOwnerHistory(did);
        console.log(`Fetched on-chain history for ${did}:`, JSON.stringify(history, null, 2));

        // Verify the history
        expect(history.length).toBe(3);
        const chainId = (await provider.getNetwork()).chainId;

        for (let i = 0; i < 3; i++) {
            const record = history[i];
            const expected = expectedHistory[i];

            // Verify message content matches expectations from transactions
            expect(record.message.identity.toLowerCase()).toBe(did.split(':').pop().toLowerCase());
            expect(record.message.oldOwner.toLowerCase()).toBe(expected.oldOwner.toLowerCase());
            expect(record.message.newOwner.toLowerCase()).toBe(expected.newOwner.toLowerCase());
            expect(record.publicKey.toLowerCase()).toBe(expected.publicKey.toLowerCase());

            // 1. Verify ownership continuity: newOwner[i-1] === oldOwner[i]
            if (i > 0) {
                const prevRecord = history[i - 1];
                expect(record.message.oldOwner.toLowerCase()).toBe(prevRecord.message.newOwner.toLowerCase());
            }

            // 2. Verify BLS Signature using the record's data
            const hash = createChangeOwnerWithPubkeyHash(
                record.message.identity,
                record.message.oldOwner,
                record.message.newOwner,
                Number(chainId),
                networkConfig.registry
            );

            const publicKeyBytes = Buffer.from(record.publicKey.slice(2), 'hex');
            const signatureBytes = Buffer.from(record.signature.slice(2), 'hex');

            const isValid = verifyBLSSignature(signatureBytes, hash, publicKeyBytes);
            expect(isValid).toBe(true);
        }
    }, 300000); // 5 minute timeout for 3 transactions
});
