/**
 * TESTCASE: changeOwnerBLS Flow Test
 *
 * Use Case:
 * - Test the BLS12-381 signature-based ownership transfer for ethr DIDs
 * - BBS keypair can change DID ownership using BLS signatures verified on-chain
 *
 * Flow:
 * 1. Generate a BBS keypair
 * 2. Derive identity (Ethereum address) from BBS public key
 * 3. Create message: abi.encodePacked(identity, newOwner, nonce, chainId)
 * 4. Sign with BLS: hashToPoint(DST, keccak256(message)) * secretKey
 * 5. Submit changeOwnerBLS transaction to the registry contract
 *
 * Contract:
 * - EthereumDIDRegistry with BLS support: 0x23f935167613bB06F4C6e997197B866E668E71AB
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { ethers } from 'ethers';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Secp256k1Keypair } from '../src/keypairs';
import {
    EthrDIDModule,
    addressToDID,
    keypairToAddress,
    bbsPublicKeyToAddress,
} from '../src/modules/ethr-did';

// =============================================================================
// Constants
// =============================================================================

const VIETCHAIN_NETWORK = 'vietchain';
const VIETCHAIN_CHAIN_ID = 84005;
const BLS_DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_';

// BLS-enabled registry contract
const BLS_REGISTRY_ADDRESS = '0x61d67c3D219c3Eb4B4B5AC9a5bB9c8646bb065Eb';

const NETWORK_CONFIG = {
    name: VIETCHAIN_NETWORK,
    rpcUrl: 'https://rpc.vietcha.in',
    registry: BLS_REGISTRY_ADDRESS,
    chainId: VIETCHAIN_CHAIN_ID,
};

// =============================================================================
// Test Suite
// =============================================================================

describe('TESTCASE: changeOwnerBLS Flow', () => {
    let ethrModule;
    let provider;
    let bbsKeypair;
    let bbsAddress;
    let bbsDID;

    beforeAll(async () => {
        await initializeWasm();

        // Initialize EthrDIDModule with BLS-enabled registry
        ethrModule = new EthrDIDModule({
            networks: [NETWORK_CONFIG],
            defaultNetwork: VIETCHAIN_NETWORK,
        });

        // Create provider for direct contract interaction
        provider = new ethers.providers.JsonRpcProvider(NETWORK_CONFIG.rpcUrl);

        // Generate BBS keypair
        bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
            id: 'test-bbs-key',
            controller: 'temp',
        });

        // Derive address and DID from BBS public key
        bbsAddress = bbsPublicKeyToAddress(bbsKeypair.publicKeyBuffer);
        bbsDID = addressToDID(bbsAddress, VIETCHAIN_NETWORK);
    }, 30000);

    // ===========================================================================
    // Unit Tests: Keypair Methods
    // ===========================================================================

    describe('Bls12381BBSKeyPairDock2023 BLS Methods', () => {
        test('publicKeyHex returns correct format', () => {
            const pubKeyHex = bbsKeypair.publicKeyHex;

            // Should be 0x-prefixed
            expect(pubKeyHex.startsWith('0x')).toBe(true);

            // Should be 192 characters (96 bytes * 2)
            expect(pubKeyHex.length).toBe(194); // 0x + 192

            // Should only contain hex characters
            expect(/^0x[0-9a-fA-F]+$/.test(pubKeyHex)).toBe(true);
        });

        test('publicKeyHex matches publicKeyBuffer', () => {
            const pubKeyHex = bbsKeypair.publicKeyHex;
            const expectedHex = `0x${Array.from(bbsKeypair.publicKeyBuffer)
                .map((b) => b.toString(16).padStart(2, '0'))
                .join('')}`;

            expect(pubKeyHex).toBe(expectedHex);
        });

        test('signBLS throws without private key', async () => {
            // Create keypair with only public key
            const publicOnlyKeypair = new Bls12381BBSKeyPairDock2023({
                publicKeyBase58: require('bs58').encode(bbsKeypair.publicKeyBuffer),
            });

            const messageHash = ethers.utils.arrayify(
                ethers.utils.keccak256('0x1234'),
            );

            expect(() => publicOnlyKeypair.signBLS(messageHash, BLS_DST)).toThrow(
                /No private key/,
            );
        });

        test('signBLS returns valid signature (48 bytes compressed G1)', async () => {
            const messageHash = ethers.utils.arrayify(
                ethers.utils.keccak256('0x1234567890abcdef'),
            );

            const signature = bbsKeypair.signBLS(messageHash, BLS_DST);

            // G1 point compressed is 48 bytes, but some implementations use 96
            // Check that it's a Uint8Array with reasonable length
            expect(signature).toBeInstanceOf(Uint8Array);
            expect(signature.length).toBeGreaterThanOrEqual(48);
        });

        test('signBLS accepts string DST', async () => {
            const messageHash = ethers.utils.arrayify(
                ethers.utils.keccak256('0xabcdef'),
            );

            // Should not throw when DST is a string
            const signature = bbsKeypair.signBLS(messageHash, BLS_DST);

            expect(signature).toBeInstanceOf(Uint8Array);
        });

        test('signBLS accepts Uint8Array DST', async () => {
            const messageHash = ethers.utils.arrayify(
                ethers.utils.keccak256('0xfedcba'),
            );
            const dstBytes = new TextEncoder().encode(BLS_DST);

            // Should not throw when DST is Uint8Array
            const signature = bbsKeypair.signBLS(messageHash, dstBytes);

            expect(signature).toBeInstanceOf(Uint8Array);
        });

        test('signatureToHex converts correctly', async () => {
            const messageHash = ethers.utils.arrayify(
                ethers.utils.keccak256('0x123456'),
            );
            const signature = bbsKeypair.signBLS(messageHash, BLS_DST);

            const sigHex = Bls12381BBSKeyPairDock2023.signatureToHex(signature);

            // Should be 0x-prefixed
            expect(sigHex.startsWith('0x')).toBe(true);

            // Should match manual conversion
            const expectedHex = `0x${Array.from(signature)
                .map((b) => b.toString(16).padStart(2, '0'))
                .join('')}`;

            expect(sigHex).toBe(expectedHex);
        });

        test('same message + DST produces same signature', async () => {
            const messageHash = ethers.utils.arrayify(
                ethers.utils.keccak256('0xdeadbeef'),
            );

            const sig1 = bbsKeypair.signBLS(messageHash, BLS_DST);
            const sig2 = bbsKeypair.signBLS(messageHash, BLS_DST);

            expect(Array.from(sig1)).toEqual(Array.from(sig2));
        });

        test('different messages produce different signatures', async () => {
            const hash1 = ethers.utils.arrayify(ethers.utils.keccak256('0x1111'));
            const hash2 = ethers.utils.arrayify(ethers.utils.keccak256('0x2222'));

            const sig1 = bbsKeypair.signBLS(hash1, BLS_DST);
            const sig2 = bbsKeypair.signBLS(hash2, BLS_DST);

            expect(Array.from(sig1)).not.toEqual(Array.from(sig2));
        });

        test('different DSTs produce different signatures', async () => {
            const messageHash = ethers.utils.arrayify(
                ethers.utils.keccak256('0xabcd'),
            );

            const sig1 = bbsKeypair.signBLS(messageHash, 'DST_ONE');
            const sig2 = bbsKeypair.signBLS(messageHash, 'DST_TWO');

            expect(Array.from(sig1)).not.toEqual(Array.from(sig2));
        });
    });

    // ===========================================================================
    // Unit Tests: Message Construction
    // ===========================================================================

    describe('Message Construction (matching contract)', () => {
        test('identity derived correctly from BBS public key', () => {
            // bbsAddress should be a valid Ethereum address
            expect(bbsAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);

            // Should be consistent
            const address2 = bbsPublicKeyToAddress(bbsKeypair.publicKeyBuffer);

            expect(bbsAddress.toLowerCase()).toBe(address2.toLowerCase());
        });

        test('message packing matches contract logic', () => {
            const identity = bbsAddress;
            const newOwner = '0x1234567890123456789012345678901234567890';
            const nonce = 0;
            const chainId = VIETCHAIN_CHAIN_ID;

            // Pack message: abi.encodePacked(identity, newOwner, nonce, chainId)
            const packed = ethers.utils.solidityPack(
                ['address', 'address', 'uint256', 'uint256'],
                [identity, newOwner, nonce, chainId],
            );

            // Should be 20 + 20 + 32 + 32 = 104 bytes = 208 hex chars + 0x
            expect(packed.length).toBe(210);

            // Should contain identity at the beginning
            expect(packed.toLowerCase()).toContain(identity.toLowerCase().slice(2));
        });

        test('keccak256 hash produces 32 bytes', () => {
            const packed = ethers.utils.solidityPack(
                ['address', 'address', 'uint256', 'uint256'],
                [bbsAddress, '0x0000000000000000000000000000000000000001', 0, VIETCHAIN_CHAIN_ID],
            );

            const hash = ethers.utils.keccak256(packed);
            const hashBytes = ethers.utils.arrayify(hash);

            expect(hashBytes.length).toBe(32);
        });
    });

    // ===========================================================================
    // Integration Tests: Contract Interaction
    // ===========================================================================

    describe('Contract Interaction', () => {
        test('can read nonce from contract', async () => {
            const registryAbi = ['function nonce(address identity) view returns (uint256)'];
            const registry = new ethers.Contract(
                BLS_REGISTRY_ADDRESS,
                registryAbi,
                provider,
            );

            const nonce = await registry.nonce(bbsAddress);

            expect(nonce).toBeDefined();
            expect(typeof nonce.toNumber()).toBe('number');
        }, 30000);

        test('can get chainId from provider', async () => {
            const network = await provider.getNetwork();

            expect(network.chainId).toBe(VIETCHAIN_CHAIN_ID);
        }, 10000);

        test('changeOwnerBLS method exists on module', () => {
            expect(typeof ethrModule.changeOwnerBLS).toBe('function');
        });

        test('changeOwnerBLS validates keypair has signBLS', async () => {
            // Create a fake keypair without signBLS method
            const fakeKeypair = {
                publicKeyBuffer: bbsKeypair.publicKeyBuffer,
                // Missing signBLS method
            };

            await expect(
                ethrModule.changeOwnerBLS(fakeKeypair, '0x0000000000000000000000000000000000000001'),
            ).rejects.toThrow(/signBLS/);
        });

        test('changeOwnerBLS validates keypair has publicKeyHex', async () => {
            const fakeKeypair = {
                signBLS: async () => new Uint8Array(96),
                // Missing publicKeyHex and address
            };

            await expect(
                ethrModule.changeOwnerBLS(fakeKeypair, '0x0000000000000000000000000000000000000001'),
            ).rejects.toThrow(/publicKeyHex/);
        });
    });

    // ===========================================================================
    // End-to-End Flow Test (requires funded account)
    // ===========================================================================

    describe('E2E: changeOwnerBLS Full Flow', () => {
        test('can construct full changeOwnerBLS message and signature', async () => {
            const newOwnerAddress = '0x0000000000000000000000000000000000000001';

            // Step 1: Get nonce
            const registryAbi = ['function nonce(address identity) view returns (uint256)'];
            const registry = new ethers.Contract(
                BLS_REGISTRY_ADDRESS,
                registryAbi,
                provider,
            );
            const nonce = await registry.nonce(bbsAddress);

            // Step 2: Get chainId
            const { chainId } = await provider.getNetwork();

            // Step 3: Pack message
            const packed = ethers.utils.solidityPack(
                ['address', 'address', 'uint256', 'uint256'],
                [bbsAddress, newOwnerAddress, nonce, chainId],
            );

            // Step 4: Sign with BLS
            const packedUint8Array = ethers.utils.arrayify(packed);

            const signature = await bbsKeypair.signBLS(packedUint8Array, BLS_DST);

            // Step 5: Convert to hex for contract
            const pubKeyHex = bbsKeypair.publicKeyHex;
            const sigHex = Bls12381BBSKeyPairDock2023.signatureToHex(signature);

            // Verify outputs
            expect(pubKeyHex).toMatch(/^0x[0-9a-fA-F]{192}$/);
            expect(sigHex).toMatch(/^0x[0-9a-fA-F]+$/);
            expect(sigHex.length).toBeGreaterThanOrEqual(98); // 0x + at least 48 bytes

            console.log('=== changeOwnerBLS Test Data ===');
            console.log('Identity:', bbsAddress);
            console.log('New Owner:', newOwnerAddress);
            console.log('Nonce:', nonce.toString());
            console.log('Chain ID:', chainId);
            console.log('Packed Message:', packed);
            console.log('Public Key (hex):', pubKeyHex);
            console.log('Signature (hex):', sigHex);
        }, 30000);

        test('changeOwnerBLS requires txSigner parameter', async () => {
            // Import Bls12381Keypair for this test
            const { Bls12381Keypair } = await import('../src/keypairs');
            const testKeypair = await Bls12381Keypair.generate();

            await expect(
                ethrModule.changeOwnerBLS(
                    testKeypair,
                    '0x0000000000000000000000000000000000000001',
                    {}, // No txSigner provided
                ),
            ).rejects.toThrow(/txSigner is required/);
        });

        // This test actually calls the contract - requires ETHR_PRIVATE_KEY env var
        const hasPrivateKey = !!process.env.ETHR_PRIVATE_KEY;

        (hasPrivateKey ? test : test.skip)(
            'changeOwnerBLS submits transaction successfully',
            async () => {
                // Import Bls12381Keypair for pure BLS (standard G2 derivation)
                const { Bls12381Keypair } = await import('../src/keypairs');

                // Create funded keypair from environment variable (for gas payment)
                const privateKeyBytes = Buffer.from(
                    process.env.ETHR_PRIVATE_KEY,
                    'hex',
                );
                const fundedKeypair = new Secp256k1Keypair(privateKeyBytes, 'private');

                // Generate pure BLS12-381 keypair (NOT BBS)
                const blsKeypair = await Bls12381Keypair.generate();

                // Generate new random address as new owner
                const newOwnerKeypair = Secp256k1Keypair.random();
                const newOwnerAddress = keypairToAddress(newOwnerKeypair);

                // Call changeOwnerBLS with the funded keypair as txSigner
                const receipt = await ethrModule.changeOwnerBLS(
                    blsKeypair,
                    newOwnerAddress,
                    { txSigner: fundedKeypair },
                );

                console.log('Transaction Hash:', receipt.transactionHash);
                console.log('Block Number:', receipt.blockNumber);
                console.log('Status:', receipt.status);

                expect(receipt.transactionHash).toBeDefined();
                expect(receipt.status).toBe(1);
            },
            60000,
        );
    });
});
