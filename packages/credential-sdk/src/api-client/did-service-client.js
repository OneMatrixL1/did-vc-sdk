import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import AbstractApiClient from './abstract';
import Bls12381BBSKeyPairDock2023 from '../vc/crypto/Bls12381BBSKeyPairDock2023';
import { keypairToAddress, createChangeOwnerWithPubkeyHash, DEFAULT_CHAIN_ID, signWithBLSKeypair, parseDID } from '../modules/ethr-did/utils';
import { DEFAULT_REGISTRY_ADDRESS } from '../vc/constants';
import { concat, keccak256, getAddress } from 'ethers';
import EthrDIDModule from '../modules/ethr-did/module';

// Default base URL for the API service
const DEFAULT_BASE_URL = 'https://api.example.com';

/**
 * DID Service API Client
 * Provides methods to interact with DID-related API services
 * Can be extended with more API methods as needed
 */
class DIDServiceClient extends AbstractApiClient {
    /**
     * @param {string} [baseUrl] - Base URL of the API service (optional, uses default if not provided)
     * @param {object} [options] - Additional options
     * @param {import('ethers').Provider} [options.provider] - Ethers provider for on-chain fallback
     * @param {string} [options.registry] - DID Registry contract address (optional, uses default if not provided)
     */
    constructor(baseUrl = DEFAULT_BASE_URL, options = {}) {
        super(baseUrl, options);
        this.provider = options.provider || null;
        this.registryAddress = options.registry || DEFAULT_REGISTRY_ADDRESS;
    }

    /**
     * Get DID owner history with signature and message
     * @param {string} did - The DID identifier
     * @returns {Promise<Array<{signature: string, message: {identity: string, oldOwner: string, newOwner: string}}>>}
     * Returns array of objects, each containing:
     * - signature: string - The cryptographic signature
     * - message: object with:
     *   - identity: string - Address (uint160) of the identity (DID address)
     *   - oldOwner: string - Address (uint160) of the previous owner
     *   - newOwner: string - Address (uint160) of the new owner
     * Example: [
     *   {
     *     signature: '0x123...',
     *     publicKey: '0x456...',
     *     message: {
     *       identity: '0x742d...',
     *       oldOwner: '0x0000...',
     *       newOwner: '0xA1B2...'
     *     }
     *   },
     *   ...
     * ]
     */
    async getDIDOwnerHistory(did) {
        this._validateParams({ did }, ['did']);

        // Parse DID to extract identity components
        const parsed = parseDID(did);
        let identity = parsed.address;
        let pId = null;

        if (parsed.isDualAddress) {
            identity = concat([parsed.secp256k1Address, parsed.bbsAddress]);
            const hash = keccak256(identity);
            pId = getAddress('0x' + hash.slice(-40));
        }

        // If DID format is invalid, return empty array (no owner history available)
        if (!identity) {
            return [];
        }

        try {
            // 1. Try to fetch from API
            const history = await this.get(`/did/${did}/owner-history`);
            if (history && Array.isArray(history) && history.length > 0) {
                return history;
            }
        } catch (error) {
            console.warn(`Failed to fetch DID owner history from API: ${error.message}. Falling back to on-chain.`);
        }

        if (this.provider) {
            const { network } = parseDID(did);
            const networkName = network || 'vietchain';

            const networkConfig = {
                name: networkName,
                rpcUrl: 'http://localhost', // Satisfy validation, provider is injected below
                registry: this.registryAddress,
            };

            const module = new EthrDIDModule({
                networks: [networkConfig],
                defaultNetwork: networkName,
            });

            // Inject existing provider into the module
            module.providers.set(networkName, this.provider);
            return module.getOwnerHistory(did);
        }

        // 3. Last fallback: Mock data (original behavior for backward compatibility/demo)
        return this._getMockDIDOwnerHistory(identity);
    }

    /**
     * Original mock implementation moved to separate method
     * @param {string} identity - Identity address or raw 40-byte identity
     * @returns {Promise<Array>} Mock history
     * @private
     */
    async _getMockDIDOwnerHistory(identity) {
        // Initialize WASM for BBS operations
        await initializeWasm();

        // Detect if identity is a Dual DID (40 bytes hex string)
        let pId = null;
        if (identity && identity.length === 82) {
            const hash = keccak256(identity);
            pId = getAddress('0x' + hash.slice(-40));
        }

        // Generate a chain of owners and sign the transitions
        // We use consistent IDs for deterministic mock data per DID
        const keypair0 = Bls12381BBSKeyPairDock2023.generate({ id: `${identity}-owner-0` });
        const keypair1 = Bls12381BBSKeyPairDock2023.generate({ id: `${identity}-owner-1` });
        const keypair2 = Bls12381BBSKeyPairDock2023.generate({ id: `${identity}-owner-2` });
        const keypair3 = Bls12381BBSKeyPairDock2023.generate({ id: `${identity}-owner-3` });

        const addr0 = keypairToAddress(keypair0);
        const addr1 = keypairToAddress(keypair1);
        const addr2 = keypairToAddress(keypair2);
        const addr3 = keypairToAddress(keypair3);

        const transitions = [
            { from: addr0, to: addr1, signer: keypair0 },
            { from: addr1, to: addr2, signer: keypair1 },
            { from: addr2, to: addr3, signer: keypair2 }
        ];

        const history = [];
        for (const transition of transitions) {
            const hash = createChangeOwnerWithPubkeyHash(
                identity,
                transition.from,
                transition.to,
                DEFAULT_CHAIN_ID,
                this.registryAddress
            );

            // Sign the hash with BLS keypair
            const signature = await signWithBLSKeypair(hash, transition.signer);

            const message = {
                identity,
                oldOwner: transition.from,
                newOwner: transition.to,
            };

            if (pId) {
                message.pId = pId;
            }

            history.push({
                signature: `0x${Buffer.from(signature).toString('hex')}`,
                publicKey: `0x${Buffer.from(transition.signer.publicKeyBuffer).toString('hex')}`,
                message,
            });
        }

        return history;
    }

}

export default DIDServiceClient;
