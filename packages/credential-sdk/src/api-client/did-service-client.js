import { keccak256, toUtf8Bytes, concat, Interface, Contract } from 'ethers';
import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { EthereumDIDRegistry } from 'ethr-did-resolver';
import AbstractApiClient from './abstract';
import Bls12381BBSKeyPairDock2023 from '../vc/crypto/Bls12381BBSKeyPairDock2023';
import { signWithBLSKeypair, keypairToAddress, createChangeOwnerWithPubkeyHash, DEFAULT_CHAIN_ID, DEFAULT_REGISTRY_ADDRESS } from '../modules/ethr-did/utils';

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

        // Parse DID to extract address
        // Expected format: did:ethr:network:address or did:ethr:address
        const parseDIDAddress = (didString) => {
            const parts = didString.split(':');
            // Get the last part which should be the address
            let address = parts[parts.length - 1];

            // Normalize address - add 0x prefix if not present
            if (!address.startsWith('0x')) {
                address = '0x' + address;
            }

            // Validate it looks like an Ethereum address (with or without 0x prefix)
            if (!address || !address.match(/^0x[a-fA-F0-9]{40}$/)) {
                // Invalid format, return null instead of throwing error
                console.warn(`Invalid DID format: unable to extract valid address from ${didString}`);
                return null;
            }

            return address;
        };

        const identity = parseDIDAddress(did);

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

        // 2. Fallback to on-chain if provider is available
        if (this.provider) {
            return this._fetchOwnerHistoryOnChain(identity);
        }

        // 3. Last fallback: Mock data (original behavior for backward compatibility/demo)
        return this._getMockDIDOwnerHistory(identity);
    }

    /**
     * Fetch owner history directly from EthereumDIDRegistry contract
     * @param {string} identity - Ethereum address of the DID
     * @returns {Promise<Array>} Owner history
     * @private
     */
    async _fetchOwnerHistoryOnChain(identity) {
        const registry = new Contract(this.registryAddress, EthereumDIDRegistry.abi, this.provider);
        const iface = new Interface(EthereumDIDRegistry.abi);

        const history = [];
        let previousChange = await registry.changed(identity);

        while (previousChange > 0n) {
            const blockNumber = Number(previousChange);
            const topics = iface.encodeFilterTopics('DIDOwnerChanged', [identity]);

            const logs = await this.provider.getLogs({
                address: this.registryAddress,
                topics,
                fromBlock: blockNumber,
                toBlock: blockNumber,
            });

            const log = logs[0];
            if (!log) break;

            const event = iface.parseLog(log);
            const { previousChange: nextPreviousChange } = event.args;

            // Extract public key and signature if it was a changeOwnerWithPubkey call
            const tx = await this.provider.getTransaction(log.transactionHash);
            try {
                const decodedTx = iface.parseTransaction({ data: tx.data });
                if (decodedTx?.name === 'changeOwnerWithPubkey') {
                    const { identity: identityArg, oldOwner, newOwner, publicKey, signature } = decodedTx.args;

                    history.unshift({
                        signature: signature,
                        publicKey: publicKey,
                        message: {
                            identity: identityArg,
                            oldOwner: oldOwner,
                            newOwner: newOwner,
                        },
                        // blockNumber: blockNumber,
                        // transactionHash: log.transactionHash
                    });
                }
            } catch (e) {
                console.debug(`Skipping non-pubkey transition at block ${blockNumber}`);
            }

            previousChange = nextPreviousChange;
        }

        return history;
    }

    /**
     * Original mock implementation moved to separate method
     * @param {string} identity - Identity address
     * @returns {Promise<Array>} Mock history
     * @private
     */
    async _getMockDIDOwnerHistory(identity) {
        // Initialize WASM for BBS operations
        await initializeWasm();

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

            history.push({
                signature: `0x${Buffer.from(signature).toString('hex')}`,
                publicKey: `0x${Buffer.from(transition.signer.publicKeyBuffer).toString('hex')}`,
                message: {
                    identity,
                    oldOwner: transition.from,
                    newOwner: transition.to
                }
            });
        }

        return history;
    }

}

export default DIDServiceClient;

