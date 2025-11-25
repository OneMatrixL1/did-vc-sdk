/**
 * EthrDIDModule - Module for managing ethr DIDs on Ethereum-compatible chains
 * @module ethr-did/module
 */

import { ethers } from 'ethers';
import { EthrDID } from 'ethr-did';
import { getResolver } from 'ethr-did-resolver';
import { Resolver as DIDResolver } from 'did-resolver';
import AbstractDIDModule from '../abstract/did/module';
import {
  validateModuleConfig,
  normalizeNetworkConfig,
} from './config';
import {
  createProvider,
  createSigner,
  addressToDID,
  parseDID,
  keypairToAddress,
  waitForTransaction,
  documentToAttributes,
  formatEthersError,
  isEthrDID,
} from './utils';

/**
 * EthrDIDModule extends AbstractDIDModule to provide ethr DID management
 * on Ethereum-compatible chains.
 *
 * @example
 * import { EthrDIDModule } from '@docknetwork/credential-sdk/modules/ethr-did';
 * import { Secp256k1Keypair } from '@docknetwork/credential-sdk/keypairs';
 *
 * // Configure for custom network
 * const module = new EthrDIDModule({
 *   networks: [{
 *     name: 'vietchain',
 *     rpcUrl: 'https://rpc.vietcha.in',
 *     registry: '0x50CbD0618e556655D902E6C3210eB97Aa8Fd0ED0'
 *   }],
 *   defaultNetwork: 'vietchain'
 * });
 *
 * // Create a new DID
 * const keypair = Secp256k1Keypair.random();
 * const did = await module.createNewDID(keypair);
 */
class EthrDIDModule extends AbstractDIDModule {
  /**
   * Create EthrDIDModule instance
   * @param {import('./config').ModuleConfig} config - Module configuration
   */
  constructor(config) {
    // Pass null as apiProvider since we don't use blockchain API pattern
    super(null);

    // Validate configuration
    validateModuleConfig(config);

    // Normalize and store network configurations
    this.networks = new Map();
    config.networks.forEach((networkConfig) => {
      const normalized = normalizeNetworkConfig(networkConfig);
      this.networks.set(normalized.name, normalized);
    });

    // Set default network - handle both string and object network configs
    if (config.defaultNetwork) {
      this.defaultNetwork = config.defaultNetwork;
    } else {
      // Get name from first network (handle both string and object)
      const firstNetwork = config.networks[0];
      this.defaultNetwork = typeof firstNetwork === 'string'
        ? firstNetwork
        : firstNetwork.name;
    }

    // Store provider options
    this.providerOptions = config.providerOptions || {};

    // Initialize providers cache
    this.providers = new Map();

    // Initialize resolver
    this.#initializeResolver();
  }

  /**
   * Returns the DID methods supported by this module
   * @returns {Array<string>} Array of supported DID method names
   */
  methods() {
    return ['ethr'];
  }

  /**
   * Initialize DID resolver with all configured networks
   */
  #initializeResolver() {
    const resolverConfig = {
      networks: Array.from(this.networks.values()).map((network) => ({
        name: network.name,
        rpcUrl: network.rpcUrl,
        registry: network.registry,
        chainId: network.chainId,
      })),
    };

    this.resolver = new DIDResolver(getResolver(resolverConfig));
  }

  /**
   * Check if this module supports resolving a given DID
   * @param {string} id - DID string or DID URL to check
   * @returns {boolean} True if this module can resolve the DID
   */
  supports(id) {
    if (typeof id !== 'string') {
      return false;
    }

    // Check if it's an ethr DID (may include fragment #key-id)
    if (!id.startsWith('did:ethr:')) {
      return false;
    }

    // Parse and check if network is supported
    // Strip fragment if present (e.g., did:ethr:network:address#key-1 -> did:ethr:network:address)
    try {
      const didWithoutFragment = id.split('#')[0];
      const { network } = parseDID(didWithoutFragment);
      const networkName = network || this.defaultNetwork;
      return this.networks.has(networkName);
    } catch (e) {
      return false;
    }
  }

  /**
   * Resolve a DID or DID URL - used by document loader
   * @param {string} id - DID string or DID URL (with fragment) to resolve
   * @returns {Promise<Object>} DID Document or Verification Method
   */
  async resolve(id) {
    // Check if there's a fragment (verification method reference)
    const fragmentIndex = id.indexOf('#');
    if (fragmentIndex !== -1) {
      const did = id.substring(0, fragmentIndex);
      const fragment = id.substring(fragmentIndex);

      // Get the full DID document
      const didDocument = await this.getDocument(did);

      // Find the verification method with matching ID
      const verificationMethod = didDocument.verificationMethod?.find(
        (vm) => vm.id === id || vm.id === fragment || vm.id.endsWith(fragment),
      );

      if (verificationMethod) {
        // Return verification method with context to preserve all fields during JSON-LD framing
        return {
          '@context': [
            'https://www.w3.org/ns/did/v1',
            'https://w3id.org/security/v2',
          ],
          ...verificationMethod,
        };
      }

      throw new Error(`Verification method not found: ${id}`);
    }

    // No fragment, return full DID document
    return this.getDocument(id);
  }

  /**
   * Get provider for a specific network
   * @param {string} [networkName] - Network name (uses default if not specified)
   * @returns {ethers.providers.JsonRpcProvider} Provider instance
   */
  #getProvider(networkName = null) {
    const name = networkName || this.defaultNetwork;

    if (!this.networks.has(name)) {
      throw new Error(`Unknown network: ${name}`);
    }

    // Return cached provider if exists
    if (this.providers.has(name)) {
      return this.providers.get(name);
    }

    // Create and cache new provider
    const networkConfig = this.networks.get(name);
    const provider = createProvider(networkConfig, this.providerOptions);
    this.providers.set(name, provider);

    return provider;
  }

  /**
   * Create EthrDID instance for operations
   * @param {import('../../keypairs/keypair-secp256k1').default} keypair - Secp256k1 keypair
   * @param {string} [networkName] - Network name
   * @returns {Promise<EthrDID>} EthrDID instance
   */
  async #createEthrDID(keypair, networkName = null) {
    const name = networkName || this.defaultNetwork;
    const networkConfig = this.networks.get(name);
    const provider = this.#getProvider(name);

    if (!networkConfig) {
      throw new Error(`Network not found: ${name}`);
    }

    const address = keypairToAddress(keypair);
    const signer = createSigner(keypair, provider);

    const ethrDidConfig = {
      identifier: address,
      provider,
      registry: networkConfig.registry,
      chainNameOrId: networkConfig.chainId || name,
      txSigner: signer,
    };

    return new EthrDID(ethrDidConfig);
  }

  /**
   * Set attributes on-chain sequentially to avoid nonce conflicts
   * @param {EthrDID} ethrDid - EthrDID instance
   * @param {Array} attributes - Array of {key, value} objects
   * @param {string} did - DID string
   * @returns {Object} Transaction object with promise
   */
  #setAttributesSequentially(ethrDid, attributes, did) {
    return {
      promise: (async () => {
        for (const attr of attributes) {
          // eslint-disable-next-line no-await-in-loop
          await ethrDid.setAttribute(attr.key, attr.value);
        }
        return { did };
      })(),
      did,
      attributes,
    };
  }

  /**
   * Override signAndSend for Ethereum transaction handling
   * @param {Object} tx - Transaction object from *Tx methods
   * @param {Object} params - Additional parameters
   * @returns {Promise<Object>} Transaction receipt
   */
  async signAndSend(tx, params = {}) {
    try {
      const { confirmations = 1 } = params;

      if (!tx || !tx.promise) {
        throw new Error('Invalid transaction object');
      }

      // Execute the transaction promise
      const txResponse = await tx.promise;

      // Handle no-op transactions (e.g., createDocumentTx with no attributes)
      if (!txResponse.wait) {
        return {
          txHash: null,
          blockNumber: null,
          success: true,
          ...txResponse,
        };
      }

      // Wait for confirmation
      const receipt = await txResponse.wait(confirmations);

      return {
        txHash: receipt.transactionHash,
        blockNumber: receipt.blockNumber,
        success: true,
        ...receipt,
      };
    } catch (error) {
      throw new Error(`Transaction failed: ${formatEthersError(error)}`);
    }
  }

  /**
   * Create a new ethr DID (convenience method)
   * @param {import('../../keypairs/keypair-secp256k1').default} keypair - Secp256k1 keypair
   * @param {string} [networkName] - Network name (uses default if not specified)
   * @returns {Promise<string>} The created DID string
   */
  async createNewDID(keypair, networkName = null) {
    const name = networkName || this.defaultNetwork;

    // Validate network exists
    if (!this.networks.has(name)) {
      throw new Error(`Unknown network: ${name}`);
    }

    const address = keypairToAddress(keypair);
    return addressToDID(address, name !== 'mainnet' ? name : null);
  }

  /**
   * Generate transaction to create a DID document with custom attributes
   * This sets additional attributes beyond the default controller
   * @param {Object} didDocument - DID Document to create
   * @param {import('../../keypairs/did-keypair').default} didKeypair - DID keypair for signing
   * @returns {Promise<Object>} Transaction object
   */
  async createDocumentTx(didDocument, didKeypair) {
    const did = String(didDocument.id);

    if (!isEthrDID(did)) {
      throw new Error(`Not an ethr DID: ${did}`);
    }

    const { network } = parseDID(did);
    const networkName = network || this.defaultNetwork;

    // Get the keypair (unwrap from DidKeypair if needed)
    const keypair = didKeypair.keyPair || didKeypair;

    // Create EthrDID instance
    const ethrDid = await this.#createEthrDID(keypair, networkName);

    // Convert document to attributes
    const attributes = documentToAttributes(didDocument);

    // If no additional attributes, just return the DID (it exists by default)
    if (attributes.length === 0) {
      return {
        promise: Promise.resolve({ did }),
        did,
      };
    }

    // Set attributes on-chain sequentially to avoid nonce conflicts
    return this.#setAttributesSequentially(ethrDid, attributes, did);
  }

  /**
   * Generate transaction to update a DID document
   * @param {Object} didDocument - Updated DID Document
   * @param {import('../../keypairs/did-keypair').default} didKeypair - DID keypair for signing
   * @returns {Promise<Object>} Transaction object
   */
  async updateDocumentTx(didDocument, didKeypair) {
    const did = String(didDocument.id);

    if (!isEthrDID(did)) {
      throw new Error(`Not an ethr DID: ${did}`);
    }

    const { network } = parseDID(did);
    const networkName = network || this.defaultNetwork;

    // Get the keypair
    const keypair = didKeypair.keyPair || didKeypair;

    // Create EthrDID instance
    const ethrDid = await this.#createEthrDID(keypair, networkName);

    // Convert document to attributes
    const attributes = documentToAttributes(didDocument);

    if (attributes.length === 0) {
      throw new Error('No attributes to update in DID document');
    }

    // Update attributes on-chain sequentially to avoid nonce conflicts
    return this.#setAttributesSequentially(ethrDid, attributes, did);
  }

  /**
   * Generate transaction to remove/revoke a DID
   * Note: ethr DIDs cannot be fully deleted, but we can revoke all delegates
   * @param {string} did - DID to remove
   * @param {import('../../keypairs/did-keypair').default} didKeypair - DID keypair for signing
   * @returns {Promise<Object>} Transaction object
   */
  async removeDocumentTx(did, didKeypair) {
    const didString = String(did);

    if (!isEthrDID(didString)) {
      throw new Error(`Not an ethr DID: ${didString}`);
    }

    const { network } = parseDID(didString);
    const networkName = network || this.defaultNetwork;

    // Get the keypair
    const keypair = didKeypair.keyPair || didKeypair;

    // Create EthrDID instance
    const ethrDid = await this.#createEthrDID(keypair, networkName);

    // Revoke the owner's delegate status (effectively deactivates the DID)
    const promise = ethrDid.revokeDelegate(keypairToAddress(keypair), 'veriKey');

    return {
      promise,
      did: didString,
    };
  }

  /**
   * Retrieve a DID document
   * @param {string} did - DID to retrieve
   * @returns {Promise<Object>} DID Document
   */
  async getDocument(did) {
    const didString = String(did);

    if (!isEthrDID(didString)) {
      throw new Error(`Not an ethr DID: ${didString}`);
    }

    try {
      const result = await this.resolver.resolve(didString);

      if (result.didResolutionMetadata?.error) {
        throw new Error(
          `Failed to resolve DID: ${result.didResolutionMetadata.error}`,
        );
      }

      if (!result.didDocument) {
        throw new Error(`DID document not found: ${didString}`);
      }

      return result.didDocument;
    } catch (error) {
      throw new Error(`Failed to get DID document: ${formatEthersError(error)}`);
    }
  }

  /**
   * Add a delegate to a DID (additional signing key)
   * @param {string} did - DID to update
   * @param {string} delegateAddress - Ethereum address of the delegate
   * @param {import('../../keypairs/keypair-secp256k1').default} keypair - Owner's keypair
   * @param {Object} options - Additional options
   * @param {string} [options.delegateType='veriKey'] - Type of delegate
   * @param {number} [options.expiresIn=86400] - Validity in seconds
   * @returns {Promise<Object>} Transaction receipt
   */
  async addDelegate(did, delegateAddress, keypair, options = {}) {
    const { delegateType = 'veriKey', expiresIn = 86400 } = options;

    const { network } = parseDID(did);
    const networkName = network || this.defaultNetwork;

    const provider = this.#getProvider(networkName);

    // Ensure address is checksummed to avoid ENS lookups
    const checksummedAddress = ethers.utils.getAddress(delegateAddress);

    const ethrDid = await this.#createEthrDID(keypair, networkName);
    const txHash = await ethrDid.addDelegate(checksummedAddress, { delegateType, expiresIn });
    return await waitForTransaction(txHash, provider);
  }

  /**
   * Revoke a delegate from a DID
   * @param {string} did - DID to update
   * @param {string} delegateAddress - Ethereum address of the delegate
   * @param {import('../../keypairs/keypair-secp256k1').default} keypair - Owner's keypair
   * @param {string} [delegateType='veriKey'] - Type of delegate
   * @returns {Promise<Object>} Transaction receipt
   */
  async revokeDelegate(did, delegateAddress, keypair, delegateType = 'veriKey') {
    const { network } = parseDID(did);
    const networkName = network || this.defaultNetwork;

    const provider = this.#getProvider(networkName);

    // Ensure address is checksummed to avoid ENS lookups
    const checksummedAddress = ethers.utils.getAddress(delegateAddress);

    const ethrDid = await this.#createEthrDID(keypair, networkName);
    const txHash = await ethrDid.revokeDelegate(checksummedAddress, delegateType);
    return await waitForTransaction(txHash, provider);
  }

  /**
   * Set an attribute on a DID
   * @param {string} did - DID to update
   * @param {string} key - Attribute key
   * @param {string} value - Attribute value
   * @param {import('../../keypairs/keypair-secp256k1').default} keypair - Owner's keypair
   * @param {number} [expiresIn] - Validity in seconds (optional)
   * @returns {Promise<Object>} Transaction receipt
   */
  async setAttribute(did, key, value, keypair, expiresIn = null) {
    const { network } = parseDID(did);
    const networkName = network || this.defaultNetwork;
    const provider = this.#getProvider(networkName);

    const ethrDid = await this.#createEthrDID(keypair, networkName);
    const txHash = expiresIn
      ? await ethrDid.setAttribute(key, value, expiresIn)
      : await ethrDid.setAttribute(key, value);
    return await waitForTransaction(txHash, provider);
  }

  /**
   * Change the owner of a DID
   * @param {string} did - DID to update
   * @param {string} newOwnerAddress - Ethereum address of new owner
   * @param {import('../../keypairs/keypair-secp256k1').default} keypair - Current owner's keypair
   * @returns {Promise<Object>} Transaction receipt
   */
  async changeOwner(did, newOwnerAddress, keypair) {
    const { network } = parseDID(did);
    const networkName = network || this.defaultNetwork;
    const provider = this.#getProvider(networkName);

    // Ensure address is checksummed to avoid ENS lookups
    const checksummedAddress = ethers.utils.getAddress(newOwnerAddress);

    const ethrDid = await this.#createEthrDID(keypair, networkName);
    const txHash = await ethrDid.changeOwner(checksummedAddress);
    return await waitForTransaction(txHash, provider);
  }
}

export default EthrDIDModule;
