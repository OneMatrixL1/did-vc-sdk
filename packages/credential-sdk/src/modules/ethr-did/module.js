/**
 * EthrDIDModule - Module for managing ethr DIDs on Ethereum-compatible chains
 * @module ethr-did/module
 */

import { ethers } from 'ethers';
import { EthrDID } from 'ethr-did';
import { getResolver } from 'ethr-did-resolver';
import { Resolver as DIDResolver } from 'did-resolver';
import b58 from 'bs58';
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
  ETHR_BBS_KEY_ID,
  generateDefaultDocument,
  createDualDID,
  signWithBLSKeypair,
} from './utils';
import { getUncompressedG2PublicKey } from './bbs-uncompressed';

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

    // Optimistic mode: return default document without blockchain fetch
    // When true, getDocument() returns a locally-generated default document
    // instead of fetching from the blockchain. Useful for performance optimization
    // when most DIDs haven't been modified on-chain.
    this.optimistic = config.optimistic ?? false;

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
   * @param {object} [options] - Resolution options
   * @param {boolean} [options.optimistic] - Use optimistic resolution (no blockchain)
   * @returns {Promise<Object>} DID Document or Verification Method
   */
  async resolve(id, options = {}) {
    // Check if there's a fragment (verification method reference)
    const fragmentIndex = id.indexOf('#');
    if (fragmentIndex !== -1) {
      const did = id.substring(0, fragmentIndex);
      const fragment = id.substring(fragmentIndex);

      // Get the full DID document
      const didDocument = await this.getDocument(did, options);

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

      // Special case: implicit BBS key (#keys-bbs) for single-address ethr DIDs
      // The BBS key is authorized in assertionMethod but not explicitly in verificationMethod
      // For BBS recovery, the public key will be provided in the proof's publicKeyBase58 field
      // Here we return a placeholder that indicates BBS recovery should be used
      if (fragment === ETHR_BBS_KEY_ID) {
        const assertionMethodIncludesBBS = didDocument.assertionMethod?.some(
          (am) => am === id || am === `${did}${ETHR_BBS_KEY_ID}` || (typeof am === 'object' && am.id === id),
        );

        if (assertionMethodIncludesBBS) {
          // Return a synthetic BBS verification method
          // This enables the BBS signature suite to use address-based recovery
          // The actual publicKeyBase58 will come from the proof during verification
          return {
            '@context': [
              'https://www.w3.org/ns/did/v1',
              'https://w3id.org/security/v2',
            ],
            id,
            type: 'Bls12381BBSRecoveryMethod2023',
            controller: did,
            // Note: publicKeyBase58 will be injected from proof by signature suite
          };
        }
      }

      throw new Error(`Verification method not found: ${id}`);
    }

    // No fragment, return full DID document
    return this.getDocument(id, options);
  }

  /**
   * Get provider for a specific network
   * @param {string} [networkName] - Network name (uses default if not specified)
   * @returns {ethers.JsonRpcProvider} Provider instance
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
   * @param {Object} keypair - Keypair instance (Secp256k1 or BBS)
   * @param {string} [networkName] - Network name
   * @param {Object} [options] - Additional options
   * @param {Object} [options.txSigner] - Custom signer for gas payment (required for BBS keypairs)
   * @returns {Promise<EthrDID>} EthrDID instance
   * @throws {Error} If BBS keypair is used without custom signer
   */
  async #createEthrDID(keypair, networkName = null, options = {}) {
    const name = networkName || this.defaultNetwork;
    const networkConfig = this.networks.get(name);
    const provider = this.#getProvider(name);

    if (!networkConfig) {
      throw new Error(`Network not found: ${name}`);
    }

    const address = keypairToAddress(keypair);

    // Use custom signer if provided, otherwise create from keypair
    const signer = options.txSigner || createSigner(keypair, provider);

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
   * Create an EthrDID instance from an address
   * Used when the identity address is known but we need a custom signer
   * @param {string} address - Ethereum address
   * @param {string} [networkName] - Network name
   * @param {Object} [options] - Additional options
   * @param {Object} [options.txSigner] - Custom signer for transactions
   * @returns {Promise<EthrDID>} EthrDID instance
   */
  async #createEthrDIDFromAddress(address, networkName = null, options = {}) {
    const name = networkName || this.defaultNetwork;
    const networkConfig = this.networks.get(name);
    const provider = this.#getProvider(name);

    if (!networkConfig) {
      throw new Error(`Network not found: ${name}`);
    }

    if (!options.txSigner) {
      throw new Error('txSigner is required when creating EthrDID from address');
    }

    const ethrDidConfig = {
      identifier: ethers.getAddress(address),
      provider,
      registry: networkConfig.registry,
      chainNameOrId: networkConfig.chainId || name,
      txSigner: options.txSigner,
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
   * Supports both Secp256k1 and BBS keypairs for address derivation.
   * @param {Object} keypair - Keypair instance (Secp256k1 or BBS)
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
   * Create a new dual-address ethr DID
   * Combines secp256k1 (for Ethereum transactions) and BBS (for privacy-preserving signatures)
   * addresses in a single DID: did:ethr:[network:]0xSecp256k1Address:0xBBSAddress
   *
   * @param {Object} secp256k1Keypair - Secp256k1 keypair for Ethereum transactions
   * @param {Object} bbsKeypair - BBS keypair for privacy-preserving signatures
   * @param {string} [networkName] - Network name (uses default if not specified)
   * @returns {Promise<string>} The created dual-address DID string
   *
   * @example
   * const secp256k1Keypair = Secp256k1Keypair.random();
   * const bbsKeypair = Bls12381BBSKeyPairDock2023.generate();
   * const did = await module.createDualAddressDID(secp256k1Keypair, bbsKeypair);
   * // Result: did:ethr:0xSecp256k1Address:0xBBSAddress
   */
  async createDualAddressDID(secp256k1Keypair, bbsKeypair, networkName = null) {
    const name = networkName || this.defaultNetwork;

    // Validate network exists
    if (!this.networks.has(name)) {
      throw new Error(`Unknown network: ${name}`);
    }

    return createDualDID(secp256k1Keypair, bbsKeypair, name !== 'mainnet' ? name : null);
  }

  /**
   * Generate transaction to create a DID document with custom attributes
   * This sets additional attributes beyond the default controller
   * @param {Object} didDocument - DID Document to create
   * @param {import('../../keypairs/did-keypair').default} didKeypair - DID keypair for signing
   * @returns {Promise<Object>} Transaction object
   * @throws {Error} If BBS keypair is used (transaction signing not yet supported)
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
   * @param {object} [options] - Resolution options
   * @param {boolean} [options.optimistic] - Use optimistic resolution (no blockchain)
   * @returns {Promise<Object>} DID Document
   */
  async getDocument(did, options = {}) {
    const didString = String(did);

    if (!isEthrDID(didString)) {
      throw new Error(`Not an ethr DID: ${didString}`);
    }

    // Determine if optimistic mode should be used
    // Per-call option takes precedence over constructor default
    const useOptimistic = options.optimistic ?? this.optimistic;

    if (useOptimistic) {
      return this.getDefaultDocument(didString);
    }

    // Fetch from blockchain
    return this.#getDocumentFromChain(didString);
  }

  /**
   * Get default DID document without blockchain fetch
   * Used for optimistic resolution when we assume no on-chain modifications.
   * @param {string} did - DID string
   * @returns {object} Default DID document
   */
  getDefaultDocument(did) {
    const didString = String(did);

    if (!isEthrDID(didString)) {
      throw new Error(`Not an ethr DID: ${didString}`);
    }

    const { network } = parseDID(didString);
    const networkConfig = this.networks.get(network || this.defaultNetwork);
    const chainId = networkConfig?.chainId || 1;

    return generateDefaultDocument(didString, { chainId });
  }

  /**
   * Get document from blockchain (original behavior)
   * @private
   * @param {string} didString - DID string (already validated)
   * @returns {Promise<Object>} DID Document from blockchain
   */
  async #getDocumentFromChain(didString) {
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

      const document = result.didDocument;

      // Normalize verification methods: convert publicKeyHex to publicKeyBase58
      if (document.verificationMethod) {
        document.verificationMethod = document.verificationMethod.map((vm) => {
          if (vm.publicKeyHex && !vm.publicKeyBase58) {
            const { publicKeyHex, ...rest } = vm;
            return {
              ...rest,
              publicKeyBase58: b58.encode(Buffer.from(publicKeyHex, 'hex')),
            };
          }
          return vm;
        });
      }

      // Add implicit BBS key authorization unless an explicit BBS key is registered
      //
      // This works like EOA (Externally Owned Account) behavior:
      // - The implicit BBS key (derived from the DID's address) is always valid
      // - Adding delegates, attributes, or other on-chain data does NOT disable it
      // - Only registering an EXPLICIT BBS key on-chain will override the implicit one
      //
      // This prevents the dangerous scenario where adding a delegate accidentally
      // breaks all previously issued BBS credentials.
      const bbsVerificationKeyTypes = [
        'Bls12381G2VerificationKeyDock2022',
        'Bls12381BBSVerificationKeyDock2023',
        'Bls12381PSVerificationKeyDock2023',
        'Bls12381BBDT16VerificationKeyDock2024',
      ];

      const hasExplicitBBSKey = document.verificationMethod?.some(
        (vm) => bbsVerificationKeyTypes.includes(vm.type),
      );

      if (!hasExplicitBBSKey) {
        // Add implicit BBS key authorization
        // This allows BBS credentials to be verified without on-chain key registration
        // The BBS public key comes from the proof's publicKeyBase58 field and is validated
        // by deriving the address and comparing with the DID's address
        const bbsKeyId = `${didString}${ETHR_BBS_KEY_ID}`;

        if (document.assertionMethod && !document.assertionMethod.includes(bbsKeyId)) {
          document.assertionMethod = [...document.assertionMethod, bbsKeyId];
        }
      }

      return document;
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
    const checksummedAddress = ethers.getAddress(delegateAddress);

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
    const checksummedAddress = ethers.getAddress(delegateAddress);

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
   * Revoke an attribute from a DID
   * @param {string} did - DID to update
   * @param {string} key - Attribute name (e.g., 'did/pub/Bls12381G2Key2020/veriKey/base58')
   * @param {string} value - Attribute value to revoke
   * @param {import('../../keypairs/keypair-secp256k1').default} keypair - Owner's keypair
   * @returns {Promise<Object>} Transaction receipt
   */
  async revokeAttribute(did, key, value, keypair) {
    const { network } = parseDID(did);
    const networkName = network || this.defaultNetwork;
    const provider = this.#getProvider(networkName);

    const ethrDid = await this.#createEthrDID(keypair, networkName);
    const txHash = await ethrDid.revokeAttribute(key, value);
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
    const checksummedAddress = ethers.getAddress(newOwnerAddress);

    const ethrDid = await this.#createEthrDID(keypair, networkName);
    const txHash = await ethrDid.changeOwner(checksummedAddress);
    return await waitForTransaction(txHash, provider);
  }

  /**
   * Change the owner of a DID using BLS signature verification
   * This method allows changing ownership using a BBS keypair signature while
   * a different keypair (gas payer) pays for the transaction.
   *
   * @param {string} did - DID to update
   * @param {string} newOwnerAddress - Ethereum address of new owner
   * @param {Object} bbsKeypair - BBS keypair to sign the ownership change
   * @param {import('../../keypairs/keypair-secp256k1').default} gasPayerKeypair - Keypair to pay for gas
   * @returns {Promise<Object>} Transaction receipt with txHash and blockNumber
   */
  async changeOwnerWithPubkey(did, newOwnerAddress, bbsKeypair, gasPayerKeypair) {
    const { network, address: identityAddress } = parseDID(did);
    const networkName = network || this.defaultNetwork;
    const provider = this.#getProvider(networkName);

    // Verify the BBS keypair matches the DID's identity
    const bbsAddress = keypairToAddress(bbsKeypair);
    if (bbsAddress.toLowerCase() !== identityAddress.toLowerCase()) {
      throw new Error(
        `BBS keypair address ${bbsAddress} does not match DID identity ${identityAddress}`,
      );
    }

    // Create signer from gas payer keypair
    const txSigner = createSigner(gasPayerKeypair, provider);

    // Create EthrDID with the DID's identity address and gas payer signer
    const ethrDid = await this.#createEthrDIDFromAddress(identityAddress, networkName, { txSigner });

    // Use BBS public key directly - the contract uses Dock's g2 generator
    // so BBS public key and signature will be compatible
    const { publicKeyBuffer } = bbsKeypair;
    const uncompressedPubkey = getUncompressedG2PublicKey(publicKeyBuffer);

    const checksummedNewOwner = ethers.getAddress(newOwnerAddress);

    // Get the EIP-712 hash for signing
    const hash = await ethrDid.createChangeOwnerWithPubkeyHash(
      checksummedNewOwner,
      uncompressedPubkey,
    );

    // Sign the hash with BLS keypair (uses same scalar as BBS public key)
    const signature = await signWithBLSKeypair(hash, bbsKeypair);

    // Submit the transaction using the gas payer's signer
    // Note: EthrDID.changeOwnerWithPubkey returns just the tx hash string
    try {
      const txHash = await ethrDid.changeOwnerWithPubkey(
        checksummedNewOwner,
        uncompressedPubkey,
        signature,
      );

      // Wait for the transaction to be mined and get full receipt
      const receipt = await provider.waitForTransaction(txHash, 1, 60000);

      return {
        txHash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed,
        status: receipt.status,
      };
    } catch (error) {
      // Re-throw with clean error to avoid BigInt serialization issues in Jest
      const cleanError = new Error(error.message);
      cleanError.code = error.code;
      cleanError.txHash = error.receipt?.hash || error.receipt?.transactionHash;
      throw cleanError;
    }
  }
}

export default EthrDIDModule;
