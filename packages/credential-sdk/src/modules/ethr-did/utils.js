/**
 * Utility functions for ethr DID operations
 * @module ethr-did/utils
 */

import { ethers } from 'ethers';

/**
 * Extract Ethereum address from a Secp256k1Keypair
 * @param {import('../../keypairs/keypair-secp256k1').default} keypair - Secp256k1 keypair
 * @returns {string} Ethereum address (0x prefixed)
 */
export function keypairToAddress(keypair) {
  return ethers.utils.computeAddress(keypair.privateKey());
}

/**
 * Create DID string from Ethereum address
 * @param {string} address - Ethereum address
 * @param {string} [network] - Network name (if not mainnet)
 * @returns {string} DID string (e.g., 'did:ethr:0x...', 'did:ethr:sepolia:0x...')
 */
export function addressToDID(address, network = null) {
  if (!address || typeof address !== 'string') {
    throw new Error('Valid Ethereum address is required');
  }

  // Validate address format
  if (!ethers.utils.isAddress(address)) {
    throw new Error(`Invalid Ethereum address: ${address}`);
  }

  // Normalize address to checksum format
  const checksumAddress = ethers.utils.getAddress(address);

  // Include network in DID if specified and not mainnet
  if (network && network !== 'mainnet') {
    return `did:ethr:${network}:${checksumAddress}`;
  }

  return `did:ethr:${checksumAddress}`;
}

/**
 * Parse DID string to extract network and address
 * @param {string} did - DID string
 * @returns {{network: string|null, address: string}} Parsed DID components
 * @throws {Error} If DID format is invalid
 */
export function parseDID(did) {
  if (!did || typeof did !== 'string') {
    throw new Error('DID must be a string');
  }

  // Match did:ethr:[network:]address pattern
  const match = did.match(/^did:ethr:(?:([a-z0-9-]+):)?(0x[0-9a-fA-F]{40})$/);

  if (!match) {
    throw new Error(`Invalid ethr DID format: ${did}`);
  }

  const network = match[1] || null;
  const address = match[2];

  // Validate address
  if (!ethers.utils.isAddress(address)) {
    throw new Error(`Invalid Ethereum address in DID: ${address}`);
  }

  return {
    network,
    address: ethers.utils.getAddress(address), // Return checksum address
  };
}

/**
 * Create ethers provider from network configuration
 * @param {import('./config').NetworkConfig} networkConfig - Network configuration
 * @param {Object} [providerOptions] - Additional provider options
 * @returns {ethers.providers.JsonRpcProvider} Ethers provider
 */
export function createProvider(networkConfig, providerOptions = {}) {
  const connectionInfo = {
    url: networkConfig.rpcUrl,
    ...providerOptions,
  };

  const network = networkConfig.chainId
    ? {
      name: networkConfig.name,
      chainId: networkConfig.chainId,
    }
    : undefined;

  return new ethers.providers.JsonRpcProvider(connectionInfo, network);
}

/**
 * Create ethers signer from keypair and provider
 * @param {import('../../keypairs/keypair-secp256k1').default} keypair - Secp256k1 keypair
 * @param {ethers.providers.Provider} provider - Ethers provider
 * @returns {ethers.Wallet} Ethers wallet (signer)
 */
export function createSigner(keypair, provider) {
  return new ethers.Wallet(keypair.privateKey(), provider);
}

/**
 * Wait for transaction confirmation
 * @param {string} txHash - Transaction hash
 * @param {ethers.providers.Provider} provider - Provider to use
 * @param {number} [confirmations=1] - Number of confirmations to wait for
 * @returns {Promise<ethers.providers.TransactionReceipt>} Transaction receipt
 */
export async function waitForTransaction(txHash, provider, confirmations = 1) {
  if (!provider) {
    throw new Error('Provider is required when waiting for transaction');
  }

  const receipt = await provider.waitForTransaction(txHash, confirmations);

  if (receipt.status === 0) {
    throw new Error(`Transaction failed: ${txHash}`);
  }
  return receipt;
}

/**
 * Convert DID document to ethr-did attributes format
 * @param {Object} didDocument - DID Document
 * @returns {Array<{key: string, value: string}>} Array of attributes
 */
export function documentToAttributes(didDocument) {
  const attributes = [];

  // Convert verification methods to attributes
  if (didDocument.verificationMethod && Array.isArray(didDocument.verificationMethod)) {
    didDocument.verificationMethod.forEach((vm) => {
      if (vm.type && vm.publicKeyHex) {
        attributes.push({
          key: `did/pub/${vm.type}`,
          value: vm.publicKeyHex,
        });
      }
    });
  }

  // Convert service endpoints to attributes
  if (didDocument.service && Array.isArray(didDocument.service)) {
    didDocument.service.forEach((service) => {
      if (service.type && service.serviceEndpoint) {
        attributes.push({
          key: `did/svc/${service.type}`,
          value: service.serviceEndpoint,
        });
      }
    });
  }

  return attributes;
}

/**
 * Format error message from ethers error
 * @param {Error} error - Error from ethers
 * @returns {string} Formatted error message
 */
export function formatEthersError(error) {
  if (error.reason) {
    return error.reason;
  }
  if (error.message) {
    return error.message;
  }
  return String(error);
}

/**
 * Check if a string is a valid ethr DID
 * @param {string} did - DID string to check
 * @returns {boolean} True if valid ethr DID
 */
export function isEthrDID(did) {
  if (!did || typeof did !== 'string') {
    return false;
  }
  return /^did:ethr:(?:[a-z0-9-]+:)?0x[0-9a-fA-F]{40}$/.test(did);
}
