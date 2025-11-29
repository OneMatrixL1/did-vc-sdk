/**
 * Utility functions for ethr DID operations
 * @module ethr-did/utils
 */

import { ethers } from 'ethers';

/**
 * Default key ID fragment for BBS keys in ethr DIDs
 * Used when creating key documents and authorizing BBS keys
 */
export const ETHR_BBS_KEY_ID = '#keys-bbs';

/**
 * Derive Ethereum address from BBS public key
 * @param {Uint8Array|Array<number>} bbsPublicKey - BBS public key (96 bytes, compressed G2 point)
 * @returns {string} Ethereum address (0x prefixed, checksummed)
 */
export function bbsPublicKeyToAddress(bbsPublicKey) {
  // Convert to Uint8Array if it's a plain array
  const publicKeyBytes = bbsPublicKey instanceof Uint8Array
    ? bbsPublicKey
    : new Uint8Array(bbsPublicKey);

  if (publicKeyBytes.length !== 96) {
    throw new Error('BBS public key must be 96 bytes');
  }

  const hash = ethers.utils.keccak256(publicKeyBytes);
  // hash is 0x-prefixed hex string, take last 40 chars (20 bytes)
  const address = `0x${hash.slice(-40)}`;
  return ethers.utils.getAddress(address); // Return checksummed
}

/**
 * Detect keypair type for address derivation
 * @param {Object} keypair - Keypair instance (Secp256k1 or BBS)
 * @returns {'secp256k1' | 'bbs'} Keypair type
 */
export function detectKeypairType(keypair) {
  // Check for BBS keypair (DockCryptoKeyPair with 96-byte publicKeyBuffer)
  if (keypair.publicKeyBuffer && keypair.publicKeyBuffer.length === 96) {
    return 'bbs';
  }
  // Check for Secp256k1Keypair (has privateKey method)
  if (typeof keypair.privateKey === 'function') {
    return 'secp256k1';
  }
  throw new Error('Unknown keypair type: must be Secp256k1Keypair or BBS keypair');
}

/**
 * Extract Ethereum address from keypair (secp256k1 or BBS)
 * @param {Object} keypair - Keypair instance (Secp256k1 or BBS)
 * @returns {string} Ethereum address (0x prefixed)
 */
export function keypairToAddress(keypair) {
  const keyType = detectKeypairType(keypair);

  if (keyType === 'bbs') {
    return bbsPublicKeyToAddress(keypair.publicKeyBuffer);
  }

  // Default: secp256k1
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
 * @param {Object} keypair - Keypair instance (Secp256k1 or BBS)
 * @param {ethers.providers.Provider} provider - Ethers provider
 * @returns {ethers.Wallet} Ethers wallet (signer)
 * @throws {Error} If BBS keypair is used (not yet supported)
 */
export function createSigner(keypair, provider) {
  const keyType = detectKeypairType(keypair);

  if (keyType === 'bbs') {
    // TODO: Implement BBS signer when contract supports it
    throw new Error('BBS transaction signing not yet supported. Contract update required.');
  }

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

/**
 * Generate a default ethr DID document without blockchain fetch.
 * This is what ethr-did-resolver returns when there's no on-chain data.
 *
 * Used for optimistic DID resolution where we assume the DID has no
 * on-chain modifications and use the default document structure.
 *
 * @param {string} did - DID string (did:ethr:[network:]0xAddress)
 * @param {object} [options] - Options
 * @param {number} [options.chainId=1] - Chain ID for blockchainAccountId
 * @returns {object} Default DID document
 * @throws {Error} If DID format is invalid
 */
export function generateDefaultDocument(did, options = {}) {
  const { chainId = 1 } = options;

  if (!isEthrDID(did)) {
    throw new Error(`Invalid ethr DID: ${did}`);
  }

  const { address } = parseDID(did);

  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
    ],
    id: did,
    verificationMethod: [{
      id: `${did}#controller`,
      type: 'EcdsaSecp256k1RecoveryMethod2020',
      controller: did,
      blockchainAccountId: `eip155:${chainId}:${address}`,
    }],
    authentication: [`${did}#controller`],
    assertionMethod: [`${did}#controller`, `${did}${ETHR_BBS_KEY_ID}`],
  };
}
