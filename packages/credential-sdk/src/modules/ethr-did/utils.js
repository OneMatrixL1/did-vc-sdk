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
 * Derive Ethereum address from a public key (supports multiple curves)
 * @param {Uint8Array|Array<number>} publicKeyBytes - Public key bytes
 * @returns {string} Ethereum address (0x prefixed, checksummed)
 * @throws {Error} If public key length is not supported
 */
export function publicKeyToAddress(publicKeyBytes) {
  // Convert to Uint8Array if it's a plain array
  const keyBytes = publicKeyBytes instanceof Uint8Array
    ? publicKeyBytes
    : new Uint8Array(publicKeyBytes);

  // BLS12-381 G2 public key (96 bytes)
  if (keyBytes.length === 96) {
    const hash = ethers.utils.keccak256(keyBytes);
    // hash is 0x-prefixed hex string, take last 40 chars (20 bytes)
    const address = `0x${hash.slice(-40)}`;
    return ethers.utils.getAddress(address); // Return checksummed
  }

  throw new Error(`Unsupported public key length: ${keyBytes.length}. Supported: 96 bytes (BLS12-381)`);
}

/**
 * Construct EIP-712 typed data for ChangeOwnerWithPubkey
 * @param {string} identity - The DID identity address
 * @param {string} signer - The signer address (derived from public key)
 * @param {string} newOwner - The new owner address
 * @param {number|string} nonce - The nonce value
 * @param {string} registryAddress - The registry contract address
 * @param {number} chainId - The chain ID
 * @returns {{domain: {name: string, version: string, chainId: number, verifyingContract: string}, types: {EIP712Domain: Array, ChangeOwnerWithPubkey: Array}, primaryType: string, message: {identity: string, signer: string, newOwner: string, nonce: string}}} EIP-712 typed data
 */
export function createChangeOwnerWithPubkeyTypedData(
  identity,
  signer,
  newOwner,
  nonce,
  registryAddress,
  chainId,
) {
  return {
    domain: {
      name: 'EthereumDIDRegistry',
      version: '1',
      chainId,
      verifyingContract: registryAddress,
    },
    types: {
      ChangeOwnerWithPubkey: [
        { name: 'identity', type: 'address' },
        { name: 'signer', type: 'address' },
        { name: 'newOwner', type: 'address' },
        { name: 'nonce', type: 'uint256' },
      ],
    },
    primaryType: 'ChangeOwnerWithPubkey',
    message: {
      identity: ethers.utils.getAddress(identity),
      signer: ethers.utils.getAddress(signer),
      newOwner: ethers.utils.getAddress(newOwner),
      nonce: ethers.BigNumber.from(nonce).toString(),
    },
  };
}

/**
 * Compute EIP-712 hash for ChangeOwnerWithPubkey
 * @param {Object} typedData - EIP-712 typed data object
 * @returns {string} The message hash (0x-prefixed)
 */
export function computeChangeOwnerWithPubkeyHash(typedData) {
  const domainSeparator = ethers.utils._TypedDataEncoder.hashDomain(typedData.domain);
  const hashStruct = ethers.utils._TypedDataEncoder.hashStruct(
    typedData.primaryType,
    typedData.types,
    typedData.message,
  );
  const hash = ethers.utils.keccak256(
    ethers.utils.solidityPack(['bytes2', 'bytes32', 'bytes32'], ['0x1901', domainSeparator, hashStruct]),
  );
  return hash;
}

/**
 * Sign a hash with BBS keypair for owner change
 * Uses the DockCryptoKeyPair signer pattern for consistency
 * @param {Uint8Array|string} hashToSign - The EIP-712 hash (0x-prefixed hex string or bytes)
 * @param {Object} bbsKeypair - BBS keypair instance with signer() method
 * @returns {Promise<Uint8Array>} The BLS signature bytes
 * @throws {Error} If signing fails
 */
export async function signWithBLSKeypair(hashToSign, bbsKeypair) {
  if (!bbsKeypair.privateKeyBuffer) {
    throw new Error('BBS keypair requires private key for signing');
  }

  // Convert hash string to bytes if needed
  let hashBytes;
  if (typeof hashToSign === 'string') {
    // Remove '0x' prefix if present
    const hexString = hashToSign.startsWith('0x') ? hashToSign.slice(2) : hashToSign;
    hashBytes = new Uint8Array(Buffer.from(hexString, 'hex'));
  } else {
    hashBytes = new Uint8Array(hashToSign);
  }

  try {
    // Use the keypair's signer() method if available
    if (bbsKeypair.signer && typeof bbsKeypair.signer === 'function') {
      const signer = bbsKeypair.signer();
      if (signer && signer.sign && typeof signer.sign === 'function') {
        const signature = await signer.sign({ data: [hashBytes] });
        return new Uint8Array(signature);
      }
    }

    // Fallback: direct access to constructor classes
    if (!bbsKeypair.constructor || !bbsKeypair.constructor.Signature) {
      throw new Error('BBS keypair must have Signature class available');
    }

    let BBSSignature = bbsKeypair.constructor.Signature;
    let BBSSecretKey = bbsKeypair.constructor.SecretKey;
    let BBSSignatureParams = bbsKeypair.constructor.SignatureParams;
    const defaultLabelBytes = bbsKeypair.constructor.defaultLabelBytes;

    // Fallback to parent constructor if not found
    if (!BBSSignature || !BBSSecretKey) {
      const Parent = Object.getPrototypeOf(bbsKeypair.constructor);
      if (Parent && Parent !== Object) {
        BBSSignature = BBSSignature || Parent.Signature;
        BBSSecretKey = BBSSecretKey || Parent.SecretKey;
        BBSSignatureParams = BBSSignatureParams || Parent.SignatureParams;
      }
    }

    if (!BBSSignature || !BBSSecretKey || !BBSSignatureParams) {
      throw new Error('BBS keypair constructor missing required cryptographic classes');
    }

    // Create secret key from buffer
    const sk = new BBSSecretKey(new Uint8Array(bbsKeypair.privateKeyBuffer));

    // Get signature params for 1 message
    const sigParams = BBSSignatureParams.getSigParamsOfRequiredSize(1, defaultLabelBytes);

    // Sign the hash as a single message
    const signature = BBSSignature.generate([hashBytes], sk, sigParams, false);

    // Return signature bytes
    return new Uint8Array(signature.value);
  } catch (e) {
    throw new Error(`Failed to sign with BBS keypair: ${e.message}`);
  }
}

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
 * Create dual-address DID string from secp256k1 and BBS addresses
 * @param {string} secp256k1Address - Ethereum address for secp256k1 key
 * @param {string} bbsAddress - Ethereum address derived from BBS key
 * @param {string} [network] - Network name (if not mainnet)
 * @returns {string} DID string (e.g., 'did:ethr:0xSecp:0xBBS')
 */
export function addressToDualDID(secp256k1Address, bbsAddress, network = null) {
  if (!secp256k1Address || typeof secp256k1Address !== 'string') {
    throw new Error('Valid secp256k1 address is required');
  }
  if (!bbsAddress || typeof bbsAddress !== 'string') {
    throw new Error('Valid BBS address is required');
  }

  // Validate address formats
  if (!ethers.utils.isAddress(secp256k1Address)) {
    throw new Error(`Invalid secp256k1 address: ${secp256k1Address}`);
  }
  if (!ethers.utils.isAddress(bbsAddress)) {
    throw new Error(`Invalid BBS address: ${bbsAddress}`);
  }

  // Normalize addresses to checksum format
  const checksumSecp = ethers.utils.getAddress(secp256k1Address);
  const checksumBBS = ethers.utils.getAddress(bbsAddress);

  // Include network in DID if specified and not mainnet
  if (network && network !== 'mainnet') {
    return `did:ethr:${network}:${checksumSecp}:${checksumBBS}`;
  }

  return `did:ethr:${checksumSecp}:${checksumBBS}`;
}

/**
 * Create dual-address DID from both keypairs
 * @param {Object} secp256k1Keypair - Secp256k1 keypair for Ethereum transactions
 * @param {Object} bbsKeypair - BBS keypair for privacy-preserving signatures
 * @param {string} [network] - Network name (if not mainnet)
 * @returns {string} Dual-address DID string
 */
export function createDualDID(secp256k1Keypair, bbsKeypair, network = null) {
  // Validate keypair types
  const secp256k1Type = detectKeypairType(secp256k1Keypair);
  if (secp256k1Type !== 'secp256k1') {
    throw new Error('First keypair must be secp256k1');
  }

  const bbsType = detectKeypairType(bbsKeypair);
  if (bbsType !== 'bbs') {
    throw new Error('Second keypair must be BBS');
  }

  // Derive addresses
  const secp256k1Address = ethers.utils.computeAddress(secp256k1Keypair.privateKey());
  const bbsAddress = bbsPublicKeyToAddress(bbsKeypair.publicKeyBuffer);

  return addressToDualDID(secp256k1Address, bbsAddress, network);
}

/**
 * Parse DID string to extract network and address(es)
 * Supports both single-address and dual-address formats:
 * - Single: did:ethr:[network:]0xAddress
 * - Dual: did:ethr:[network:]0xSecp256k1Address:0xBBSAddress
 *
 * @param {string} did - DID string
 * @returns {{network: string|null, address: string, secp256k1Address?: string, bbsAddress?: string, isDualAddress: boolean}} Parsed DID components
 * @throws {Error} If DID format is invalid
 */
export function parseDID(did) {
  if (!did || typeof did !== 'string') {
    throw new Error('DID must be a string');
  }

  // Try dual-address format first: did:ethr:[network:]0xSecp:0xBBS
  const dualMatch = did.match(
    /^did:ethr:(?:([a-z0-9-]+):)?(0x[0-9a-fA-F]{40}):(0x[0-9a-fA-F]{40})$/,
  );

  if (dualMatch) {
    const network = dualMatch[1] || null;
    const secp256k1Address = dualMatch[2];
    const bbsAddress = dualMatch[3];

    // Validate both addresses
    if (!ethers.utils.isAddress(secp256k1Address)) {
      throw new Error(`Invalid secp256k1 address in DID: ${secp256k1Address}`);
    }
    if (!ethers.utils.isAddress(bbsAddress)) {
      throw new Error(`Invalid BBS address in DID: ${bbsAddress}`);
    }

    return {
      network,
      secp256k1Address: ethers.utils.getAddress(secp256k1Address),
      bbsAddress: ethers.utils.getAddress(bbsAddress),
      // Backward compatibility: primary address is secp256k1
      address: ethers.utils.getAddress(secp256k1Address),
      isDualAddress: true,
    };
  }

  // Fall back to single-address format: did:ethr:[network:]0xAddress
  const singleMatch = did.match(/^did:ethr:(?:([a-z0-9-]+):)?(0x[0-9a-fA-F]{40})$/);

  if (!singleMatch) {
    throw new Error(`Invalid ethr DID format: ${did}`);
  }

  const network = singleMatch[1] || null;
  const address = singleMatch[2];

  // Validate address
  if (!ethers.utils.isAddress(address)) {
    throw new Error(`Invalid Ethereum address in DID: ${address}`);
  }

  return {
    network,
    address: ethers.utils.getAddress(address), // Return checksum address
    isDualAddress: false,
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
 * Check if a string is a valid ethr DID (single or dual address)
 * @param {string} did - DID string to check
 * @returns {boolean} True if valid ethr DID
 */
export function isEthrDID(did) {
  if (!did || typeof did !== 'string') {
    return false;
  }
  // Match single OR dual address format
  return /^did:ethr:(?:[a-z0-9-]+:)?0x[0-9a-fA-F]{40}(?::0x[0-9a-fA-F]{40})?$/.test(did);
}

/**
 * Check if a string is a dual-address ethr DID
 * @param {string} did - DID string to check
 * @returns {boolean} True if dual-address ethr DID
 */
export function isDualAddressEthrDID(did) {
  if (!did || typeof did !== 'string') {
    return false;
  }
  return /^did:ethr:(?:[a-z0-9-]+:)?0x[0-9a-fA-F]{40}:0x[0-9a-fA-F]{40}$/.test(did);
}

/**
 * Generate a default ethr DID document without blockchain fetch.
 * This is what ethr-did-resolver returns when there's no on-chain data.
 *
 * Used for optimistic DID resolution where we assume the DID has no
 * on-chain modifications and use the default document structure.
 *
 * Supports both single-address and dual-address DIDs:
 * - Single: did:ethr:[network:]0xAddress - generates controller + implicit BBS
 * - Dual: did:ethr:[network:]0xSecp:0xBBS - generates both controller and BBS verification methods
 *
 * @param {string} did - DID string (did:ethr:[network:]0xAddress or did:ethr:[network:]0xSecp:0xBBS)
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

  const parsed = parseDID(did);

  if (parsed.isDualAddress) {
    // Dual-address DID: include both secp256k1 and BBS verification methods
    return {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
        'https://ld.truvera.io/security/bbs23/v1',
      ],
      id: did,
      verificationMethod: [
        {
          id: `${did}#controller`,
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: did,
          blockchainAccountId: `eip155:${chainId}:${parsed.secp256k1Address}`,
        },
        {
          id: `${did}${ETHR_BBS_KEY_ID}`,
          type: 'Bls12381BBSRecoveryMethod2023',
          controller: did,
          blockchainAccountId: `eip155:${chainId}:${parsed.bbsAddress}`,
        },
      ],
      authentication: [`${did}#controller`],
      assertionMethod: [`${did}#controller`, `${did}${ETHR_BBS_KEY_ID}`],
    };
  }

  // Single-address DID: backward compatible behavior
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
      blockchainAccountId: `eip155:${chainId}:${parsed.address}`,
    }],
    authentication: [`${did}#controller`],
    assertionMethod: [`${did}#controller`, `${did}${ETHR_BBS_KEY_ID}`],
  };
}
