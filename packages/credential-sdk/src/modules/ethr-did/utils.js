/**
 * Utility functions for ethr DID operations
 * @module ethr-did/utils
 */

import { ethers } from 'ethers';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { getUncompressedG2PublicKey } from './bbs-uncompressed';

/**
 * Default key ID fragment for BBS keys in ethr DIDs
 * Used when creating key documents and authorizing BBS keys
 */
export const ETHR_BBS_KEY_ID = '#keys-bbs';

/**
 * Decompress BLS G2 public key from compressed (96 bytes) to uncompressed (192 bytes)
 * @param {Uint8Array} compressedKey - Compressed G2 public key (96 bytes)
 * @returns {Uint8Array} 192-byte uncompressed G2 public key
 * @throws {Error} If decompression fails
 */
function decompressPublicKey(compressedKey) {
  try {
    const pubKeyPoint = bls.G2.ProjectivePoint.fromHex(compressedKey);
    return new Uint8Array(pubKeyPoint.toRawBytes(false)); // false = uncompressed format
  } catch (error) {
    throw new Error(`Failed to decompress public key: ${error.message}`);
  }
}

/**
 * Derive Ethereum address from a public key (supports multiple curves)
 * Handles both compressed (96 bytes) and uncompressed (192 bytes) BLS12-381 G2 public keys
 * @param {Uint8Array|Array<number>} publicKeyBytes - Public key bytes (96 bytes compressed or 192 bytes uncompressed)
 * @returns {string} Ethereum address (0x prefixed, checksummed)
 * @throws {Error} If public key length is not supported
 */
export function publicKeyToAddress(publicKeyBytes) {
  // Convert to Uint8Array if it's a plain array
  const keyBytes = publicKeyBytes instanceof Uint8Array
    ? publicKeyBytes
    : new Uint8Array(publicKeyBytes);

  // Decompress if needed
  const uncompressedKey = keyBytes.length === 96
    ? decompressPublicKey(keyBytes)
    : keyBytes;

  // Validate length
  if (uncompressedKey.length !== 192) {
    throw new Error(`Unsupported public key length: ${keyBytes.length}. Supported: 96 bytes (compressed) or 192 bytes (uncompressed) BLS12-381 G2`);
  }

  // Derive address from uncompressed key
  const hashBytes = ethers.utils.arrayify(
    ethers.utils.keccak256(uncompressedKey),
  );
  const addressBytes = hashBytes.slice(-20);
  return ethers.utils.getAddress(
    ethers.utils.hexlify(addressBytes),
  );
}

/**
 * Derive Ethereum address from BBS public key
 * @param {Uint8Array|Array<number>} bbsPublicKey - BBS public key (192 bytes, uncompressed G2 point)
 * @returns {string} Ethereum address (0x prefixed, checksummed)
 */
export function bbsPublicKeyToAddress(bbsPublicKey) {
  return publicKeyToAddress(bbsPublicKey);
}

/**
 * Detect keypair type for address derivation
 * @param {Object} keypair - Keypair instance (Secp256k1Keypair or BBS-based)
 * @returns {'secp256k1' | 'bbs'} Keypair type
 * @throws {Error} If keypair type cannot be determined
 */
export function detectKeypairType(keypair) {
  if (!keypair || typeof keypair !== 'object') {
    throw new Error('Invalid keypair: must be an object');
  }

  // Primary detection: Check constructor name for explicit type identification
  const constructorName = keypair.constructor?.name;

  // BBS keypair classes (all extend DockCryptoKeyPair)
  const bbsKeypairNames = [
    'Bls12381BBSKeyPairDock2023',
    'Bls12381BBSKeyPairDock2022',
    'Bls12381G2KeyPairDock2022',
    'Bls12381PSKeyPairDock2023',
    'Bls12381BDDT16KeyPairDock2024',
    'Bls12381BBDT16KeyPairDock2024',
    'DockCryptoKeyPair',
  ];

  if (constructorName === 'Secp256k1Keypair') {
    return 'secp256k1';
  }

  if (bbsKeypairNames.includes(constructorName)) {
    return 'bbs';
  }

  // Fallback: Duck-typing for plain objects used in optimistic verification
  // If object has publicKeyBuffer but no recognized constructor, treat as BBS
  // This supports off-chain verification where only the public key is available
  if (keypair.publicKeyBuffer && !keypair.privateKey) {
    const len = keypair.publicKeyBuffer.length;
    if (len === 96 || len === 192) {
      return 'bbs';
    }
  }

  // If object has privateKey method, likely secp256k1
  if (typeof keypair.privateKey === 'function') {
    return 'secp256k1';
  }

  // Unable to determine type
  throw new Error(
    `Unknown keypair type: constructor name is "${constructorName}". `
    + 'Expected Secp256k1Keypair or a BBS keypair class (DockCryptoKeyPair-based).',
  );
}

/**
 * Extract Ethereum address from keypair (secp256k1 or BBS)
 * Handles both 96-byte (compressed) and 192-byte (uncompressed) BBS public keys
 * @param {Object} keypair - Keypair instance (Secp256k1 or BBS)
 * @returns {string} Ethereum address (0x prefixed)
 */
export function keypairToAddress(keypair) {
  const keyType = detectKeypairType(keypair);

  if (keyType === 'bbs') {
    const keyLength = keypair.publicKeyBuffer.length;

    // Already uncompressed (192 bytes) - can derive address directly
    if (keyLength === 192) {
      return bbsPublicKeyToAddress(keypair.publicKeyBuffer);
    }

    // Compressed key (96 bytes) - need to convert to uncompressed
    if (keyLength === 96) {
      // If keypair has _keypair.pk (BBSPublicKey object), use it for decompression
      // Otherwise decompress the raw 96-byte buffer
      const sourceKey = (keypair._keypair && keypair._keypair.pk)
        ? keypair._keypair.pk
        : keypair.publicKeyBuffer;

      const uncompressedKey = getUncompressedG2PublicKey(sourceKey);
      return bbsPublicKeyToAddress(uncompressedKey);
    }

    throw new Error(`Unexpected BBS public key length: ${keyLength} bytes. Expected 96 (compressed) or 192 (uncompressed).`);
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

/**
 * Convert compressed BLS G1 signature to 96-byte uncompressed format
 * Required for smart contract compatibility (BBS scheme uses G1 signatures with G2 public keys)
 * Supports 48-byte compressed G1 format
 * @param {Uint8Array} compressedSignature - Compressed G1 signature (48 bytes)
 * @returns {Uint8Array} 96-byte uncompressed G1 signature
 * @throws {Error} If decompression fails
 */
function decompressG1Signature(compressedSignature) {
  if (!compressedSignature) {
    throw new Error('Signature is required');
  }

  const len = compressedSignature.length;
  if (len !== 48) {
    throw new Error(
      'BBS signature must be 48 bytes (compressed G1), '
      + `got ${len} bytes. Use 96 bytes if already uncompressed.`,
    );
  }

  try {
    // For 48-byte compressed G1 signatures
    const sigPoint = bls.G1.ProjectivePoint.fromHex(compressedSignature);
    const uncompressed = sigPoint.toRawBytes(false); // false = uncompressed format

    if (uncompressed.length !== 96) {
      throw new Error(`Decompression produced ${uncompressed.length} bytes, expected 96`);
    }

    return new Uint8Array(uncompressed);
  } catch (error) {
    throw new Error(
      `Failed to decompress BLS G1 signature: ${error.message}. `
      + 'Ensure the signature is a valid 48-byte compressed G1 signature.',
    );
  }
}

/**
 * Sign a hash with BBS keypair for owner change
 * Returns 96-byte uncompressed G1 signature for contract compatibility
 * Uses the DockCryptoKeyPair signer pattern for consistency
 * BBS scheme: G2 public keys with G1 signatures
 * @param {string} hashToSign - The EIP-712 hash (0x-prefixed hex string or bytes)
 * @param {Object} bbsKeypair - BBS keypair instance with signer() method
 * @returns {Promise<Uint8Array>} The BLS signature bytes (96 bytes uncompressed G1)
 * @throws {Error} If signing fails
 */
export async function signWithBLSKeypair(hashToSign, bbsKeypair) {
  if (!bbsKeypair.privateKeyBuffer) {
    throw new Error('BBS keypair requires private key for signing');
  }

  // Convert hash string to bytes if needed
  const hexString = hashToSign.startsWith('0x') ? hashToSign.slice(2) : hashToSign;
  const hashBytes = new Uint8Array(Buffer.from(hexString, 'hex'));

  // Create G1 signature (BBS scheme uses G1 for signatures, G2 for public keys)
  // 1. Convert private key to scalar
  const privateKeyScalar = bls.G2.normPrivateKeyToScalar(bbsKeypair.privateKeyBuffer);

  // 2. Hash message to G1 point using contract's DST
  const messagePoint = bls.G1.hashToCurve(hashBytes, { DST: 'BLS_DST' });

  // 3. Multiply by private key to get signature
  const signaturePoint = messagePoint.multiply(privateKeyScalar);

  // 4. Return uncompressed G1 signature (96 bytes)
  return signaturePoint.toRawBytes(false);
}
