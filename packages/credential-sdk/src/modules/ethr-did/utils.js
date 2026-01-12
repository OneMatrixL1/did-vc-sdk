/**
 * Utility functions for ethr DID operations
 * @module ethr-did/utils
 */

import { keccak256, getBytes, getAddress, hexlify, isAddress, computeAddress, JsonRpcProvider, Wallet, AbiCoder, toUtf8Bytes, concat } from 'ethers';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { getUncompressedG2PublicKey } from './bbs-uncompressed';

/**
 * Default key ID fragment for BBS keys in ethr DIDs
 * Used when creating key documents and authorizing BBS keys
 */
export const ETHR_BBS_KEY_ID = '#keys-bbs';

/**
 * Default chain ID and registry address for DID operations
 */
export const DEFAULT_CHAIN_ID = 1337;
export const DEFAULT_REGISTRY_ADDRESS = '0x8697547b3b82327B70A90C6248662EC083ad5A62';

/**
 * Convert private key to hex string
 * @param {Uint8Array|string} privateKey - Private key bytes or hex string
 * @returns {string} 0x-prefixed hex string
 */
function toPrivateKeyHex(privateKey) {
  if (typeof privateKey === 'string') {
    return privateKey;
  }
  return hexlify(privateKey);
}

/**
 * Derive Ethereum address from BLS G2 public key
 * Handles both compressed (96 bytes) and uncompressed (192 bytes) formats
 * @param {Uint8Array|Array<number>} publicKeyBytes - BLS G2 public key
 * @returns {string} Ethereum address (0x prefixed, checksummed)
 * @throws {Error} If public key length is invalid
 */
export function publicKeyToAddress(publicKeyBytes) {
  // Normalize to Uint8Array
  const keyBytes = publicKeyBytes instanceof Uint8Array
    ? publicKeyBytes
    : new Uint8Array(publicKeyBytes);

  // Ensure uncompressed format (192 bytes)
  let uncompressed;
  if (keyBytes.length === 96) {
    // Decompress: 96 bytes → 192 bytes
    const point = bls.G2.ProjectivePoint.fromHex(keyBytes);
    uncompressed = point.toRawBytes(false);
  } else if (keyBytes.length === 192) {
    // Already uncompressed
    uncompressed = keyBytes;
  } else {
    throw new Error(`Invalid BLS public key length: ${keyBytes.length} bytes. Expected 96 (compressed) or 192 (uncompressed)`);
  }

  // Derive address: keccak256(pubkey)[last 20 bytes]
  const hash = keccak256(uncompressed);
  const addressBytes = getBytes(hash).slice(-20);
  return getAddress(hexlify(addressBytes));
}

/**
 * Detect keypair type using constructor name and duck typing
 * @param {Object} keypair - Keypair instance
 * @returns {'secp256k1' | 'bbs'} Keypair type
 * @throws {Error} If keypair type cannot be determined
 */
export function detectKeypairType(keypair) {
  if (!keypair || typeof keypair !== 'object') {
    throw new Error('Invalid keypair: must be an object');
  }

  // Primary: Check constructor name
  const constructorName = keypair.constructor?.name;

  if (constructorName === 'Secp256k1Keypair' || keypair.keyPair) {
    return 'secp256k1';
  }

  // BBS keypair classes (from @docknetwork/crypto-wasm-ts)
  const bbsKeypairNames = [
    'Bls12381BBSKeyPairDock2023',
    'Bls12381BBSKeyPairDock2022',
    'Bls12381G2KeyPairDock2022',
    'Bls12381PSKeyPairDock2023',
    'Bls12381BDDT16KeyPairDock2024',
    'Bls12381BBDT16KeyPairDock2024',
    'DockCryptoKeyPair',
  ];

  if (bbsKeypairNames.includes(constructorName)) {
    return 'bbs';
  }

  // BBS keypairs always have this property
  if (keypair.publicKeyBuffer) {
    const len = keypair.publicKeyBuffer.length;
    if (len === 96 || len === 192) {
      return 'bbs';
    }
  }

  // Unknown type
  throw new Error('Unknown keypair type. Expected secp256k1 or BBS keypair');
}

/**
 * Extract Ethereum address from keypair (secp256k1 or BLS)
 * @param {Object} keypair - Keypair with either privateKey() method or publicKeyBuffer
 * @returns {string} Ethereum address (0x prefixed, checksummed)
 * @throws {Error} If keypair format is invalid
 */
export function keypairToAddress(keypair) {
  const keyType = detectKeypairType(keypair);

  if (keyType === 'secp256k1') {
    // Standard Secp256k1Keypair with privateKey() method
    if (typeof keypair.privateKey === 'function') {
      return computeAddress(toPrivateKeyHex(keypair.privateKey()));
    }

    // Elliptic library KeyPair object (has ec and priv)
    if (keypair.ec && keypair.priv) {
      // Convert BN private key to hex string
      const privKeyHex = `0x${keypair.priv.toString('hex', 64)}`;
      return computeAddress(privKeyHex);
    }

    throw new Error('Cannot extract private key from secp256k1 keypair');
  }

  // BLS
  return publicKeyToAddress(keypair.publicKeyBuffer);
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
  if (!isAddress(address)) {
    throw new Error(`Invalid Ethereum address: ${address}`);
  }

  // Normalize address to checksum format
  const checksumAddress = getAddress(address);

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
  if (!isAddress(secp256k1Address)) {
    throw new Error(`Invalid secp256k1 address: ${secp256k1Address}`);
  }
  if (!isAddress(bbsAddress)) {
    throw new Error(`Invalid BBS address: ${bbsAddress}`);
  }

  // Normalize addresses to checksum format
  const checksumSecp = getAddress(secp256k1Address);
  const checksumBBS = getAddress(bbsAddress);

  // Include network in DID if specified and not mainnet
  if (network && network !== 'mainnet') {
    return `did:ethr:${network}:${checksumSecp}:${checksumBBS}`;
  }

  return `did:ethr:${checksumSecp}:${checksumBBS}`;
}

/**
 * Create dual-address DID from both keypairs
 * @param {Object} secp256k1Keypair - Secp256k1 keypair
 * @param {Object} bbsKeypair - BBS keypair
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
  const secp256k1Address = computeAddress(toPrivateKeyHex(secp256k1Keypair.privateKey()));
  const bbsAddress = publicKeyToAddress(bbsKeypair.publicKeyBuffer);

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
    if (!isAddress(secp256k1Address)) {
      throw new Error(`Invalid secp256k1 address in DID: ${secp256k1Address}`);
    }
    if (!isAddress(bbsAddress)) {
      throw new Error(`Invalid BBS address in DID: ${bbsAddress}`);
    }

    return {
      network,
      secp256k1Address: getAddress(secp256k1Address),
      bbsAddress: getAddress(bbsAddress),
      // Backward compatibility: primary address is secp256k1
      address: getAddress(secp256k1Address),
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
  if (!isAddress(address)) {
    throw new Error(`Invalid Ethereum address in DID: ${address}`);
  }

  return {
    network,
    address: getAddress(address), // Return checksum address
    isDualAddress: false,
  };
}

/**
 * Create ethers provider from network configuration
 * @param {import('./config').NetworkConfig} networkConfig - Network configuration
 * @param {Object} [providerOptions] - Additional provider options
 * @returns {JsonRpcProvider} Ethers provider
 */
export function createProvider(networkConfig, providerOptions = {}) {
  const network = networkConfig.chainId
    ? {
      name: networkConfig.name,
      chainId: networkConfig.chainId,
    }
    : undefined;

  return new JsonRpcProvider(networkConfig.rpcUrl, network, providerOptions);
}

/**
 * Create ethers signer from keypair and provider
 * @param {Object} keypair - Keypair instance
 * @param {ethers.Provider} provider - Ethers provider
 * @returns {Wallet} Ethers wallet (signer)
 * @throws {Error} If BBS keypair is used (not yet supported)
 */
export function createSigner(keypair, provider) {
  const keyType = detectKeypairType(keypair);

  if (keyType === 'bbs') {
    throw new Error('BBS transaction signing not yet supported. Contract update required.');
  }

  return new Wallet(toPrivateKeyHex(keypair.privateKey()), provider);
}

/**
 * Wait for transaction confirmation
 * @param {string} txHash - Transaction hash
 * @param {ethers.Provider} provider - Provider to use
 * @param {number} [confirmations=1] - Number of confirmations to wait for
 * @returns {Promise<ethers.TransactionReceipt>} Transaction receipt
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
 * Extract private key bytes from BBS keypair
 * Handles wrapped private key formats from @docknetwork/crypto-wasm-ts
 * @param {Object} bbsKeypair - BBS keypair with privateKeyBuffer
 * @returns {Uint8Array} Raw private key bytes
 * @throws {Error} If keypair has no private key
 */
function extractBBSPrivateKeyBytes(bbsKeypair) {
  if (!bbsKeypair.privateKeyBuffer) {
    throw new Error('BBS keypair requires private key');
  }

  let privateKeyBytes = bbsKeypair.privateKeyBuffer;
  if (privateKeyBytes && privateKeyBytes.value) {
    privateKeyBytes = new Uint8Array(privateKeyBytes.value);
  } else if (!(privateKeyBytes instanceof Uint8Array)) {
    privateKeyBytes = new Uint8Array(privateKeyBytes);
  }
  return privateKeyBytes;
}

/**
 * Convert BBS private key bytes to scalar for signing
 *
 * @param {Uint8Array} privateKeyBytes - Raw private key bytes from BBS keypair
 * @returns {bigint} Scalar value for use with Noble curves
 */
function bbsPrivateKeyToScalar(privateKeyBytes) {
  // BBS stores private key as little-endian, reverse for big-endian interpretation
  const reversed = new Uint8Array(privateKeyBytes).reverse();
  const hex = Buffer.from(reversed).toString('hex');
  return bls.fields.Fr.create(BigInt(`0x${hex}`));
}

/**
 * Sign a hash with BBS keypair for owner change
 * Returns 96-byte uncompressed G1 signature for contract compatibility
 *
 * @param {string} hashToSign - The EIP-712 hash (0x-prefixed hex string or bytes)
 * @param {Object} bbsKeypair - BBS keypair instance with privateKeyBuffer
 * @returns {Promise<Uint8Array>} The BLS signature bytes (96 bytes uncompressed G1)
 * @throws {Error} If signing fails
 */
export async function signWithBLSKeypair(hashToSign, bbsKeypair) {
  const privateKeyBytes = extractBBSPrivateKeyBytes(bbsKeypair);

  // Convert hash string to bytes if needed
  let hashBytes;
  if (typeof hashToSign === 'string') {
    const hexString = hashToSign.startsWith('0x') ? hashToSign.slice(2) : hashToSign;
    hashBytes = new Uint8Array(Buffer.from(hexString, 'hex'));
  } else {
    hashBytes = new Uint8Array(hashToSign);
  }

  try {
    // Convert BBS private key (little-endian) to scalar
    const privateKeyScalar = bbsPrivateKeyToScalar(privateKeyBytes);

    // Hash message to G1 point using contract's DST
    const DST = 'BLS_DST';
    const messagePoint = bls.G1.hashToCurve(hashBytes, { DST });

    // Multiply by private key scalar to get signature
    const signaturePoint = messagePoint.multiply(privateKeyScalar);

    // Return uncompressed G1 signature (96 bytes)
    return signaturePoint.toRawBytes(false);
  } catch (e) {
    const message = e && e.message ? e.message : String(e);
    throw new Error(`Failed to sign with BBS keypair: ${message}`);
  }
}

/**
 * Negated G2 generator for BLS verification, matching BLSDockBBS.sol contract
 * Derived from hash_to_curve('DockBBSSignature2023') and negated.
 * Used for pairing check: e(sig, N_G2) * e(msg, PK) == 1
 */
const N_G2_HEX = '151113a09ccd914117226445cd4d5aa6d82218d8d3f5b517d7b43020c94ee0121642129e969b3e14c41b737823f65dcf02445bd9067ed201f4b93771091e40c8920deb706ce68690b02eb80ebddc6c7b5001e5087170d04b70e2fb85b8f5fd510dd7275196d32fba62ba5d15c45aaa87494aa7bab4fa7e5c9f903739c83c410a19d8b22e12a777fedc6f4552c75a0ddc0c71cc5492173d4d92a5ee851c15cdc171269f0ac4cd0a371205341e5ccc4367f69d1609fa0dc1ffaca9cbbee6580f95';

/**
 * Verify a BLS signature against a hash and public key
 * Matches the verification logic in EthereumDIDRegistry.sol
 *
 * @param {Uint8Array|string} signature - 96-byte uncompressed G1 signature
 * @param {Uint8Array|string} hashToVerify - 32-byte hash (e.g. EIP-712 hash)
 * @param {Uint8Array|string} publicKey - 192-byte uncompressed G2 public key
 * @returns {boolean} True if signature is valid
 */
export function verifyBLSSignature(signature, hashToVerify, publicKey) {
  try {
    const uncompressedPubkey = getUncompressedG2PublicKey(publicKey);

    // Normalize inputs to Uint8Array
    const sigBytes = getBytes(signature);
    const hashBytes = getBytes(hashToVerify);
    const pkBytes = getBytes(uncompressedPubkey);

    const DST = 'BLS_DST';
    const sigPoint = bls.G1.ProjectivePoint.fromHex(sigBytes);
    const pkPoint = bls.G2.ProjectivePoint.fromHex(pkBytes);
    const msgPoint = bls.G1.hashToCurve(hashBytes, { DST });

    // pairing(G1, G2, withFinalExponent = true)
    // Check: e(sig, N_G2) * e(msg, pk) == 1
    const nG2Point = bls.G2.ProjectivePoint.fromHex(N_G2_HEX);
    const p1 = bls.pairing(sigPoint, nG2Point, false);
    const p2 = bls.pairing(msgPoint, pkPoint, false);
    const total = bls.fields.Fp12.mul(p1, p2);

    return bls.fields.Fp12.eql(bls.fields.Fp12.finalExponentiate(total), bls.fields.Fp12.ONE);
  } catch (e) {
    return false;
  }
}
/**
 * Create EIP-712 hash for changing owner with public key
 * Matches the logic in EthereumDIDRegistry and DIDServiceClient
 *
 * @param {string} identity - DID identity address
 * @param {string} oldOwner - Current owner address
 * @param {string} newOwner - New owner address
 * @param {number} [chainId=DEFAULT_CHAIN_ID] - Chain ID
 * @param {string} [registryAddress=DEFAULT_REGISTRY_ADDRESS] - Registry contract address
 * @returns {string} EIP-712 hash
 */
export function createChangeOwnerWithPubkeyHash(identity, oldOwner, newOwner, chainId = DEFAULT_CHAIN_ID, registryAddress = DEFAULT_REGISTRY_ADDRESS) {
  const coder = AbiCoder.defaultAbiCoder();
  const typeHash = keccak256(toUtf8Bytes('ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)'));
  const structHash = keccak256(
    coder.encode(
      ['bytes32', 'address', 'address', 'address'],
      [typeHash, identity, oldOwner, newOwner],
    ),
  );

  const domainSeparator = keccak256(
    coder.encode(
      ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
      [
        keccak256(toUtf8Bytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')),
        keccak256(toUtf8Bytes('EthereumDIDRegistry')),
        keccak256(toUtf8Bytes('1')),
        chainId,
        registryAddress,
      ],
    ),
  );

  return keccak256(concat(['0x1901', domainSeparator, structHash]));
}
