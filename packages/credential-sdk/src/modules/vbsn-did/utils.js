/**
 * Utility functions for vbsn DID operations
 * @module vbsn-did/utils
 */

import { isAddress, getAddress } from 'ethers';

/**
 * Create DID string from Ethereum address using did:vbsn method
 * @param {string} address - Ethereum address
 * @param {string} [network] - Network name (if not mainnet)
 * @returns {string} DID string (e.g., 'did:vbsn:0x...', 'did:vbsn:sepolia:0x...')
 */
export function vbsnAddressToDID(address, network = null) {
  if (!address || typeof address !== 'string') {
    throw new Error('Valid Ethereum address is required');
  }

  if (!isAddress(address)) {
    throw new Error(`Invalid Ethereum address: ${address}`);
  }

  const checksumAddress = getAddress(address);

  if (network && network !== 'mainnet') {
    return `did:vbsn:${network}:${checksumAddress}`;
  }

  return `did:vbsn:${checksumAddress}`;
}
