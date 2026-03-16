/**
 * Generic DID computation utility.
 * @module did-utils
 */

import { isAddress, getAddress } from 'ethers';

/**
 * Compute a DID string from an Ethereum address and method name.
 * @param {'ethr'|'vbsn'} method - DID method
 * @param {string} address - Ethereum address
 * @param {string} [network] - Optional network name
 * @returns {string} DID string
 */
export function computeDID(method, address, network = null) {
  if (!address || !isAddress(address)) {
    throw new Error(`Invalid address: ${address}`);
  }
  const checksumAddr = getAddress(address);
  if (network && network !== 'mainnet') {
    return `did:${method}:${network}:${checksumAddr}`;
  }
  return `did:${method}:${checksumAddr}`;
}
