/**
 * Optimistic credential verification for ethr DIDs
 *
 * Provides a helper function that tries optimistic resolution first
 * (no blockchain RPC), then falls back to blockchain if verification fails.
 *
 * @module ethr-did/verify-optimistic
 */

import { verifyCredential } from '../../vc';

/**
 * @typedef {Object} StorageAdapter
 * @property {(did: string) => Promise<boolean>} has - Check if DID needs blockchain
 * @property {(did: string) => Promise<void>} set - Mark DID as needing blockchain
 */

/**
 * Verify credential with optimistic-first resolution strategy.
 *
 * Tries optimistic resolution (no blockchain RPC) first. If verification fails,
 * retries with blockchain resolution. Optionally uses storage to remember
 * which DIDs have been modified on-chain.
 *
 * @param {object} credential - Verifiable credential to verify
 * @param {object} options - Verification options
 * @param {import('./module').default} options.module - EthrDIDModule instance
 * @param {StorageAdapter} [options.storage] - Optional storage adapter
 * @returns {Promise<object>} Verification result
 *
 * @example
 * // Simple usage (no storage)
 * const result = await verifyCredentialOptimistic(credential, { module });
 *
 * @example
 * // With localStorage (persists across page refreshes)
 * const storage = createLocalStorageAdapter();
 * const result = await verifyCredentialOptimistic(credential, { module, storage });
 *
 * @example
 * // With sessionStorage (clears on tab close)
 * const storage = createSessionStorageAdapter();
 * const result = await verifyCredentialOptimistic(credential, { module, storage });
 */
export async function verifyCredentialOptimistic(credential, options) {
  const { module, storage = null, ...verifyOptions } = options;

  if (!module) {
    throw new Error('module is required');
  }

  // Extract issuer DID
  const issuerDID = typeof credential.issuer === 'string'
    ? credential.issuer
    : credential.issuer?.id;

  if (!issuerDID) {
    throw new Error('credential.issuer is required');
  }

  // Check if this DID is known to need blockchain resolution
  const needsBlockchain = storage ? await storage.has(issuerDID) : false;

  if (!needsBlockchain) {
    // Try optimistic first (no blockchain RPC)
    const optimisticResolver = {
      supports: (id) => module.supports(id),
      resolve: (id) => module.resolve(id, { optimistic: true }),
    };

    const result = await verifyCredential(credential, {
      ...verifyOptions,
      resolver: optimisticResolver,
    });

    if (result.verified) {
      return result;
    }

    // Mark DID as needing blockchain for future calls
    if (storage) {
      await storage.set(issuerDID);
    }
  }

  // Fallback to blockchain resolution
  return verifyCredential(credential, {
    ...verifyOptions,
    resolver: module,
  });
}

/**
 * Create a localStorage adapter for verifyCredentialOptimistic.
 * Persists across page refreshes but clears when browser data is cleared.
 *
 * @param {string} [prefix='ethr:modified:'] - Key prefix in localStorage
 * @returns {StorageAdapter}
 *
 * @example
 * const storage = createLocalStorageAdapter();
 * const result = await verifyCredentialOptimistic(credential, { module, storage });
 */
export function createLocalStorageAdapter(prefix = 'ethr:modified:') {
  return {
    has: (did) => Promise.resolve(localStorage.getItem(`${prefix}${did}`) !== null),
    set: (did) => Promise.resolve(localStorage.setItem(`${prefix}${did}`, '1')),
  };
}

/**
 * Create a sessionStorage adapter for verifyCredentialOptimistic.
 * Clears when tab/window is closed.
 *
 * @param {string} [prefix='ethr:modified:'] - Key prefix in sessionStorage
 * @returns {StorageAdapter}
 *
 * @example
 * const storage = createSessionStorageAdapter();
 * const result = await verifyCredentialOptimistic(credential, { module, storage });
 */
export function createSessionStorageAdapter(prefix = 'ethr:modified:') {
  return {
    has: (did) => Promise.resolve(sessionStorage.getItem(`${prefix}${did}`) !== null),
    set: (did) => Promise.resolve(sessionStorage.setItem(`${prefix}${did}`, '1')),
  };
}

/**
 * Create an in-memory storage adapter for verifyCredentialOptimistic.
 * Useful for testing or single-page apps where you want per-session caching.
 * Clears when page is refreshed.
 *
 * @returns {StorageAdapter & { clear: () => void }}
 *
 * @example
 * const storage = createMemoryStorageAdapter();
 * const result = await verifyCredentialOptimistic(credential, { module, storage });
 * storage.clear(); // Clear cache when needed
 */
export function createMemoryStorageAdapter() {
  const cache = new Set();
  return {
    has: (did) => Promise.resolve(cache.has(did)),
    set: (did) => Promise.resolve(cache.add(did)),
    clear: () => cache.clear(),
  };
}
