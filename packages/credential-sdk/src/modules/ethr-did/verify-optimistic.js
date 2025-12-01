/**
 * Optimistic credential verification for ethr DIDs
 *
 * Provides a helper function that tries optimistic resolution first
 * (no blockchain RPC), then falls back to blockchain if verification fails.
 *
 * @module ethr-did/verify-optimistic
 */

import { verifyCredential } from '../../vc';
import { verifyPresentation } from '../../vc/presentations';

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

/**
 * Extract presenter DID from a verifiable presentation.
 * @param {object} presentation - Verifiable presentation
 * @returns {string|null} Presenter DID or null if not found
 */
function extractPresenterDID(presentation) {
  if (presentation.holder) {
    return typeof presentation.holder === 'string'
      ? presentation.holder
      : presentation.holder?.id;
  }
  const verificationMethod = presentation.proof?.verificationMethod;
  if (verificationMethod) {
    const vmId = typeof verificationMethod === 'string'
      ? verificationMethod
      : verificationMethod?.id;
    return vmId?.split('#')[0];
  }
  return null;
}

/**
 * Extract issuer DIDs from credentials in a presentation.
 * @param {object} presentation - Verifiable presentation
 * @returns {string[]} Array of issuer DIDs
 */
function extractIssuerDIDs(presentation) {
  const credentials = presentation.verifiableCredential || [];
  const credentialArray = Array.isArray(credentials) ? credentials : [credentials];
  return credentialArray.map((cred) => {
    const issuer = cred.issuer;
    return typeof issuer === 'string' ? issuer : issuer?.id;
  }).filter(Boolean);
}

/**
 * Extract all unique DIDs from a presentation (presenter + issuers).
 * @param {object} presentation - Verifiable presentation
 * @returns {string[]} Array of unique DIDs
 */
function extractAllDIDs(presentation) {
  const dids = new Set();
  const presenterDID = extractPresenterDID(presentation);
  if (presenterDID) dids.add(presenterDID);
  extractIssuerDIDs(presentation).forEach((did) => dids.add(did));
  return Array.from(dids);
}

/**
 * Identify which specific DIDs need blockchain resolution and mark them in storage.
 * Tests each credential individually, then tests presenter DID separately.
 * @param {object} presentation - Verifiable presentation
 * @param {object} module - EthrDIDModule instance
 * @param {StorageAdapter} storage - Storage adapter
 * @param {object} verifyOptions - Verification options
 */
async function identifyAndMarkFailedDIDs(presentation, module, storage, verifyOptions) {
  const credentials = presentation.verifiableCredential || [];
  const credentialArray = Array.isArray(credentials) ? credentials : [credentials];

  // Test each credential individually with optimistic resolution
  for (const credential of credentialArray) {
    const issuerDID = typeof credential.issuer === 'string'
      ? credential.issuer
      : credential.issuer?.id;

    if (!issuerDID || await storage.has(issuerDID)) continue;

    const optimisticResolver = {
      supports: (id) => module.supports(id),
      resolve: (id) => module.resolve(id, { optimistic: true }),
    };

    const result = await verifyCredential(credential, {
      ...verifyOptions,
      resolver: optimisticResolver,
    });

    if (!result.verified) {
      await storage.set(issuerDID);
    }
  }

  // Test presenter DID separately
  const presenterDID = extractPresenterDID(presentation);
  if (presenterDID && !await storage.has(presenterDID)) {
    // Create a hybrid resolver: blockchain for presenter, optimistic for others
    const presenterTestResolver = {
      supports: (id) => module.supports(id),
      resolve: (id) => (id === presenterDID || id.startsWith(`${presenterDID}#`)
        ? module.resolve(id, { optimistic: false }) // blockchain for presenter
        : module.resolve(id, { optimistic: true })), // optimistic for issuers
    };

    const result = await verifyPresentation(presentation, {
      ...verifyOptions,
      resolver: presenterTestResolver,
    });

    // If it succeeds with blockchain presenter, the presenter DID was modified on-chain
    if (result.verified) {
      await storage.set(presenterDID);
    }
  }
}

/**
 * Verify presentation with optimistic-first resolution strategy.
 *
 * Tries optimistic resolution (no blockchain RPC) for all DIDs first.
 * If verification fails, identifies which specific DID(s) failed and marks
 * them in storage, then retries with blockchain resolution.
 *
 * @param {object} presentation - Verifiable presentation to verify
 * @param {object} options - Verification options
 * @param {import('./module').default} options.module - EthrDIDModule instance
 * @param {StorageAdapter} [options.storage] - Optional storage adapter
 * @param {string} options.challenge - Proof challenge (required for authentication)
 * @param {string} [options.domain] - Proof domain (optional)
 * @returns {Promise<object>} Verification result
 *
 * @example
 * // Simple usage (no storage)
 * const result = await verifyPresentationOptimistic(presentation, {
 *   module,
 *   challenge: 'test-challenge',
 * });
 *
 * @example
 * // With memory storage (identifies which DIDs need blockchain)
 * const storage = createMemoryStorageAdapter();
 * const result = await verifyPresentationOptimistic(presentation, {
 *   module,
 *   storage,
 *   challenge: 'test-challenge',
 *   domain: 'test-domain',
 * });
 */
export async function verifyPresentationOptimistic(presentation, options) {
  const { module, storage = null, ...verifyOptions } = options;

  if (!module) {
    throw new Error('module is required');
  }

  if (!presentation) {
    throw new TypeError('"presentation" property is required');
  }

  const allDIDs = extractAllDIDs(presentation);

  // Check if ANY DID needs blockchain resolution
  const needsBlockchain = storage
    ? await Promise.all(allDIDs.map((did) => storage.has(did)))
      .then((results) => results.some((r) => r))
    : false;

  if (!needsBlockchain) {
    // Try optimistic first (no blockchain RPC)
    const optimisticResolver = {
      supports: (id) => module.supports(id),
      resolve: (id) => module.resolve(id, { optimistic: true }),
    };

    const result = await verifyPresentation(presentation, {
      ...verifyOptions,
      resolver: optimisticResolver,
    });

    if (result.verified) {
      return result;
    }

    // Granular failure detection - identify which specific DID(s) failed
    if (storage) {
      await identifyAndMarkFailedDIDs(presentation, module, storage, verifyOptions);
    }
  }

  // Fallback to blockchain resolution
  return verifyPresentation(presentation, {
    ...verifyOptions,
    resolver: module,
  });
}
