/**
 * Optimistic credential verification for ethr DIDs
 *
 * Provides helper functions that try optimistic resolution first
 * (no blockchain RPC), then fall back to blockchain if verification fails.
 *
 * @module ethr-did/verify-optimistic
 */

import { verifyCredential } from '../../vc';
import { verifyPresentation } from '../../vc/presentations';

/**
 * Verify credential with optimistic-first resolution strategy.
 *
 * Tries optimistic resolution (no blockchain RPC) first. If verification fails,
 * retries with blockchain resolution.
 *
 * @param {object} credential - Verifiable credential to verify
 * @param {object} options - Verification options
 * @param {import('./module').default} options.module - EthrDIDModule instance
 * @returns {Promise<object>} Verification result
 *
 * @example
 * const result = await verifyCredentialOptimistic(credential, { module });
 */
export async function verifyCredentialOptimistic(credential, options) {
  const { module, ...verifyOptions } = options;

  if (!module) {
    throw new Error('module is required');
  }

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

  // Fallback to blockchain resolution
  return verifyCredential(credential, {
    ...verifyOptions,
    resolver: module,
  });
}

/**
 * Verify presentation with optimistic-first resolution strategy.
 *
 * Tries optimistic resolution (no blockchain RPC) for all DIDs first.
 * If verification fails, retries with blockchain resolution.
 *
 * @param {object} presentation - Verifiable presentation to verify
 * @param {object} options - Verification options
 * @param {import('./module').default} options.module - EthrDIDModule instance
 * @param {string} options.challenge - Proof challenge (required for authentication)
 * @param {string} [options.domain] - Proof domain (optional)
 * @returns {Promise<object>} Verification result
 *
 * @example
 * const result = await verifyPresentationOptimistic(presentation, {
 *   module,
 *   challenge: 'test-challenge',
 * });
 */
export async function verifyPresentationOptimistic(presentation, options) {
  const { module, ...verifyOptions } = options;

  if (!module) {
    throw new Error('module is required');
  }

  if (!presentation) {
    throw new TypeError('"presentation" property is required');
  }

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

  // Fallback to blockchain resolution
  return verifyPresentation(presentation, {
    ...verifyOptions,
    resolver: module,
  });
}
