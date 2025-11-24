/**
 * Ethr DID Module - Manage DIDs on Ethereum-compatible chains
 * @module ethr-did
 */

import EthrDIDModuleClass from './module';

export { default as EthrDIDModule } from './module';
export * from './config';
export * from './utils';

/**
 * Factory function to create EthrDIDModule with configuration
 * @param {import('./config').ModuleConfig} config - Module configuration
 * @returns {import('./module').default} EthrDIDModule instance
 *
 * @example
 * import { createEthrDIDModule } from '@docknetwork/credential-sdk/modules/ethr-did';
 *
 * const module = createEthrDIDModule({
 *   networks: ['mainnet', 'sepolia'], // Use defaults
 *   defaultNetwork: 'sepolia'
 * });
 *
 * @example
 * // Custom network configuration
 * const module = createEthrDIDModule({
 *   networks: [{
 *     name: 'vietchain',
 *     rpcUrl: 'https://rpc.vietcha.in',
 *     registry: '0x50CbD0618e556655D902E6C3210eB97Aa8Fd0ED0'
 *   }]
 * });
 */
export function createEthrDIDModule(config) {
  return new EthrDIDModuleClass(config);
}
