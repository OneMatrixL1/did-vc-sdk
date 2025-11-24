/**
 * Default network configurations for ethr DID management
 * @module ethr-did/config
 */

/**
 * Standard ERC1056 DID Registry contract address on mainnet
 * @see https://github.com/uport-project/ethr-did-registry
 */
export const STANDARD_REGISTRY_ADDRESS = '0xdca7ef03e98e0dc2b855be647c39abe984193675';

/**
 * Default network configurations for common Ethereum-compatible chains
 * @type {Object.<string, NetworkConfig>}
 */
export const DEFAULT_NETWORKS = {
  mainnet: {
    name: 'mainnet',
    description: 'Ethereum Mainnet',
    rpcUrl: 'https://mainnet.infura.io/v3/',
    chainId: 1,
    registry: STANDARD_REGISTRY_ADDRESS,
  },
  sepolia: {
    name: 'sepolia',
    description: 'Ethereum Sepolia Testnet',
    rpcUrl: 'https://sepolia.infura.io/v3/',
    chainId: 11155111,
    registry: '0x03d5003bf0e79c5f5223588f347eba39afbc3818',
  },
  polygon: {
    name: 'polygon',
    description: 'Polygon Mainnet',
    rpcUrl: 'https://polygon-rpc.com',
    chainId: 137,
    registry: '0x41D788c9c5D335362D713152F407692c5EEAfAae',
  },
  'polygon-amoy': {
    name: 'polygon-amoy',
    description: 'Polygon Amoy Testnet',
    rpcUrl: 'https://rpc-amoy.polygon.technology',
    chainId: 80002,
    registry: '0x03d5003bf0e79c5f5223588f347eba39afbc3818',
  },
  arbitrum: {
    name: 'arbitrum',
    description: 'Arbitrum One',
    rpcUrl: 'https://arb1.arbitrum.io/rpc',
    chainId: 42161,
    registry: '0xdca7ef03e98e0dc2b855be647c39abe984fcf21',
  },
  optimism: {
    name: 'optimism',
    description: 'Optimism Mainnet',
    rpcUrl: 'https://mainnet.optimism.io',
    chainId: 10,
    registry: '0xdca7ef03e98e0dc2b855be647c39abe984fcf21',
  },
};

/**
 * Validate network configuration
 * @param {NetworkConfig} config - Network configuration to validate
 * @throws {Error} If configuration is invalid
 */
export function validateNetworkConfig(config) {
  if (!config) {
    throw new Error('Network configuration is required');
  }

  if (!config.name || typeof config.name !== 'string') {
    throw new Error('Network name is required and must be a string');
  }

  if (!config.rpcUrl || typeof config.rpcUrl !== 'string') {
    throw new Error(`RPC URL is required for network "${config.name}"`);
  }

  // Validate RPC URL format
  try {
    const url = new URL(config.rpcUrl);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) {
      throw new Error('Invalid protocol');
    }
  } catch (e) {
    throw new Error(`Invalid RPC URL for network "${config.name}": ${config.rpcUrl}`);
  }

  if (!config.registry || typeof config.registry !== 'string') {
    throw new Error(`Registry contract address is required for network "${config.name}"`);
  }

  // Validate Ethereum address format (0x followed by 40 hex characters)
  if (!/^0x[0-9a-fA-F]{40}$/.test(config.registry)) {
    throw new Error(`Invalid registry contract address for network "${config.name}": ${config.registry}`);
  }

  if (config.chainId !== undefined && typeof config.chainId !== 'number') {
    throw new Error(`Chain ID must be a number for network "${config.name}"`);
  }
}

/**
 * Normalize network configuration by applying defaults
 * @param {NetworkConfig} config - Network configuration to normalize
 * @returns {NetworkConfig} Normalized configuration
 */
export function normalizeNetworkConfig(config) {
  // Check if it's a reference to a default network
  if (typeof config === 'string' && DEFAULT_NETWORKS[config]) {
    return { ...DEFAULT_NETWORKS[config] };
  }

  // Merge with default if name matches a known network
  if (config.name && DEFAULT_NETWORKS[config.name]) {
    return {
      ...DEFAULT_NETWORKS[config.name],
      ...config,
    };
  }

  return { ...config };
}

/**
 * Validate module configuration
 * @param {ModuleConfig} config - Module configuration to validate
 * @throws {Error} If configuration is invalid
 */
export function validateModuleConfig(config) {
  if (!config) {
    throw new Error('Module configuration is required');
  }

  if (!config.networks || !Array.isArray(config.networks) || config.networks.length === 0) {
    throw new Error('At least one network configuration is required');
  }

  // Validate each network
  config.networks.forEach((network) => {
    const normalized = normalizeNetworkConfig(network);
    validateNetworkConfig(normalized);
  });

  // Validate default network if specified
  if (config.defaultNetwork) {
    const networkNames = config.networks.map((n) => (typeof n === 'string' ? n : n.name));
    if (!networkNames.includes(config.defaultNetwork)) {
      throw new Error(`Default network "${config.defaultNetwork}" not found in networks configuration`);
    }
  }
}

/**
 * Create network configuration for VietChain
 * @param {string} [rpcUrl='https://rpc.vietcha.in'] - RPC URL
 * @param {string} [registry='0xF0889fb2473F91c068178870ae2e1A0408059A03'] - Registry contract address
 * @returns {NetworkConfig} VietChain network configuration
 */
export function createVietChainConfig(
  rpcUrl = 'https://rpc.vietcha.in',
  registry = '0xF0889fb2473F91c068178870ae2e1A0408059A03',
) {
  return {
    name: 'vietchain',
    description: 'VietChain Network',
    rpcUrl,
    registry,
  };
}

/**
 * @typedef {Object} NetworkConfig
 * @property {string} name - Network identifier (e.g., 'mainnet', 'sepolia', 'vietchain')
 * @property {string} [description] - Human-readable network description
 * @property {string} rpcUrl - RPC endpoint URL for the network
 * @property {string} registry - DID Registry contract address (ERC1056)
 * @property {number} [chainId] - EIP-155 chain ID
 */

/**
 * @typedef {Object} ModuleConfig
 * @property {Array<NetworkConfig|string>} networks - Array of network configurations or network names
 * @property {string} [defaultNetwork] - Default network to use (must be in networks array)
 * @property {Object} [providerOptions] - Additional provider options (gas, timeout, etc.)
 */
