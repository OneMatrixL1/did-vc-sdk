/**
 * Unit tests for EthrDIDModule
 *
 * These tests cover configuration, utilities, and local operations.
 * For integration tests requiring network connectivity, see:
 * - ethr-did.integration.test.js
 */

import { EthrDIDModule, createVietChainConfig, validateModuleConfig, validateNetworkConfig, normalizeNetworkConfig, DEFAULT_NETWORKS } from '../src/modules/ethr-did';
import { addressToDID, parseDID, isEthrDID, keypairToAddress } from '../src/modules/ethr-did/utils';
import { Secp256k1Keypair } from '../src/keypairs';

describe('EthrDID Configuration', () => {
  test('validateNetworkConfig accepts valid config', () => {
    const config = {
      name: 'testnet',
      rpcUrl: 'https://test.example.com',
      registry: '0x1234567890123456789012345678901234567890',
    };

    expect(() => validateNetworkConfig(config)).not.toThrow();
  });

  test('validateNetworkConfig rejects invalid registry address', () => {
    const config = {
      name: 'testnet',
      rpcUrl: 'https://test.example.com',
      registry: 'invalid-address',
    };

    expect(() => validateNetworkConfig(config)).toThrow(/Invalid registry contract address/);
  });

  test('validateNetworkConfig rejects invalid RPC URL', () => {
    const config = {
      name: 'testnet',
      rpcUrl: 'not-a-url',
      registry: '0x1234567890123456789012345678901234567890',
    };

    expect(() => validateNetworkConfig(config)).toThrow(/Invalid RPC URL/);
  });

  test('normalizeNetworkConfig uses defaults for known networks', () => {
    const normalized = normalizeNetworkConfig('mainnet');
    expect(normalized.name).toBe('mainnet');
    expect(normalized.registry).toBeDefined();
    expect(normalized.rpcUrl).toBeDefined();
  });

  test('normalizeNetworkConfig merges custom with defaults', () => {
    const normalized = normalizeNetworkConfig({
      name: 'mainnet',
      rpcUrl: 'https://custom.rpc.com',
    });

    expect(normalized.name).toBe('mainnet');
    expect(normalized.rpcUrl).toBe('https://custom.rpc.com');
    expect(normalized.registry).toBe(DEFAULT_NETWORKS.mainnet.registry);
  });

  test('createVietChainConfig returns valid config', () => {
    const config = createVietChainConfig();

    expect(config.name).toBe('vietchain');
    expect(config.rpcUrl).toBe('https://rpc.vietcha.in');
    expect(config.registry).toBe('0xF0889fb2473F91c068178870ae2e1A0408059A03');
  });

  test('validateModuleConfig accepts valid config', () => {
    const config = {
      networks: [createVietChainConfig()],
    };

    expect(() => validateModuleConfig(config)).not.toThrow();
  });

  test('validateModuleConfig rejects empty networks', () => {
    const config = {
      networks: [],
    };

    expect(() => validateModuleConfig(config)).toThrow(/At least one network/);
  });
});

describe('EthrDID Utilities', () => {
  test('addressToDID creates correct mainnet DID', () => {
    const address = '0x557Ed38510Dd3585B2B2068Dd463f12C7E0D9781';
    const did = addressToDID(address);

    // Should be checksum address
    expect(did).toMatch(/^did:ethr:0x[0-9a-fA-F]{40}$/);
  });

  test('addressToDID creates correct network-specific DID', () => {
    const address = '0x557Ed38510Dd3585B2B2068Dd463f12C7E0D9781';
    const did = addressToDID(address, 'sepolia');

    expect(did).toMatch(/^did:ethr:sepolia:0x[0-9a-fA-F]{40}$/);
  });

  test('addressToDID rejects invalid address', () => {
    expect(() => addressToDID('invalid')).toThrow(/Invalid Ethereum address/);
  });

  test('parseDID extracts network and address correctly', () => {
    const did = 'did:ethr:sepolia:0x1234567890123456789012345678901234567890';
    const parsed = parseDID(did);

    expect(parsed.network).toBe('sepolia');
    expect(parsed.address).toBe('0x1234567890123456789012345678901234567890');
  });

  test('parseDID handles mainnet DID without network', () => {
    const did = 'did:ethr:0x1234567890123456789012345678901234567890';
    const parsed = parseDID(did);

    expect(parsed.network).toBeNull();
    expect(parsed.address).toBe('0x1234567890123456789012345678901234567890');
  });

  test('parseDID rejects invalid DID format', () => {
    expect(() => parseDID('did:invalid:0x1234')).toThrow(/Invalid ethr DID format/);
  });

  test('isEthrDID validates correct DIDs', () => {
    expect(isEthrDID('did:ethr:0x1234567890123456789012345678901234567890')).toBe(true);
    expect(isEthrDID('did:ethr:sepolia:0x1234567890123456789012345678901234567890')).toBe(true);
    expect(isEthrDID('did:dock:0x1234')).toBe(false);
    expect(isEthrDID('invalid')).toBe(false);
  });

  test('keypairToAddress generates valid address', () => {
    const keypair = Secp256k1Keypair.random();
    const address = keypairToAddress(keypair);

    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });
});

describe('EthrDIDModule', () => {
  let module;

  beforeEach(() => {
    // Create module with test configuration
    module = new EthrDIDModule({
      networks: [
        createVietChainConfig(),
        'sepolia', // Use default config
      ],
      defaultNetwork: 'vietchain',
    });
  });

  test('constructor initializes with valid config', () => {
    expect(module).toBeInstanceOf(EthrDIDModule);
    expect(module.defaultNetwork).toBe('vietchain');
    expect(module.networks.size).toBe(2);
  });

  test('constructor throws with invalid config', () => {
    expect(() => new EthrDIDModule({ networks: [] })).toThrow(/At least one network/);
  });

  test('createNewDID generates valid DID', async () => {
    const keypair = Secp256k1Keypair.random();
    const did = await module.createNewDID(keypair);

    expect(isEthrDID(did)).toBe(true);
    expect(did).toContain('did:ethr:vietchain:');
  });

  test('createNewDID on different network', async () => {
    const keypair = Secp256k1Keypair.random();
    const did = await module.createNewDID(keypair, 'sepolia');

    expect(isEthrDID(did)).toBe(true);
    expect(did).toContain('did:ethr:sepolia:');
  });

  test('createNewDID throws for unknown network', async () => {
    const keypair = Secp256k1Keypair.random();

    await expect(module.createNewDID(keypair, 'unknown')).rejects.toThrow(/Unknown network/);
  });
});

describe('EthrDID Multi-Network Support', () => {
  test('module handles multiple networks', () => {
    const module = new EthrDIDModule({
      networks: [
        'mainnet',
        'sepolia',
        createVietChainConfig(),
      ],
      defaultNetwork: 'mainnet',
    });

    expect(module.networks.size).toBe(3);
    expect(module.networks.has('mainnet')).toBe(true);
    expect(module.networks.has('sepolia')).toBe(true);
    expect(module.networks.has('vietchain')).toBe(true);
  });

  test('can create DIDs on different networks', async () => {
    const module = new EthrDIDModule({
      networks: ['mainnet', 'sepolia', createVietChainConfig()],
      defaultNetwork: 'mainnet',
    });

    const keypair = Secp256k1Keypair.random();

    const mainnetDID = await module.createNewDID(keypair, 'mainnet');
    const sepoliaDID = await module.createNewDID(keypair, 'sepolia');
    const vietChainDID = await module.createNewDID(keypair, 'vietchain');

    expect(parseDID(mainnetDID).network).toBeNull(); // Mainnet doesn't include network in DID
    expect(parseDID(sepoliaDID).network).toBe('sepolia');
    expect(parseDID(vietChainDID).network).toBe('vietchain');
  });
});

describe('EthrDID Integration with Keypairs', () => {
  test('Secp256k1Keypair generates consistent address', () => {
    const keypair = Secp256k1Keypair.random();
    const address1 = keypairToAddress(keypair);
    const address2 = keypairToAddress(keypair);

    expect(address1).toBe(address2);
  });

  test('Different keypairs generate different addresses', () => {
    const keypair1 = Secp256k1Keypair.random();
    const keypair2 = Secp256k1Keypair.random();

    const address1 = keypairToAddress(keypair1);
    const address2 = keypairToAddress(keypair2);

    expect(address1).not.toBe(address2);
  });

  test('DID creation uses keypair correctly', async () => {
    const module = new EthrDIDModule({
      networks: [createVietChainConfig()],
    });

    const keypair = Secp256k1Keypair.random();
    const expectedAddress = keypairToAddress(keypair);
    const did = await module.createNewDID(keypair);
    const parsed = parseDID(did);

    expect(parsed.address.toLowerCase()).toBe(expectedAddress.toLowerCase());
  });
});
