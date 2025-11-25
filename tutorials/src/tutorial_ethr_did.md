# Ethr DID Management

The SDK provides comprehensive support for managing DIDs on Ethereum-compatible blockchains using the `EthrDIDModule`. This module enables you to create, update, resolve, and manage ethr DIDs on any EVM-compatible chain.

## Overview

Ethr DIDs (`did:ethr`) are decentralized identifiers that use the Ethereum blockchain and the ERC-1056 DID Registry standard. The SDK's `EthrDIDModule` provides:

- **Universal Configuration**: Works with any Ethereum-compatible chain (Ethereum, Polygon, Arbitrum, custom chains like VietChain, etc.)
- **Multi-Network Support**: Manage DIDs across multiple networks in a single module instance
- **Full DID Lifecycle**: Create, update, resolve, and revoke DIDs
- **VC/VP Signing**: Sign Verifiable Credentials and Presentations with ethr DIDs
- **Delegate Management**: Add and revoke delegates for DIDs
- **Attribute Management**: Set custom attributes on DIDs

## Installation

The ethr DID functionality is included in the credential-sdk package:

```bash
yarn add @docknetwork/credential-sdk
```

## Quick Start

### Basic Configuration

```javascript
import { EthrDIDModule } from '@docknetwork/credential-sdk/modules/ethr-did';
import { Secp256k1Keypair } from '@docknetwork/credential-sdk/keypairs';

// Configure for a specific network
const module = new EthrDIDModule({
  networks: [{
    name: 'sepolia',
    rpcUrl: 'https://sepolia.infura.io/v3/YOUR_API_KEY',
    registry: '0x03d5003bf0e79c5f5223588f347eba39afbc3818',
  }],
});

// Create a new DID
const keypair = Secp256k1Keypair.random();
const did = await module.createNewDID(keypair);
console.log('Created DID:', did);
// Output: did:ethr:sepolia:0xABC...
```

### Using Default Network Configurations

The module includes pre-configured settings for common networks:

```javascript
import { EthrDIDModule } from '@docknetwork/credential-sdk/modules/ethr-did';

// Use default configurations
const module = new EthrDIDModule({
  networks: ['sepolia', 'vietchain'],
  defaultNetwork: 'sepolia',
});
```

Supported default networks:
- `sepolia` - Ethereum Sepolia Testnet (registry: `0x03d5003bf0e79c5f5223588f347eba39afbc3818`)
- `vietchain` - VietChain Network (registry: `0xF0889fb2473F91c068178870ae2e1A0408059A03`)

For other networks (mainnet, polygon, arbitrum, etc.), use custom configuration with the appropriate registry address.

## Custom Network Configuration

### Configuring VietChain (or any custom EVM chain)

```javascript
import { EthrDIDModule, createVietChainConfig } from '@docknetwork/credential-sdk/modules/ethr-did';

// Use the helper function
const module = new EthrDIDModule({
  networks: [createVietChainConfig()],
});

// Or configure manually
const module = new EthrDIDModule({
  networks: [{
    name: 'vietchain',
    rpcUrl: 'https://rpc.vietcha.in',
    registry: '0xF0889fb2473F91c068178870ae2e1A0408059A03',
    chainId: 88, // Optional
  }],
});
```

### Multi-Network Setup

```javascript
const module = new EthrDIDModule({
  networks: [
    'sepolia',
    'vietchain',
    {
      name: 'mainnet',
      rpcUrl: 'https://mainnet.infura.io/v3/YOUR_API_KEY',
      registry: '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b',
    },
  ],
  defaultNetwork: 'sepolia',
});

// Create DIDs on different networks
const sepoliaDID = await module.createNewDID(keypair); // Uses default
const vietChainDID = await module.createNewDID(keypair, 'vietchain');
const mainnetDID = await module.createNewDID(keypair, 'mainnet');
```

## Working with DIDs

### Creating a DID

```javascript
import { Secp256k1Keypair } from '@docknetwork/credential-sdk/keypairs';

const keypair = Secp256k1Keypair.random();
const did = await module.createNewDID(keypair);

// DID format: did:ethr:network:address
// For mainnet: did:ethr:0x1234...
// For other networks: did:ethr:sepolia:0x1234...
```

### Resolving a DID Document

```javascript
const document = await module.getDocument(did);
console.log('DID Document:', document);

// Returns standard DID Document:
// {
//   '@context': '...',
//   id: 'did:ethr:sepolia:0x...',
//   verificationMethod: [...],
//   authentication: [...],
//   assertionMethod: [...]
// }
```

### Setting Attributes

Add custom attributes to your DID (requires on-chain transaction):

```javascript
// Add a service endpoint
await module.setAttribute(
  did,
  'did/svc/MessagingService',
  'https://example.com/messaging',
  keypair,
);

// Add a public key
await module.setAttribute(
  did,
  'did/pub/Secp256k1/veriKey',
  keypairHex,
  keypair,
  86400, // Optional: expires in 24 hours (seconds)
);

// Resolve to see updated attributes
const updatedDoc = await module.getDocument(did);
```

### Managing Delegates

Delegates allow other keys to act on behalf of the DID:

```javascript
// Add a delegate
const delegateKeypair = Secp256k1Keypair.random();
const delegateAddress = keypairToAddress(delegateKeypair);

await module.addDelegate(
  did,
  delegateAddress,
  keypair, // Owner's keypair
  {
    delegateType: 'veriKey', // Type of delegate
    expiresIn: 86400, // Valid for 24 hours
  },
);

// Revoke a delegate
await module.revokeDelegate(
  did,
  delegateAddress,
  keypair,
  'veriKey',
);
```

### Transferring Ownership

```javascript
const newOwnerKeypair = Secp256k1Keypair.random();
const newOwnerAddress = keypairToAddress(newOwnerKeypair);

await module.changeOwner(did, newOwnerAddress, keypair);

// After this, only the new owner can update the DID
```

## Signing Verifiable Credentials

Use ethr DIDs to sign Verifiable Credentials:

```javascript
import { issueCredential } from '@docknetwork/credential-sdk/vc';

// Create a credential
const credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://www.w3.org/2018/credentials/examples/v1',
  ],
  type: ['VerifiableCredential', 'UniversityDegreeCredential'],
  issuer: did,
  issuanceDate: new Date().toISOString(),
  credentialSubject: {
    id: 'did:example:student123',
    degree: {
      type: 'BachelorDegree',
      name: 'Bachelor of Science',
    },
  },
};

// Create key document for signing
const keyDoc = {
  id: `${did}#controller`,
  controller: did,
  type: 'EcdsaSecp256k1VerificationKey2019',
  privateKeyHex: Array.from(keypair.privateKey())
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(''),
  publicKeyHex: Array.from(keypair.publicKey())
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(''),
};

// Sign the credential
const signedCredential = await issueCredential(keyDoc, credential);
```

## Creating Verifiable Presentations

```javascript
import { VerifiablePresentation, signPresentation } from '@docknetwork/credential-sdk/vc';

// Create presentation
const presentation = new VerifiablePresentation('http://example.com/presentations/1');
presentation.addCredential(signedCredential);
presentation.setHolder(did);

// Sign the presentation
const signedPresentation = await signPresentation(
  presentation.toJSON(),
  keyDoc,
  'challenge-from-verifier',
  'verifier.example.com',
);
```

## Advanced Topics

### Custom Provider Options

```javascript
const module = new EthrDIDModule({
  networks: [{
    name: 'custom',
    rpcUrl: 'https://rpc.custom.com',
    registry: '0x...',
  }],
  providerOptions: {
    timeout: 30000, // 30 seconds
    headers: {
      'Authorization': 'Bearer token',
    },
  },
});
```

### Working with Existing Private Keys

```javascript
import { Secp256k1Keypair } from '@docknetwork/credential-sdk/keypairs';

// From hex private key
const privateKeyHex = '0x1234...';
const privateKeyBytes = new Uint8Array(
  privateKeyHex.slice(2).match(/.{2}/g).map(byte => parseInt(byte, 16))
);

const keypair = new Secp256k1Keypair(privateKeyBytes, 'private');
const did = await module.createNewDID(keypair);
```

### Transaction Gas Management

```javascript
// Set custom gas limit for transactions
const receipt = await module.setAttribute(
  did,
  'key',
  'value',
  keypair,
);

// Access transaction details
console.log('Gas used:', receipt.gasUsed.toString());
console.log('Block number:', receipt.blockNumber);
console.log('Transaction hash:', receipt.transactionHash);
```

### Error Handling

```javascript
try {
  await module.setAttribute(did, 'key', 'value', keypair);
} catch (error) {
  if (error.message.includes('insufficient funds')) {
    console.log('Need more ETH for gas fees');
  } else if (error.message.includes('nonce')) {
    console.log('Transaction nonce issue, retry');
  } else {
    console.log('Other error:', error.message);
  }
}
```

## DID Format

Ethr DIDs follow this format:

```text
did:ethr:[network:]address

Examples:
- did:ethr:0x1234567890123456789012345678901234567890 (mainnet)
- did:ethr:sepolia:0x1234567890123456789012345678901234567890 (sepolia)
- did:ethr:vietchain:0x1234567890123456789012345678901234567890 (custom chain)
```

## Utility Functions

The module exports useful utility functions:

```javascript
import {
  addressToDID,
  parseDID,
  isEthrDID,
  keypairToAddress,
} from '@docknetwork/credential-sdk/modules/ethr-did';

// Convert address to DID
const did = addressToDID('0x1234...', 'sepolia');

// Parse DID to components
const { network, address } = parseDID(did);

// Check if string is valid ethr DID
if (isEthrDID(did)) {
  // Process DID
}

// Get Ethereum address from keypair
const address = keypairToAddress(keypair);
```

## Best Practices

### 1. Network Selection
- Use testnets (Sepolia) for development
- Keep RPC URLs in environment variables
- Use dedicated RPC endpoints for production

### 2. Key Management
- Never expose private keys in code
- Use hardware wallets for high-value DIDs
- Rotate delegates regularly

### 3. Transaction Management
- Always check gas prices before transactions
- Handle transaction failures gracefully
- Wait for sufficient confirmations (production: 12+ blocks)

### 4. DID Resolution
- Cache resolved DID documents when appropriate
- Handle network errors during resolution
- Use resolver timeout settings

## Troubleshooting

### Network Connection Issues

```javascript
// Test network connectivity
try {
  const provider = module._getProvider('vietchain');
  const blockNumber = await provider.getBlockNumber();
  console.log('Connected! Current block:', blockNumber);
} catch (error) {
  console.log('Connection failed:', error.message);
}
```

### Gas Estimation

```javascript
// The module automatically estimates gas, but you can check:
const gasPrice = await provider.getGasPrice();
console.log('Current gas price:', ethers.utils.formatUnits(gasPrice, 'gwei'), 'gwei');
```

### DID Not Resolving

- Check network connectivity
- Verify the DID format is correct
- Ensure the registry contract address is correct
- Check if the DID has been created on-chain (basic DIDs exist off-chain)

## Example: Complete DID Lifecycle

```javascript
import { EthrDIDModule, createVietChainConfig, keypairToAddress } from '@docknetwork/credential-sdk/modules/ethr-did';
import { Secp256k1Keypair } from '@docknetwork/credential-sdk/keypairs';

async function completeDIDLifecycle() {
  // 1. Setup module
  const module = new EthrDIDModule({
    networks: [createVietChainConfig()],
  });

  // 2. Create DID
  const keypair = Secp256k1Keypair.random();
  const did = await module.createNewDID(keypair);
  console.log('Created:', did);

  // 3. Resolve initial document
  let doc = await module.getDocument(did);
  console.log('Initial document:', doc);

  // 4. Add service endpoint (on-chain)
  await module.setAttribute(
    did,
    'did/svc/Website',
    'https://example.com',
    keypair,
  );

  // 5. Add delegate
  const delegateKeypair = Secp256k1Keypair.random();
  await module.addDelegate(
    did,
    keypairToAddress(delegateKeypair),
    keypair,
  );

  // 6. Resolve updated document
  doc = await module.getDocument(did);
  console.log('Updated document:', doc);

  // 7. Sign a credential (see "Signing Verifiable Credentials" section above)

  // 8. Revoke delegate
  await module.revokeDelegate(
    did,
    keypairToAddress(delegateKeypair),
    keypair,
  );

  // 9. Transfer ownership
  const newOwner = Secp256k1Keypair.random();
  await module.changeOwner(
    did,
    keypairToAddress(newOwner),
    keypair,
  );

  console.log('DID lifecycle complete!');
}
```

## Resources

- [ERC-1056 DID Registry Specification](https://github.com/ethereum/EIPs/issues/1056)
- [Ethr DID Method Specification](https://github.com/decentralized-identity/ethr-did-resolver)
- [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- [Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)

## See Also

- [DID Resolver Tutorial](./tutorial_resolver.md)
- [Verifiable Credentials Tutorial](./concepts_vcdm.md)
- [Keypairs Documentation](../packages/credential-sdk/src/keypairs/README.md)
