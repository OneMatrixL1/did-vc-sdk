# @docknetwork/credential-sdk

An API-agnostic Javascript library for working with Verifiable Credentials, DIDs, Claim Deduction and more.

## Features

- **Flexible Credential Issuance**: Issue verifiable credentials with customizable and embeddable JSON schema validators.

- **DID Management**: Manage DIDs with support for various key types and update operations, including adding/removing keys, controllers, and service endpoints.

- **Credential Verification**: Verify credentials using predefined or custom DID resolvers.

- **Extensible DID Resolvers**: Support for universal, key, and network-specific DID resolvers, including Ethereum and Dock.

- **Blockchain Interaction**: Seamlessly interact with the Dock blockchain for DID and credential management.

## Installation

You can install the `@docknetwork/credential-sdk` via npm:

```bash
npm install @docknetwork/credential-sdk
```

Or via yarn:

```bash
yarn add @docknetwork/credential-sdk
```

## Quick Start

### 1. Initialize DID Module

Create an instance of `EthrDIDModule` to manage Ethereum-based DIDs.

```javascript
import { EthrDIDModule } from '@docknetwork/credential-sdk/modules/ethr-did';

const ethrDIDModule = new EthrDIDModule({
  networks: [
    {
      name: 'sepolia',
      rpcUrl: 'https://rpc.sepolia.org',
      registry: '0xdcaad4d2a90c9578afe73211c1d0309990520f99'
    }
  ],
  defaultNetwork: 'sepolia'
});
```

### 2. Create a DID

Generate a new DID using a `Secp256k1Keypair`.

```javascript
import { Secp256k1Keypair } from '@docknetwork/credential-sdk/keypairs';

const keypair = Secp256k1Keypair.random();
const did = await ethrDIDModule.createNewDID(keypair);
console.log(`Created DID: ${did}`);
```

### 3. Issue a Verifiable Credential

Sign a credential using an issuer's key and DID.

```javascript
import { issueCredential } from '@docknetwork/credential-sdk/vc';

const issuerKeyDoc = {
  id: `${did}#keys-1`,
  controller: did,
  type: 'EcdsaSecp256k1VerificationKey2019',
  keypair: keypair,
};

const credential = await issueCredential(issuerKeyDoc, {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  issuer: did,
  issuanceDate: new Date().toISOString(),
  credentialSubject: {
    id: 'did:example:holder',
    degree: 'Bachelor of Science'
  }
});
```

### 4. Verify a Credential

Check the validity and signature of a credential.

```javascript
import { verifyCredential } from '@docknetwork/credential-sdk/vc';

const result = await verifyCredential(credential);
console.log('Verified:', result.verified);
```

## Documentation

Detailed documentation and API reference:
- [BBS+ Selective Disclosure](./docs/bbs-selective-disclosure.md) - Selective disclosure with BBS+ signatures.
- [Optimistic DID Resolution](./docs/optimistic-did-resolution.md) - High-performance local-first DID resolution.
- [DID Owner Proof](./docs/did-owner-proof.md) - Cryptographic history proofs for off-chain resolution.
- [Dock Network Documentation](https://docs.dock.io) - Comprehensive resource for the Dock ecosystem.

## Core Data Structures

The SDK uses a set of "Typed" structures to ensure type safety and consistent serialization across different platforms (e.g., Substrate, Ethereum, and Browser).

### Available Types

- **TypedBytes**: Binary data as `Uint8Array` with base58/base64/hex conversions.
- **TypedString**: UTF-8 encoded string management.
- **TypedEnum**: Extensible enumeration types for complex state management.
- **TypedStruct**: Dictionary-like data with strict key/type constraints.
- **TypedTuple**: Fixed-size collections with ordered type checks.

See [Types Overview](#types-overview-1) for more details.

## Contribution

Contributions are welcome! Please open issues or submit pull requests to improve the SDK.

## Types Overview

<details>
<summary>Click to expand full types list</summary>

- **TypedNumber**: Strict numerical handling.
- **TypedArray**: Uniform handling of a single item type.
- **TypedMap**: Consistent key/value type management.
- **TypedSet**: Unique values management.
- **TypedUUID**: Robust UUID generation and validation.
- **TypedNull**: Placeholder for empty values.

### Utility Mixins

- **anyOf**: Ordered type construction from multiple types.
- **option**: Graceful handling of missing/null data.
- **sized**: Enforces specific data sizes.
- **withBase**: Adds `from`, `toJSON`, and equality checks.
- **withEq**: Deep comparison for complex objects.
- **withQualifier**: Support for prefixed strings (like DIDs).
</details>

## License

MIT License. See [LICENSE](./LICENSE) for details.

## License

This SDK is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more details.

For any questions or issues, please refer to our [GitHub repository](https://github.com/docknetwork/credential-sdk).
