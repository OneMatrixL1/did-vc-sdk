# DID Owner Proof (Off-chain Resolver History)

## Overview

`didOwnerProof` is a mechanism used within the Dock Credential SDK to provide a verifiable history of DID ownership transitions. This is particularly useful for **off-chain resolvers** and **optimistic DID resolution**, where a verifier might not have immediate or complete access to the on-chain event history of an Ethr DID.

By attaching a `didOwnerProof` to a Verifiable Credential (VC) or Verifiable Presentation (VP), the issuer/holder provides the necessary cryptographic evidence to prove that a specific public key was authorized to sign on behalf of the DID at a certain point in time.

## How it Works

A `didOwnerProof` consists of a chain of ownership transitions. Each transition proves that the owner of the DID changed from an `oldOwner` to a `newOwner`.

### Data Structure

The `didOwnerProof` is an array of transition objects:

```json
[
  {
    "signature": "0x...", 
    "publicKey": "0x...",
    "message": {
      "identity": "0x...", 
      "oldOwner": "0x...",
      "newOwner": "0x..."
    }
  },
  ...
]
```

| Field | Description |
|-------|-------------|
| `signature` | A BLS signature proving the transition, signed by the `oldOwner`. |
| `publicKey` | The BLS public key of the `oldOwner` used to verify the signature. |
| `message.identity` | The Ethereum address of the DID (the `identity` in ERC-1056). |
| `message.oldOwner` | The Ethereum address of the owner *before* this transition. |
| `message.newOwner` | The Ethereum address of the owner *after* this transition. |

### Verification Logic

The SDK verifies the history chain using the following rules:

1. **Continuity**: The `newOwner` of transition `i` must exactly match the `oldOwner` of transition `i+1`.
2. **Identity Consistency**: The `identity` in every message must match the subject DID being verified.
3. **Key Derivation**: The `publicKey` provided in each transition must derive to the `oldOwner` address.
4. **Signature Validity**: The `signature` must be a valid BLS signature over the hash of the transition message (`identity`, `oldOwner`, `newOwner`).

## Usage in VCs and VPs

### Automatic Fetching

When issuing a credential using `issueCredential`, the SDK automatically attempts to fetch the DID owner history from a configured `DIDServiceClient` if `didOwnerProof` is not already present.

```javascript
import { issueCredential } from '@docknetwork/credential-sdk/vc';

// The SDK will automatically attach didOwnerProof if possible
const signedVC = await issueCredential(keyDoc, unsignedCredential);
```

### Manual Attachment

You can also manually attach a `didOwnerProof` to your credential or presentation:

```javascript
const credential = {
  ...baseCredential,
  didOwnerProof: [ /* ... array of transitions ... */ ]
};
```

## Why use didOwnerProof?

1. **Optimistic Fallback**: In **Optimistic DID Resolution**, if verification fails with a default DID document, the `didOwnerProof` provides a secondary verification path that doesn't require a slow blockchain RPC call.
2. **Off-chain Verification**: Enables verification in environments with limited or no blockchain access, assuming the verifier trusts the initial state of the DID.
3. **Performance**: Significantly reduces latency by avoiding multiple `eth_getLogs` calls to reconstruct the ownership history on the fly.

## Related Documentation

- [Optimistic DID Resolution](./optimistic-did-resolution.md)
- [Ethr DID Module](../README.md)
