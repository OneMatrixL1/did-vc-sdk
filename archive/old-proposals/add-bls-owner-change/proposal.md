# Change: Add BLS12-381 Owner Change Support for Ethr-DID

## Why

Users with BLS12-381 keypairs need to manage ownership of their ethr DIDs. Currently, the ethr-did-registry only supports ECDSA (secp256k1) signatures for owner changes. Adding BLS12-381 support enables privacy-preserving credential holders to manage their DID ownership using the same keypair they use for BBS signatures.

## What Changes

- **NEW** BLS12-381 keypair handling in ethr-did SDK
- **NEW** Address derivation from BLS12-381 public keys (keccak256 hash of 96-byte G2 public key)
- **NEW** EIP-712 typed data structure: `ChangeOwnerWithPubkey(address identity, address signer, address newOwner, uint256 nonce)`
- **NEW** Contract function `changeOwnerWithPubkey` in EthereumDIDRegistry that:
  - Accepts public key and signature (any curve that supports address derivation)
  - Routes to appropriate verification (BLS12-381 for 96-byte pubkeys)
  - Verifies signature using on-chain pairing/verification
  - Includes nonce in signed message for explicit replay protection
  - Updates owner mapping
- **NEW** SDK methods to sign and submit owner change transactions with BLS keypairs
- **BREAKING**: None - this is additive functionality

## Impact

- Affected specs: `ethr-did-registry` (new capability)
- Affected code:
  - `/Users/one/workspace/ethr-did-registry/contracts/EthereumDIDRegistry.sol`
  - `/Users/one/workspace/sdk/packages/credential-sdk/src/modules/ethr-did/`
  - `/Users/one/workspace/sdk/packages/ethr-did/src/`

## Design Considerations

### EIP-712 Message Structure

```
ChangeOwnerWithPubkey(address identity, address signer, address newOwner, uint256 nonce)
```

This structure includes:
1. `signer` - Explicit authorization: proves who signed the message (derived from provided public key)
2. `nonce` - Explicit replay protection: signature commits to specific nonce value
3. `identity` - The DID being modified
4. `newOwner` - The new owner address

### Signature Verification Flow

1. Derive address from provided public key (e.g., keccak256 of 96-byte G2 key for BLS)
2. Verify derived address matches current owner
3. Reconstruct EIP-712 hash from `(identity, signer, newOwner, nonce)`
4. Verify nonce matches expected value for the signer
5. Route signature verification based on public key length:
   - 96 bytes → BLS12-381 G2 verification
   - (Future: 32 bytes → Ed25519, 64 bytes → secp256k1)
6. If valid, increment nonce and update owner mapping

### Extensible Design

The generic naming allows support for multiple signature schemes without interface changes:
- **BLS12-381**: Uses `changeOwnerWithPubkey` with 96-byte G2 public key
- **ECDSA**: Uses existing `changeOwnerEIP712` (no pubkey needed, ecrecover derives signer)
- **Future curves**: Add verification logic for other public key lengths
