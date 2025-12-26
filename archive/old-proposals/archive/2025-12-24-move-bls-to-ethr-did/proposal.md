# Change: Move BLS Owner Change to ethr-did Libraries

## Why

The BLS12-381 owner change functionality is currently implemented in `credential-sdk` as utility functions and direct contract calls. This creates several issues:

1. **Leaky Abstraction**: Some DID operations go through the ethr-did library (`changeOwner`) while BLS operations bypass it entirely
2. **Limited Reusability**: Other projects using the custom registry cannot leverage BLS functionality without credential-sdk
3. **Inconsistent API**: Users must understand two different patterns for owner changes
4. **Maintenance Burden**: BLS logic duplicates concerns that belong in ethr-did (nonce management, contract interaction, signature handling)

Since the EthereumDIDRegistry contract has been extended with `changeOwnerWithPubkey`, the ethr-did library should expose this capability through its standard API.

## What Changes

**ethr-did-resolver (packages/ethr-did-resolver):**
- **NEW** `EthrDidController.changeOwnerWithPubkey()` method matching the pattern of existing `changeOwner()`
- **NEW** `EthrDidController.createChangeOwnerWithPubkeyHash()` for generating signature hashes
- **NEW** Support for BLS12-381 public key address derivation (keccak256 of 96-byte G2 public key)
- **NEW** Nonce management via `pubkeyNonce(address)` contract call
- **NEW** Contract interface for `changeOwnerWithPubkey(address identity, address newOwner, uint256 pubkeyNonceParam, bytes publicKey, bytes signature)`

**ethr-did (packages/ethr-did):**
- **NEW** `EthrDID.changeOwnerWithPubkey(newOwner, publicKey, signature)` method
- **NEW** Wrapper that delegates to `EthrDidController.changeOwnerWithPubkey()`
- **MODIFIED** TypeScript types to support BLS signatures alongside existing ECDSA

**credential-sdk (packages/credential-sdk):**
- **MODIFIED** `EthrDIDModule.changeOwnerWithPubkey()` simplified to use ethr-did library
- **REMOVED** Direct contract interaction code (nonce fetching, transaction encoding)
- **RETAINED** BLS signing utilities (`signWithBLSKeypair`) as SDK-specific crypto operations
- **RETAINED** EIP-712 typed data construction (may be moved or remain as SDK convenience)

## Impact

- **Affected packages**: ethr-did, ethr-did-resolver, credential-sdk
- **Breaking changes**: None - this refactors internal implementation while maintaining credential-sdk public API
- **Benefits**:
  - Cleaner separation: ethr-did handles registry operations, credential-sdk handles credential-specific logic
  - Reusable: Any project can use BLS owner changes through ethr-did
  - Consistent: All owner change operations follow the same pattern
  - Testable: BLS logic can be tested independently in ethr-did test suite

## Design Considerations

### Architecture Layers

```
┌─────────────────────────────────────────────┐
│ credential-sdk/EthrDIDModule                │
│ - High-level DID + credential operations   │
│ - BLS keypair integration                   │
│ - Simplified changeOwnerWithPubkey()        │
└────────────────┬────────────────────────────┘
                 │ uses
┌────────────────▼────────────────────────────┐
│ ethr-did/EthrDID                            │
│ - DID operations API                        │
│ - changeOwner(), changeOwnerWithPubkey()    │
└────────────────┬────────────────────────────┘
                 │ uses
┌────────────────▼────────────────────────────┐
│ ethr-did-resolver/EthrDidController         │
│ - Registry contract interaction             │
│ - Nonce management                          │
│ - Transaction building & submission         │
└─────────────────────────────────────────────┘
```

### Implementation Strategy

1. **Add to ethr-did-resolver first**: Implement controller methods with proper contract interaction
2. **Expose via ethr-did**: Add thin wrapper matching existing `changeOwner()` pattern
3. **Simplify credential-sdk**: Replace direct contract calls with ethr-did library calls
4. **Maintain compatibility**: Keep credential-sdk public API unchanged

### BLS-Specific Concerns

- **Address Derivation**: Implemented in ethr-did-resolver helpers (follows existing `interpretIdentifier` pattern)
- **Signature Format**: ethr-did accepts opaque `bytes` signature, credential-sdk handles BLS signing
- **Public Key Handling**: 96-byte Uint8Array passed through ethr-did to contract

### Signature Pattern Consistency

Both ECDSA and BLS owner changes will follow the same pattern:

```javascript
// ECDSA (existing)
const ethrDid = new EthrDID(config)
await ethrDid.changeOwner(newOwner)

// BLS (new - same pattern)
const ethrDid = new EthrDID(config)
await ethrDid.changeOwnerWithPubkey(newOwner, publicKey, signature)
```

The credential-sdk wraps these with keypair handling:

```javascript
// credential-sdk provides convenience
await ethrDidModule.changeOwnerWithPubkey(did, newOwner, bbsKeypair)
```
