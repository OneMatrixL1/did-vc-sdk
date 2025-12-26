# Proposal: Switch to BBS G2 Keypair Scheme

**Change ID**: `switch-to-bbs-g2-scheme`
**Status**: Draft
**Created**: 2025-12-25
**Author**: SDK Team

## Summary

Unify the SDK to use BBS G2 keypairs (96-byte compressed, 192-byte uncompressed) for both Verifiable Credential signing and DID ownership. This replaces the current BLS G1 inverted scheme and ensures a single keypair can be used across all operations.

## Problem Statement

### Current State

The SDK currently uses **two different cryptographic schemes**:

1. **Verifiable Credentials (BBS)**:
   - Public Key: G2 point (96 bytes compressed)
   - Signatures: G1 point
   - Address derivation: `keccak256(96-byte compressed G2)`

2. **DID Ownership (BLS inverted)**:
   - Public Key: G1 point (96 bytes uncompressed)
   - Signatures: G2 point (192 bytes uncompressed)
   - Address derivation: `keccak256(96-byte uncompressed G1)`

### Issues

1. **Two different keypairs required**: Users need separate keys for VC signing vs DID ownership
2. **Address mismatch**: Same logical identity derives different addresses
3. **Complexity**: Two different code paths for key management
4. **User confusion**: Not obvious which keypair to use for which operation
5. **DID documents inconsistency**: Public key in VC proof ≠ public key controlling DID

## Proposed Solution

### Use BBS G2 Scheme Everywhere

Adopt the BBS G2 keypair scheme as the single standard:

- **Public Key**: G2 point, 96 bytes compressed, 192 bytes uncompressed
- **Signatures**: G1 point, 48-96 bytes
- **Address Derivation**: `keccak256(192-byte uncompressed G2)` [last 20 bytes]

### Key Changes

1. **Contract**: Accept G2 public keys (192B uncompressed) instead of G1
2. **SDK Address Derivation**: Use uncompressed G2 keys for address calculation
3. **Unified Keypair**: Same BBS keypair for both VC signing and DID ownership
4. **Consistent Verification**: Same public key appears in both VC proofs and DID documents

## Benefits

### User Experience

- **Single Keypair**: One BBS keypair for all operations
- **Consistent Addresses**: Same address across VC signing and DID ownership
- **Simpler**: One key management flow instead of two

### Technical

- **Code Reduction**: Remove duplicate BLS G1 code paths
- **Standard Compliance**: Align with BBS+ signature standard
- **Library Support**: Leverage existing BBS libraries (`@docknetwork/crypto-wasm-ts`)
- **Verification Simplicity**: Use standard BLS pairing `e(sig_G1, pk_G2, msg_G1)`

### Security

- **Proven Cryptography**: BBS+ is well-studied and standardized
- **No Custom Pairing**: Use library's built-in verification
- **Consistent Security Properties**: Same security guarantees across all operations

## Technical Details

### Address Derivation Change

**Before (BLS G1 compressed)**:
```typescript
// SDK derives from 96-byte compressed G1 key
const address = keccak256(compressedG1Key)[last 20 bytes]
```

**After (BBS G2 uncompressed)**:
```typescript
// SDK expands compressed G2 to uncompressed, then derives
const uncompressed = expandG2Key(compressedG2Key)  // 96B → 192B
const address = keccak256(uncompressed)[last 20 bytes]
```

### Contract Changes

**Before (BLS inverted scheme)**:
```solidity
function changeOwnerWithPubkey(
    bytes calldata publicKey,    // 96B G1 uncompressed
    bytes calldata signature     // 192B G2 uncompressed
) {
    // Verify: e(pk_G1, msg_G2) = e(G1_gen, sig_G2)
}
```

**After (BBS standard scheme)**:
```solidity
function changeOwnerWithPubkey(
    bytes calldata publicKey,    // 192B G2 uncompressed
    bytes calldata signature     // 48B or 96B G1
) {
    // Verify: e(sig_G1, pk_G2, msg_G1) - standard BBS
}
```

### SDK Changes

1. **bls-utils.ts**: Remove G1 functions, add G2 expansion
2. **helpers.ts**: Update `deriveAddressFromG1` → `deriveAddressFromG2`
3. **credential-sdk/utils.js**: Update `bbsPublicKeyToAddress` to use uncompressed
4. **ethr-did-resolver**: Use BBS keypairs instead of BLS

## Migration Path

### For Existing Users

**Breaking Change**: YES - Address derivation changes

**Migration Strategy**:
1. Users must regenerate keypairs or re-derive addresses
2. Provide migration tool to convert old addresses to new format
3. Document the breaking change clearly in CHANGELOG

### For New Users

- Single, straightforward keypair generation
- Clear documentation on BBS G2 usage
- Examples showing unified workflow

## Dependencies

### Internal

- `packages/ethr-did-resolver/src/bls-utils.ts`
- `packages/ethr-did-resolver/src/helpers.ts`
- `packages/credential-sdk/src/modules/ethr-did/utils.js`
- `packages/credential-sdk/src/vc/crypto/Bls12381BBSKeyPairDock2023.js`
- Contract: `/Users/one/workspace/ethr-did-registry/contracts/EthereumDIDRegistry.sol`

### External

- `@noble/curves/bls12-381` - For G2 key expansion
- `@docknetwork/crypto-wasm-ts` - BBS keypair generation
- `@onematrix/bls-solidity` - BLS2 library (contract side)

## Risks & Mitigations

### Risk 1: Breaking Change to Address Derivation

**Impact**: Existing addresses become invalid
**Mitigation**:
- Provide clear migration guide
- Version the change appropriately (major version bump)
- Offer migration tool for address conversion

### Risk 2: BLS2 Library Doesn't Support G2 Compression

**Impact**: Contract cannot accept 96-byte compressed G2 keys
**Mitigation**: SDK expands to 192 bytes before contract call (same pattern as current G2 signatures)

### Risk 3: Gas Costs May Change

**Impact**: G2 operations might have different costs than G1
**Mitigation**: Benchmark gas costs, optimize if needed

## Alternatives Considered

### Alternative 1: Keep Dual Scheme

**Pros**: No breaking changes
**Cons**: Continued complexity, user confusion, two keypairs needed

**Decision**: Rejected - doesn't solve the core problem

### Alternative 2: Use BLS G1 for Everything

**Pros**: Matches current DID scheme
**Cons**: Doesn't align with VC/BBS standards, would break VC signing

**Decision**: Rejected - VC signing is more important to align with standards

### Alternative 3: Support Both Schemes

**Pros**: Backward compatibility
**Cons**: Even more complexity, doesn't solve fragmentation

**Decision**: Rejected - makes problem worse

## Success Criteria

- [ ] Same BBS keypair works for both VC signing and DID ownership
- [ ] Single address derivation method across all operations
- [ ] Contract accepts G2 public keys (192B uncompressed)
- [ ] Contract verifies G1 signatures correctly
- [ ] All tests pass with new scheme
- [ ] Migration guide published
- [ ] Breaking changes documented in CHANGELOG

## Timeline Estimate

- **Proposal Review**: 1-2 days
- **Implementation**: 3-5 days
- **Testing**: 2-3 days
- **Documentation**: 1-2 days
- **Total**: ~1-2 weeks

## Related Changes

- `invert-bls-scheme` - Previous attempt, will be superseded
- `simplify-bls-eip712` - Will be incorporated into this change
