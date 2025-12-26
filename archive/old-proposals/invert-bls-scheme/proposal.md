# Proposal: Invert BLS Signature Scheme for SDK Compatibility

**Change ID**: `invert-bls-scheme`
**Status**: Draft
**Priority**: High
**Scope**: Contract + SDK Integration

---

## Problem Statement

The EthereumDIDRegistry contract currently uses a BLS12-381 signature scheme that is **inverted** from the SDK's `@noble/curves/bls12-381` library:

| Component | Contract Expects | SDK Generates | Compatible? |
|-----------|------------------|---------------|-------------|
| Public Key | G2 (96 bytes) | G1 (48 bytes) | ❌ No |
| Signature | G1 (96 bytes) | G2 (96 bytes) | ❌ Inverted |

This incompatibility means:
- ❌ SDK cannot generate fresh BLS keypairs for use with the contract
- ❌ Users must rely on external signing services or pre-signed test vectors
- ❌ Poor developer experience for BLS-based owner changes
- ✅ SDK can still read from contract and generate correct EIP-712 hashes

---

## Proposed Solution

**Change the contract's `changeOwnerWithPubkey()` function to accept:**
- **G1 public keys** (48 bytes compressed OR 96 bytes uncompressed)
- **G2 signatures** (192 bytes uncompressed)

This aligns with the SDK's native BLS implementation and enables:
- ✅ Fresh keypair generation directly in SDK
- ✅ Native signing without external services
- ✅ Better developer experience
- ✅ Standard BLS variant (G1 keys + G2 signatures)

---

## Impact Analysis

### Benefits
- **SDK Integration**: Direct compatibility with `@noble/curves/bls12-381`
- **Developer Experience**: No need for external BLS signing services
- **Fresh Keys**: Can generate and use new keypairs natively
- **Standard Format**: Aligns with common BLS12-381 implementations

### Breaking Changes
- **Existing Signatures**: Any pre-existing BLS signatures will be invalid
- **Test Data**: All test vectors need regeneration
- **Migration**: Requires contract redeployment

### Affected Components
1. **Contract**: `changeOwnerWithPubkey()` in EthereumDIDRegistry.sol
2. **SDK**: Can now use native BLS key generation
3. **Tests**: All BLS-related tests need updates
4. **Documentation**: Update examples and migration guides

---

## Key Questions

### Q1: Does @onematrix/bls-solidity support inverted pairing?
**Status**: Needs investigation
**Impact**: Critical - determines implementation feasibility

The library provides:
- `g1Unmarshal()` / `g1UnmarshalCompressed()` - for G1 points ✅
- `g2Unmarshal()` - for G2 points ✅
- `verifySingle(sig_G1, pubkey_G2, message_G1)` - current verification

**Need to verify**: Can we use inverted pairing `e(pubkey_G1, message_G2) = e(G1_gen, sig_G2)`?

### Q2: Should we support compressed signatures?
**Recommendation**: Start with uncompressed (192 bytes) only
**Rationale**: Simpler initial implementation, can add compression later

### Q3: How to handle address derivation from compressed G1 keys?
**Options**:
1. Support both compressed (48 bytes) and uncompressed (96 bytes)
2. Always expand compressed to uncompressed before hashing
3. Support only uncompressed initially

**Recommendation**: Support both formats for flexibility

### Q4: Migration path for existing deployments?
**Options**:
1. **Breaking change**: Deploy new contract version (recommended for development)
2. **Dual function**: Add `changeOwnerWithPubkeyG1()` alongside existing function
3. **Auto-detect**: Route based on public key length

**Recommendation**: Breaking change (new deployment) for clean implementation

---

## Dependencies

- **@onematrix/bls-solidity library** must support inverted pairing verification
- **EthereumDIDRegistry contract** must be redeployable (or new version)
- **SDK test infrastructure** must support BLS key generation

---

## Out of Scope

- Supporting both old and new schemes in same contract
- Migrating existing on-chain BLS owners (would need re-signing)
- Implementing compressed G2 signatures (192 → 96 bytes compression)
- Changes to other DID methods (only affects ethr-did BLS features)

---

## Success Criteria

1. ✅ SDK can generate fresh BLS keypairs with `@noble/curves/bls12-381`
2. ✅ Generated keys work with contract's `changeOwnerWithPubkey()`
3. ✅ All existing integration tests pass with new scheme
4. ✅ Gas costs remain reasonable (benchmark against old scheme)
5. ✅ Clear migration documentation for developers

---

## Related Work

- **Current State**: `BLS_INTEGRATION_VERIFIED.md` proves SDK + contract integration works with verified test vectors
- **Key Format Analysis**: `BLS_KEY_FORMAT_ANALYSIS.md` documents the G1/G2 mismatch
- **Passing Tests**: `e2e-bls-verified.test.ts` (9/9 passing with verified data)

---

## Next Steps

1. **Investigate** @onematrix/bls-solidity pairing capabilities
2. **Design** updated contract function signature
3. **Implement** prototype in test contract
4. **Generate** test vectors with SDK
5. **Validate** gas costs and security
6. **Deploy** and integrate with SDK

---

**Prepared by**: Claude Code
**Date**: 2025-12-25
