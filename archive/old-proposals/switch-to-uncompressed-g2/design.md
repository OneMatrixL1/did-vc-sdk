# Design: Uncompressed G2 Public Keys for BBS Signatures

## Context

The SDK uses the BBS signature scheme (2023 version) from `@docknetwork/crypto-wasm-ts`, which provides BLS12-381 cryptographic primitives. Currently, the SDK extracts **compressed G2 public keys (96 bytes)** using the `.value` property of `BBSPublicKey` instances.

However, the Ethereum smart contract (`EthereumDIDRegistry.sol`) uses the `@onematrix/bls-solidity` library, which requires **uncompressed G2 public keys (192 bytes)** for pairing verification via BLS12-381 precompiles.

**Key Incompatibility:**
- **Compressed G2**: 96 bytes (x-coordinate only, y-coordinate computed)
- **Uncompressed G2**: 192 bytes (both x and y coordinates explicitly stored)

The contract explicitly validates 192-byte format at multiple points (lines 94, 425, 443).

## Goals / Non-Goals

**Goals:**
- Extract and use **192-byte uncompressed G2 public keys** from `BBSPublicKey`
- Update address derivation to hash uncompressed keys consistently with contract
- Maintain compatibility with contract's BLS verification precompiles
- Clear migration path for existing implementations

**Non-Goals:**
- Supporting both compressed and uncompressed formats simultaneously
- Backward compatibility with 96-byte compressed addresses
- Changes to BBS+ (2022 scheme) - only affects BBS (2023)
- Modifying the underlying crypto-wasm-ts library

## Decisions

### Decision 1: Use Uncompressed Format Only
**Choice**: Use 192-byte uncompressed G2 public keys exclusively for BBS 2023.

**Rationale:**
- Contract requires uncompressed format (cannot be changed without contract upgrade)
- BLS12-381 precompiles (EIP-2537) expect uncompressed points
- Simpler implementation without format conversion logic
- Consistent with inverted BLS scheme (already uses uncompressed G2 signatures)

**Alternatives Considered:**
- **Auto-expand compressed to uncompressed**: Adds complexity, error-prone
- **Support both formats**: Increases test surface, harder to maintain

### Decision 2: Extract Uncompressed via crypto-wasm-ts API
**Choice**: Investigate and use `@docknetwork/crypto-wasm-ts` API to serialize uncompressed G2 points.

**Rationale:**
- The library already handles BLS12-381 curve operations
- `.value` likely returns compressed format by default
- May have `.toBytes()`, `.toUncompressed()`, or similar method
- Avoids manual point expansion (error-prone)

**Implementation Plan:**
1. Check `BBSPublicKey` API documentation
2. Look for uncompressed serialization methods
3. If not available, investigate underlying point representation
4. Fallback: Manual expansion using curve arithmetic (not preferred)

### Decision 3: Breaking Change for Address Derivation
**Choice**: Accept that Ethereum addresses will change when switching from compressed to uncompressed key hashing.

**Rationale:**
- Address = `keccak256(publicKey).slice(-20)`
- Hashing different bytes (96 vs 192) produces different addresses
- Contract already expects uncompressed, so SDK must match
- Clean break better than dual-format complexity

**Migration:**
- Document the breaking change prominently
- Provide migration script to regenerate addresses
- Update all test data and examples

### Decision 4: Update Size Validation
**Choice**: Change all 96-byte validations to 192 bytes for BBS 2023 keys.

**Rationale:**
- Contract validation: `require(publicKey.length == 192, ...)`
- SDK must match contract expectations exactly
- Clear error messages when wrong format detected

**Affected Locations:**
- `bbsPublicKeyToAddress()` - Update from 96 to 192
- `publicKeyToAddress()` - Update G2 branch from 96 to 192
- All BBS 2023 key handling code

## Technical Details

### G2 Point Format (BLS12-381)

**Compressed (96 bytes):**
```
[48 bytes x-coordinate] [48 bytes flag + compressed data]
```

**Uncompressed (192 bytes):**
```
[96 bytes x-coordinate] [96 bytes y-coordinate]
```

Each coordinate is a field element in Fq2 (quadratic extension field):
- x = (x0, x1) where each component is 48 bytes
- y = (y0, y1) where each component is 48 bytes

### Address Derivation Change

**Current (Compressed):**
```javascript
publicKeyBytes = bbsPublicKey.value; // 96 bytes compressed
address = keccak256(publicKeyBytes).slice(-20);
```

**Updated (Uncompressed):**
```javascript
publicKeyBytes = bbsPublicKey.toUncompressed(); // 192 bytes uncompressed
address = keccak256(publicKeyBytes).slice(-20);
```

**Result**: Different hash → different address (breaking change)

### Integration with Contract

The contract's `BLS2.g2Unmarshal()` expects uncompressed format:
```solidity
// EthereumDIDRegistry.sol:94
BLS2.PointG2 memory publicKey = BLS2.g2Unmarshal(publicKeyBytes);
```

This unmarshal expects:
```
Input: 192 bytes [x0_hi, x0_lo, x1_hi, x1_lo, y0_hi, y0_lo, y1_hi, y1_lo]
Output: PointG2 struct with coordinates
```

## Risks / Trade-offs

### Risk 1: Breaking Existing Addresses
**Impact**: HIGH - All existing BBS-derived addresses become invalid

**Mitigation:**
- Clear migration documentation
- Version bump (major)
- Deprecation notice for old format
- Provide address conversion tool

### Risk 2: crypto-wasm-ts API Uncertainty
**Impact**: MEDIUM - May not have straightforward uncompressed serialization

**Mitigation:**
- Investigate library source code
- Check for `.toBytes(compressed=false)` or similar
- Manual expansion as fallback (validate against test vectors)
- Contact library maintainers if needed

### Risk 3: Performance Impact
**Impact**: LOW - Larger keys (192 vs 96 bytes) in storage/transmission

**Trade-off:**
- **Benefit**: Contract compatibility, correct verification
- **Cost**: 2x storage for public keys
- **Verdict**: Correctness outweighs size

### Risk 4: Test Data Regeneration
**Impact**: MEDIUM - All BBS test keypairs need regeneration

**Mitigation:**
- Systematic test data update process
- Verify against contract test vectors
- Document regeneration steps

## Migration Plan

### Phase 1: Investigation (Current)
1. Explore `@docknetwork/crypto-wasm-ts` API for uncompressed serialization
2. Verify method exists or determine fallback approach
3. Create proof-of-concept extraction code

### Phase 2: Implementation
1. Update `Bls12381BBSKeyPairDock2023.js` key extraction
2. Update `bbsPublicKeyToAddress()` validation and hashing
3. Update `Bls12381BBSRecoveryMethod2023.js` key handling
4. Update size validations throughout codebase

### Phase 3: Testing
1. Generate new BBS test keypairs with uncompressed keys
2. Verify address derivation matches contract expectations
3. Test signature verification end-to-end with contract
4. Run full integration test suite

### Phase 4: Documentation
1. Update all "96 bytes" references to "192 bytes"
2. Create migration guide for address regeneration
3. Update API documentation
4. Update examples and tutorials

### Rollback Plan
If uncompressed extraction fails:
- **Option A**: Manual expansion using curve arithmetic
- **Option B**: Fork crypto-wasm-ts to add uncompressed method
- **Option C**: Use different BBS library (last resort)

## Open Questions

### Q1: Does BBSPublicKey have an uncompressed serialization method?
**Status**: Needs investigation
**Action**: Check library docs and source code
**Priority**: Critical - blocks implementation

### Q2: Should we support compressed keys in any capacity?
**Recommendation**: No - contract only supports uncompressed
**Rationale**: Simplicity, correctness, no dual-format complexity

### Q3: How to handle existing deployed addresses?
**Recommendation**: Breaking change with migration guide
**Rationale**: Clean break better than maintaining dual formats

### Q4: Impact on BBS+ (2022) scheme?
**Answer**: No impact - this change only affects BBS (2023)
**Rationale**: BBS+ uses different key types (BBSPlusPublicKeyG2)
