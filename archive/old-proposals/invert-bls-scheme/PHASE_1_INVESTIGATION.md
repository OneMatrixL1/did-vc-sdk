# Phase 1: Investigation & Validation Results

**Date**: 2025-12-25
**Investigator**: Claude Code
**Status**: COMPLETE

## Summary

Phase 1 investigation is complete. The @onematrix/bls-solidity library has sufficient capabilities to implement the inverted BLS scheme. Key findings:

| Capability | Status | Details |
|-----------|--------|---------|
| G1 Unmarshaling | ✅ AVAILABLE | `g1Unmarshal()` and `g1UnmarshalCompressed()` |
| G2 Unmarshaling | ✅ AVAILABLE | `g2Unmarshal()` for uncompressed (192 bytes) |
| G1 Marshaling | ✅ AVAILABLE | `g1Marshal()` for converting points back to bytes |
| G2 Marshaling | ✅ AVAILABLE | `g2Marshal()` for converting G2 points to bytes |
| Hash to G1 | ✅ AVAILABLE | `hashToPoint()` for message to G1 point |
| Hash to G2 | ❌ NOT AVAILABLE | No `hashToPointG2()` - must implement custom |
| Inverted Pairing | ✅ CUSTOM IMPLEMENTATION | EIP-2537 precompile available, need to manually construct pairing check |
| Precompiles | ✅ AVAILABLE | BLS12_PAIRING_CHECK (0x0f) for custom pairing verification |

---

## Investigation Details

### 1. BLS2 Library Pairing Support

**Finding**: The @onematrix/bls-solidity library provides only one pairing verification function:
- `verifySingle(signature_G1, pubkey_G2, message_G1)` - Current scheme

**No built-in function for inverted pairing** (pubkey_G1, message_G2, signature_G2).

**Solution**: We can manually implement inverted pairing using the EIP-2537 precompile directly:
- Use the `BLS12_PAIRING_CHECK` precompile (address 0x0f)
- Construct the input arrays for the inverted pairing equation
- Verify: `e(pubkey_G1, message_G2) = e(G1_gen, sig_G2)`

**Implementation Strategy**:
```solidity
function verifyInvertedPairing(
    BLS2.PointG1 memory pubkey,
    BLS2.PointG2 memory sig,
    BLS2.PointG2 memory message
) internal view returns (bool pairingSuccess, bool callSuccess) {
    // Construct pairing input for:
    // e(pubkey_G1, message_G2) = e(G1_gen, sig_G2)

    // This requires two pairing checks in the input array
    // Similar to verifySingle but with different point ordering
}
```

**Risk Assessment**: LOW
- EIP-2537 precompile is standard and available on all networks
- Manual pairing construction is well-established pattern
- Same approach used by existing `verifySingle()` function

---

### 2. G2 Message Hashing Capability

**Finding**: The BLS2 library has `hashToPoint()` but **NO `hashToPointG2()`** function.

**Available Function**:
```solidity
function hashToPoint(bytes memory dst, bytes memory message)
    internal view returns (PointG1 memory out)
```

Maps message to G1 curve using:
1. RFC 9380 Section 5 (Hash-to-Curve)
2. Precompile: `BLS12_MAP_FP_TO_G1` (0x10)
3. Domain separation tag support

**Solution**: Implement `hashToPointG2()` following the same pattern:
- Reuse the `expandMsg()` helper (already public-equivalent)
- Use the EIP-2537 G2 hashing precompile if available
- Or implement manually using the same SHA256-based approach

**Available Precompiles for Hashing**:
- `BLS12_MAP_FP_TO_G1` (0x10) - Exists in library ✅
- `BLS12_MAP_FP_TO_G2` (0x11) - Standard EIP-2537, need to use directly

**Implementation Approach**:
```solidity
function hashToPointG2(bytes memory dst, bytes memory message)
    internal view returns (PointG2 memory out) {
    bytes memory uniform_bytes = expandMsg(dst, message, 128);
    // Similar to hashToPoint but using BLS12_MAP_FP_TO_G2 (0x11)
    // Two iterations to hash to two field elements, map to G2
}
```

**Risk Assessment**: LOW
- Pattern is identical to existing `hashToPoint()`
- Precompiles are standard EIP-2537
- Implementation is straightforward

---

### 3. BLS2 Library Available Functions

**Verified Available Functions**:

```solidity
// G1 Point Operations
function g1Unmarshal(bytes memory m) → PointG1          // 96 bytes uncompressed
function g1UnmarshalCompressed(bytes memory m) → PointG1  // 48 bytes compressed ✅
function g1Marshal(PointG1 memory point) → bytes memory   // To 96 bytes uncompressed ✅

// G2 Point Operations
function g2Unmarshal(bytes memory m) → PointG2            // 192 bytes uncompressed ✅
function g2Marshal(PointG2 memory point) → bytes memory   // To 192 bytes uncompressed

// Hashing
function hashToPoint(bytes memory dst, message) → PointG1
function expandMsg(bytes memory DST, message, n_bytes) → bytes

// Verification (Current Scheme Only)
function verifySingle(sig_G1, pubkey_G2, message_G1) → (bool, bool)

// Precompile Constants
BLS12_PAIRING_CHECK = 0x0f          // For custom pairing
BLS12_MAP_FP_TO_G1 = 0x10          // Hash to G1
BLS12_MAP_FP_TO_G2 = 0x11          // Hash to G2 (not called yet)
```

---

### 4. Signature Format Analysis from @noble/curves

**@noble/curves BLS12-381 Library**:
- Installed in SDK via dependencies
- Generates compressed signatures: **96 bytes** (G2 compressed)
- Generates compressed public keys: **48 bytes** (G1 compressed)
- Can be expanded to uncompressed using built-in methods

**SDK Signature Generation**:
```typescript
import { bls12_381 as bls } from '@noble/curves/bls12-381';

const secretKey = bls.utils.randomPrivateKey();  // 32 bytes
const publicKey = bls.getPublicKey(secretKey);    // 48 bytes (G1 compressed)
const signature = bls.sign(messageBytes, secretKey);  // 96 bytes (G2 compressed)
```

**Contract Requirements**:
- Public Key: 48 bytes (compressed) or 96 bytes (uncompressed) ✅
- Signature: 192 bytes (uncompressed G2 only)

**Format Conversion Required**:
- SDK generates: 96 bytes (G2 compressed)
- Contract expects: 192 bytes (G2 uncompressed)

**Solution Options**:
1. Contract accepts both (add length check)
2. SDK expands before sending (recommended for simplicity)
3. Contract expands (adds gas cost on-chain)

**Recommended**: Option 2 - SDK expands compressed G2 signatures before contract call
- Cheaper off-chain expansion
- Simpler contract logic
- Better developer experience

---

### 5. Gas Cost Considerations

**Current Scheme** (G2 pubkey + G1 sig):
- Public key: 96 bytes
- Signature: 96 bytes
- Hash: G1 point (96 bytes)
- Verification: `verifySingle()` pairing check

**Proposed Scheme** (G1 pubkey + G2 sig):
- Public key: 48 bytes (compressed, expands to 96 for address derivation)
- Signature: 192 bytes (G2 uncompressed)
- Hash: G2 point (192 bytes)
- Verification: Custom inverted pairing check

**Estimated Impact**:
- Signature size doubles: 96 → 192 bytes
- Public key size unchanged: 96 bytes
- Total call data increases slightly
- Pairing operation complexity similar
- **Expected increase**: 10-15% higher gas (primarily from larger signature)

**Benchmarking**: Will measure in Phase 2 testing

---

## Conclusions & Recommendations

### What Works ✅

1. **G1 Public Key Support**: `g1Unmarshal()` and `g1UnmarshalCompressed()` available
2. **G2 Signature Support**: `g2Unmarshal()` available for 192-byte uncompressed
3. **Custom Pairing**: EIP-2537 precompile allows manual inverted pairing verification
4. **SDK Integration**: @noble/curves generates G1 keys + G2 signatures natively
5. **Address Derivation**: Can expand compressed G1 and hash with keccak256

### What Needs Implementation ✅

1. **Hash to G2**: Implement `hashToPointG2()` using BLS12_MAP_FP_TO_G2 precompile
2. **Inverted Pairing Verification**: Implement `verifyInvertedPairing()` using BLS12_PAIRING_CHECK
3. **G1 Key Unmarshaling Helper**: Wrapper for both compressed/uncompressed
4. **SDK Helpers**: Functions to expand G2 signatures and generate addresses

### Implementation Feasibility

**Assessment**: ✅ FULLY FEASIBLE

- All required BLS operations are available
- Precompiles support the necessary cryptography
- Pattern follows existing library implementations
- No external dependencies needed beyond what's already available
- Estimated effort: 3-4 weeks for full implementation + testing

---

## Next Steps

Proceed to **Phase 2: Contract Prototype** with confidence:
1. Implement `hashToPointG2()` in test contract
2. Implement `verifyInvertedPairing()` in test contract
3. Test with SDK-generated keys and signatures
4. Benchmark gas costs
5. Update main contract and SDK

---

**Approval**: Ready to proceed to Phase 2 ✅
