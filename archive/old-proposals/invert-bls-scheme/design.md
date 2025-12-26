# Design: Invert BLS Signature Scheme

## Architecture Overview

This change inverts the BLS12-381 signature scheme used in the EthereumDIDRegistry contract to align with the SDK's `@noble/curves/bls12-381` library.

```
┌─────────────────────────────────────────────────────────────────┐
│                     Current Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  SDK (@noble/curves)          Contract (@onematrix/bls)        │
│  ┌─────────────────┐          ┌─────────────────┐              │
│  │ Generate Keys   │          │ Verify          │              │
│  │ - G1 pubkey (48)│    ❌    │ - G2 pubkey (96)│              │
│  │ - G2 sig (96)   │ MISMATCH │ - G1 sig (96)   │              │
│  └─────────────────┘          └─────────────────┘              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     Proposed Architecture                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  SDK (@noble/curves)          Contract (@onematrix/bls)        │
│  ┌─────────────────┐          ┌─────────────────┐              │
│  │ Generate Keys   │          │ Verify          │              │
│  │ - G1 pubkey (48)│    ✅    │ - G1 pubkey (48)│              │
│  │ - G2 sig (96)   │   MATCH  │ - G2 sig (192)  │              │
│  └─────────────────┘          └─────────────────┘              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Changes

### 1. Contract: EthereumDIDRegistry.sol

**Function**: `changeOwnerWithPubkey()`

#### Current Implementation
```solidity
function changeOwnerWithPubkey(
    address identity,
    address oldOwner,
    address newOwner,
    bytes calldata publicKey,    // 96 bytes (G2 uncompressed)
    bytes calldata signature     // 96 bytes (G1 uncompressed)
) external {
    // Derive address from G2 public key
    address signer = publicKeyToAddress(publicKey);

    // Unmarshal as G2 and G1
    BLS2.PointG2 memory pubkey = BLS2.g2Unmarshal(publicKey);
    BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);

    // Verify: e(sig_G1, G2_gen) = e(message_G1, pubkey_G2)
    BLS2.PointG1 memory message = BLS2.hashToPoint("BLS_DST", abi.encodePacked(hash));
    (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pubkey, message);
}
```

#### Proposed Implementation
```solidity
function changeOwnerWithPubkey(
    address identity,
    address oldOwner,
    address newOwner,
    bytes calldata publicKey,    // 48 or 96 bytes (G1 compressed/uncompressed)
    bytes calldata signature     // 192 bytes (G2 uncompressed)
) external {
    // Derive address from G1 public key (handle both formats)
    address signer = deriveAddressFromG1(publicKey);

    // Unmarshal G1 public key
    BLS2.PointG1 memory pubkey = unmarshalG1(publicKey);

    // Unmarshal G2 signature
    require(signature.length == 192, "invalid_signature_length");
    BLS2.PointG2 memory sig = BLS2.g2Unmarshal(signature);

    // Hash message to G2 (inverted from current)
    BLS2.PointG2 memory message = BLS2.hashToPointG2("BLS_DST", abi.encodePacked(hash));

    // Verify inverted pairing: e(pubkey_G1, sig_G2) = e(G1_gen, message_G2)
    (bool pairingSuccess, bool callSuccess) = verifyInvertedPairing(pubkey, sig, message);
}
```

---

### 2. Key Changes Required

#### A. Public Key Unmarshaling

**Before**: Only G2 (96 bytes)
```solidity
require(publicKey.length == 96, "unsupported_pubkey_type");
BLS2.PointG2 memory pubkey = BLS2.g2Unmarshal(publicKey);
```

**After**: G1 compressed (48 bytes) OR uncompressed (96 bytes)
```solidity
function unmarshalG1(bytes calldata publicKey) internal view returns (BLS2.PointG1 memory) {
    if (publicKey.length == 48) {
        // Compressed G1
        return BLS2.g1UnmarshalCompressed(publicKey);
    } else if (publicKey.length == 96) {
        // Uncompressed G1
        return BLS2.g1Unmarshal(publicKey);
    } else {
        revert("invalid_pubkey_length");
    }
}
```

#### B. Signature Unmarshaling

**Before**: G1 (96 bytes uncompressed)
```solidity
BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);
```

**After**: G2 (192 bytes uncompressed)
```solidity
require(signature.length == 192, "invalid_signature_length");
BLS2.PointG2 memory sig = BLS2.g2Unmarshal(signature);
```

#### C. Address Derivation

**Before**: From G2 (96 bytes)
```solidity
function publicKeyToAddress(bytes memory publicKey) internal pure returns (address) {
    return address(uint160(uint256(keccak256(publicKey))));
}
```

**After**: From G1 (48 or 96 bytes)
```solidity
function deriveAddressFromG1(bytes calldata publicKey) internal view returns (address) {
    bytes memory expandedKey;

    if (publicKey.length == 48) {
        // Expand compressed G1 to uncompressed
        BLS2.PointG1 memory point = BLS2.g1UnmarshalCompressed(publicKey);
        expandedKey = BLS2.g1Marshal(point);  // Returns 96 bytes
    } else {
        expandedKey = publicKey;
    }

    return address(uint160(uint256(keccak256(expandedKey))));
}
```

#### D. Pairing Verification

**Current Pairing Equation**:
```
e(sig_G1, G2_generator) = e(message_G1, pubkey_G2)
```

**Inverted Pairing Equation**:
```
e(pubkey_G1, message_G2) = e(G1_generator, sig_G2)
```

**Implementation** (needs BLS2 library investigation):
```solidity
function verifyInvertedPairing(
    BLS2.PointG1 memory pubkey,
    BLS2.PointG2 memory sig,
    BLS2.PointG2 memory message
) internal view returns (bool pairingSuccess, bool callSuccess) {
    // Option 1: Use BLS2 library if it supports inverted verification
    // return BLS2.verifySingleInverted(pubkey, sig, message);

    // Option 2: Manual pairing check using precompiles
    // Compute: e(pubkey, message) and e(G1_gen, sig)
    // Check if they're equal

    // Needs investigation of BLS2 library capabilities
}
```

---

### 3. SDK Changes

**Enabled Capability**: Fresh keypair generation

```typescript
import { bls12_381 as bls } from '@noble/curves/bls12-381';

// Generate fresh BLS keypair
const secretKey = bls.utils.randomPrivateKey();  // 32 bytes
const publicKey = bls.getPublicKey(secretKey);    // 48 bytes (G1 compressed)
const publicKeyHex = '0x' + Buffer.from(publicKey).toString('hex');

// Sign EIP-712 message hash
const messageHash = await controller.createChangeOwnerWithPubkeyHash(newOwner);
const messageBytes = ethers.getBytes(messageHash);
const signature = bls.sign(messageBytes, secretKey);  // 96 bytes (G2 compressed)
const signatureHex = '0x' + Buffer.from(signature).toString('hex');

// Call contract with SDK-generated keys
await registry.changeOwnerWithPubkey(
    identity,
    currentOwner,
    newOwner,
    publicKeyHex,    // ✅ 48 bytes G1 (compressed)
    signatureHex     // ⚠️  96 bytes but need 192 bytes uncompressed!
);
```

**Issue Identified**: SDK generates compressed G2 signatures (96 bytes), but contract expects uncompressed (192 bytes).

**Solution Options**:
1. **Contract accepts both**: Check signature length and unmarshal accordingly
2. **SDK expands**: Convert compressed to uncompressed before calling contract
3. **Use uncompressed mode**: If @noble/curves supports it

---

## Technical Constraints

### 1. BLS2 Library Investigation Required

**Critical Questions**:
- ✅ Does `g1UnmarshalCompressed()` exist? → **YES** (confirmed in library)
- ✅ Does `g2Unmarshal()` exist? → **YES** (confirmed in library)
- ❓ Does library support inverted pairing verification?
- ❓ Can we hash to G2 points (`hashToPointG2()`)?
- ❓ What's the gas cost difference?

### 2. Signature Compression Handling

**@noble/curves generates**:
- Compressed G2 signature: 96 bytes
- Uncompressed would be: 192 bytes

**Contract Options**:
1. Accept both compressed (96) and uncompressed (192)
2. Require uncompressed only
3. SDK handles decompression

### 3. Backward Compatibility

**Breaking Change**: Old G2 pubkey + G1 sig signatures become invalid

**Migration Options**:
- **Option A**: New contract deployment (clean slate)
- **Option B**: Versioned function (`changeOwnerWithPubkeyV2`)
- **Option C**: Length-based routing (detect format by byte length)

**Recommendation**: Option A (new deployment) for simplicity

---

## Gas Cost Analysis

**Needs Benchmarking**:
- G2 operations are typically more expensive than G1
- Moving signature to G2 (larger point) may increase gas
- Compression/decompression adds computational cost

**Comparison Points**:
```
Current:  G2 pubkey (96) + G1 sig (96) = ~XXX,XXX gas
Proposed: G1 pubkey (48) + G2 sig (192) = ~YYY,YYY gas
          G1 pubkey (96) + G2 sig (192) = ~ZZZ,ZZZ gas
```

---

## Security Considerations

### 1. Pairing Verification
- Must ensure inverted pairing is mathematically sound
- Verify BLS2 library implementation is audited
- Test against known attack vectors

### 2. Address Derivation
- Compressed vs uncompressed G1 keys must derive same address
- Hash function must remain keccak256 for consistency
- Prevent address collision attacks

### 3. Replay Protection
- EIP-712 structure remains unchanged
- Owner change still provides replay protection
- No new attack surface introduced

---

## Implementation Strategy

### Phase 1: Investigation
1. Study BLS2 library source code
2. Verify inverted pairing support
3. Confirm G2 hashing capability
4. Benchmark gas costs

### Phase 2: Prototype
1. Create test contract with new scheme
2. Generate SDK test vectors
3. Verify pairing equations work
4. Compare gas costs

### Phase 3: Integration
1. Update EthereumDIDRegistry contract
2. Update SDK to use native key generation
3. Regenerate all test data
4. Update documentation

### Phase 4: Testing
1. Unit tests for all new functions
2. Integration tests SDK ↔ Contract
3. Gas benchmarking
4. Security review

---

## Trade-offs

| Aspect | Current (G2+G1) | Proposed (G1+G2) |
|--------|-----------------|------------------|
| **SDK Compatibility** | ❌ Incompatible | ✅ Compatible |
| **Fresh Key Gen** | ❌ Not possible | ✅ Possible |
| **Gas Cost** | Lower (G1 sig) | Higher (G2 sig) |
| **Public Key Size** | 96 bytes | 48-96 bytes |
| **Signature Size** | 96 bytes | 192 bytes |
| **Implementation** | ✅ Already done | ⚠️  Needs work |
| **Backward Compat** | N/A | ❌ Breaking |

---

## Open Questions

1. **Does BLS2 support inverted pairing natively?**
   - If YES: Use library function
   - If NO: Implement custom pairing check

2. **Should we support compressed G2 signatures?**
   - If YES: Add decompression logic
   - If NO: Require SDK to expand

3. **How to handle migration?**
   - New deployment vs versioned functions

4. **What's the gas cost impact?**
   - Need benchmarking data to decide

---

**Status**: Design draft - awaiting technical investigation
