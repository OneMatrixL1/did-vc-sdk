# Design Document: Switch to BBS G2 Keypair Scheme

## Architecture Overview

This change unifies the SDK's cryptographic approach by adopting BBS G2 keypairs as the single standard for both Verifiable Credential signing and DID ownership.

## Current Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CURRENT STATE (FRAGMENTED)               │
└─────────────────────────────────────────────────────────────┘

Verifiable Credentials (BBS):
┌──────────────┐
│ BBS Keypair  │
│ G2 PubKey    │  96 bytes (compressed)
│ G1 Signature │
└──────────────┘
       │
       ├─> Sign VC
       ├─> Derive Address: keccak256(96B compressed G2)
       └─> Address: 0xABCD...

DID Ownership (BLS Inverted):
┌──────────────┐
│ BLS Keypair  │
│ G1 PubKey    │  96 bytes (uncompressed)
│ G2 Signature │  192 bytes (uncompressed)
└──────────────┘
       │
       ├─> Change Owner
       ├─> Derive Address: keccak256(96B uncompressed G1)
       └─> Address: 0x1234...  (DIFFERENT!)

Problem: 0xABCD... ≠ 0x1234...
```

## Target Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    TARGET STATE (UNIFIED)                    │
└─────────────────────────────────────────────────────────────┘

Single BBS Keypair for Everything:
┌──────────────────────┐
│   BBS Keypair        │
│   G2 PubKey          │  96B compressed → 192B uncompressed
│   G1 Signature       │  48B/96B
└──────────────────────┘
       │
       ├─> Sign VC
       ├─> Change DID Owner
       ├─> Derive Address: keccak256(192B uncompressed G2)
       └─> Address: 0xABCD... (SAME!)

Benefits: Single keypair, consistent address, simpler UX
```

## Component Interactions

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│   User      │         │   SDK            │         │  Contract   │
│             │         │                  │         │             │
│             │         │                  │         │             │
│ Generate    │────────>│ generateBbs      │         │             │
│ Keypair     │         │ Keypair()        │         │             │
│             │         │ - G2: 96B comp   │         │             │
│             │         │ - Secret: 32B    │         │             │
│             │<────────│                  │         │             │
│             │         │                  │         │             │
│ Derive      │────────>│ expandG2(96B)    │         │             │
│ Address     │         │   → 192B         │         │             │
│             │         │ keccak256(192B)  │         │             │
│             │<────────│ → address        │         │             │
│             │         │                  │         │             │
│ Sign VC     │────────>│ signWithBbs()    │         │             │
│             │         │ - msg → G1 sig   │         │             │
│             │<────────│                  │         │             │
│             │         │                  │         │             │
│ Change DID  │────────>│ expandG2(96B)    │         │             │
│ Owner       │         │   → 192B         │────────>│ changeOwner │
│             │         │ signMsg → G1 sig │         │ WithPubkey  │
│             │         │                  │         │ - Unmarshal │
│             │         │                  │         │   G2 (192B) │
│             │         │                  │         │ - Hash to   │
│             │         │                  │         │   G1 point  │
│             │         │                  │<────────│ - Verify    │
│             │         │                  │ Success │   pairing   │
│             │<─────────────────────────────────────│             │
└─────────────┘         └──────────────────┘         └─────────────┘
```

## Key Technical Decisions

### Decision 1: Use Uncompressed G2 for Address Derivation

**Rationale**:
- Contract's BLS2 library doesn't support G2 decompression (line 10: "Compression is not currently available")
- Must use uncompressed format (192B) for consistency
- SDK can easily expand 96B → 192B using `@noble/curves`

**Trade-offs**:
- **Pro**: Consistent with contract capabilities
- **Pro**: No complex on-chain decompression (saves gas)
- **Con**: Larger key size sent to contract
- **Con**: Breaking change to address derivation

**Alternative Considered**: Implement G2 decompression in contract
- **Rejected**: Too complex (~100+ lines of assembly), high gas cost, error-prone

---

### Decision 2: SDK Expands Keys Before Contract Call

**Rationale**:
- Decompression is cheap in JavaScript (3 lines, <1ms)
- Decompression is expensive in Solidity (100+ lines, high gas)
- Follows same pattern as current G2 signature expansion

**Implementation**:
```typescript
// SDK side
const compressed = bbsKeypair.publicKeyBuffer;  // 96 bytes
const uncompressed = expandG2PublicKey(compressed);  // 192 bytes
await contract.changeOwnerWithPubkey(..., uncompressed, ...);
```

```solidity
// Contract side
function changeOwnerWithPubkey(bytes calldata publicKey, ...) {
    require(publicKey.length == 192, "invalid_pubkey_length");
    BLS2.PointG2 memory pubkey = BLS2.g2Unmarshal(publicKey);
    // ... use pubkey
}
```

---

### Decision 3: Use Standard BBS Pairing

**Rationale**:
- BLS2 library already has `verifySingle(sig_G1, pk_G2, msg_G1)`
- No need for custom pairing logic
- Standard BBS+ signature verification

**Previous (Custom Inverted Pairing)**:
```solidity
function verifyInvertedPairing(
    BLS2.PointG1 memory pubkey,
    BLS2.PointG2 memory sig,
    BLS2.PointG2 memory message
) {
    // 50+ lines of custom pairing logic
}
```

**New (Standard BBS)**:
```solidity
// Just use the library!
(bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pubkey, message);
require(pairingSuccess && callSuccess, "bad_signature");
```

---

### Decision 4: Breaking Change to Address Derivation

**Rationale**:
- Current state is fragmented (two different addresses)
- Unification requires picking one standard
- Better to break once than maintain fragmentation forever

**Migration Strategy**:
1. Major version bump (e.g., v3.0.0)
2. Clear BREAKING CHANGE notice in CHANGELOG
3. Migration guide with examples
4. Deprecation period not feasible (addresses are fundamentally different)

**User Impact**:
```typescript
// Old (BLS G1 compressed)
const address = keccak256(96_byte_compressed_G1)  // 0x1234...

// New (BBS G2 uncompressed)
const address = keccak256(192_byte_uncompressed_G2)  // 0xABCD...

// User must regenerate addresses or migrate
```

---

## Data Flow

### Address Derivation Flow

```
BBS Keypair Generation:
  ┌─────────────────────┐
  │ Generate Secret Key │
  │ (32 bytes random)   │
  └──────────┬──────────┘
             │
             ▼
  ┌─────────────────────┐
  │ Derive G2 PubKey    │
  │ (96 bytes compressed)│
  └──────────┬──────────┘
             │
             ▼
  ┌─────────────────────┐
  │ Expand to 192 bytes │
  │ (uncompressed G2)   │
  └──────────┬──────────┘
             │
             ▼
  ┌─────────────────────┐
  │ keccak256(192B)     │
  └──────────┬──────────┘
             │
             ▼
  ┌─────────────────────┐
  │ Take last 20 bytes  │
  │ → Ethereum Address  │
  └─────────────────────┘
```

### Signature Verification Flow (Contract)

```
changeOwnerWithPubkey(identity, oldOwner, newOwner, publicKey, signature):
  │
  ├─> Validate lengths
  │   - publicKey == 192 bytes
  │   - signature == 48 or 96 bytes
  │
  ├─> Derive signer address
  │   - keccak256(publicKey)[last 20 bytes]
  │
  ├─> Verify signer == identityOwner(identity)
  │
  ├─> Create EIP-712 hash
  │   - keccak256(abi.encode(TYPEHASH, identity, oldOwner, newOwner))
  │
  ├─> Unmarshal G2 public key
  │   - BLS2.g2Unmarshal(publicKey) → pubkey
  │
  ├─> Hash message to G1 point
  │   - hashToPointG1("BLS_DST", hash) → message
  │
  ├─> Unmarshal G1 signature
  │   - If 48B: BLS2.g1UnmarshalCompressed(signature)
  │   - If 96B: BLS2.g1Unmarshal(signature)
  │   - → sig
  │
  ├─> Verify pairing
  │   - BLS2.verifySingle(sig, pubkey, message)
  │   - Checks: e(sig_G1, pubkey_G2) = e(message_G1, G2_gen)
  │
  └─> If valid: Update owner
      - owners[identity] = newOwner
      - emit DIDOwnerChanged(...)
```

## Security Considerations

### Cryptographic Security

**BBS+ Signatures**:
- Well-studied signature scheme
- Based on BLS12-381 pairing-friendly curve
- Security reduction to computational Diffie-Hellman assumption
- Used in W3C Verifiable Credentials standards

**Pairing Verification**:
- Standard BBS pairing: `e(sig_G1, pk_G2) = e(msg_G1, G2_gen)`
- Uses EIP-2537 precompiles (audited, part of Ethereum protocol)
- No custom cryptographic code

### Address Derivation Security

**Properties**:
- One-way function (keccak256)
- Collision resistance
- Pre-image resistance
- Second pre-image resistance

**Consistency**:
- Same public key → same address (deterministic)
- Different public keys → different addresses (with overwhelming probability)

### Contract Security

**Access Control**:
- Only current owner can change owner
- Signature verification ensures authentic requests
- EIP-712 prevents replay attacks across networks

**Input Validation**:
- Validate key lengths
- Validate signature lengths
- Check address derivation matches signer
- Verify EIP-712 structure

## Performance Considerations

### Gas Costs

**New Operations**:
- `hashToPointG1()`: Uses precompile `0x10` (BLS12_MAP_FP_TO_G1)
- `BLS2.g2Unmarshal()`: Existing library function
- `BLS2.verifySingle()`: Existing library function (uses precompile `0x0f`)

**Estimated Gas**:
- G1 point hashing: ~30,000 gas (precompile)
- G1 addition: ~500 gas (precompile)
- G2 unmarshal: ~5,000 gas (memory operations)
- Pairing check: ~100,000 gas (precompile)
- **Total**: ~135,000 gas (estimate)

**Comparison to Previous**:
- Previous (G2 hashing + custom pairing): ~140,000 gas
- **Expected**: Similar or slightly better

### SDK Performance

**Key Expansion**:
- `expandG2PublicKey()`: <1ms (JavaScript)
- Uses `@noble/curves` library (optimized)
- No performance impact

**Address Derivation**:
- Additional keccak256 of 192 bytes vs 96 bytes: negligible
- Still <1ms total

## Testing Strategy

### Unit Tests

**Contract**:
- Test `hashToPointG1()` with known vectors
- Test `deriveAddressFromG2()` with known addresses
- Test `changeOwnerWithPubkey()` with valid signatures
- Test rejection of invalid signatures
- Test access control (bad_actor)

**SDK**:
- Test `expandG2PublicKey()` 96B → 192B
- Test address derivation consistency
- Test signature generation and verification
- Test round-trip: generate → sign → verify

### Integration Tests

- SDK generates keypair
- SDK derives address
- SDK sends to contract
- Contract verifies and updates state
- Read back state, verify correctness

### E2E Tests

- Full workflow: VC issuance + DID owner change
- Same keypair for both operations
- Verify address consistency
- Real blockchain deployment (vietchain/testnet)

## Rollout Plan

### Phase 1: Development
- Implement contract changes
- Implement SDK changes
- Write unit tests
- Write integration tests

### Phase 2: Testing
- Run full test suite
- Deploy to testnet
- Performance benchmarking
- Security review

### Phase 3: Documentation
- Update README files
- Write migration guide
- Update API docs
- Create examples

### Phase 4: Release
- Version bump (major)
- Publish CHANGELOG
- Tag release
- Deploy to npm

### Phase 5: Support
- Monitor for issues
- Provide migration support
- Update documentation as needed

## Open Questions

1. **Q**: Should we provide a migration tool for existing users?
   **A**: Yes, create a script that helps users understand new address derivation

2. **Q**: What about backward compatibility for old addresses?
   **A**: Not feasible - addresses are fundamentally different. Clean break is better.

3. **Q**: Should we deprecate old BLS G1 code or remove it entirely?
   **A**: Remove it - no reason to maintain two schemes after migration

4. **Q**: What version number should this be?
   **A**: Major version bump required (breaking change)

## References

- BBS+ Signatures: https://tools.ietf.org/id/draft-irtf-cfrg-bbs-signatures-00.html
- BLS12-381: https://hackmd.io/@benjaminion/bls12-381
- EIP-2537: https://eips.ethereum.org/EIPS/eip-2537
- W3C VC Data Model: https://www.w3.org/TR/vc-data-model/
- @noble/curves: https://github.com/paulmillr/noble-curves
- @onematrix/bls-solidity: https://github.com/onematrix-io/bls-solidity
