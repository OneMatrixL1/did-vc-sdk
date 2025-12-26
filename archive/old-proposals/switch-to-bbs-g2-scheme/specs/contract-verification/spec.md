# Capability: Contract BBS Signature Verification

This capability defines how the EthereumDIDRegistry smart contract verifies BBS signatures for DID owner changes.

## MODIFIED Requirements

### Requirement: Accept G2 Public Keys

The contract MUST accept **192-byte uncompressed** G2 public keys in `changeOwnerWithPubkey()`.

**Function**: `changeOwnerWithPubkey(address identity, address oldOwner, address newOwner, bytes calldata publicKey, bytes calldata signature)`

**Parameters**:
- `publicKey`: MUST be exactly 192 bytes (uncompressed G2 point)
- `signature`: MUST be 48 bytes (compressed G1) or 96 bytes (uncompressed G1)

#### Scenario: Accept 192-byte G2 public key

**Given** a valid 192-byte uncompressed G2 public key

**When** calling `changeOwnerWithPubkey()` with this key

**Then** the contract:
- Accepts the key without error
- Successfully unmarshals it as a G2 point
- Proceeds with signature verification

#### Scenario: Reject invalid public key lengths

**Given** a public key that is not 192 bytes

**When** calling `changeOwnerWithPubkey()`

**Then** the contract reverts with error "invalid_pubkey_length"

---

### Requirement: Hash Message to G1 Point

The contract MUST provide a function to hash messages to G1 curve points.

**Function**: `hashToPointG1(bytes memory dst, bytes memory message) internal view returns (BLS2.PointG1 memory)`

**Implementation**:
- Use EIP-2537 precompile `0x10` (BLS12_MAP_FP_TO_G1)
- Use EIP-2537 precompile `0x0b` (BLS12_G1ADD)
- Follow RFC 9380 Section 5 hash-to-curve algorithm

#### Scenario: Hash message produces valid G1 point

**Given** a message to hash

**When** `hashToPointG1("BLS_DST", message)` is called

**Then** it returns:
- Valid G1 point on BLS12-381 curve
- Point is 96 bytes when marshaled (uncompressed)
- Deterministic (same input → same output)

---

### Requirement: Derive Address from G2 Public Key

The contract MUST derive Ethereum addresses from 192-byte uncompressed G2 public keys.

**Function**: `deriveAddressFromG2(bytes calldata publicKeyBytes) internal pure returns (address)`

**Algorithm**:
1. Require `publicKeyBytes.length == 192`
2. Compute `hash = keccak256(publicKeyBytes)`
3. Return `address(uint160(uint256(hash)))`

#### Scenario: Derive address from 192-byte G2 key

**Given** a 192-byte uncompressed G2 public key

**When** `deriveAddressFromG2()` is called

**Then** it returns:
- Valid Ethereum address (20 bytes)
- Same address as SDK derivation for same key
- Deterministic (same key → same address)

#### Scenario: Reject non-192-byte inputs

**Given** a public key that is not 192 bytes

**When** `deriveAddressFromG2()` is called

**Then** it reverts with error "invalid_g2_pubkey_length"

---

### Requirement: Verify BBS Signatures

The contract MUST verify BBS signatures using standard BLS pairing.

**Verification Algorithm**:
1. Unmarshal G2 public key
2. Hash EIP-712 message to G1 point
3. Unmarshal G1 signature (support both 48B compressed and 96B uncompressed)
4. Verify pairing: `e(sig_G1, pubkey_G2) = e(message_G1, G2_gen)`
5. Use `BLS2.verifySingle(sig, pubkey, message)` for verification

#### Scenario: Valid BBS signature verifies successfully

**Given**:
- Valid 192-byte G2 public key
- Valid G1 signature (48 or 96 bytes)
- Matching EIP-712 message hash

**When** `changeOwnerWithPubkey()` is called

**Then** the contract:
- Successfully verifies the signature
- Updates the owner
- Emits `DIDOwnerChanged` event
- Returns success

#### Scenario: Invalid signature is rejected

**Given**:
- Valid G2 public key
- Invalid or mismatched signature

**When** `changeOwnerWithPubkey()` is called

**Then** the contract reverts with error "bad_signature"

#### Scenario: Support compressed and uncompressed G1 signatures

**Given** the same message signed with a BBS keypair

**When** submitting either:
- 48-byte compressed G1 signature, OR
- 96-byte uncompressed G1 signature

**Then** the contract:
- Accepts both formats
- Verifies correctly for both
- Both result in successful owner change

---

### Requirement: Maintain EIP-712 Message Structure

The contract MUST continue using EIP-712 for message hashing.

**EIP-712 Structure**:
```solidity
bytes32 CHANGE_OWNER_WITH_PUBKEY_TYPEHASH = keccak256(
    "ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)"
);
```

#### Scenario: EIP-712 hash prevents replay attacks

**Given** a valid signature for identity A

**When** attempting to replay for identity B

**Then** the signature verification fails (different EIP-712 hash)

---

## REMOVED Requirements

### Requirement: Verify Inverted BLS Pairing (DEPRECATED)

The custom `verifyInvertedPairing()` function is REMOVED and replaced by standard `BLS2.verifySingle()`.

**Old Function**: `verifyInvertedPairing(BLS2.PointG1 memory pubkey, BLS2.PointG2 memory sig, BLS2.PointG2 memory message)`

**New Function**: Use `BLS2.verifySingle(BLS2.PointG1 memory sig, BLS2.PointG2 memory pubkey, BLS2.PointG1 memory message)`

**Rationale**: Standard BBS pairing is simpler and uses built-in library function.

---

### Requirement: Accept G1 Public Keys (DEPRECATED)

The contract no longer accepts G1 public keys.

**Old**: `publicKey.length == 96` (G1 uncompressed)
**New**: `publicKey.length == 192` (G2 uncompressed)

**Migration**: Users MUST send G2 keys instead of G1 keys.

---

### Requirement: Hash to G2 Points (DEPRECATED for signatures)

The `hashToPointG2()` function is no longer used for message hashing in `changeOwnerWithPubkey()`.

**Old**: Hash message to G2 point
**New**: Hash message to G1 point (using `hashToPointG1()`)

**Rationale**: BBS standard uses G1 for messages, G2 for public keys.
