# Spec: BLS Signature Scheme

**Capability**: BLS12-381 Signature Scheme for Owner Changes
**Change Type**: MODIFIED

---

## MODIFIED Requirements

### Requirement: Contract SHALL accept G1 public keys for BLS owner changes

The `changeOwnerWithPubkey()` function SHALL accept BLS12-381 G1 public keys instead of G2 public keys.

**Rationale**: Aligns with SDK's `@noble/curves/bls12-381` library which generates G1 public keys natively.

#### Scenario: Contract accepts compressed G1 public key (48 bytes)

**Given** a valid BLS12-381 keypair generated with `@noble/curves/bls12-381`
**And** the public key is in compressed G1 format (48 bytes)
**When** calling `changeOwnerWithPubkey()` with the compressed G1 public key
**Then** the contract SHALL successfully unmarshal the public key
**And** the contract SHALL derive the Ethereum address from the G1 public key
**And** the address derivation SHALL match keccak256 hash of the uncompressed form

#### Scenario: Contract accepts uncompressed G1 public key (96 bytes)

**Given** a valid BLS12-381 keypair
**And** the public key is in uncompressed G1 format (96 bytes)
**When** calling `changeOwnerWithPubkey()` with the uncompressed G1 public key
**Then** the contract SHALL successfully unmarshal the public key
**And** the contract SHALL derive the Ethereum address correctly

#### Scenario: Contract rejects invalid public key lengths

**Given** a public key with invalid byte length
**When** calling `changeOwnerWithPubkey()` with the invalid public key
**Then** the contract SHALL revert with error "invalid_pubkey_length"
**And** valid lengths are 48 bytes (compressed G1) or 96 bytes (uncompressed G1)

---

### Requirement: Contract SHALL accept G2 signatures for BLS owner changes

The `changeOwnerWithPubkey()` function SHALL accept BLS12-381 G2 signatures instead of G1 signatures.

**Rationale**: SDK generates G2 signatures when using G1 public keys, completing the inverted scheme.

#### Scenario: Contract accepts uncompressed G2 signature (192 bytes)

**Given** a valid message signed with BLS private key using `@noble/curves/bls12-381`
**And** the signature is in uncompressed G2 format (192 bytes)
**When** calling `changeOwnerWithPubkey()` with the G2 signature
**Then** the contract SHALL successfully unmarshal the signature as G2 point
**And** the contract SHALL verify the signature using inverted BLS pairing

#### Scenario: Contract rejects invalid signature lengths

**Given** a signature with invalid byte length
**When** calling `changeOwnerWithPubkey()` with the invalid signature
**Then** the contract SHALL revert with error "invalid_signature_length"
**And** valid length is 192 bytes (uncompressed G2)

---

### Requirement: Contract SHALL use inverted BLS pairing for signature verification

The contract SHALL verify signatures using the inverted BLS12-381 pairing equation appropriate for G1 public keys and G2 signatures.

**Rationale**: G1 pubkeys + G2 signatures require inverted pairing compared to G2 pubkeys + G1 signatures.

#### Scenario: Valid signature passes verification

**Given** an identity with BLS G1 public key as owner
**And** a message hash signed with the corresponding BLS private key
**And** the signature is a valid G2 signature
**When** the contract verifies the signature
**Then** the pairing check `e(pubkey_G1, message_G2) = e(G1_gen, sig_G2)` SHALL succeed
**And** the contract SHALL accept the signature as valid

#### Scenario: Invalid signature fails verification

**Given** an identity with BLS G1 public key as owner
**And** a message hash signed with a different private key
**When** the contract verifies the signature
**Then** the pairing check SHALL fail
**And** the contract SHALL revert with error "bad_signature"

#### Scenario: Signature for different message fails verification

**Given** an identity with BLS G1 public key as owner
**And** a signature valid for a different message
**When** the contract verifies the signature against current message
**Then** the pairing check SHALL fail
**And** the contract SHALL revert with error "bad_signature"

---

### Requirement: Address derivation SHALL work for both compressed and uncompressed G1 keys

The contract SHALL derive the same Ethereum address from both compressed (48 bytes) and uncompressed (96 bytes) forms of a G1 public key.

**Rationale**: Ensures consistency regardless of key format used.

#### Scenario: Compressed and uncompressed G1 derive same address

**Given** a BLS G1 public key in compressed format (48 bytes)
**And** the same public key in uncompressed format (96 bytes)
**When** deriving the Ethereum address from compressed form
**And** deriving the Ethereum address from uncompressed form
**Then** both addresses SHALL be identical
**And** the address SHALL be last 20 bytes of keccak256(uncompressed_form)

---

### Requirement: Message hashing SHALL use G2 curve for inverted scheme

The contract SHALL hash messages to G2 curve points instead of G1 when using inverted BLS scheme.

**Rationale**: Inverted pairing requires message on G2 when public key is on G1.

#### Scenario: EIP-712 hash is converted to G2 point

**Given** an EIP-712 message hash for owner change
**When** the contract prepares the message for BLS verification
**Then** the hash SHALL be converted to a G2 curve point
**And** the conversion SHALL use domain separation tag "BLS_DST"
**And** the resulting G2 point SHALL be used in pairing verification

---

## REMOVED Requirements

### ~~Requirement: Contract SHALL accept G2 public keys~~

**Removed**: This requirement is replaced by the new G1 public key requirement.

**Previous Behavior**: Contract accepted 96-byte G2 public keys
**New Behavior**: Contract accepts 48 or 96-byte G1 public keys

---

### ~~Requirement: Contract SHALL accept G1 signatures~~

**Removed**: This requirement is replaced by the new G2 signature requirement.

**Previous Behavior**: Contract accepted 96-byte G1 signatures
**New Behavior**: Contract accepts 192-byte G2 signatures

---

## Implementation Notes

### Public Key Unmarshaling

```solidity
function unmarshalG1(bytes calldata publicKey) internal view returns (BLS2.PointG1 memory) {
    if (publicKey.length == 48) {
        return BLS2.g1UnmarshalCompressed(publicKey);
    } else if (publicKey.length == 96) {
        return BLS2.g1Unmarshal(publicKey);
    } else {
        revert("invalid_pubkey_length");
    }
}
```

### Signature Unmarshaling

```solidity
require(signature.length == 192, "invalid_signature_length");
BLS2.PointG2 memory sig = BLS2.g2Unmarshal(signature);
```

### Address Derivation

```solidity
function deriveAddressFromG1(bytes calldata publicKey) internal view returns (address) {
    bytes memory expandedKey;
    if (publicKey.length == 48) {
        BLS2.PointG1 memory point = BLS2.g1UnmarshalCompressed(publicKey);
        expandedKey = BLS2.g1Marshal(point);
    } else {
        expandedKey = publicKey;
    }
    return address(uint160(uint256(keccak256(expandedKey))));
}
```

### Pairing Verification

```solidity
// Hash message to G2 (not G1)
BLS2.PointG2 memory message = BLS2.hashToPointG2("BLS_DST", abi.encodePacked(hash));

// Verify inverted pairing
(bool pairingSuccess, bool callSuccess) = verifyInvertedPairing(pubkey, sig, message);
```

---

## Migration Impact

**Breaking Change**: YES

- Existing G2 public keys will not work with new contract
- Existing G1 signatures will not work with new contract
- All BLS-based owner changes must be re-signed with new scheme
- Contract must be redeployed (or new version deployed)

---

## Testing Requirements

- [ ] Test compressed G1 public key (48 bytes)
- [ ] Test uncompressed G1 public key (96 bytes)
- [ ] Test G2 signature (192 bytes)
- [ ] Test address derivation consistency
- [ ] Test inverted pairing verification with valid signatures
- [ ] Test inverted pairing verification rejects invalid signatures
- [ ] Test error handling for invalid lengths
- [ ] Integration test with SDK-generated keys

---

**Last Updated**: 2025-12-25
**Status**: Proposed
