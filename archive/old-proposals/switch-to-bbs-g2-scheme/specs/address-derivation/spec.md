# Capability: Address Derivation from BBS G2 Keys

This capability defines how Ethereum addresses are derived from BBS G2 public keys.

## MODIFIED Requirements

### Requirement: Derive Ethereum Address from G2 Public Key

The SDK MUST derive Ethereum addresses from **uncompressed** G2 public keys using keccak256.

**Function**: `deriveAddressFromG2(publicKey: Uint8Array | string): string`

**Parameters**:
- `publicKey`: G2 public key (96 bytes compressed OR 192 bytes uncompressed)

**Returns**:
- Checksummed Ethereum address (0x-prefixed, 42 characters)

**Algorithm**:
1. If input is 96 bytes: expand to 192 bytes uncompressed
2. If input is 192 bytes: use directly
3. Compute `hash = keccak256(uncompressed192Bytes)`
4. Take last 20 bytes of hash
5. Return as checksummed address

#### Scenario: Derive address from 96-byte compressed key

**Given** a 96-byte compressed G2 public key

**When** `deriveAddressFromG2()` is called

**Then** it:
- Expands the key to 192 bytes
- Computes keccak256(192 bytes)
- Returns the last 20 bytes as a checksummed address
- Address matches the address derived from the 192-byte version of the same key

#### Scenario: Derive address from 192-byte uncompressed key

**Given** a 192-byte uncompressed G2 public key

**When** `deriveAddressFromG2()` is called

**Then** it:
- Uses the key directly (no expansion needed)
- Computes keccak256(192 bytes)
- Returns the last 20 bytes as a checksummed address

#### Scenario: Compressed and uncompressed derive same address

**Given** a G2 public key in both compressed (96B) and uncompressed (192B) formats

**When** deriving addresses from both formats

**Then** both MUST produce identical addresses

#### Scenario: Invalid key length throws error

**Given** a public key that is neither 96 nor 192 bytes

**When** `deriveAddressFromG2()` is called

**Then** it throws an error indicating invalid key length

---

### Requirement: BBS Public Key to Address (credential-sdk)

The `bbsPublicKeyToAddress()` function in credential-sdk MUST use **uncompressed** G2 keys for address derivation.

**Function**: `bbsPublicKeyToAddress(bbsPublicKey: Uint8Array): string`

**Breaking Change**: YES - address derivation algorithm changes from compressed to uncompressed

#### Scenario: Derive address from BBS keypair publicKeyBuffer

**Given** a `Bls12381BBSKeyPairDock2023` keypair with 96-byte compressed public key

**When** `bbsPublicKeyToAddress(keypair.publicKeyBuffer)` is called

**Then** it:
- Expands 96 bytes to 192 bytes internally
- Derives address from 192-byte uncompressed key
- Returns checksummed Ethereum address

#### Scenario: Address consistency with contract

**Given** a BBS keypair used for both VC signing and DID ownership

**When** deriving address in SDK and contract

**Then** both MUST produce the same address
- SDK: `bbsPublicKeyToAddress(publicKeyBuffer)`
- Contract: `deriveAddressFromG2(publicKey)`
- Result: Identical addresses

---

## REMOVED Requirements

### Requirement: Derive Address from G1 Public Key (DEPRECATED)

The old `deriveAddressFromG1()` function that derived addresses from G1 public keys is REMOVED.

**Function**: `deriveAddressFromG1()` - DEPRECATED

**Rationale**: Unified BBS G2 scheme replaces BLS G1 scheme.

**Migration**:
- Replace calls to `deriveAddressFromG1()` with `deriveAddressFromG2()`
- Note: Addresses WILL BE DIFFERENT - this is a breaking change
- Users MUST regenerate addresses using new derivation method

#### Scenario: Migration from G1 to G2 addresses

**Given** an existing address derived from G1 key

**When** migrating to G2-based derivation

**Then** the new address WILL be different
- Old: `keccak256(96B G1)` or `keccak256(48B G1)`
- New: `keccak256(192B G2)`
- Users MUST update their systems with new addresses
