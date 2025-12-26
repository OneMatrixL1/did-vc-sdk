# Ethr DID BLS Spec Delta

## MODIFIED Requirements

### Requirement: BBS Public Key to Ethereum Address Derivation
The system SHALL derive Ethereum addresses from **192-byte uncompressed G2 public keys** for BBS-based identities.

#### Scenario: Derive address from BBS public key
- **GIVEN** a BBS public key as `Uint8Array` or `Array<number>`
- **WHEN** calling `bbsPublicKeyToAddress(bbsPublicKey)`
- **THEN** the system SHALL validate the key is exactly **192 bytes**
- **AND** compute `keccak256(publicKeyBytes)` over all 192 bytes
- **AND** return the last 20 bytes as a checksummed Ethereum address

#### Scenario: Invalid BBS public key size
- **GIVEN** a public key with size != 192 bytes
- **WHEN** calling `bbsPublicKeyToAddress(bbsPublicKey)`
- **THEN** the system SHALL throw an error: "BBS public key must be 192 bytes"

### Requirement: Public Key to Address (Multi-Curve Support)
The `publicKeyToAddress()` function SHALL support 192-byte BLS12-381 G2 public keys.

#### Scenario: Detect BLS12-381 G2 public key
- **GIVEN** a 192-byte public key byte array
- **WHEN** calling `publicKeyToAddress(publicKeyBytes)`
- **THEN** the system SHALL identify it as a BLS12-381 G2 public key
- **AND** compute the address via `keccak256(keyBytes).slice(-20)`

#### Scenario: Unsupported key length
- **GIVEN** a public key with unsupported length (not 192 bytes)
- **WHEN** calling `publicKeyToAddress(publicKeyBytes)`
- **THEN** the system SHALL throw an error: "Unsupported public key length: {length}. Supported: 192 bytes (BLS12-381)"

## MODIFIED Requirements

### Requirement: BBS Key Recovery Method Verification
The `Bls12381BBSRecoveryMethod2023` class SHALL handle **192-byte uncompressed G2 public keys** for signature verification.

#### Scenario: Verify signature with uncompressed G2 key
- **GIVEN** a BBS signature, message, and 192-byte uncompressed G2 public key
- **WHEN** performing signature verification
- **THEN** the system SHALL instantiate `new BBSPublicKey(u8aToU8a(publicKeyBuffer))`
- **AND** use the uncompressed format for pairing verification
- **AND** return verification result (true/false)

#### Scenario: Extract public key from verification method
- **GIVEN** a DID document verification method with BBS public key
- **WHEN** extracting the public key bytes
- **THEN** the system SHALL expect **192 bytes** in uncompressed format
- **AND** validate the key size before using it

## ADDED Requirements

### Requirement: Documentation of G2 Format
All BBS-related documentation SHALL specify "192-byte uncompressed G2 public key" format.

#### Scenario: Update utility function documentation
- **GIVEN** JSDoc comments for BBS key functions
- **WHEN** developers read the documentation
- **THEN** comments SHALL explicitly state "192 bytes, uncompressed G2 point"
- **AND** reference the format as compatible with `BLS2.g2Unmarshal()`

#### Scenario: Update architecture documentation
- **GIVEN** files like `ethr-bbs-recovery-verification.md`
- **WHEN** describing BBS public keys
- **THEN** documentation SHALL state "192 bytes (uncompressed G2)"
- **AND** clarify the change from compressed (96 bytes) to uncompressed (192 bytes)
