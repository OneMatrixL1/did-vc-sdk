# BBS Signatures Spec Delta

## ADDED Requirements

### Requirement: Uncompressed G2 Public Key Format
The BBS signature scheme (2023) SHALL use **192-byte uncompressed G2 public keys** for compatibility with Ethereum smart contract BLS verification precompiles.

#### Scenario: Extract uncompressed public key from BBSPublicKey
- **GIVEN** a `BBSPublicKey` instance from `@docknetwork/crypto-wasm-ts`
- **WHEN** extracting the public key bytes for on-chain verification
- **THEN** the system SHALL serialize the key as **192 bytes** in uncompressed G2 format
- **AND** the format SHALL be `[x0_hi, x0_lo, x1_hi, x1_lo, y0_hi, y0_lo, y1_hi, y1_lo]` where each component is 48 bytes

#### Scenario: Validate public key size for BBS 2023
- **GIVEN** a public key byte array for BBS 2023 scheme
- **WHEN** validating the key size
- **THEN** the system SHALL require exactly **192 bytes**
- **AND** reject any keys with size != 192 bytes with clear error message

#### Scenario: Address derivation from uncompressed G2 key
- **GIVEN** a 192-byte uncompressed G2 public key
- **WHEN** deriving an Ethereum address
- **THEN** the system SHALL compute `address = keccak256(publicKey).slice(-20)`
- **AND** use the full 192 bytes as input to keccak256

## MODIFIED Requirements

### Requirement: BBS Public Key Serialization
The `Bls12381BBSKeyPairDock2023` class SHALL serialize public keys as **192-byte uncompressed G2 points** instead of 96-byte compressed format.

#### Scenario: Serialize public key for credential
- **GIVEN** a BBS keypair instance
- **WHEN** accessing the `publicKeyBuffer` property
- **THEN** the system SHALL return **192 bytes** representing the uncompressed G2 public key
- **AND** the format SHALL be compatible with `BLS2.g2Unmarshal()` in smart contracts

#### Scenario: Initialize keypair from public key bytes
- **GIVEN** 192-byte uncompressed G2 public key bytes
- **WHEN** creating a `BBSPublicKey` instance
- **THEN** the system SHALL correctly parse the uncompressed format
- **AND** support signature verification operations

## REMOVED Requirements

### Requirement: Compressed G2 Public Key Support
**Reason**: Ethereum smart contracts require uncompressed format; compressed format (96 bytes) is incompatible with BLS precompiles.

**Migration**: Regenerate all BBS keypairs and derive new Ethereum addresses using uncompressed keys. Addresses will change due to different hash input (192 vs 96 bytes).
