# Capability: BBS Keypair Generation

This capability defines the generation and management of BBS G2 keypairs used for both Verifiable Credential signing and DID ownership.

## ADDED Requirements

### Requirement: Generate BBS G2 Keypair

The SDK MUST provide a function to generate BBS keypairs with G2 public keys.

**Function**: `generateBbsKeypair()`

**Returns**:
- `secretKey`: 32-byte secret key
- `publicKey`: 96-byte compressed G2 public key
- `publicKeyUncompressed`: 192-byte uncompressed G2 public key
- `publicKeyHex`: Hex-encoded public key

#### Scenario: Generate fresh BBS keypair

**Given** a request to generate a new BBS keypair

**When** `generateBbsKeypair()` is called

**Then** it returns a keypair object with:
- Secret key of exactly 32 bytes
- Public key (compressed) of exactly 96 bytes
- Public key (uncompressed) of exactly 192 bytes
- Valid G2 point on BLS12-381 curve

#### Scenario: Compressed and uncompressed keys represent same point

**Given** a generated BBS keypair

**When** comparing the compressed (96B) and uncompressed (192B) public keys

**Then** both MUST represent the same G2 point
- Expanding compressed MUST produce uncompressed
- Both MUST derive the same Ethereum address

---

### Requirement: Expand G2 Public Key

The SDK MUST provide a function to expand compressed G2 public keys to uncompressed format.

**Function**: `expandG2PublicKey(compressed: Uint8Array): Uint8Array`

**Parameters**:
- `compressed`: 96-byte compressed G2 public key

**Returns**:
- 192-byte uncompressed G2 public key

#### Scenario: Expand 96-byte compressed to 192-byte uncompressed

**Given** a 96-byte compressed G2 public key

**When** `expandG2PublicKey()` is called

**Then** it returns:
- Exactly 192 bytes
- Valid uncompressed G2 point
- Mathematically equivalent to the input compressed point

#### Scenario: Reject invalid input length

**Given** an invalid input (not 96 bytes)

**When** `expandG2PublicKey()` is called

**Then** it throws an error with message indicating expected length

---

### Requirement: Sign with BBS Keypair

The SDK MUST provide a function to sign messages using BBS keypairs.

**Function**: `signWithBbs(message: Uint8Array, secretKey: Uint8Array)`

**Returns**:
- `signature`: G1 signature (48 or 96 bytes)
- `signatureHex`: Hex-encoded signature

#### Scenario: Sign message produces valid G1 signature

**Given** a BBS secret key and a message

**When** `signWithBbs()` is called

**Then** it returns:
- Valid G1 signature
- Signature length is 48 bytes (compressed) or 96 bytes (uncompressed)
- Signature verifies correctly with corresponding public key

#### Scenario: Same message with same key produces same signature

**Given** a BBS keypair and a message

**When** signing the same message twice with the same key

**Then** both signatures MUST be identical

---

### Requirement: Verify BBS Signature

The SDK MUST provide a function to verify BBS signatures locally.

**Function**: `verifyBbsSignature(message, signature, publicKey): boolean`

#### Scenario: Valid signature verifies successfully

**Given** a message, valid signature, and corresponding public key

**When** `verifyBbsSignature()` is called

**Then** it returns `true`

#### Scenario: Invalid signature fails verification

**Given** a message, signature from different key, and public key

**When** `verifyBbsSignature()` is called

**Then** it returns `false`

---

## MODIFIED Requirements

None - this is a new capability

## REMOVED Requirements

### Requirement: Generate BLS G1 Keypair (DEPRECATED)

The old `generateBlsKeypair()` function that generated G1 public keys is REMOVED and replaced by `generateBbsKeypair()`.

**Rationale**: Consolidating to single BBS G2 scheme for consistency.

**Migration**: Users MUST update to `generateBbsKeypair()` and regenerate keypairs.
