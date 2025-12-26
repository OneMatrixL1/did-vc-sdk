## ADDED Requirements

### Requirement: Public Key Address Derivation

The system SHALL derive an Ethereum-compatible address from a public key using curve-specific methods:
- **BLS12-381**: keccak256 hash of 96-byte compressed G2 public key, take last 20 bytes
- **Future curves**: Define derivation methods as needed

The system SHALL apply EIP-55 checksum encoding to all derived addresses.

#### Scenario: Valid BLS public key address derivation
- **GIVEN** a 96-byte BLS12-381 G2 public key
- **WHEN** the address derivation function is called
- **THEN** the system returns a valid checksummed Ethereum address
- **AND** the same public key always produces the same address

#### Scenario: Invalid public key length rejected
- **GIVEN** a public key with unsupported length
- **WHEN** the address derivation function is called
- **THEN** the system rejects with an error indicating invalid or unsupported key length

---

### Requirement: Owner Change with Public Key EIP-712 Message Structure

The system SHALL use the following EIP-712 typed data structure for owner changes with public key verification:

```
Domain:
  name: "EthereumDIDRegistry"
  version: "1"
  chainId: <current chain ID>
  verifyingContract: <registry contract address>

Types:
  ChangeOwnerWithPubkey:
    identity: address
    signer: address
    newOwner: address
    nonce: uint256
```

#### Scenario: EIP-712 message construction
- **GIVEN** an identity address, signer address, new owner address, and nonce
- **WHEN** the EIP-712 message is constructed
- **THEN** the struct hash equals `keccak256(abi.encode(CHANGE_OWNER_WITH_PUBKEY_TYPEHASH, identity, signer, newOwner, nonce))`
- **AND** the signable hash equals `keccak256("\x19\x01" || DOMAIN_SEPARATOR || structHash)`

#### Scenario: Nonce commitment in message
- **GIVEN** a signer creating an owner change signature
- **WHEN** the EIP-712 message includes a nonce
- **THEN** the signature is only valid for that specific nonce value
- **AND** prevents replay even if contract state is rolled back

---

### Requirement: Owner Change with Public Key Contract Function

The EthereumDIDRegistry contract SHALL provide a `changeOwnerWithPubkey` function that accepts:
1. `identity` (address) - The DID identity being modified
2. `newOwner` (address) - The new owner address
3. `nonce` (uint256) - The nonce committed to in the signature
4. `publicKey` (bytes) - The public key (length determines signature type)
5. `signature` (bytes) - The signature over the EIP-712 hash

The function SHALL:
- Derive signer address from public key
- Verify derived address matches current owner
- Verify nonce matches `pubkeyNonce[signer]`
- Route signature verification based on public key length (96 bytes → BLS12-381)
- If valid, increment nonce and update owner

#### Scenario: Successful BLS owner change
- **GIVEN** a valid BLS keypair where the derived address equals the current owner
- **AND** the current `pubkeyNonce[owner]` is N
- **AND** a valid BLS signature over the EIP-712 hash of `ChangeOwnerWithPubkey(identity, owner, newOwner, N)`
- **WHEN** `changeOwnerWithPubkey(identity, newOwner, N, publicKey, signature)` is called
- **THEN** the owner mapping is updated to the new owner
- **AND** the `DIDOwnerChanged` event is emitted
- **AND** the `pubkeyNonce[owner]` is incremented to N+1

#### Scenario: BLS signature verification failure
- **GIVEN** an invalid BLS signature
- **WHEN** `changeOwnerWithPubkey` is called
- **THEN** the transaction reverts with error "bad_signature"

#### Scenario: Public key address mismatch
- **GIVEN** a public key whose derived address does not match the current owner
- **WHEN** `changeOwnerWithPubkey` is called
- **THEN** the transaction reverts with error "unauthorized"

#### Scenario: Nonce mismatch
- **GIVEN** a nonce parameter that does not match `pubkeyNonce[signer]`
- **WHEN** `changeOwnerWithPubkey` is called
- **THEN** the transaction reverts with error "invalid_nonce"

#### Scenario: Zero address rejected
- **GIVEN** a newOwner parameter of address(0)
- **WHEN** `changeOwnerWithPubkey` is called
- **THEN** the transaction reverts with error "invalid_new_owner"

#### Scenario: Unsupported public key length
- **GIVEN** a public key with length not supported by the contract
- **WHEN** `changeOwnerWithPubkey` is called
- **THEN** the transaction reverts with error "unsupported_pubkey_type"

---

### Requirement: Public Key Nonce Management

The system SHALL maintain a `pubkeyNonce` mapping for public-key-based signatures to prevent replay attacks.

#### Scenario: Nonce prevents signature replay
- **GIVEN** a valid owner change signature that was already used
- **AND** the nonce was incremented after first use
- **WHEN** the same signature is submitted again with the old nonce
- **THEN** the transaction reverts with error "invalid_nonce"

#### Scenario: Nonce query
- **GIVEN** an address
- **WHEN** the `pubkeyNonce(address)` function is called
- **THEN** the system returns the current nonce value for that address

#### Scenario: Independent nonce mappings
- **GIVEN** an address has both EIP-191 nonce and pubkey nonce
- **WHEN** a pubkey-based owner change is executed
- **THEN** only `pubkeyNonce` is incremented
- **AND** the EIP-191 `nonce` remains unchanged

---

### Requirement: SDK Owner Change with Public Key Method

The ethr-did SDK SHALL provide a `changeOwnerWithPubkey` method that:
1. Auto-detects keypair type from the keypair object
2. Queries current `pubkeyNonce` from the contract
3. Constructs the EIP-712 typed data message with nonce
4. Signs the message hash with the private key (using appropriate signing method)
5. Submits the transaction to the registry contract

#### Scenario: SDK changes owner with BLS keypair
- **GIVEN** an EthrDID instance with a BLS keypair
- **AND** the BLS-derived address is the current owner
- **AND** the current `pubkeyNonce` is N
- **WHEN** `changeOwnerWithPubkey(newOwnerAddress)` is called
- **THEN** the SDK queries `pubkeyNonce` from the contract
- **AND** constructs the EIP-712 message with nonce N
- **AND** signs with the BLS private key
- **AND** submits the transaction with publicKey and signature
- **AND** returns the transaction receipt on success

#### Scenario: SDK auto-detects BLS keypair
- **GIVEN** a BLS keypair object with 96-byte public key
- **WHEN** `changeOwnerWithPubkey` is called with this keypair
- **THEN** the SDK automatically uses BLS signing
- **AND** includes the 96-byte public key in the transaction

---

### Requirement: Cross-Keypair Ownership Transfer

The system SHALL support transferring ownership between different keypair types (secp256k1 <-> BLS12-381).

#### Scenario: Transfer from ECDSA to BLS owner
- **GIVEN** a DID currently owned by a secp256k1 address
- **AND** a target BLS keypair with derived address
- **WHEN** the current owner signs a `changeOwnerEIP712` transaction with the BLS-derived address as newOwner
- **THEN** the BLS keypair holder becomes the new owner
- **AND** can manage the DID using `changeOwnerWithPubkey`

#### Scenario: Transfer from BLS to ECDSA owner
- **GIVEN** a DID currently owned by a BLS-derived address
- **AND** a target secp256k1 address
- **WHEN** the BLS owner signs a `changeOwnerWithPubkey` transaction with the secp256k1 address as newOwner
- **THEN** the secp256k1 keypair holder becomes the new owner
- **AND** can manage the DID using `changeOwnerEIP712` or `changeOwnerSigned`

#### Scenario: Round-trip ownership transfer
- **GIVEN** a DID that starts with ECDSA owner
- **WHEN** ownership is transferred to BLS address, then back to ECDSA address
- **THEN** both transfers complete successfully
- **AND** the final owner can use ECDSA-based owner change methods
- **AND** nonces for both signature types are independent
