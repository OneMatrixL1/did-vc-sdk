# Capability: BLS Owner Change in ethr-did-resolver

## ADDED Requirements

### Requirement: Derive Ethereum address from BLS12-381 public key

The system SHALL provide a function to derive an Ethereum address from a BLS12-381 G2 public key by computing the keccak256 hash of the 96-byte public key and taking the last 20 bytes.

#### Scenario: Convert BLS public key to Ethereum address

**GIVEN** a 96-byte BLS12-381 G2 public key
**WHEN** `publicKeyToAddress(publicKey)` is called
**THEN** the function SHALL return a checksummed Ethereum address derived from keccak256(publicKey)
**AND** the address SHALL use the last 20 bytes of the hash

#### Scenario: Reject unsupported public key lengths

**GIVEN** a public key with length other than 96 bytes
**WHEN** `publicKeyToAddress(publicKey)` is called
**THEN** the function SHALL throw an error indicating unsupported key length

### Requirement: Create EIP-712 hash for changeOwnerWithPubkey

The system SHALL provide a method to construct the EIP-712 typed data hash for the `changeOwnerWithPubkey` operation, including automatic nonce retrieval from the registry contract.

#### Scenario: Generate signing hash with automatic nonce

**GIVEN** a configured EthrDidController
**AND** a new owner address
**AND** a public key
**WHEN** `createChangeOwnerWithPubkeyHash(newOwner, publicKey)` is called
**THEN** the method SHALL derive the signer address from the public key
**AND** SHALL query `pubkeyNonce(signerAddress)` from the registry contract
**AND** SHALL construct EIP-712 typed data with domain `{name: 'EthereumDIDRegistry', version: '1', chainId, verifyingContract}`
**AND** SHALL use message type `ChangeOwnerWithPubkey(address identity, address signer, address newOwner, uint256 nonce)`
**AND** SHALL return the keccak256 hash of the structured data

#### Scenario: Hash includes correct identity address

**GIVEN** an EthrDidController for DID `did:ethr:0x123...`
**WHEN** `createChangeOwnerWithPubkeyHash(newOwner, publicKey)` is called
**THEN** the EIP-712 message.identity SHALL equal `0x123...` (the DID address)

### Requirement: Submit changeOwnerWithPubkey transaction

The system SHALL provide a method to submit a `changeOwnerWithPubkey` transaction to the EthereumDIDRegistry contract with a public key and signature.

#### Scenario: Submit owner change with BLS signature

**GIVEN** a configured EthrDidController with a transaction signer
**AND** a new owner address
**AND** a 96-byte BLS public key
**AND** a valid BLS signature
**WHEN** `changeOwnerWithPubkey(newOwner, publicKey, signature, options)` is called
**THEN** the method SHALL derive the signer address from the public key
**AND** SHALL query the current `pubkeyNonce(signerAddress)`
**AND** SHALL encode a transaction calling `changeOwnerWithPubkey(identity, newOwner, nonce, publicKey, signature)`
**AND** SHALL submit the transaction using the configured signer
**AND** SHALL wait for the transaction receipt
**AND** SHALL return the transaction receipt

#### Scenario: Transaction includes correct parameters

**GIVEN** an EthrDidController for identity `0xAAA...`
**AND** new owner `0xBBB...`
**AND** public key deriving to signer `0xCCC...`
**AND** current nonce is 5
**WHEN** `changeOwnerWithPubkey(0xBBB..., publicKey, signature)` is called
**THEN** the contract call SHALL include parameters `(0xAAA..., 0xBBB..., 5, publicKey, signature)`

#### Scenario: Handle transaction revert errors

**GIVEN** a configured EthrDidController
**WHEN** `changeOwnerWithPubkey()` is called
**AND** the contract reverts (e.g., invalid signature)
**THEN** the method SHALL throw an error with the revert reason

### Requirement: Support transaction options for changeOwnerWithPubkey

The system SHALL accept optional transaction parameters (gas limit, gas price, etc.) when submitting changeOwnerWithPubkey transactions.

#### Scenario: Custom gas limit

**GIVEN** an EthrDidController
**WHEN** `changeOwnerWithPubkey(newOwner, publicKey, signature, {gasLimit: 200000})` is called
**THEN** the transaction SHALL use gasLimit of 200000

#### Scenario: Custom from address

**GIVEN** an EthrDidController
**WHEN** `changeOwnerWithPubkey(newOwner, publicKey, signature, {from: '0xXYZ...'})` is called
**THEN** the transaction SHALL be sent from address `0xXYZ...`

## MODIFIED Requirements

None - this capability is additive to ethr-did-resolver.

## REMOVED Requirements

None - no existing functionality is removed.

---

## Relationships

**Depends on:**
- EthereumDIDRegistry contract must implement `changeOwnerWithPubkey(address identity, address newOwner, uint256 pubkeyNonceParam, bytes publicKey, bytes signature)`
- EthereumDIDRegistry contract must implement `pubkeyNonce(address) returns (uint256)`

**Enables:**
- `ethr-did-bls` capability (wrapper methods in ethr-did)
- `credential-sdk-bls-simplified` capability (simplified credential-sdk implementation)
