# Capability: Simplified BLS Owner Change in credential-sdk

## ADDED Requirements

None - this capability refactors internal implementation without adding new functionality.

## MODIFIED Requirements

### Requirement: Simplify changeOwnerWithPubkey implementation

The EthrDIDModule.changeOwnerWithPubkey method SHALL use the ethr-did library for registry interaction instead of direct contract calls.

#### Scenario: Use ethr-did library for owner change

**GIVEN** an EthrDIDModule instance
**AND** a DID with BLS owner
**AND** a new owner address
**AND** a BBS keypair
**WHEN** `changeOwnerWithPubkey(did, newOwner, bbsKeypair)` is called
**THEN** the method SHALL create an EthrDID instance
**AND** SHALL generate the signing hash using ethr-did methods
**AND** SHALL sign the hash with the BBS keypair
**AND** SHALL submit the transaction via `ethrDid.changeOwnerWithPubkey()`
**AND** SHALL NOT directly interact with the registry contract

#### Scenario: Maintain existing public API

**GIVEN** code using the current EthrDIDModule.changeOwnerWithPubkey API
**WHEN** the refactored implementation is deployed
**THEN** the existing code SHALL continue to work without modification
**AND** the method signature SHALL remain unchanged
**AND** the return value format SHALL remain unchanged

#### Scenario: Preserve error handling behavior

**GIVEN** an EthrDIDModule instance
**WHEN** `changeOwnerWithPubkey()` encounters an error
**THEN** the error messages SHALL be equivalent to or better than the current implementation
**AND** all error cases SHALL still be handled (invalid DID, wrong owner, signature failure, etc.)

### Requirement: Remove direct contract interaction code

The EthrDIDModule SHALL NOT directly construct registry contract instances or encode transactions for BLS owner changes.

#### Scenario: No manual contract instantiation

**GIVEN** the refactored EthrDIDModule.changeOwnerWithPubkey implementation
**WHEN** the method executes
**THEN** it SHALL NOT create ethers.Contract instances for the registry
**AND** it SHALL NOT manually encode transaction data
**AND** it SHALL NOT directly query contract nonces

#### Scenario: Delegate registry operations to ethr-did

**GIVEN** the refactored implementation
**WHEN** registry contract interaction is needed
**THEN** all such interaction SHALL go through ethr-did/ethr-did-resolver methods

### Requirement: Retain BLS signing in credential-sdk

The credential-sdk SHALL continue to handle BLS/BBS cryptographic signing operations.

#### Scenario: Sign with BBS keypair

**GIVEN** an EthrDIDModule instance
**WHEN** `changeOwnerWithPubkey(did, newOwner, bbsKeypair)` is called
**THEN** the method SHALL use `signWithBLSKeypair()` utility to sign the hash
**AND** the signature SHALL be generated from the bbsKeypair.privateKeyBuffer
**AND** the signature format SHALL match contract expectations

#### Scenario: BLS utilities remain in credential-sdk

**GIVEN** the refactored implementation
**THEN** functions like `signWithBLSKeypair()` and `publicKeyToAddress()` MAY remain in credential-sdk utils
**AND** these utilities MAY be used by credential-sdk even if duplicated in ethr-did-resolver
**OR** credential-sdk MAY import these from ethr-did-resolver to avoid duplication

## REMOVED Requirements

### Requirement: Remove manual nonce management

The EthrDIDModule SHALL NOT manually query `pubkeyNonce` from the registry contract.

#### Scenario: Nonce handled by ethr-did

**GIVEN** the refactored implementation
**WHEN** `changeOwnerWithPubkey()` is called
**THEN** nonce retrieval SHALL be delegated to ethr-did-resolver
**AND** credential-sdk SHALL NOT contain code to query `pubkeyNonce(address)`

### Requirement: Remove manual EIP-712 construction

The EthrDIDModule SHALL NOT manually construct EIP-712 typed data for changeOwnerWithPubkey.

#### Scenario: EIP-712 handled by ethr-did

**GIVEN** the refactored implementation
**WHEN** a signing hash is needed
**THEN** the hash SHALL be obtained from ethr-did methods
**AND** credential-sdk SHALL NOT construct the EIP-712 domain or message structure
**AND** the `createChangeOwnerWithPubkeyTypedData()` utility MAY be removed or deprecated

### Requirement: Remove manual transaction encoding

The EthrDIDModule SHALL NOT manually encode `changeOwnerWithPubkey` contract function calls.

#### Scenario: Transaction encoding handled by ethr-did

**GIVEN** the refactored implementation
**WHEN** a transaction needs to be submitted
**THEN** the transaction encoding SHALL be handled by ethr-did-resolver
**AND** credential-sdk SHALL NOT use `ethers.utils.Interface.encodeFunctionData` for changeOwnerWithPubkey

---

## Relationships

**Depends on:**
- `ethr-did-bls` capability (provides EthrDID.changeOwnerWithPubkey)
- `ethr-did-resolver-bls` capability (provides underlying implementation)

**Benefits from:**
- Cleaner separation of concerns (registry operations in ethr-did, credentials in credential-sdk)
- Reduced code complexity in credential-sdk
- Better testability (can test layers independently)
- Consistent API patterns (all owner changes go through ethr-did)

**Maintains compatibility with:**
- Existing credential-sdk users (no public API changes)
- Existing test suites (may need minor adjustments but same coverage)
