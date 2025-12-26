# Capability: BLS Owner Change in ethr-did

## ADDED Requirements

### Requirement: Expose changeOwnerWithPubkey method

The EthrDID class SHALL provide a `changeOwnerWithPubkey` method that delegates to the underlying EthrDidController, following the same pattern as the existing `changeOwner` method.

#### Scenario: Change owner with BLS public key and signature

**GIVEN** an EthrDID instance with a configured controller
**AND** a new owner address
**AND** a BLS public key
**AND** a valid signature
**WHEN** `changeOwnerWithPubkey(newOwner, publicKey, signature)` is called
**THEN** the method SHALL delegate to `controller.changeOwnerWithPubkey(newOwner, publicKey, signature)`
**AND** SHALL return the transaction hash

#### Scenario: Require controller for changeOwnerWithPubkey

**GIVEN** an EthrDID instance without a controller (no provider configured)
**WHEN** `changeOwnerWithPubkey(newOwner, publicKey, signature)` is called
**THEN** the method SHALL throw an error indicating no controller is available

#### Scenario: Pass transaction options through

**GIVEN** an EthrDID instance
**WHEN** `changeOwnerWithPubkey(newOwner, publicKey, signature, {gasLimit: 150000})` is called
**THEN** the method SHALL pass the options to the controller
**AND** the transaction SHALL use the specified gas limit

### Requirement: Return consistent transaction hash format

The system SHALL return transaction hashes in the same format for both `changeOwner` and `changeOwnerWithPubkey` operations.

#### Scenario: Transaction hash format consistency

**GIVEN** an EthrDID instance
**WHEN** `changeOwnerWithPubkey()` succeeds
**THEN** the returned value SHALL be a string containing the transaction hash
**AND** the format SHALL match the format returned by `changeOwner()`

### Requirement: Handle errors from controller

The system SHALL propagate errors from the EthrDidController with appropriate context.

#### Scenario: Contract revert during changeOwnerWithPubkey

**GIVEN** an EthrDID instance
**WHEN** `changeOwnerWithPubkey()` is called
**AND** the controller throws an error due to contract revert
**THEN** the method SHALL propagate the error
**AND** the error message SHALL include context about the failed operation

#### Scenario: Network error during changeOwnerWithPubkey

**GIVEN** an EthrDID instance
**WHEN** `changeOwnerWithPubkey()` is called
**AND** the controller throws a network error
**THEN** the method SHALL propagate the error
**AND** the error SHALL retain network error details

## MODIFIED Requirements

None - this capability adds new methods without modifying existing functionality.

## REMOVED Requirements

None - no existing functionality is removed.

---

## Relationships

**Depends on:**
- `ethr-did-resolver-bls` capability (provides EthrDidController.changeOwnerWithPubkey)

**Enables:**
- `credential-sdk-bls-simplified` capability (credential-sdk can use ethr-did methods)

**Follows pattern of:**
- Existing `EthrDID.changeOwner()` method (same delegation pattern)
- Existing `EthrDID.changeOwnerSigned()` method (similar signature handling)
