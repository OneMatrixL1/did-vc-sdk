# BLS EIP-712 Simplified

## ADDED Requirements

### Requirement: EIP-712 structure includes oldOwner for replay protection
The `ChangeOwnerWithPubkey` EIP-712 structure MUST contain: identity, oldOwner, and newOwner. The oldOwner field MUST be included in the signed message and verified against the current owner in the contract.

**Rationale**: Including oldOwner (the current owner at time of signing) in the message provides automatic replay protection. If ownership changes, old signatures become invalid because oldOwner != currentOwner. This eliminates the need for a separate nonce counter.

#### Scenario: Computing EIP-712 hash for BLS owner change
```typescript
Given an identity address, new owner address, and the current owner address
When computing the EIP-712 hash for signing
Then the TypeHash MUST be: keccak256("ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)")
And the struct encoding MUST include exactly 3 fields: identity, oldOwner, newOwner
And the oldOwner MUST be the current owner at time of hash creation
```

#### Scenario: Contract verifying BLS signature with owner check
```solidity
Given a changeOwnerWithPubkey transaction with identity, oldOwner, newOwner, publicKey, signature
When the contract constructs the EIP-712 hash
Then it MUST use: keccak256(abi.encode(TYPEHASH, identity, oldOwner, newOwner))
And it MUST verify: oldOwner == identityOwner(identity)
And signature verification MUST succeed if signed with the correct private key
And the signature MUST be invalid if ownership already changed
```

### Requirement: No nonce counter needed for BLS signatures
The implementation MUST NOT use a nonce counter for BLS owner changes. The oldOwner field provides sufficient replay protection.

**Rationale**: Traditional nonce-based replay protection is designed for externally-owned accounts. For structured data (EIP-712), including mutable state (oldOwner) in the signed message is a cleaner approach.

#### Scenario: Preventing replay after ownership change
```
Given Alice owns identity X and signs changeOwnerWithPubkey(X, alice, bob)
And Bob successfully becomes the new owner
When an attacker replays the signature (X, alice, bob)
Then the contract checks: alice == identityOwner(X)
And the check fails because currentOwner is now bob
And the transaction reverts
```

### Requirement: Gas efficiency through simpler encoding
The simplified structure MUST reduce gas costs and storage usage.

#### Scenario: Gas and storage comparison
```
Given the old structure using 4 fields: identity, signer, newOwner, nonce
And the old contract maintaining a pubkeyNonce mapping for each signer
And the new structure using 3 fields: identity, oldOwner, newOwner
And the new contract with no nonce mapping
When measuring costs
Then the new structure MUST eliminate the pubkeyNonce storage mapping
And the new structure MUST use less gas for hash computation
```

## MODIFIED Requirements

### Requirement: Contract TypeHash constant matches new structure
The `CHANGE_OWNER_WITH_PUBKEY_TYPEHASH` constant in EthereumDIDRegistry MUST be updated.

#### Scenario: TypeHash value
```solidity
Given the CHANGE_OWNER_WITH_PUBKEY_TYPEHASH constant
Then its value MUST be: keccak256("ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)")
And it MUST NOT include signer or nonce parameters
```

### Requirement: TypeScript hash computation matches contract
The `createChangeOwnerWithPubkeyHash()` method MUST compute hashes that exactly match the contract's verification logic.

#### Scenario: Cross-platform hash consistency
```typescript
Given identical inputs (identity, oldOwner, newOwner) in both TypeScript and Solidity
When computing the EIP-712 hash
Then TypeScript createChangeOwnerWithPubkeyHash() MUST produce the same hash
And Solidity changeOwnerWithPubkey() verification MUST succeed with that hash
```
