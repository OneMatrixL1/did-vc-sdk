# Design: Simplify BLS EIP-712 Structure

## Architecture

### Previous Flow (Removed)
1. User calls `createChangeOwnerWithPubkeyHash(newOwner, publicKey)`
2. Derive signer: `signer = publicKeyToAddress(publicKey)`
3. Fetch nonce: `nonce = contract.pubkeyNonce(signer)`
4. Build EIP-712 message with **4 fields**: `{identity, signer, newOwner, nonce}`
5. Compute hash
6. User signs hash with BLS private key
7. Submit transaction with signature
8. Contract verifies signature matches message containing `signer` and `nonce`

**Why this was removed:**
- `signer` field: Redundant - BLS signature already proves owner authorization
- `nonce` field: Unnecessary - ownership change provides natural replay protection

### Implemented Flow (Simplified)
1. User calls `createChangeOwnerWithPubkeyHash(newOwner, publicKey)`
2. Get current owner: `oldOwner = await this.getOwner(identity)`
3. Build EIP-712 message with **3 fields**: `{identity, oldOwner, newOwner}`
4. Compute hash using:
   - TypeHash: `keccak256("ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)")`
   - StructHash: `keccak256(abi.encode([typeHash, identity, oldOwner, newOwner]))`
   - DomainSeparator: EIP-712 domain for EthereumDIDRegistry
5. User signs hash with BLS private key
6. Submit transaction with signature
7. Contract verifies:
   - Derive signer from publicKey: `signer = publicKeyToAddress(publicKey)`
   - Verify BLS signature over hash
   - Check `signer == identityOwner(identity)` (owner authorization)
   - Check `oldOwner == identityOwner(identity)` (replay protection)
   - Update owner to newOwner and emit event

## Security Analysis

### Why Signer Field is Redundant

**Current assumption**: Including `signer` in the message ensures only the current owner can create valid signatures.

**Reality**: The BLS signature already proves this:
- BLS signature verification: `e(signature, G2) = e(hash_to_curve(message), publicKey)`
- This cryptographically proves the signer knows the private key for `publicKey`
- The contract derives `signer = publicKeyToAddress(publicKey)`
- The contract checks `require(signer == currentOwner)`

Including `signer` in the message adds zero security because:
1. You can't create a valid signature without the private key
2. The public key determines the signer address deterministically
3. The contract already verifies ownership through derived address

### What Actually Provides Security

1. **BLS Signature** - Proves private key ownership (owner authorization)
2. **OldOwner in Message** - Prevents replay after ownership change
3. **NewOwner** - Specifies what's being changed to
4. **Identity** - Specifies which DID is being changed
5. **Domain Separator** - Prevents cross-contract replays

The `signer` and `nonce` fields are redundant. **OldOwner provides replay protection** because:
- If oldOwner signs `{identity, oldOwner, newOwner}`
- And someone changes the owner to a different address
- The old signature is no longer valid because oldOwner != currentOwner
- No nonce counter needed!

## Implementation Details

### Contract Implementation (EthereumDIDRegistry.sol)

**CHANGE_OWNER_WITH_PUBKEY_TYPEHASH Constant:**
```solidity
// Simplified 3-field structure with owner-based replay protection
// Removed: signer field (proven by BLS signature), nonce field (unnecessary)
bytes32 public constant CHANGE_OWNER_WITH_PUBKEY_TYPEHASH =
  keccak256("ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)");
```

**changeOwnerWithPubkey() Function:**
```solidity
function changeOwnerWithPubkey(
  address identity,
  address oldOwner,
  address newOwner,
  bytes calldata publicKey,
  bytes calldata signature
) external {
  // Parameter validation
  require(newOwner != address(0), "invalid_new_owner");

  // Derive signer from public key
  address signer = publicKeyToAddress(abi.encodePacked(publicKey));

  // Ownership verification
  require(signer == identityOwner(identity), "unauthorized");

  // Replay protection: verify oldOwner is current owner
  require(oldOwner == identityOwner(identity), "invalid_owner");

  // EIP-712 signature verification
  bytes32 structHash = keccak256(abi.encode(
    CHANGE_OWNER_WITH_PUBKEY_TYPEHASH,
    identity,
    oldOwner,
    newOwner
  ));
  bytes32 hash = keccak256(abi.encodePacked(EIP191_HEADER, DOMAIN_SEPARATOR, structHash));

  // Route to BLS verification for 96-byte keys
  if (publicKey.length == 96) {
    BLS2.PointG1 memory message = BLS2.hashToPoint("BLS_DST", abi.encodePacked(hash));
    bytes memory messageBytes = BLS2.g1Marshal(message);
    bytes memory pubkeyBytes = abi.encodePacked(publicKey);
    _verifyBlsSignature(pubkeyBytes, messageBytes, signature);
  } else {
    revert("unsupported_pubkey_type");
  }

  // Update owner
  owners[identity] = newOwner;
  emit DIDOwnerChanged(identity, newOwner, changed[identity]);
  changed[identity] = block.number;
}
```

**Key Implementation Points:**
- No `pubkeyNonce` mapping (removed for storage cleanup)
- No nonce increment logic (owner-based replay protection used instead)
- Ownership verification: `signer == identityOwner(identity)` (authorization)
- Replay protection: `oldOwner == identityOwner(identity)` (temporal check)
- Both checks ensure only current owner can initiate change

### TypeScript Implementation (EthrDidController)

**createChangeOwnerWithPubkeyHash() Method:**
```typescript
async createChangeOwnerWithPubkeyHash(newOwner: address, publicKey: Uint8Array): Promise<string> {
  // Get current owner (acts as replay protection in signature)
  const oldOwner = await this.getOwner(this.address)
  const registryAddress = await this.contract.getAddress()

  // Get chain ID for domain separator
  const provider = this.contract.runner?.provider
  if (!provider) throw new Error('No provider configured')
  const network = await provider.getNetwork()
  const chainId = network.chainId

  // Build 3-field message
  const message = {
    identity: this.address,
    oldOwner,
    newOwner,
  }

  // Compute EIP-712 hash
  const coder = AbiCoder.defaultAbiCoder()
  const typeHash = keccak256(
    toUtf8Bytes('ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)')
  )
  const structHash = keccak256(
    coder.encode(
      ['bytes32', 'address', 'address', 'address'],
      [typeHash, message.identity, message.oldOwner, message.newOwner]
    )
  )

  const domainSeparator = keccak256(
    coder.encode(
      ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
      [
        keccak256(toUtf8Bytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')),
        keccak256(toUtf8Bytes('EthereumDIDRegistry')),
        keccak256(toUtf8Bytes('1')),
        chainId,
        registryAddress,
      ]
    )
  )

  return keccak256(concat(['0x1901', domainSeparator, structHash]))
}
```

**changeOwnerWithPubkey() Method:**
```typescript
async changeOwnerWithPubkey(
  newOwner: address,
  publicKey: Uint8Array,
  signature: Uint8Array,
  options: Overrides = {}
): Promise<TransactionReceipt> {
  const overrides = {
    gasLimit: 123456,
    ...options,
  }

  const contract = await this.attachContract(overrides.from ?? undefined)
  delete overrides.from

  // Get current owner (for signature verification)
  const oldOwner = await this.getOwner(this.address)

  // Submit transaction with simplified 3-field message
  const txResponse = await contract.changeOwnerWithPubkey(
    this.address,
    oldOwner,
    newOwner,
    publicKey,
    signature,
    overrides
  )

  return await txResponse.wait()
}
```

**Key Implementation Points:**
- No signer derivation in message construction (only in contract for verification)
- No nonce lookup (removed entire concept)
- Fetch oldOwner from contract state (represents current owner at signing time)
- Simpler: 3 fields vs 4, no counter tracking
- Client is stateless: doesn't maintain nonce counter

### Migration from Old Implementation

**Old 4-field structure:**
```
TypeHash: ChangeOwnerWithPubkey(address identity,address signer,address newOwner,uint256 nonce)
Fields: identity, signer, newOwner, nonce
Replay Protection: nonce counter per signer
Storage: pubkeyNonce mapping per signer
```

**New 3-field structure:**
```
TypeHash: ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)
Fields: identity, oldOwner, newOwner
Replay Protection: owner state check
Storage: No additional mapping needed
```

**Breaking Change:**
- Old signatures won't work on new contract (different TypeHash, different field count)
- Must deploy new contract and update all clients simultaneously
- No gradual rollout possible

## Trade-offs

### Advantages (Why We Made This Change)

**Simplicity:**
- 25% fewer fields in message (3 vs 4)
- No nonce counter tracking in TypeScript client
- Fewer state mutations in contract
- Cleaner code (easier to understand and audit)

**Performance:**
- Less encoding/hashing (one fewer field)
- No nonce lookup required
- No pubkeyNonce storage mapping
- Slightly lower gas cost due to simpler logic

**Security Model:**
- Clearer security properties (signature proves ownership, ownership change prevents replays)
- Only semantically meaningful fields
- Aligns with EIP-712 best practices
- Ownership-based replay protection is more elegant than nonce-based

**Maintenance:**
- Fewer state variables to track
- Smaller contract surface area
- Less likely to encounter nonce desynchronization bugs

### Disadvantages (Costs of Change)

**Breaking Change:**
- Requires contract redeployment (can't be done in-place)
- Old signatures won't work on new contract
- All clients must be updated simultaneously
- No gradual rollout possible

**Migration Complexity:**
- Must choose exact moment to deploy new contract
- All systems using BLS owner changes must update together
- Can't run old and new contracts in parallel
- Any in-flight signatures become invalid

## Testing & Validation

### Unit Tests (Implemented)
```typescript
// Hash generation with new structure
- Correct 3-field format: (identity, oldOwner, newOwner)
- Consistent hash across multiple calls
- Different hash for different identities
- Different hash for different new owners
- Correct TypeHash: keccak256("ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)")
```

### Integration Tests (Implemented)
```typescript
// End-to-end owner change
- Successfully change owner using BLS signature
- oldOwner matches current owner before state change
- DIDOwnerChanged event emitted correctly
```

### Security Tests (Implemented)
```typescript
// Replay protection via owner change
- Old signatures fail after owner changes
- Verify oldOwner must match identityOwner(identity)
- Confirm contract has NO pubkeyNonce mapping
- Signature invalid through owner mismatch, not nonce counter
```

### Compatibility Tests (Implemented)
```typescript
// Hash consistency
- Identical hash computation in TypeScript and Solidity
- Correct domain separator components
- Old 4-field signatures fail with new contract
- Old contract doesn't accept new 3-field hashes
```

### Verification Results
All tests pass:
- 3.13: Hash generation with new structure
- 3.14: Integration tests for BLS owner change
- 3.15: Hash consistency between TypeScript and Solidity
- 3.16: Old signatures fail with new contract
- 3.17: Replay protection via owner change
- 3.18: Full test suite validation

## Performance Analysis

### Gas Cost Reduction
Expected improvements from removing nonce field:

**Message Encoding:**
- Old: 4 fields (128 bytes encoded)
- New: 3 fields (96 bytes encoded)
- Savings: 32 bytes per hash computation

**Contract Storage:**
- Old: pubkeyNonce mapping (1 uint per signer)
- New: No mapping
- Savings: One storage slot per signer (indefinitely)

**Computation:**
- Old: 1 nonce lookup + 1 nonce increment = 2 SSTORE operations
- New: 0 nonce operations
- Savings: 2 SSTORE per transaction

Estimated total gas savings: ~5-8% per changeOwnerWithPubkey transaction

## Documentation Updates

All documentation has been updated to reflect the simplified structure:

**Contract Documentation (EthereumDIDRegistry.sol):**
- CHANGE_OWNER_WITH_PUBKEY_TYPEHASH constant documented
- changeOwnerWithPubkey() function has comprehensive JSDoc
- Explains 3-field structure
- Documents replay protection mechanism
- Lists all error conditions

**TypeScript Documentation (EthrDidController):**
- createChangeOwnerWithPubkeyHash() comprehensive JSDoc
  - Message structure explanation
  - Replay protection mechanism
  - How it works step-by-step
  - Security implications
- changeOwnerWithPubkey() comprehensive JSDoc
  - Transaction flow
  - Error handling
  - Replay protection example

**Migration Documentation (BREAKING_CHANGES.md):**
- Detailed comparison: old vs new structure
- Why this change was made
- Migration steps for deployments and clients
- Security analysis
- FAQ addressing common questions
- References to related documentation
