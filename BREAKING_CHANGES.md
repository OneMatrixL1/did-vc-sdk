# Breaking Changes

## v2.0.0: Simplified BLS EIP-712 Structure

### Summary
The EIP-712 message structure for BLS-based owner changes has been simplified from 4 fields to 3 fields. Replay protection has been changed from nonce-based to owner-based. **This is a breaking change that requires contract redeployment and simultaneous client updates.**

### What Changed

#### Old Structure (4 fields with nonce-based replay protection)
```
ChangeOwnerWithPubkey(address identity, address signer, address newOwner, uint256 nonce)
```

Parameters:
- `identity` - The DID identity
- `signer` - The signer address (derived from public key)
- `newOwner` - The new owner
- `nonce` - A counter for replay protection

Replay Protection: Nonce-based
- Track a nonce per signer
- Increment nonce after each signature use
- Prevent replaying old signatures by checking nonce hasn't been used

#### New Structure (3 fields with owner-based replay protection)
```
ChangeOwnerWithPubkey(address identity, address oldOwner, address newOwner)
```

Parameters:
- `identity` - The DID identity
- `oldOwner` - The current owner at signing time (acts as replay protection)
- `newOwner` - The new owner

Replay Protection: Owner-based
- Include the current owner in the signed message
- If owner changes, the oldOwner field becomes stale
- Contract checks: `require(oldOwner == identityOwner(identity))`
- Old signatures automatically invalid after ownership change (no counter needed)

### Why This Change

**The signer and nonce fields were redundant:**

1. **Signer is redundant:**
   - BLS signature verification already proves the signer knows the private key
   - Owner is derived deterministically from the public key
   - Contract already verifies `signer == currentOwner`
   - Including signer in the message provides zero additional security

2. **Nonce is unnecessary:**
   - Owner-based replay protection is simpler and more elegant
   - No need to track and increment a counter
   - Ownership change automatically invalidates old signatures
   - Fewer state mutations in the contract

3. **Benefits of the new structure:**
   - Simpler message structure (fewer fields to encode/verify)
   - Less computation (no nonce lookup/increment)
   - Clearer security model (signature proves ownership, ownership state prevents replays)
   - Aligns with EIP-712 best practices (only include necessary data)
   - Easier to audit (simpler code)

### Migration Guide

**This is a hard breaking change. All affected systems must be updated simultaneously.**

#### For Contract Deployments

1. **Deploy new contract** with simplified EIP-712 structure
   - `CHANGE_OWNER_WITH_PUBKEY_TYPEHASH` is different (different field count)
   - Old signatures will be invalid on new contract
   - pubkeyNonce mapping is removed (storage cleanup)

2. **Do not run both contracts in parallel**
   - Old contract: uses nonce-based replay protection
   - New contract: uses owner-based replay protection
   - Cannot interop between versions - must choose one

3. **Update registry address** in all clients pointing to new contract

#### For TypeScript Clients (ethr-did-resolver)

The `createChangeOwnerWithPubkeyHash()` method has been updated:

**Before:**
```typescript
// Derived signer from public key
const signer = publicKeyToAddress(publicKey)
// Fetched nonce for signer
const nonce = await contract.pubkeyNonce(signer)

// Message had 4 fields: identity, signer, newOwner, nonce
const message = {
  identity: this.address,
  signer,
  newOwner,
  nonce,
}

const typeHash = keccak256(
  toUtf8Bytes('ChangeOwnerWithPubkey(address identity,address signer,address newOwner,uint256 nonce)')
)
```

**After:**
```typescript
// Get current owner
const oldOwner = await this.getOwner(this.address)

// Message has 3 fields: identity, oldOwner, newOwner
const message = {
  identity: this.address,
  oldOwner,
  newOwner,
}

const typeHash = keccak256(
  toUtf8Bytes('ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)')
)
```

**No changes needed to:**
- `changeOwnerWithPubkey()` method signature (still takes same parameters)
- Other methods (changeOwner, changeOwnerEIP712, etc.)
- credential-sdk (uses library methods automatically)
- ethr-did (thin wrapper, inherits updates)

#### Migration Steps

1. **Prepare new contract deployment**
   - Build contract with new EIP-712 structure
   - Deploy to staging/testnet for validation
   - Verify gas usage and other metrics

2. **Update all clients**
   - Update ethr-did-resolver package version
   - Update any direct consumers of createChangeOwnerWithPubkeyHash()
   - Verify hash computation matches new contract

3. **Coordinate deployment**
   - Choose deployment time when all clients can be updated
   - Deploy new contract and update client simultaneously
   - No grace period possible - old and new are incompatible

4. **Verify migration**
   - Test changeOwnerWithPubkey() with new contract
   - Verify replay protection still works (test signature fails after owner change)
   - Check gas usage vs previous version
   - Audit simplification for security compliance

### Security Considerations

**Owner-based replay protection is secure because:**

1. Signature proves owner authorized the change (BLS verification)
2. Owner is included in signed message
3. If owner changes, oldOwner becomes stale
4. Contract enforces: oldOwner == currentOwner
5. Attempting to replay old signature fails immediately

**Example attack scenario:**
```
1. Alice (owner) signs: ChangeOwnerWithPubkey(identity, alice, bob)
2. Bob becomes owner (via new signature or other means)
3. Attacker tries to replay: ChangeOwnerWithPubkey(identity, alice, bob)
4. Contract check: alice != bob (current owner)
5. Transaction reverts with "invalid_owner"
```

**Comparison to nonce-based protection:**
```
Nonce-based:
- Pro: Independent of state (can verify signature offline)
- Con: Need to track counter per signer
- Con: Risk of nonce desynchronization in complex flows

Owner-based (NEW):
- Pro: Simpler (no counter tracking)
- Pro: State-based protection is natural for ownership changes
- Pro: Impossible to use signature after owner changes
- Con: Must fetch current owner to construct message
```

### Testing

**Tests should verify:**

1. New hash computation matches contract
2. Old signatures fail with new contract
3. Replay protection works (signature fails after owner change)
4. New structure has 3 fields, old had 4
5. changeOwnerWithPubkey() still changes owner correctly
6. Event emission (DIDOwnerChanged) still works
7. No regression in other changeOwner variants

### FAQ

**Q: Can I still use the old contract?**
A: Yes, but it will not receive updates. You must choose: either use old contract indefinitely, or migrate to new contract.

**Q: What if I have pending signatures in my application?**
A: They will be invalid on the new contract. You must generate new signatures with the new message structure using the updated client libraries.

**Q: Do I need to migrate immediately?**
A: No, but all systems using BLS owner changes must migrate together. If you're not using changeOwnerWithPubkey(), this change doesn't affect you.

**Q: What about other DID methods (delegates, attributes)?**
A: They are unchanged. Only the BLS owner change (changeOwnerWithPubkey) is affected.

**Q: Will there be a v2.1.0 that supports both old and new?**
A: No. The old and new structures are cryptographically incompatible. You must deploy new contract and update clients simultaneously.

**Q: How does this compare to versioning the TypeHash?**
A: We chose structural simplification instead of versioning because:
- Old structure was suboptimal
- Versioning would double complexity
- Migration is clean cut - no legacy compatibility needed
- Owner-based replay protection is superior

### References

- OpenSpec Change: `simplify-bls-eip712`
- EIP-712: https://eips.ethereum.org/EIPS/eip-712
- Design Doc: `/openspec/changes/simplify-bls-eip712/design.md`
