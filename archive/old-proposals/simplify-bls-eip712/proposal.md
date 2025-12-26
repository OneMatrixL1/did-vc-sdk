# Simplify BLS EIP-712 Structure

## Summary
Remove the redundant `signer` field from the `ChangeOwnerWithPubkey` EIP-712 structure. The signer address is already verified through BLS signature validation and including it in the signed message provides no additional security.

## Problem
The current EIP-712 structure for BLS owner changes includes four fields:
```
ChangeOwnerWithPubkey(address identity, address signer, address newOwner, uint256 nonce)
```

The `signer` field is redundant because:
1. The signer address is derived from the BLS public key (`publicKeyToAddress(publicKey)`)
2. BLS signature verification already proves the signer owns the private key
3. The contract verifies `signer == currentOwner` using the derived address
4. Including `signer` in the message doesn't add security - it's already guaranteed by the cryptographic signature

This adds unnecessary complexity to:
- EIP-712 message construction
- Signature creation
- Message validation

## Proposed Solution
Simplify the EIP-712 structure to:
```
ChangeOwnerWithPubkey(address identity, address oldOwner, address newOwner)
```

This replaces the nonce-based replay protection with owner-based replay protection:
- **oldOwner** proves this signature was created by the current owner (acts as replay protection)
- **newOwner** specifies the new owner address
- If ownership changes, old signatures become invalid automatically

This aligns with the existing `ChangeOwner` structure:
```
ChangeOwner(address identity, address newOwner)
```

But adds explicit `oldOwner` to the signature, proving authorization.

### Changes Required

**Contract (ethr-did-registry):**
- Update `CHANGE_OWNER_WITH_PUBKEY_TYPEHASH` constant
- Update `structHash` encoding in `changeOwnerWithPubkey()`

**TypeScript (ethr-did-resolver):**
- Update `createChangeOwnerWithPubkeyHash()` to use oldOwner instead of nonce
- Get current owner via `this.controller.getOwner(identity)`
- Include oldOwner in EIP-712 message

**No changes needed in:**
- credential-sdk: Uses the library methods, automatically benefits from simplification
- ethr-did: Thin wrapper, no changes needed

## Benefits
1. **Simpler message structure** - Fewer fields to encode/verify
2. **Less computation** - No need to derive signer for message construction
3. **Clearer security model** - Signature proves ownership, no redundant fields
4. **Consistent with standards** - EIP-712 messages should only include necessary data
5. **Easier to audit** - Simpler code is easier to review for security

## Risks & Mitigation
- **Contract must be redeployed** - Existing deployments would need migration
- **Breaking change** - Signatures created with old structure won't work with new contract
- **Migration strategy**: Deploy new contract, update all clients before switching

## Open Questions
1. Are there any existing deployments using the current structure?
2. Do we need a migration period or can we do a clean break?
3. Should we version the TypeHash or just replace it?
