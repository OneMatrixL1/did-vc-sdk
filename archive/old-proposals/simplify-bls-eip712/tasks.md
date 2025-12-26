# Tasks: Simplify BLS EIP-712 Structure

## Phase 1: Contract Updates
- [ ] 1.1: Update CHANGE_OWNER_WITH_PUBKEY_TYPEHASH to use (identity, oldOwner, newOwner)
- [ ] 1.2: Update structHash encoding to use oldOwner instead of signer and nonce
- [ ] 1.3: Add verification: require(oldOwner == identityOwner(identity))
- [ ] 1.4: Remove pubkeyNonce mapping from contract (storage cleanup)
- [ ] 1.5: Remove nonce increment logic
- [ ] 1.6: Compile and verify contract builds successfully

## Phase 2: TypeScript Library Updates
- [ ] 2.7: Update createChangeOwnerWithPubkeyHash() in ethr-did-resolver controller.ts
- [ ] 2.8: Get oldOwner via controller.getOwner(identity)
- [ ] 2.9: Remove signer derivation from message construction
- [ ] 2.10: Build EIP-712 message with {identity, oldOwner, newOwner}
- [ ] 2.11: Update AbiCoder.encode() to 3 fields instead of 4
- [ ] 2.12: Build and verify TypeScript compilation

## Phase 3: Testing
- [x] 3.13: Write unit test for hash generation with new structure
- [x] 3.14: Update integration tests for BLS owner change
- [x] 3.15: Verify hash matches between contract and TypeScript
- [x] 3.16: Test that old signatures fail with new contract
- [x] 3.17: Test replay protection (signature fails after owner change)
- [x] 3.18: Run full test suite and verify all pass

## Phase 4: Documentation
- [ ] 4.19: Update contract comments explaining new EIP-712 structure
- [ ] 4.20: Update TypeScript JSDoc for createChangeOwnerWithPubkeyHash()
- [ ] 4.21: Update design docs and architecture notes
- [ ] 4.22: Add breaking change notes for documentation

## Phase 5: Validation
- [x] 5.23: Gas comparison test (before vs after)
- [x] 5.24: Storage usage comparison (no pubkeyNonce mapping)
- [x] 5.25: Security review of simplified structure
- [x] 5.26: Verify replay protection works as designed
- [x] 5.27: Final lint and format check
