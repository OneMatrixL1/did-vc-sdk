# OpenSpec Proposal: Invert BLS Signature Scheme

## ✅ Status: VALIDATED

The OpenSpec proposal has been created and validated successfully.

## 📁 Files Created

```
openspec/changes/invert-bls-scheme/
├── proposal.md          # Main proposal document
├── design.md            # Technical design and architecture
├── tasks.md             # 68 implementation tasks across 8 phases
├── specs/
│   ├── bls-signature-scheme/
│   │   └── spec.md      # Contract BLS scheme requirements
│   └── contract-compatibility/
│       └── spec.md      # SDK integration requirements
└── SUMMARY.md           # This file
```

## 📊 Quick Facts

- **Change ID**: `invert-bls-scheme`
- **Total Tasks**: 68 tasks
- **Phases**: 8 (Investigation → Testing → Deployment)
- **Specs**: 2 capabilities
- **Breaking Change**: YES (contract redeployment required)

## 🎯 Objectives

### Current Problem
- Contract expects: G2 public keys (96 bytes) + G1 signatures (96 bytes)
- SDK generates: G1 public keys (48 bytes) + G2 signatures (96 bytes)
- Result: **INCOMPATIBLE** ❌

### Proposed Solution
Change contract to accept:
- **G1 public keys** (48 or 96 bytes)
- **G2 signatures** (192 bytes)

### Expected Outcome
- ✅ SDK can generate fresh BLS keypairs natively
- ✅ No external signing services needed
- ✅ Better developer experience
- ✅ Aligns with standard BLS12-381 implementations

## 📋 Requirements Summary

### Spec 1: BLS Signature Scheme (Contract)
- ✅ MODIFIED: Accept G1 public keys (48 or 96 bytes)
- ✅ MODIFIED: Accept G2 signatures (192 bytes)
- ✅ MODIFIED: Use inverted BLS pairing verification
- ✅ MODIFIED: Derive address from G1 keys
- ✅ MODIFIED: Hash messages to G2 curve
- ❌ REMOVED: G2 public key requirement
- ❌ REMOVED: G1 signature requirement

### Spec 2: SDK Contract Compatibility
- ✅ ADDED: Native BLS keypair generation
- ✅ ADDED: BLS message signing
- ✅ ADDED: Signature format conversion
- ✅ MODIFIED: Integration tests use fresh keys
- ✅ UNCHANGED: EIP-712 hash generation
- ✅ UNCHANGED: Non-BLS features

## 🔍 Critical Investigation Items

1. **BLS2 Library Pairing Support** (CRITICAL)
   - Does `@onematrix/bls-solidity` support inverted pairing?
   - Can we use `e(pubkey_G1, message_G2) = e(G1_gen, sig_G2)`?
   - Status: NEEDS INVESTIGATION

2. **Gas Cost Impact**
   - G2 operations are typically more expensive
   - Benchmark: Current vs Proposed scheme
   - Status: NEEDS BENCHMARKING

3. **Signature Format**
   - SDK generates compressed G2 (96 bytes)
   - Contract may need uncompressed (192 bytes)
   - Solution: Format conversion layer
   - Status: NEEDS IMPLEMENTATION

## 📈 Implementation Phases

### Phase 1: Investigation & Validation
- [ ] BLS2 library pairing capabilities
- [ ] G2 message hashing support
- [ ] Gas cost benchmarking
- [ ] SDK signature format testing

### Phase 2: Contract Prototype
- [ ] Test contract with inverted scheme
- [ ] G1 address derivation
- [ ] Inverted pairing verification
- [ ] Message hashing to G2

### Phase 3: Test Data Generation
- [ ] Generate fresh BLS test vectors
- [ ] Create test vector JSON
- [ ] Validate test vectors

### Phase 4: Contract Implementation
- [ ] Update `changeOwnerWithPubkey()`
- [ ] Add helper functions
- [ ] Update error messages

### Phase 5: Testing
- [ ] Unit tests for contract
- [ ] Integration tests SDK ↔ Contract
- [ ] Update existing BLS tests
- [ ] Gas benchmarking

### Phase 6: SDK Integration
- [ ] Update EthrDidController
- [ ] Add BLS helper functions
- [ ] Update SDK tests

### Phase 7: Documentation
- [ ] Contract documentation
- [ ] SDK documentation
- [ ] Migration guide

### Phase 8: Deployment & Validation
- [ ] Deploy to testnet
- [ ] Test on testnet
- [ ] SDK integration validation
- [ ] Prepare for mainnet

## ⚠️ Breaking Changes

**Impact**: HIGH

- All existing BLS signatures become invalid
- Contract must be redeployed
- Test data must be regenerated
- Migration required for existing BLS users

**Mitigation**:
- Deploy as new contract version
- Provide clear migration documentation
- Support period for old contract (if applicable)

## ✅ Success Criteria

1. SDK generates fresh BLS keypairs with `@noble/curves/bls12-381` ✓
2. Generated keys work with contract's `changeOwnerWithPubkey()` ✓
3. All integration tests pass with new scheme ✓
4. Gas costs remain reasonable ✓
5. Clear migration documentation provided ✓

## 🔗 Related Documentation

- `BLS_INTEGRATION_VERIFIED.md` - Current integration status (9/9 tests passing)
- `BLS_KEY_FORMAT_ANALYSIS.md` - G1/G2 mismatch analysis
- `BLS_SCHEME_COMPARISON.txt` - Visual comparison diagrams
- `PROPOSAL_INVERT_BLS_SCHEME.md` - Original proposal document

## 📞 Next Steps

1. **Review this proposal** - Gather feedback from stakeholders
2. **Investigate BLS2 library** - Confirm pairing support (CRITICAL)
3. **Approve or request changes** - Decision point
4. **Begin Phase 1** - Investigation and validation tasks
5. **Use `/openspec apply invert-bls-scheme`** - When ready to implement

## 📝 Notes

- This proposal is for **ethr-did-registry contract** changes
- SDK changes are complementary and enable the full workflow
- Both components must be updated together for the feature to work
- The proposal is validated and ready for review/approval

---

**Created**: 2025-12-25
**Status**: Draft (awaiting approval)
**Validation**: ✅ PASSED (openspec validate --strict)
