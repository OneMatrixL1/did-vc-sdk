# Switch to BBS G2 Keypair Scheme - OpenSpec Proposal

**Status**: ✅ VALIDATED
**Change ID**: `switch-to-bbs-g2-scheme`
**Created**: 2025-12-25

## Quick Summary

This proposal unifies the SDK to use **BBS G2 keypairs** for both:
1. Verifiable Credential signing
2. DID ownership and control

**Key Benefit**: Single keypair, consistent addresses, simpler user experience.

## What's Included

### 📄 Core Documents

1. **proposal.md** - Main proposal with problem statement, solution, and architectural decisions
2. **design.md** - Technical design document with data flows, security considerations, and performance analysis
3. **tasks.md** - Detailed implementation tasks (28 tasks across 6 phases)

### 📋 Specifications

1. **bbs-keypair-generation** - Keypair generation, expansion, signing, and verification
2. **address-derivation** - Address derivation from G2 public keys (uncompressed)
3. **contract-verification** - Contract-side BBS signature verification

## Key Changes

### Breaking Changes

⚠️ **Address Derivation Algorithm Changes**:
- **Old**: `keccak256(96-byte compressed G1)` or `keccak256(96-byte compressed G2)`
- **New**: `keccak256(192-byte uncompressed G2)`

**Impact**: Existing addresses will change. Users must regenerate addresses.

### Components Affected

- **Contract** (`EthereumDIDRegistry.sol`):
  - New: `hashToPointG1()`, `deriveAddressFromG2()`, `expandG2PublicKey()`
  - Modified: `changeOwnerWithPubkey()` to accept G2 keys + G1 signatures
  - Removed: `verifyInvertedPairing()`, old BLS G1 logic

- **SDK Core** (`ethr-did-resolver`):
  - New: `generateBbsKeypair()`, `expandG2PublicKey()`, `deriveAddressFromG2()`
  - Modified: `signWithBbs()`, `verifyBbsSignature()`
  - Removed: Old BLS G1 generation and utilities

- **Credential SDK**:
  - Modified: `bbsPublicKeyToAddress()` to use uncompressed keys
  - Modified: ethr-did module to use BBS keypairs

## Implementation Plan

### Phase 1: Contract Updates (5 tasks)
- Implement G2 key handling
- Implement `hashToPointG1()`
- Implement `deriveAddressFromG2()`
- Update `changeOwnerWithPubkey()`
- Remove obsolete functions

### Phase 2: SDK Core (4 tasks)
- Add G2 expansion
- Update address derivation
- Update keypair generation
- Update signature functions

### Phase 3: Credential SDK (3 tasks)
- Update `bbsPublicKeyToAddress()`
- Verify BBS keypair generation
- Update ethr-did module

### Phase 4: Testing (4 tasks)
- E2E tests
- Credential SDK tests
- Contract integration tests
- Address consistency tests

### Phase 5: Documentation (4 tasks)
- Technical docs
- Migration guide
- CHANGELOG
- Example code

### Phase 6: Cleanup (3 tasks)
- Remove old code
- Final integration test
- Deployment preparation

**Total**: 28 tasks, estimated 1-2 weeks

## Validation

```bash
✅ openspec validate switch-to-bbs-g2-scheme --strict
```

**Result**: Valid ✓

## Next Steps

To implement this proposal:

```bash
# Review the proposal
openspec show switch-to-bbs-g2-scheme

# When approved, apply the changes
openspec apply switch-to-bbs-g2-scheme
```

## Files Structure

```
openspec/changes/switch-to-bbs-g2-scheme/
├── README.md              # This file
├── proposal.md            # Main proposal
├── design.md              # Technical design
├── tasks.md               # Implementation tasks
└── specs/                 # Capability specifications
    ├── bbs-keypair-generation/
    │   └── spec.md
    ├── address-derivation/
    │   └── spec.md
    └── contract-verification/
        └── spec.md
```

## Related Changes

- `invert-bls-scheme` - Will be superseded by this change
- `simplify-bls-eip712` - Will be incorporated into this change

## Migration Guide

See the full migration guide in `proposal.md` section "Migration Path".

**Key Points**:
1. This is a **breaking change** (major version bump required)
2. Addresses WILL change - users must regenerate
3. Migration tool will be provided
4. Clear documentation in CHANGELOG

## Questions?

Review the full proposal documents for detailed information:
- **Architecture**: See `design.md`
- **Tasks**: See `tasks.md`
- **Requirements**: See `specs/*/spec.md`
