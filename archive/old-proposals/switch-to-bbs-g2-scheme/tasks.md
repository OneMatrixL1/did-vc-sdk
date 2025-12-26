# Tasks: Switch to BBS G2 Keypair Scheme

## Phase 1: Contract Updates

### Task 1.1: Create G2 Key Expansion Function
- [ ] Implement `expandG2PublicKey()` in contract (or accept only uncompressed)
- [ ] OR: Accept 192-byte uncompressed G2 keys only (simpler approach)
- [ ] Update validation to require `publicKey.length == 192`
- [ ] Test with sample compressed/uncompressed G2 keys

**Files**:
- `/Users/one/workspace/ethr-did-registry/contracts/EthereumDIDRegistry.sol`

**Validation**: Unit test verifying 192-byte G2 key acceptance

---

### Task 1.2: Create `hashToPointG1()` Function
- [ ] Implement `hashToPointG1()` using EIP-2537 precompile `0x10`
- [ ] Follow same pattern as existing `hashToPointG2()`
- [ ] Use `BLS12_MAP_FP_TO_G1` and `BLS12_G1ADD` precompiles
- [ ] Test with sample messages

**Files**:
- `/Users/one/workspace/ethr-did-registry/contracts/EthereumDIDRegistry.sol`

**Validation**: Unit test verifying G1 point hashing produces valid points

---

### Task 1.3: Create `deriveAddressFromG2()` Function
- [ ] Implement `deriveAddressFromG2(bytes calldata publicKeyBytes)`
- [ ] Require `publicKeyBytes.length == 192`
- [ ] Return `address(uint160(uint256(keccak256(publicKeyBytes))))`
- [ ] Mark as `internal pure`
- [ ] Test with known G2 key → address mappings

**Files**:
- `/Users/one/workspace/ethr-did-registry/contracts/EthereumDIDRegistry.sol`

**Validation**: Unit test with test vectors from `generate-bbs-keypair.ts`

---

### Task 1.4: Update `changeOwnerWithPubkey()` Function
- [ ] Change `publicKey` parameter validation to `require(publicKey.length == 192)`
- [ ] Change `signature` parameter validation to `require(signature.length == 48 || signature.length == 96)`
- [ ] Replace `deriveAddressFromG1(publicKey)` with `deriveAddressFromG2(publicKey)`
- [ ] Unmarshal G2 public key: `BLS2.PointG2 memory pubkey = BLS2.g2Unmarshal(publicKey)`
- [ ] Hash message to G1: `BLS2.PointG1 memory message = hashToPointG1("BLS_DST", ...)`
- [ ] Unmarshal G1 signature with compression support
- [ ] Use `BLS2.verifySingle(sig, pubkey, message)` for verification
- [ ] Update all comments to reflect G2/G1 (not G1/G2)

**Files**:
- `/Users/one/workspace/ethr-did-registry/contracts/EthereumDIDRegistry.sol`

**Validation**: Integration test with SDK-generated BBS keypairs

---

### Task 1.5: Remove Obsolete Functions (Optional)
- [ ] Remove or deprecate `deriveAddressFromG1()`
- [ ] Remove or deprecate `verifyInvertedPairing()`
- [ ] Remove or deprecate `hashToPointG2()` if not used elsewhere
- [ ] Update documentation

**Files**:
- `/Users/one/workspace/ethr-did-registry/contracts/EthereumDIDRegistry.sol`

**Validation**: Contract still compiles, tests still pass

---

## Phase 2: SDK Core Utilities (ethr-did-resolver)

### Task 2.1: Add G2 Expansion Function
- [ ] Create `expandG2PublicKey(compressed: Uint8Array): Uint8Array` in `bls-utils.ts`
- [ ] Use `bls.G2.ProjectivePoint.fromHex(compressed)`
- [ ] Use `point.toRawBytes(false)` for uncompressed format
- [ ] Validate input: 96 bytes
- [ ] Validate output: 192 bytes
- [ ] Add unit tests

**Files**:
- `packages/ethr-did-resolver/src/bls-utils.ts`

**Validation**: Unit test verifying 96B → 192B expansion matches test vectors

---

### Task 2.2: Update `deriveAddressFromG1` to `deriveAddressFromG2`
- [ ] Rename function to `deriveAddressFromG2`
- [ ] Accept G2 public keys (96B compressed OR 192B uncompressed)
- [ ] If 96B: expand to 192B first
- [ ] If 192B: use directly
- [ ] Derive address: `keccak256(uncompressed192B)[last 20 bytes]`
- [ ] Update all callers
- [ ] Add unit tests with BBS test vectors

**Files**:
- `packages/ethr-did-resolver/src/helpers.ts`

**Validation**: Test with known BBS keypair addresses

---

### Task 2.3: Update BLS Utils to Generate BBS Keypairs
- [ ] Update `generateBlsKeypair()` → `generateBbsKeypair()`
- [ ] Generate G2 public keys (96B compressed)
- [ ] Return G2 public key in both compressed and uncompressed formats
- [ ] Update signature generation to use G1 (not G2)
- [ ] Remove old BLS G1 generation code
- [ ] Add comprehensive tests

**Files**:
- `packages/ethr-did-resolver/src/bls-utils.ts`

**Validation**: Generated keypairs work with BBS signature verification

---

### Task 2.4: Update Signature Functions
- [ ] Update `signWithBls()` → `signWithBbs()`
- [ ] Generate G1 signatures (not G2)
- [ ] Keep G1 signatures compressed (48B or 96B)
- [ ] Remove G2 signature expansion code
- [ ] Update verification to use BBS pairing
- [ ] Add unit tests

**Files**:
- `packages/ethr-did-resolver/src/bls-utils.ts`

**Validation**: Signatures verify correctly with BBS scheme

---

## Phase 3: SDK Credential Module (credential-sdk)

### Task 3.1: Update `bbsPublicKeyToAddress()`
- [ ] Update to use **uncompressed** G2 keys for address derivation
- [ ] Accept 96B compressed G2 keys as input (backward compat)
- [ ] Expand to 192B uncompressed internally
- [ ] Derive address from 192B: `keccak256(uncompressed)[last 20 bytes]`
- [ ] Update documentation
- [ ] Add tests comparing old vs new addresses

**Files**:
- `packages/credential-sdk/src/modules/ethr-did/utils.js`

**Validation**: Test with BBS keypairs, verify consistent addresses

---

### Task 3.2: Update BBS Keypair Generation
- [ ] Verify `Bls12381BBSKeyPairDock2023` generates G2 public keys
- [ ] Ensure `publicKeyBuffer` is 96 bytes (compressed G2)
- [ ] Update any documentation referring to key sizes
- [ ] Add tests

**Files**:
- `packages/credential-sdk/src/vc/crypto/Bls12381BBSKeyPairDock2023.js`

**Validation**: Keypairs work with VC signing and DID ownership

---

### Task 3.3: Update ethr-did Module
- [ ] Update DID document construction to use G2 public keys
- [ ] Ensure verification methods reference BBS keys correctly
- [ ] Update `createNewDID()` to use BBS keypairs
- [ ] Update `createDualAddressDID()` if needed
- [ ] Add integration tests

**Files**:
- `packages/credential-sdk/src/modules/ethr-did/module.js`

**Validation**: DIDs created with BBS keypairs resolve correctly

---

## Phase 4: Testing & Validation

### Task 4.1: Update E2E Tests (ethr-did-resolver)
- [ ] Update `e2e-bls-sdk-complete.test.ts` → rename to `e2e-bbs-sdk-complete.test.ts`
- [ ] Change expectations: 192B public keys, 48B/96B signatures
- [ ] Update address derivation tests
- [ ] Update contract interaction tests
- [ ] Ensure no mocking, real on-chain verification
- [ ] All 9+ tests must pass

**Files**:
- `packages/ethr-did-resolver/src/__tests__/e2e-bbs-sdk-complete.test.ts`

**Validation**: 100% passing tests, real blockchain verification

---

### Task 4.2: Update Credential SDK Tests
- [ ] Update BBS VC issuance tests
- [ ] Verify same keypair works for VC signing and DID ownership
- [ ] Test address consistency across operations
- [ ] Update address derivation tests
- [ ] Add migration tests (old format → new format)

**Files**:
- `packages/credential-sdk/tests/ethr-vc-issuance-bbs.test.js`
- `packages/credential-sdk/tests/ethr-did-bbs.test.js`

**Validation**: All BBS-related tests pass

---

### Task 4.3: Contract Integration Tests
- [ ] Deploy fresh contract with G2 support
- [ ] Test SDK → Contract flow with BBS keypairs
- [ ] Verify on-chain state changes
- [ ] Test signature verification on-chain
- [ ] Benchmark gas costs
- [ ] Compare with previous BLS G1 costs

**Files**:
- `packages/ethr-did-resolver/src/__tests__/changeOwnerWithPubkey-integration.test.ts`

**Validation**: On-chain verification successful, gas costs acceptable

---

### Task 4.4: Address Derivation Consistency Tests
- [ ] Create test suite verifying address consistency
- [ ] Test: BBS keypair → same address for VC and DID
- [ ] Test: Compressed vs uncompressed derivation matches
- [ ] Test: SDK address == Contract address
- [ ] Document test vectors

**Files**:
- New test file: `packages/credential-sdk/tests/bbs-address-consistency.test.js`

**Validation**: All consistency checks pass

---

## Phase 5: Documentation & Migration

### Task 5.1: Update Technical Documentation
- [ ] Update README files to reflect BBS G2 scheme
- [ ] Update API documentation for changed functions
- [ ] Add BBS keypair generation examples
- [ ] Document address derivation algorithm
- [ ] Update architecture diagrams if any

**Files**:
- `packages/ethr-did-resolver/README.md`
- `packages/credential-sdk/README.md`
- `docs/` folder files

**Validation**: Documentation review, no broken links

---

### Task 5.2: Create Migration Guide
- [ ] Document the breaking change clearly
- [ ] Explain old vs new address derivation
- [ ] Provide migration script/tool
- [ ] Show before/after examples
- [ ] List all affected APIs
- [ ] Provide troubleshooting section

**Files**:
- `MIGRATION_BBS_G2.md` (new file)
- `CHANGELOG.md`

**Validation**: Migration guide tested with sample user

---

### Task 5.3: Update CHANGELOG
- [ ] Add breaking change notice
- [ ] List all modified functions
- [ ] Document migration path
- [ ] Version bump (major version)
- [ ] Link to migration guide

**Files**:
- `CHANGELOG.md`
- `package.json` (version bump)

**Validation**: Changelog follows semantic versioning

---

### Task 5.4: Create Example Code
- [ ] Create end-to-end example using BBS keypairs
- [ ] Show: Generate keypair → Issue VC → Change DID owner
- [ ] Demonstrate address consistency
- [ ] Add to examples/ folder
- [ ] Include comments explaining each step

**Files**:
- `examples/bbs-unified-keypair.js` (new file)

**Validation**: Example runs successfully, produces expected output

---

## Phase 6: Cleanup & Finalization

### Task 6.1: Remove Old BLS G1 Code
- [ ] Remove old `generateBlsKeypair()` if fully replaced
- [ ] Remove old `deriveAddressFromG1()` if not needed
- [ ] Remove BLS G1 test files
- [ ] Update imports across codebase
- [ ] Ensure no dead code remains

**Files**:
- `packages/ethr-did-resolver/src/bls-utils.ts`
- `packages/ethr-did-resolver/src/helpers.ts`

**Validation**: No broken imports, all tests pass

---

### Task 6.2: Final Integration Test
- [ ] Run full test suite across all packages
- [ ] Verify: credential-sdk tests pass
- [ ] Verify: ethr-did-resolver tests pass
- [ ] Verify: contract integration tests pass
- [ ] Verify: no regressions in other modules
- [ ] Test on real blockchain (vietchain/testnet)

**Validation**: 100% test pass rate, no regressions

---

### Task 6.3: Deployment Preparation
- [ ] Build all packages
- [ ] Generate type definitions
- [ ] Run linting and formatting
- [ ] Update package versions
- [ ] Tag release
- [ ] Prepare release notes

**Validation**: Clean build, no errors, ready for release

---

## Summary

**Total Tasks**: 28
**Estimated Time**: 1-2 weeks
**Breaking Changes**: YES (address derivation)
**Deployment**: Requires major version bump

## Dependencies Between Tasks

**Sequence**:
1. Phase 1 (Contract) must complete before Phase 4.3
2. Phase 2 (SDK Core) must complete before Phase 3
3. Phase 3 must complete before Phase 4.1, 4.2
4. Phase 4 must complete before Phase 5
5. Phase 5 must complete before Phase 6

**Parallelizable**:
- Tasks within Phase 1 can run in parallel (1.1-1.5)
- Tasks within Phase 2 can run in parallel (2.1-2.4)
- Tasks within Phase 4 can run in parallel after dependencies met
- Documentation tasks (5.1-5.4) can run in parallel
