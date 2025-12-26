# Tasks: Invert BLS Signature Scheme

## Phase 1: Investigation & Validation

- [x] **Investigate BLS2 library pairing support**
  - [x] Read @onematrix/bls-solidity source code for pairing functions
  - [x] Confirm existence of inverted pairing verification
  - [x] Document available pairing verification methods
  - [x] Identify if custom implementation needed

- [x] **Verify G2 message hashing capability**
  - [x] Check if `hashToPointG2()` exists in BLS2 library
  - [x] Test message to G2 point conversion
  - [x] Document hashing interface and parameters

- [ ] **Benchmark gas costs**
  - [ ] Deploy test contract with current scheme (G2 pubkey + G1 sig)
  - [ ] Deploy test contract with proposed scheme (G1 pubkey + G2 sig)
  - [ ] Measure gas costs for both schemes
  - [ ] Compare and document results
  - [ ] Determine if gas increase is acceptable

- [x] **Test @noble/curves signature formats**
  - [x] Generate compressed G2 signature (96 bytes)
  - [x] Investigate uncompressed G2 format (192 bytes)
  - [x] Test conversion between compressed/uncompressed
  - [x] Document SDK signature generation capabilities

**Phase 1 Result**: All critical investigations complete. See PHASE_1_INVESTIGATION.md for detailed findings.

## Phase 2: Contract Prototype

- [x] **Create test contract with inverted scheme**
  - [x] Copy EthereumDIDRegistry to test environment
  - [x] Update `changeOwnerWithPubkey()` function signature
  - [x] Implement G1 public key unmarshaling (compressed + uncompressed)
  - [x] Implement G2 signature unmarshaling
  - [ ] Deploy to local testnet (Phase 3)

- [x] **Implement address derivation for G1 keys**
  - [x] Create `deriveAddressFromG1()` helper function
  - [x] Handle compressed G1 (48 bytes) format
  - [x] Handle uncompressed G1 (96 bytes) format
  - [x] Ensure consistent address derivation across formats
  - [ ] Add unit tests for address derivation (Phase 3)

- [x] **Implement inverted pairing verification**
  - [x] Use custom pairing check using EIP-2537 precompiles
  - [x] Verify pairing equation: e(pubkey_G1, message_G2) = e(G1_gen, sig_G2)
  - [ ] Add unit tests for pairing verification (Phase 3)

- [x] **Update message hashing**
  - [x] Create `hashToPointG2()` (G2 instead of G1)
  - [x] Verify domain separation tag ("BLS_DST") usage
  - [x] Implement hash-to-curve using RFC 9380 approach
  - [ ] Add unit tests for message hashing (Phase 3)

**Phase 2 Result**: Contract implementation complete. See IMPLEMENTATION_SUMMARY.md for details.

## Phase 3: Test Data Generation

- [ ] **Generate fresh BLS test vectors with SDK**
  - [ ] Use `@noble/curves/bls12-381` to generate keypairs
  - [ ] Create secret key (32 bytes)
  - [ ] Derive G1 public key (48 bytes compressed)
  - [ ] Generate test message hash
  - [ ] Sign with BLS to get G2 signature (96 bytes compressed)
  - [ ] Expand signature to uncompressed if needed (192 bytes)
  - [ ] Document test vector generation process

- [ ] **Create test vector JSON file**
  - [ ] Format: `{ secretKey, publicKey, signature, message, expectedAddress }`
  - [ ] Include multiple test cases
  - [ ] Add edge cases (different message lengths, etc.)
  - [ ] Save to `test/data/bls_signature_inverted.json`

- [ ] **Validate test vectors**
  - [ ] Verify signature with SDK's `bls.verify()`
  - [ ] Derive address and check against expected
  - [ ] Ensure all test vectors are cryptographically valid

## Phase 4: Contract Implementation

- [ ] **Update EthereumDIDRegistry.sol**
  - [ ] Modify `changeOwnerWithPubkey()` function
  - [ ] Update parameter validation (accept 48, 96, or 192 byte inputs)
  - [ ] Replace G2 unmarshaling with G1 unmarshaling
  - [ ] Replace G1 signature with G2 signature unmarshaling
  - [ ] Update address derivation logic
  - [ ] Update pairing verification

- [ ] **Add helper functions**
  - [ ] `unmarshalG1(bytes calldata)` - handles compressed/uncompressed
  - [ ] `deriveAddressFromG1(bytes calldata)` - address from G1 key
  - [ ] `verifyInvertedPairing(PointG1, PointG2, PointG2)` - verification

- [ ] **Update error messages**
  - [ ] Change "unsupported_pubkey_type" to specific length errors
  - [ ] Add "invalid_pubkey_length" for wrong G1 sizes
  - [ ] Add "invalid_signature_length" for wrong G2 sizes
  - [ ] Ensure error messages are descriptive

## Phase 5: Testing

- [ ] **Unit tests for contract changes**
  - [ ] Test G1 compressed public key (48 bytes)
  - [ ] Test G1 uncompressed public key (96 bytes)
  - [ ] Test G2 signature (192 bytes)
  - [ ] Test address derivation consistency
  - [ ] Test invalid public key lengths
  - [ ] Test invalid signature lengths
  - [ ] Test pairing verification with valid signatures
  - [ ] Test pairing verification rejects invalid signatures

- [ ] **Integration tests: SDK ↔ Contract**
  - [ ] Generate fresh keypair in SDK
  - [ ] Sign message with SDK
  - [ ] Call contract's `changeOwnerWithPubkey()` with SDK-generated data
  - [ ] Verify transaction succeeds
  - [ ] Verify owner changed on-chain
  - [ ] Test end-to-end workflow

- [ ] **Update existing BLS tests**
  - [ ] Replace old test vectors with new ones
  - [ ] Update `bls-owner-change.test.ts`
  - [ ] Update `bls-signature.test.ts`
  - [ ] Ensure all tests pass with new scheme

- [ ] **Gas benchmarking**
  - [ ] Measure gas for compressed G1 pubkey (48 bytes)
  - [ ] Measure gas for uncompressed G1 pubkey (96 bytes)
  - [ ] Compare with old scheme
  - [ ] Document results in test output

## Phase 6: SDK Integration

- [ ] **Update SDK's EthrDidController**
  - [ ] Remove dependency on external BLS signing
  - [ ] Add native BLS key generation method
  - [ ] Add native BLS signing method
  - [ ] Ensure `createChangeOwnerWithPubkeyHash()` still works
  - [ ] Add helper for signature expansion if needed

- [ ] **Add SDK helper functions**
  - [ ] `generateBlsKeypair()` - returns { secretKey, publicKey }
  - [ ] `signWithBls(message, secretKey)` - returns signature
  - [ ] `expandBlsSignature(compressed)` - if needed for 96→192 bytes

- [ ] **Update SDK tests**
  - [ ] Update `e2e-bls-verified.test.ts` to use fresh keys
  - [ ] Remove reliance on pre-signed test vectors
  - [ ] Add test for fresh key generation
  - [ ] Add test for native signing
  - [ ] Ensure all 9 tests still pass

## Phase 7: Documentation

- [ ] **Update contract documentation**
  - [ ] Document new `changeOwnerWithPubkey()` signature
  - [ ] Add examples with G1 keys and G2 signatures
  - [ ] Document supported key formats (compressed/uncompressed)
  - [ ] Add migration guide from old scheme

- [ ] **Update SDK documentation**
  - [ ] Document BLS key generation API
  - [ ] Add example: generate keypair → sign → call contract
  - [ ] Update `BLS_INTEGRATION_VERIFIED.md`
  - [ ] Update `BLS_KEY_FORMAT_ANALYSIS.md`

- [ ] **Create migration guide**
  - [ ] Document breaking changes
  - [ ] Provide migration steps for existing users
  - [ ] Include code examples before/after
  - [ ] Note that old signatures are invalid

## Phase 8: Deployment & Validation

- [ ] **Deploy to testnet**
  - [ ] Deploy updated AdminManagement contract
  - [ ] Deploy updated EthereumDIDRegistry contract
  - [ ] Verify contract on block explorer

- [ ] **Test on testnet**
  - [ ] Run integration tests against deployed contract
  - [ ] Generate fresh keypair and test end-to-end
  - [ ] Verify gas costs on real network
  - [ ] Test edge cases

- [ ] **SDK integration validation**
  - [ ] Update SDK contract addresses for testnet
  - [ ] Run full SDK test suite against testnet
  - [ ] Verify all features work
  - [ ] Document any issues

- [ ] **Prepare for mainnet** (if applicable)
  - [ ] Security review of contract changes
  - [ ] Final gas optimization review
  - [ ] Prepare deployment scripts
  - [ ] Document deployment process

---

**Total Tasks**: 68
**Estimated Effort**: Medium-High (requires contract changes + SDK integration)
**Critical Path**: Investigation → Prototype → Contract Implementation → Testing
