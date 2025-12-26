# Implementation Tasks

## 1. Update BBS Public Key Serialization
- [ ] 1.1 Modify `Bls12381BBSKeyPairDock2023.js` to extract uncompressed G2 (192 bytes)
- [ ] 1.2 Investigate `@docknetwork/crypto-wasm-ts` API for uncompressed serialization
- [ ] 1.3 Update `DockCryptoKeyPair.js` to handle 192-byte public key buffers
- [ ] 1.4 Ensure backward compatibility or clear migration path

## 2. Update Address Derivation
- [ ] 2.1 Update `bbsPublicKeyToAddress()` in `utils.js` to expect 192 bytes
- [ ] 2.2 Update validation from `!== 96` to `!== 192`
- [ ] 2.3 Update `publicKeyToAddress()` to handle 192-byte G2 keys
- [ ] 2.4 Update documentation comments to reflect uncompressed format

## 3. Update Recovery Method
- [ ] 3.1 Update `Bls12381BBSRecoveryMethod2023.js` public key handling
- [ ] 3.2 Ensure signature verification uses 192-byte keys
- [ ] 3.3 Update key instantiation: `new BBSPublicKey(...)` with correct format

## 4. Update Documentation
- [ ] 4.1 Update all "96 bytes compressed G2" references to "192 bytes uncompressed G2"
- [ ] 4.2 Update `ethr-bbs-recovery-verification.md`
- [ ] 4.3 Update `cto-report-bbs-ethr-did.md`
- [ ] 4.4 Update `ethr-bbs-flow-data-examples.md`
- [ ] 4.5 Create migration guide for address changes

## 5. Update Tests
- [ ] 5.1 Regenerate BBS test keypairs with uncompressed public keys
- [ ] 5.2 Update `BBS_KEYPAIR_TEST_DATA.md` (if exists)
- [ ] 5.3 Update all BBS-related unit tests
- [ ] 5.4 Update integration tests with contract
- [ ] 5.5 Verify address derivation matches contract expectations

## 6. Validation
- [ ] 6.1 Run all BBS credential tests
- [ ] 6.2 Test end-to-end with contract signature verification
- [ ] 6.3 Verify public key → address derivation consistency
- [ ] 6.4 Test backward compatibility handling (if applicable)
- [ ] 6.5 Run full test suite: `yarn test`
