# Tasks: Move BLS Owner Change to ethr-did Libraries

## Phase 1: ethr-did-resolver Foundation

1. **Add BLS public key address derivation helper**
   - Create `publicKeyToAddress()` in `helpers.ts`
   - Support 96-byte BLS12-381 G2 public keys (keccak256 hash)
   - Add unit tests for address derivation
   - Validation: Test vectors match expected addresses

2. **Add changeOwnerWithPubkey contract interface**
   - Define contract function signature in controller
   - Add `pubkeyNonce(address)` view function interface
   - Validation: TypeScript compilation succeeds

3. **Implement createChangeOwnerWithPubkeyHash()**
   - Add method to `EthrDidController`
   - Query `pubkeyNonce` from contract
   - Construct EIP-712 typed data structure
   - Return hash ready for signing
   - Validation: Unit test produces correct EIP-712 hash

4. **Implement changeOwnerWithPubkey() in controller**
   - Add method to `EthrDidController`
   - Accept `newOwner`, `publicKey`, `signature` parameters
   - Derive signer address from public key
   - Fetch current nonce
   - Encode and submit transaction
   - Wait for receipt and return
   - Validation: Integration test with mock contract

## Phase 2: ethr-did Wrapper

5. **Add changeOwnerWithPubkey() to EthrDID class**
   - Create method matching changeOwner() pattern
   - Delegate to `controller.changeOwnerWithPubkey()`
   - Handle errors consistently with existing methods
   - Validation: TypeScript types are correct

6. **Add TypeScript types for BLS signatures**
   - Define signature type (Uint8Array or hex string)
   - Export public key types
   - Update IConfig if needed
   - Validation: TypeScript compilation with strict mode

7. **Write unit tests for EthrDID.changeOwnerWithPubkey()**
   - Test successful owner change
   - Test error handling (invalid signature, wrong owner, etc.)
   - Mock controller interactions
   - Validation: 100% code coverage for new method

## Phase 3: Integration Tests

8. **Create integration test with local registry**
   - Deploy test EthereumDIDRegistry with changeOwnerWithPubkey
   - Generate BLS keypair
   - Test full owner change flow
   - Verify nonce increment
   - Verify owner updated on-chain
   - Validation: Test passes against real contract

9. **Test BLS signature verification on-chain**
   - Use real BLS signing (via credential-sdk initially)
   - Submit changeOwnerWithPubkey transaction
   - Verify signature validates correctly
   - Validation: Transaction succeeds without revert

## Phase 4: credential-sdk Simplification

10. **Refactor EthrDIDModule.changeOwnerWithPubkey()**
    - Remove direct contract interaction code
    - Remove nonce fetching logic
    - Use `ethrDid.changeOwnerWithPubkey()` from library
    - Keep BLS signing with `signWithBLSKeypair()`
    - Validation: Existing tests still pass

11. **Update credential-sdk to use new ethr-did methods**
    - Update imports to use ethr-did exports
    - Remove duplicated EIP-712 construction if moved to ethr-did
    - Validation: No regression in credential-sdk tests

12. **Clean up redundant utility functions**
    - Evaluate if `createChangeOwnerWithPubkeyTypedData` stays in credential-sdk or moves
    - Remove any dead code from refactoring
    - Validation: No unused imports or functions

## Phase 5: Documentation & Polish

13. **Add JSDoc documentation to new methods**
    - Document all public methods in ethr-did
    - Include examples for changeOwnerWithPubkey
    - Document parameters, return types, and errors
    - Validation: JSDoc generates clean API docs

14. **Update ethr-did README**
    - Add BLS owner change example
    - Explain public key requirements
    - Link to credential-sdk for BLS signing
    - Validation: README is clear and accurate

15. **Add CHANGELOG entries**
    - Add entry in ethr-did CHANGELOG
    - Add entry in ethr-did-resolver CHANGELOG
    - Add entry in credential-sdk CHANGELOG (refactoring note)
    - Validation: Follows conventional commits format

16. **Version bump preparation**
    - Update package.json versions
    - Ensure peer dependencies are correct
    - Validation: `yarn install` succeeds with new versions

## Phase 6: Testing & Validation

17. **Run full test suite**
    - ethr-did tests pass
    - ethr-did-resolver tests pass
    - credential-sdk tests pass
    - Validation: All tests green

18. **Manual integration test**
    - Deploy registry to test network
    - Create DID with BLS owner
    - Change owner using credential-sdk
    - Verify on-chain state
    - Validation: Full flow works end-to-end

19. **TypeScript compilation check**
    - Build all three packages
    - Verify no type errors
    - Check generated .d.ts files
    - Validation: `yarn build` succeeds for all packages

20. **Lint and format**
    - Run ESLint on all modified files
    - Fix any linting errors
    - Validation: `yarn lint` passes

## Dependencies & Parallelization

**Sequential dependencies:**
- Phase 1 → Phase 2 → Phase 4 (ethr-did-resolver must be done before ethr-did, which must be done before credential-sdk refactor)
- Phase 3 (integration tests) depends on Phase 1-2
- Phase 6 depends on all previous phases

**Can be parallelized:**
- Within Phase 1: tasks 1-2 can be done in parallel
- Phase 5 (documentation) can start once Phase 4 is complete
- Integration tests (Phase 3) can be written while Phase 2 is in progress

**Critical path:**
Phase 1 (tasks 1-4) → Phase 2 (tasks 5-7) → Phase 4 (tasks 10-12) → Phase 6 (tasks 17-20)
