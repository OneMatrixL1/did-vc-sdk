# Change: Switch BBS Signatures to Uncompressed G2 Public Keys

## Why

The SDK currently uses **96-byte compressed G2 public keys** from `@docknetwork/crypto-wasm-ts` for BBS signatures (2023 scheme). However, the Ethereum smart contract's BLS verification precompiles (`BLS2.g2Unmarshal`) require **192-byte uncompressed G2 public keys**.

This incompatibility means:
- ❌ SDK-generated BBS public keys cannot be validated by the contract
- ❌ Address derivation from public keys uses wrong format (compressed vs uncompressed)
- ❌ Contract signature verification will fail for SDK-generated credentials
- ❌ Integration between SDK and on-chain verification is broken

The contract explicitly validates:
- Line 425: `require(signature.length == 192, "invalid_signature_length")`
- Line 94, 443: `BLS2.g2Unmarshal(publicKeyBytes)` expects 192-byte uncompressed format

## What Changes

- Update SDK to use **192-byte uncompressed G2 public keys** for BBS 2023 scheme
- Update public key extraction to serialize uncompressed format from `BBSPublicKey`
- Update address derivation (`bbsPublicKeyToAddress`) to hash **192-byte uncompressed** keys
- Update all references from "96 bytes compressed G2" to "192 bytes uncompressed G2"
- Update test data and documentation to reflect new format
- **BREAKING**: Existing addresses derived from compressed keys will change

## Impact

**Affected Specs:**
- `bbs-signatures` (if exists) - Updated public key format requirements
- `ethr-did-bls` (if exists) - Updated key handling and address derivation

**Affected Code:**
- `packages/credential-sdk/src/vc/crypto/Bls12381BBSKeyPairDock2023.js` - Key serialization
- `packages/credential-sdk/src/vc/crypto/Bls12381BBSRecoveryMethod2023.js` - Public key handling
- `packages/credential-sdk/src/modules/ethr-did/utils.js` - Address derivation and documentation
- `packages/credential-sdk/src/vc/crypto/common/DockCryptoKeyPair.js` - Public key buffer extraction
- All BBS-related tests and documentation

**Breaking Changes:**
- **BREAKING**: Ethereum addresses derived from BBS public keys will change (compressed → uncompressed hash)
- **BREAKING**: Public key size validation changes from 96 to 192 bytes
- **BREAKING**: Existing credentials with 96-byte keys incompatible with contract verification

**Migration Path:**
- Regenerate BBS keypairs using updated SDK
- Derive new Ethereum addresses from 192-byte uncompressed public keys
- Update contract interactions to use new format
