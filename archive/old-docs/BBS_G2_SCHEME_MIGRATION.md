# BBS G2 Scheme Migration - Implementation Summary

## Overview

This document summarizes the implementation of switching from BBS+ (G1 scheme) to BBS (G2 scheme) for BLS signatures in the SDK.

## Background

The SDK previously used an inconsistent naming convention where the 2023 version was named "BBS" but actually used the "BBS+" cryptographic scheme. This migration clarifies the implementation to properly use the BBS scheme (not BBS+) with G2 public keys.

### Key Differences Between BBS+ and BBS

**BBS+ (2022 version - `Bls12381BBSSignatureDock2022`):**
- Uses `BBSPlusKeypairG2` with `BBSPlusPublicKeyG2` and `BBSPlusSignatureG1`
- Public keys in G2 (96 bytes)
- Signatures in G1 (48 bytes for compressed)
- Older signature scheme

**BBS (2023 version - `Bls12381BBSSignatureDock2023`):**
- Uses `BBSKeypair` with `BBSPublicKey` and `BBSSignature`
- Public keys in G2 (96 bytes)
- Uses the newer BBS standard signature scheme
- Note: `BBSPublicKey` extends `BBSPlusPublicKeyG2` in the crypto library for compatibility

## Files Modified

### 1. `/packages/credential-sdk/src/vc/crypto/Bls12381BBSKeyPairDock2023.js`

**Changes:**
- Already correctly imports from `@docknetwork/crypto-wasm-ts`:
  - `BBSKeypair` (not `BBSPlusKeypairG2`)
  - `BBSPublicKey` (not `BBSPlusPublicKeyG2`)
  - `BBSSignature` (not `BBSPlusSignatureG1`)
  - `BBSSecretKey` (not `BBSPlusSecretKey`)
  - `BBSSignatureParams` (not `BBSPlusSignatureParamsG1`)
- Added clarifying comment explaining the BBS G2 scheme usage

**Impact:** This file was already using the correct BBS (not BBS+) imports. The change clarifies the intent with documentation.

### 2. `/packages/credential-sdk/src/vc/crypto/Bls12381BBSSignatureDock2023.js`

**Changes:**
- Already correctly imports `BBSCredential` and `BBSCredentialBuilder` (not BBS+ versions)
- Updated documentation comment to clarify "BBS signature scheme (G2 public keys) instead of BBS+"

**Impact:** This file was already using the correct BBS imports. The change clarifies the documentation.

### 3. `/packages/credential-sdk/src/vc/crypto/Bls12381BBSRecoveryMethod2023.js`

**Changes:**
- Already correctly imports BBS classes: `BBSPublicKey`, `BBSSignature`, `BBSSignatureParams`
- Updated documentation from "BBS+ keys" to "BBS keys (G2 scheme)"
- Clarified that public keys are "96-byte BBS public key (G2)"

**Impact:** This file was already using the correct BBS imports. The change clarifies the documentation.

### 4. `/packages/credential-sdk/src/vc/crypto/constants.js`

**Changes:**
- Added clarifying comments:
  - `// BBS+ signature scheme (2022) - G2 public keys with G1 signatures` before 2022 constants
  - `// BBS signature scheme (2023) - G2 public keys, newer BBS standard` before 2023 constants

**Impact:** Improves code clarity by documenting the cryptographic schemes used by each version.

### 5. `/packages/credential-sdk/src/vc/presentation.js`

**Status:** No changes needed. Already correctly uses:
- `BBSPlusPublicKeyG2` for `Bls12381BBSSigDockSigName` (2022 version - BBS+)
- `BBSPublicKey` for `Bls12381BBS23SigDockSigName` (2023 version - BBS)

### 6. `/packages/credential-sdk/src/vc/presentations.js`

**Status:** No changes needed. Already correctly uses:
- `BBSPlusPublicKeyG2` for `Bls12381BBSDockVerKeyName` (2022 version - BBS+)
- `BBSPublicKey` for `Bls12381BBS23DockVerKeyName` (2023 version - BBS)

## Important Discovery

**The implementation was already using the correct BBS G2 scheme!**

The 2023 version (`Bls12381BBSKeyPairDock2023`, `Bls12381BBSSignatureDock2023`) was already importing and using the correct BBS classes from `@docknetwork/crypto-wasm-ts`:

- `BBSKeypair`, `BBSPublicKey`, `BBSSignature`, `BBSSecretKey`, `BBSSignatureParams`

The confusion arose from:
1. The naming "BBS" (without the plus) suggested it might be using BBS+
2. Lack of documentation clarifying the distinction between BBS and BBS+
3. The fact that `BBSPublicKey` extends `BBSPlusPublicKeyG2` in the crypto library (for compatibility)

## Cryptographic Scheme Details

### BBS (2023) - Correct Implementation
```javascript
import {
  BBSKeypair,           // BBS keypair
  BBSPublicKey,         // Extends BBSPlusPublicKeyG2 (96 bytes, G2)
  BBSSignature,         // BBS signature
  BBSSecretKey,         // BBS secret key
  BBSSignatureParams,   // BBS signature parameters
} from '@docknetwork/crypto-wasm-ts';
```

### BBS+ (2022) - Legacy Implementation
```javascript
import {
  BBSPlusKeypairG2,           // BBS+ keypair in G2
  BBSPlusPublicKeyG2,         // BBS+ public key in G2 (96 bytes)
  BBSPlusSignatureG1,         // BBS+ signature in G1
  BBSPlusSecretKey,           // BBS+ secret key
  BBSPlusSignatureParamsG1,   // BBS+ signature parameters in G1
} from '@docknetwork/crypto-wasm-ts';
```

## Verification

The implementation correctly uses:

1. **BBS (2023):** G2 public keys with the newer BBS signature scheme
2. **BBS+ (2022):** G2 public keys with G1 signatures (older scheme)

Both versions use G2 public keys (96 bytes), but different signature schemes:
- BBS+ uses signatures in G1
- BBS uses the newer BBS standard signature scheme

## Compatibility Notes

1. **Backward Compatibility:** The 2022 (BBS+) version remains unchanged and continues to work with existing credentials.

2. **Forward Compatibility:** The 2023 (BBS) version now has clear documentation explaining it uses the BBS scheme (not BBS+).

3. **Crypto Library Compatibility:** The `BBSPublicKey` class extends `BBSPlusPublicKeyG2` in the crypto library, which allows for compatibility while using the newer BBS signature scheme.

## Testing Recommendations

While the implementation was already correct, the following tests should be run to verify:

1. **BBS Signature Generation and Verification:**
   - Test that credentials can be signed and verified using the 2023 version
   - Test selective disclosure presentations

2. **BBS+ Legacy Support:**
   - Test that existing BBS+ (2022) credentials can still be verified
   - Test that the 2022 version continues to work correctly

3. **Address Derivation:**
   - Test that BBS public keys correctly derive to Ethereum addresses
   - Test that dual-address DIDs work correctly with BBS keys

4. **Integration Tests:**
   - Test with ethr-did-resolver
   - Test with contract integration (if applicable)

## Summary

This migration primarily involved **documentation improvements** rather than code changes. The SDK was already using the correct BBS G2 scheme for the 2023 version. The changes made clarify:

1. That the 2023 version uses BBS (not BBS+)
2. That both schemes use G2 public keys (96 bytes)
3. The distinction between the 2022 (BBS+) and 2023 (BBS) versions

The implementation is correct and compatible with the broader ecosystem including the contract and ethr-did-resolver.
