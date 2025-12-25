# Switch to Uncompressed G2 Public Keys for BBS Signatures

## Overview

This document describes the breaking change to switch BBS signature public keys from 96-byte compressed G2 format to 192-byte uncompressed G2 format for compatibility with Ethereum smart contract BLS verification precompiles.

## Why This Change?

The EthereumDIDRegistry smart contract uses BLS12-381 curve operations through EIP-2537 precompiles, which expect **uncompressed G2 points (192 bytes)**, not compressed format (96 bytes).

**Before this change:**
- SDK generates: 96-byte compressed G2 public keys
- Contract expects: 192-byte uncompressed G2 public keys
- Result: **INCOMPATIBLE** - signatures cannot be verified on-chain

**After this change:**
- SDK will generate: 192-byte uncompressed G2 public keys
- Contract expects: 192-byte uncompressed G2 public keys
- Result: **COMPATIBLE** - full on-chain verification support

## Technical Details

### G2 Point Format

#### Compressed Format (96 bytes)
```
[48 bytes x-coordinate] [48 bytes flag + compressed data]

Structure in Fq2 (quadratic extension field):
- x = (x0, x1)  where x0, x1 are each 48 bytes
- y is computed from curve equation: y^2 = x^3 + b
```

#### Uncompressed Format (192 bytes)
```
[48 bytes x0_hi] [48 bytes x0_lo] [48 bytes x1_hi] [48 bytes x1_lo]
[48 bytes y0_hi] [48 bytes y0_lo] [48 bytes y1_hi] [48 bytes y1_lo]

Structure in Fq2 (quadratic extension field):
- x = (x0, x1) with both coordinates explicitly stored
- y = (y0, y1) with both coordinates explicitly stored
- Total: 8 × 48 = 384 bits = 192 bytes
```

### Address Derivation Change

The Ethereum address is derived by hashing the public key:

**Old (Compressed - 96 bytes input):**
```javascript
address = ethers.utils.getAddress(
  '0x' + ethers.utils.keccak256(compressedKey96Bytes).slice(-40)
);
// Example: 0xDeriveDFromCompressed96Bytes
```

**New (Uncompressed - 192 bytes input):**
```javascript
address = ethers.utils.getAddress(
  '0x' + ethers.utils.keccak256(uncompressedKey192Bytes).slice(-40)
);
// Example: 0xDifferentAddressFromUncompressed192
```

**BREAKING CHANGE:** Since the input to keccak256 is different (96 vs 192 bytes), the derived address will be different. All existing addresses will change.

## Files Modified

### Core SDK Files

1. **`packages/credential-sdk/src/modules/ethr-did/utils.js`**
   - `publicKeyToAddress(publicKeyBytes)`: Updated to expect 192 bytes
   - `bbsPublicKeyToAddress(bbsPublicKey)`: Updated to expect 192 bytes
   - `detectKeypairType(keypair)`: Updated to detect 192-byte BBS keys
   - Documentation updated to specify "192 bytes uncompressed G2"

2. **`packages/credential-sdk/src/vc/crypto/Bls12381BBSRecoveryMethod2023.js`**
   - Constructor validation: Changed from 96 to 192 bytes
   - Documentation updated to "192-byte uncompressed G2"
   - Error messages clarified for new format

3. **`packages/credential-sdk/src/vc/crypto/common/DockCryptoKeyPair.js`**
   - Added `getPublicKeyBufferUncompressed()` method
   - Added `validatePublicKeyFormat()` method
   - Documentation explains compressed vs uncompressed handling
   - Stores reference to original keypair for uncompressed access

4. **NEW: `packages/credential-sdk/src/modules/ethr-did/bbs-uncompressed.js`**
   - Utility module for uncompressed G2 handling
   - `getUncompressedG2PublicKey(bbsPublicKey)`: Main conversion function
   - `createContractPublicKeyBuffer(keypair)`: Helper for contract interaction
   - `getMigrationInfo()`: Documents breaking change and migration path
   - `validatePublicKeyFormat(publicKeyBytes)`: Format validation utility

## Migration Guide

### For Users with Existing BBS Keys

**Your existing BBS addresses will change.**

Steps to migrate:

1. **Backup old addresses** - Document all current BBS-derived Ethereum addresses
2. **Regenerate BBS keypairs** - Create new keypairs once uncompressed support is available
3. **Recalculate addresses** - Derive Ethereum addresses from new 192-byte uncompressed keys
4. **Update smart contract** - Re-register new addresses with the contract
5. **Retire old keys** - Remove old BBS keypairs from your system

### For New Implementations

Simply use the updated API - all new keys will automatically use the uncompressed format:

```javascript
// Generate new BBS keypair (will use 192-byte uncompressed format)
const params = BBSSignatureParams.getSigParamsOfRequiredSize(1, BBS_SIGNATURE_PARAMS_LABEL_BYTES);
const keypair = Bls12381BBSKeyPairDock2023.generate({ params });

// Get the uncompressed public key for contract interaction
const uncompressedKey = keypair.getPublicKeyBufferUncompressed(); // 192 bytes
console.log(uncompressedKey.length); // 192

// Derive Ethereum address
const address = bbsPublicKeyToAddress(uncompressedKey);
console.log(address); // 0xNewAddress...
```

## Critical Dependency

**This change requires support from `@docknetwork/crypto-wasm-ts` library.**

The current version only provides compressed G2 format (96 bytes). To enable uncompressed format (192 bytes), one of the following must be implemented in the crypto library:

1. **Add `toUncompressed()` method to BBSPublicKey**
   ```typescript
   class BBSPublicKey {
     toUncompressed(): Uint8Array; // Returns 192 bytes
   }
   ```

2. **Add uncompressed flag to `toBytes()` method**
   ```typescript
   class BBSPublicKey {
     toBytes(compressed?: boolean): Uint8Array;
     // Usage: pk.toBytes(false) returns 192 bytes
   }
   ```

### Current Status

- **crypto-wasm-ts version**: 0.63.0 (as of this implementation)
- **Current support**: Compressed G2 only (96 bytes)
- **Uncompressed support**: NOT YET AVAILABLE
- **Blocker**: Implementation awaiting library enhancement

### Workarounds (Not Recommended)

If library update is delayed:

1. **Manual expansion** - Implement BLS12-381 curve arithmetic to expand compressed to uncompressed (complex, error-prone)
2. **Alternative library** - Switch to a different BLS implementation that provides uncompressed keys
3. **Contract modification** - Update smart contract to accept 96-byte compressed keys (defeats compatibility goal)

## API Reference

### Updated Functions

#### `publicKeyToAddress(publicKeyBytes)`
```javascript
/**
 * Derive Ethereum address from a public key
 * @param {Uint8Array|Array<number>} publicKeyBytes - Public key bytes
 * @returns {string} Ethereum address (0x prefixed, checksummed)
 * @throws {Error} If public key is not 192 bytes
 */
export function publicKeyToAddress(publicKeyBytes) { ... }
```

**Change**: Previously accepted 96 bytes, now requires 192 bytes

#### `bbsPublicKeyToAddress(bbsPublicKey)`
```javascript
/**
 * Derive Ethereum address from BBS public key
 * @param {Uint8Array|Array<number>} bbsPublicKey - BBS public key (192 bytes, uncompressed G2)
 * @returns {string} Ethereum address (0x prefixed, checksummed)
 * @throws {Error} If key is not 192 bytes
 */
export function bbsPublicKeyToAddress(bbsPublicKey) { ... }
```

**Change**: Previously accepted 96 bytes, now requires 192 bytes

#### `detectKeypairType(keypair)`
```javascript
/**
 * Detect keypair type for address derivation
 * @param {Object} keypair - Keypair instance
 * @returns {'secp256k1' | 'bbs'} Keypair type
 * @throws {Error} If keypair type is not recognized
 */
export function detectKeypairType(keypair) { ... }
```

**Change**: Now detects BBS keypairs by 192-byte public key length

### New Functions

#### `getUncompressedG2PublicKey(bbsPublicKey)`
```javascript
/**
 * Convert BBSPublicKey to 192-byte uncompressed G2 format
 * @param {Object} bbsPublicKey - BBSPublicKey instance
 * @returns {Uint8Array} 192-byte uncompressed G2 public key
 * @throws {Error} If crypto-wasm-ts does not support uncompressed serialization
 */
export function getUncompressedG2PublicKey(bbsPublicKey) { ... }
```

#### `validatePublicKeyFormat(publicKeyBytes)`
```javascript
/**
 * Validate public key format for contract compatibility
 * @param {Uint8Array} publicKeyBytes - Public key to validate
 * @returns {Object} Validation result
 */
export function validatePublicKeyFormat(publicKeyBytes) { ... }
```

**Returns:**
```javascript
{
  valid: true,              // or false
  error: null,              // or error message
  format: 'uncompressed',   // or 'compressed' or 'unknown'
  contractCompatible: true, // or undefined
}
```

#### `DockCryptoKeyPair.getPublicKeyBufferUncompressed()`
```javascript
/**
 * Get public key in uncompressed G2 format for smart contract interaction
 * @returns {Uint8Array} 192-byte uncompressed G2 public key
 * @throws {Error} If uncompressed serialization is not supported
 */
getPublicKeyBufferUncompressed() { ... }
```

## Testing & Validation

### Unit Tests to Update

1. **Test public key size validation**
   - Change assertions from 96 to 192 bytes
   - Verify rejection of 96-byte keys with appropriate error messages

2. **Test address derivation**
   - Generate test vectors with 192-byte uncompressed keys
   - Verify addresses match contract expectations

3. **Test BBS recovery verification**
   - Ensure verification works with 192-byte keys
   - Validate address comparison logic

### Integration Tests

1. **SDK ↔ Contract Compatibility**
   - Generate BBS keypair with SDK
   - Extract 192-byte uncompressed public key
   - Call contract's `changeOwnerWithPubkey()` with new format
   - Verify owner changed successfully

2. **Address Consistency**
   - Verify SDK-derived address matches contract-derived address
   - Test both compressed and uncompressed key handling

## Performance Impact

### Size Impact
- **Public key**: 96 bytes → 192 bytes (2x larger)
- **Contract calldata**: +96 bytes per transaction using BBS keys
- **Storage**: If storing keys on-chain, 2x increase

### Gas Impact (Estimated)
- **Minor increase**: ~5-10% due to larger calldata
- **Negligible impact**: Cryptographic operations unchanged
- **Overall**: Acceptable for improved compatibility

## Success Criteria

- [ ] All 96-byte validation updated to 192-byte
- [ ] Address derivation functions accept 192-byte input
- [ ] BBS recovery verification handles 192-byte keys
- [ ] Documentation updated (96 bytes → 192 bytes uncompressed G2)
- [ ] Error messages clarify the format requirement
- [ ] Unit tests updated and passing
- [ ] Integration tests passing with contract
- [ ] Migration guide provided
- [ ] Breaking change clearly communicated

## Version

- **Implementation Date**: 2025-12-25
- **Change Type**: BREAKING
- **Affected Component**: BBS signatures (2023 scheme)
- **Not Affected**: BBS+ (2022 scheme), other signature schemes

## References

- EIP-2537: BLS12-381 Precompile
- BLS12-381 Specification
- G2 Point Serialization (RFC 9380)
- EthereumDIDRegistry Contract
- @docknetwork/crypto-wasm-ts Library
