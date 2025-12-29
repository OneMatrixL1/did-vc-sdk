# BLS Signature Verification for changeOwnerWithPubkey

## Problem

BBS keypairs from `@docknetwork/crypto-wasm-ts` use a **custom G2 generator** (not standard BLS12-381 G2.BASE), causing signature verification to fail on-chain.

## Root Cause

| Component | Standard BLS | Dock BBS |
|-----------|-------------|----------|
| G2 Generator | G2.BASE | hash_to_curve('DockBBSSignature2023') |
| Private Key | Big-endian | Little-endian |
| Public Key | sk * G2.BASE | sk * Dock_G2 |

## Solution

### 1. Contract: Use Dock's G2 Generator

Updated `BLS2.sol` with Dock's negated G2 constants:

```solidity
// Dock BBS g2 generator (negated) from label "DockBBSSignature2023"
uint128 private constant N_G2_X1_HI = 0x151113a09ccd914117226445cd4d5aa6;
uint256 private constant N_G2_X1_LO = 0xd82218d8d3f5b517...;
// ... (full constants in BLS2.sol)
```

### 2. SDK: Convert Private Key Endianness

```javascript
function bbsPrivateKeyToScalar(privateKeyBytes) {
  // BBS = little-endian, Noble = big-endian
  const reversed = new Uint8Array(privateKeyBytes).reverse();
  return bls.fields.Fr.create(BigInt('0x' + Buffer.from(reversed).toString('hex')));
}
```

### 3. Gas Limit

BLS pairing costs ~174k+ gas. Set `gasLimit: 500000`.

## Verification Flow

```
1. SDK: Generate BBS keypair (pubkey = sk * Dock_G2)
2. SDK: Sign message → signature = sk * H(message) in G1
3. Contract: Verify e(sig, -Dock_G2) * e(H(m), pubkey) == 1
```

## Gas Usage

~202,000 gas per `changeOwnerWithPubkey` call.

## Files Changed

- `ethr-did-registry/.../BLS2.sol` - Dock G2 constants
- `ethr-did-resolver/src/controller.ts` - Gas limit 500k
- `credential-sdk/src/modules/ethr-did/utils.js` - Endian conversion
- `credential-sdk/src/modules/ethr-did/module.js` - Identity validation
