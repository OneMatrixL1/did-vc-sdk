# BBS Address-Based Recovery Verification for Ethr DIDs

## Overview

This document describes the implementation of BBS signature verification for `did:ethr` DIDs without requiring on-chain public key storage. The solution embeds the BBS public key in the credential proof and validates it by deriving the Ethereum address from the public key.

## Problem Statement

### Background

The `did:ethr` method uses Ethereum addresses as identifiers. For secp256k1 keys, the EIP-712 standard allows recovering the public key directly from the signature, enabling verification without storing the public key on-chain (`EcdsaSecp256k1RecoveryMethod2020`).

However, BBS+ signatures have fundamentally different properties:
- **Cannot recover public key from signature**: Unlike ECDSA, BBS signatures don't support public key recovery
- **Different key size**: BBS public keys are 96 bytes vs 33 bytes for compressed secp256k1
- **Different curve**: BBS uses BLS12-381 curve, not secp256k1

### The Challenge

When creating an ethr DID from a BBS keypair:
1. We derive an Ethereum address from the BBS public key using `keccak256(publicKey).slice(-20)`
2. The DID is created: `did:ethr:[network:]0xAddress`
3. **Problem**: The on-chain DID document only contains `EcdsaSecp256k1RecoveryMethod2020`, not the BBS public key
4. **Result**: Verification fails because the verifier cannot obtain the BBS public key

### Previous Workaround

Tests used mock DID documents with the BBS public key pre-populated:
```javascript
networkCache[did] = {
  verificationMethod: [{
    type: 'Bls12381G2VerificationKeyDock2023',
    publicKeyBase58: '...' // BBS public key
  }]
};
```

This approach required:
- Registering BBS public keys on-chain (expensive, not always possible)
- Or using mock documents (not production-ready)

## Solution: Address-Based Recovery

### Concept

The solution mirrors `EcdsaSecp256k1RecoveryMethod2020` but receives the public key explicitly instead of recovering it from the signature:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Verification Flow                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Extract publicKeyBase58 from proof                          │
│                     │                                            │
│                     ▼                                            │
│  2. Derive address: keccak256(publicKey).slice(-20)             │
│                     │                                            │
│                     ▼                                            │
│  3. Compare derived address with DID's address                  │
│                     │                                            │
│         ┌──────────┴──────────┐                                 │
│         │                     │                                  │
│         ▼                     ▼                                  │
│     MATCH               MISMATCH                                │
│         │                     │                                  │
│         ▼                     ▼                                  │
│  4. Verify BBS          REJECT                                  │
│     signature           (wrong key)                             │
│         │                                                        │
│         ▼                                                        │
│     VALID/INVALID                                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Security Model

The security relies on the collision resistance of keccak256:
- An attacker cannot create a different BBS keypair that produces the same Ethereum address
- The address acts as a commitment to the public key
- If `keccak256(attackerPublicKey).slice(-20) === legitimateAddress`, the attacker has found a keccak256 collision (computationally infeasible)

### Comparison with EcdsaSecp256k1RecoveryMethod2020

| Aspect | EcdsaSecp256k1RecoveryMethod2020 | Bls12381BBSRecoveryMethod2023 |
|--------|----------------------------------|-------------------------------|
| Public key source | Recovered from signature | Embedded in proof |
| Key size | 33 bytes (compressed) | 96 bytes |
| Curve | secp256k1 | BLS12-381 |
| Address derivation | `keccak256(uncompressedPubKey).slice(-20)` | `keccak256(bbsPubKey).slice(-20)` |
| On-chain storage needed | No | No |

## Implementation Details

### Files Modified/Created

```
src/vc/crypto/
├── Bls12381BBSRecoveryMethod2023.js    # NEW: Recovery verification key class
├── Bls12381BBSSignatureDock2023.js     # MODIFIED: Embed public key, use recovery
├── common/
│   └── CustomLinkedDataSignature.js    # MODIFIED: Include publicKeyBase58 in proof
├── constants.js                         # MODIFIED: Added constant
└── index.js                            # MODIFIED: Export new class

src/vc/
└── helpers.js                          # MODIFIED: Handle recovery method type

src/modules/ethr-did/
├── module.js                           # MODIFIED: Add #keys-bbs to default docs
└── utils.js                            # MODIFIED: Added ETHR_BBS_KEY_ID constant

tests/
├── ethr-bbs-recovery.test.js           # NEW: Core recovery verification tests
├── ethr-bbs-security.test.js           # NEW: Security and attack vector tests
├── ethr-did-bbs-key-authorization.test.js  # NEW: On-chain data detection tests
└── ethr-bbs-real-resolver.test.js      # NEW: Real resolver integration tests
```

### 1. Bls12381BBSRecoveryMethod2023 Class

**Location**: `src/vc/crypto/Bls12381BBSRecoveryMethod2023.js`

This class implements the verification key for BBS address-based recovery.

#### Constructor

```javascript
constructor(publicKeyBase58, controller, expectedAddress)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `publicKeyBase58` | `string` | Base58-encoded BBS public key (96 bytes) |
| `controller` | `string` | The DID that controls this key |
| `expectedAddress` | `string` | Expected Ethereum address from the DID |

The constructor:
1. Stores the public key in both Base58 and buffer formats
2. Derives the Ethereum address from the public key
3. Stores both expected and derived addresses for comparison

#### Static Methods

##### `from(verificationMethod)`

Constructs from a verification method object (standard LD signature pattern):

```javascript
const method = Bls12381BBSRecoveryMethod2023.from({
  publicKeyBase58: 'base58EncodedKey...',
  controller: 'did:ethr:0x...'
});
```

##### `fromProof(proof, issuerDID)`

**Primary factory method** - Constructs from a proof object during verification:

```javascript
const method = Bls12381BBSRecoveryMethod2023.fromProof(
  {
    type: 'Bls12381BBSSignatureDock2023',
    publicKeyBase58: 'base58EncodedKey...',
    verificationMethod: 'did:ethr:0x123...#keys-bbs'
  },
  'did:ethr:0x123...'
);
```

Key behaviors:
- Extracts `publicKeyBase58` from proof (throws if missing)
- Extracts expected address from DID (last segment after `:`)
- Sets `id` property from `proof.verificationMethod` for purpose validation

##### `verifierFactory(publicKeyBuffer, expectedAddress)`

Creates a verifier object with address validation:

```javascript
const verifier = Bls12381BBSRecoveryMethod2023.verifierFactory(
  publicKeyBuffer,
  '0x123...'
);

const result = await verifier.verify({
  data: [msg1, msg2, ...],
  signature: signatureBytes
});
```

**Verification steps**:
1. Derive address from public key using `bbsPublicKeyToAddress()`
2. Compare with expected address (case-insensitive)
3. If mismatch, return `false` immediately
4. If match, verify BBS signature using crypto-wasm-ts
5. Return signature verification result

### 2. Bls12381BBSSignatureDock2023 Modifications

**Location**: `src/vc/crypto/Bls12381BBSSignatureDock2023.js`

#### signerFactory Override

Adds `publicKeyBase58` to the signer object:

```javascript
static signerFactory(keypair, verificationMethod) {
  const baseSigner = {
    id: verificationMethod,
    async sign({ data }) { /* ... */ }
  };

  // Add publicKeyBase58 for ethr DID address verification
  if (keypair && keypair.publicKeyBuffer) {
    baseSigner.publicKeyBase58 = b58.encode(
      new Uint8Array(keypair.publicKeyBuffer)
    );
  }

  return baseSigner;
}
```

#### getVerificationMethod Override

Routes ethr DIDs to recovery method:

```javascript
async getVerificationMethod({ proof, documentLoader }) {
  const verificationMethodId = typeof proof.verificationMethod === 'object'
    ? proof.verificationMethod.id
    : proof.verificationMethod;

  // Check for embedded public key + ethr DID
  if (proof.publicKeyBase58 && verificationMethodId) {
    const didPart = verificationMethodId.split('#')[0];

    if (isEthrDID(didPart)) {
      // Use BBS recovery method for ethr DIDs
      return Bls12381BBSRecoveryMethod2023.fromProof(proof, didPart);
    }
  }

  // Fall back to standard resolution
  return super.getVerificationMethod({ proof, documentLoader });
}
```

#### verifySignature Override

Handles `Bls12381BBSRecoveryMethod2023` instances:

```javascript
async verifySignature({ verifyData, verificationMethod, proof }) {
  if (verificationMethod instanceof Bls12381BBSRecoveryMethod2023) {
    const signatureBytes = this.constructor.extractSignatureBytes(proof);
    const verifier = verificationMethod.verifier();
    return verifier.verify({ data: verifyData, signature: signatureBytes });
  }

  return super.verifySignature({ verifyData, verificationMethod, proof });
}
```

#### getTrimmedProofAndValue Override

**Critical**: Strips `publicKeyBase58` before verification:

```javascript
static getTrimmedProofAndValue(document, explicitProof) {
  const [trimmedProof, proofVal] = super.getTrimmedProofAndValue(
    document,
    explicitProof
  );

  // Remove publicKeyBase58 - it was added after signing
  delete trimmedProof.publicKeyBase58;

  return [trimmedProof, proofVal];
}
```

**Why this is necessary**:
- `publicKeyBase58` is added to the proof AFTER signing
- BBS signatures verify against specific message fields
- Including `publicKeyBase58` in the canonicalized proof would break verification
- The error without this fix: `"Cannot encode message with name proof.publicKeyBase58"`

### 3. CustomLinkedDataSignature Modification

**Location**: `src/vc/crypto/common/CustomLinkedDataSignature.js`

Includes `publicKeyBase58` in the final proof:

```javascript
// In createProof method, after signature creation:
if (this.signer && this.signer.publicKeyBase58) {
  finalProof.publicKeyBase58 = this.signer.publicKeyBase58;
}
```

### 4. Address Derivation Utility

**Location**: `src/modules/ethr-did/utils.js`

```javascript
export function bbsPublicKeyToAddress(publicKeyBuffer) {
  const buffer = u8aToU8a(publicKeyBuffer);

  if (buffer.length !== 96) {
    throw new Error(
      `BBS public key must be 96 bytes, got ${buffer.length}`
    );
  }

  const hash = keccak256(buffer);
  // Take last 20 bytes as Ethereum address
  const address = '0x' + Buffer.from(hash.slice(-20)).toString('hex');

  return ethers.getAddress(address); // Checksummed
}
```

## Credential Proof Structure

### Before (without embedded public key)

```json
{
  "proof": {
    "type": "Bls12381BBSSignatureDock2023",
    "created": "2024-01-15T10:30:00Z",
    "verificationMethod": "did:ethr:0x123...#keys-bbs",
    "proofPurpose": "assertionMethod",
    "proofValue": "base58EncodedSignature..."
  }
}
```

### After (with embedded public key)

```json
{
  "proof": {
    "type": "Bls12381BBSSignatureDock2023",
    "created": "2024-01-15T10:30:00Z",
    "verificationMethod": "did:ethr:0x123...#keys-bbs",
    "proofPurpose": "assertionMethod",
    "proofValue": "base58EncodedSignature...",
    "publicKeyBase58": "base58EncodedBBSPublicKey..."
  }
}
```

The `publicKeyBase58` field:
- Contains 96-byte BBS public key encoded in Base58
- Is added AFTER the signature is created
- Is stripped during verification before signature check
- Enables self-contained credential verification

## Usage Examples

### Issuing a Credential

```javascript
import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { issueCredential } from '@truvera/credential-sdk/vc';
import Bls12381BBSKeyPairDock2023 from '@truvera/credential-sdk/vc/crypto/Bls12381BBSKeyPairDock2023';
import { keypairToAddress, addressToDID } from '@truvera/credential-sdk/modules/ethr-did/utils';
import { Bls12381BBS23DockVerKeyName } from '@truvera/credential-sdk/vc/crypto/constants';

// Initialize WASM
await initializeWasm();

// Generate BBS keypair
const bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
  id: 'issuer-key',
  controller: 'temp'
});

// Derive ethr DID from BBS public key
const address = keypairToAddress(bbsKeypair);
const ethrDID = addressToDID(address, 'mainnet'); // or specific network

// Create key document for signing
const keyDoc = {
  id: `${ethrDID}#keys-bbs`,
  controller: ethrDID,
  type: Bls12381BBS23DockVerKeyName,
  keypair: bbsKeypair
};

// Create unsigned credential
const credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://ld.truvera.io/security/bbs/v1'
  ],
  type: ['VerifiableCredential'],
  issuer: ethrDID,
  issuanceDate: new Date().toISOString(),
  credentialSubject: {
    id: 'did:example:holder123',
    name: 'John Doe'
  }
};

// Issue credential (publicKeyBase58 is automatically embedded)
const signedCredential = await issueCredential(keyDoc, credential);

console.log(signedCredential.proof.publicKeyBase58); // BBS public key embedded
```

### Verifying a Credential

```javascript
import { verifyCredential } from '@truvera/credential-sdk/vc';

// The credential contains embedded publicKeyBase58
const result = await verifyCredential(signedCredential);

if (result.verified) {
  console.log('Credential is valid!');
  // The verification:
  // 1. Extracted publicKeyBase58 from proof
  // 2. Derived address from BBS public key
  // 3. Compared with issuer DID address
  // 4. Verified BBS signature
} else {
  console.log('Verification failed:', result.error);
}
```

### Manual Address Verification

```javascript
import { bbsPublicKeyToAddress } from '@truvera/credential-sdk/modules/ethr-did/utils';
import b58 from 'bs58';

// From a credential proof
const publicKeyBuffer = b58.decode(credential.proof.publicKeyBase58);
const derivedAddress = bbsPublicKeyToAddress(publicKeyBuffer);

// Extract address from issuer DID
const issuerDID = credential.issuer;
const didAddress = issuerDID.split(':').pop();

// Compare
if (derivedAddress.toLowerCase() === didAddress.toLowerCase()) {
  console.log('Public key matches DID address');
} else {
  console.log('WARNING: Public key does not match DID!');
}
```

## DID Document Requirements

For verification to succeed, the DID document needs:

1. **Valid `assertionMethod`** that includes the verification method ID from the proof
2. **Does NOT need** the BBS public key in `verificationMethod` array

### Automatic BBS Key Authorization

The `EthrDIDModule.getDocument()` method automatically adds `#keys-bbs` to `assertionMethod` for **default documents only** (DIDs with no on-chain modifications).

```javascript
// In EthrDIDModule.getDocument():
const hasOnChainData = result.didDocumentMetadata?.versionId !== undefined;

if (!hasOnChainData) {
  // Add #keys-bbs for default documents only
  document.assertionMethod = [...document.assertionMethod, bbsKeyId];
}
```

**Behavior by scenario:**

| Scenario | On-Chain Data | `#keys-bbs` Added | Reason |
|----------|---------------|-------------------|--------|
| Fresh DID (no transactions) | None | ✅ Yes | Default document, automatic authorization |
| Modified DID (setAttribute, addDelegate, etc.) | Has events | ❌ No | Respect on-chain configuration |

**Why this design?**

- **Fresh DIDs**: Automatically support BBS without requiring on-chain transactions
- **Modified DIDs**: Users explicitly configured their DID document, so we respect their choices
- **Security**: Prevents permanently enabling BBS if user intentionally removed it on-chain

### Minimal DID Document Example

For a fresh DID with no on-chain data, the resolved document looks like:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:ethr:0x123...",
  "verificationMethod": [
    {
      "id": "did:ethr:0x123...#controller",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "did:ethr:0x123...",
      "blockchainAccountId": "eip155:1:0x123..."
    }
  ],
  "assertionMethod": [
    "did:ethr:0x123...#controller",
    "did:ethr:0x123...#keys-bbs"
  ]
}
```

Note: `#keys-bbs` is listed in `assertionMethod` but there's no corresponding entry in `verificationMethod` with the BBS public key. The public key comes from the proof itself.

## Security Considerations

### Strengths

1. **No on-chain storage required**: BBS public keys don't need to be registered
2. **Self-contained credentials**: All verification data is in the credential
3. **Address binding**: Public key is cryptographically bound to DID via keccak256
4. **Collision resistance**: Finding a different key with same address requires breaking keccak256

### Limitations

1. **Larger proof size**: Additional ~130 bytes for Base58-encoded 96-byte public key
2. **No key rotation detection**: Can't detect if a different key was used for same address (though this would require a keccak256 collision)
3. **Requires `assertionMethod` authorization**: DID document must authorize the verification method ID

### Attack Vectors Considered

| Attack | Mitigation |
|--------|------------|
| Replace public key in proof | Address derivation would fail to match DID |
| Use different keypair with same address | Requires keccak256 collision (infeasible) |
| Modify credential content | BBS signature verification would fail |
| Replay with different DID | Address comparison would fail |
| Impersonate another DID | Attacker's key derives to different address |
| Add BBS to secp256k1-only DID | Address mismatch + no `#keys-bbs` authorization |
| Swap proof between credentials | Signature binds to credential content |
| Use credential after key rotation | Old credentials remain valid for original DID |

## Backward Compatibility

### Non-ethr DIDs

Credentials from non-ethr DIDs (e.g., `did:dock:`, `did:example:`) continue to work with standard verification:

```javascript
// This still works - uses standard DID document resolution
const nonEthrCredential = {
  issuer: 'did:example:issuer123',
  proof: {
    verificationMethod: 'did:example:issuer123#keys-bbs',
    // publicKeyBase58 is still included but not used for address verification
  }
};

await verifyCredential(nonEthrCredential); // Uses standard resolution
```

### Ethr DIDs with On-Chain BBS Keys

If an ethr DID has a BBS public key registered on-chain, both verification methods work:
1. Standard resolution finds the key in DID document
2. Recovery method validates address derivation

The recovery method is only used when:
- `proof.publicKeyBase58` exists AND
- Verification method is an ethr DID

## Test Coverage

### Test Files

| Test File | Description | Tests |
|-----------|-------------|-------|
| `ethr-bbs-recovery.test.js` | Core recovery verification tests | 13 |
| `ethr-bbs-security.test.js` | Security and attack vector tests | 22 |
| `ethr-did-bbs-key-authorization.test.js` | On-chain data detection tests | 8 |
| `ethr-bbs-real-resolver.test.js` | Real resolver integration tests | 2 |
| **Total** | | **45** |

### Security Tests (`tests/ethr-bbs-security.test.js`)

| Category | Tests |
|----------|-------|
| Impersonation Attacks | 2 |
| Credential Tampering Attacks | 6 |
| Proof Manipulation Attacks | 4 |
| Cross-DID Attacks | 2 |
| Key Rotation Scenarios | 2 |
| No BBS Keypair Scenarios | 3 |
| Invalid Public Key Attacks | 3 |

### Key Authorization Tests (`tests/ethr-did-bbs-key-authorization.test.js`)

| Category | Tests |
|----------|-------|
| No on-chain data (adds `#keys-bbs`) | 3 |
| Has on-chain data (respects config) | 3 |
| Edge cases | 2 |

### Key Test Cases

**Recovery Verification:**
1. Constructor validation: Public key, controller, address derivation
2. fromProof extraction: Handles proof object correctly
3. Missing publicKeyBase58: Throws appropriate error
4. Address mismatch rejection: Wrong public key is rejected
5. Embedded public key in proof: Issuance includes publicKeyBase58
6. Self-contained verification: Works without BBS key in DID doc
7. Multi-network support: Works on mainnet, sepolia, polygon, vietchain

**Security:**
8. Attacker cannot impersonate victim DID
9. Replaced public key fails verification
10. Tampered credential content fails
11. Proof cannot be reused across credentials
12. Key rotation: Old credentials valid, cannot claim for new DID
13. BBS credential fails if DID has no BBS authorization

**Key Authorization:**
14. `#keys-bbs` added when `versionId` is undefined
15. `#keys-bbs` NOT added when `versionId` exists
16. Respects on-chain `assertionMethod` configuration

## Glossary

| Term | Definition |
|------|------------|
| BBS+ | Boneh-Boyen-Shacham signature scheme with selective disclosure |
| BLS12-381 | Elliptic curve used by BBS+ signatures |
| ethr DID | Decentralized identifier using Ethereum addresses |
| keccak256 | Cryptographic hash function used by Ethereum |
| Recovery method | Verification method that derives/recovers public key |
| publicKeyBase58 | Base58-encoded public key embedded in proof |
| Address derivation | Computing Ethereum address from public key hash |

## References

- [DID Ethr Method Specification](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
- [BBS+ Signatures](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html)
- [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
