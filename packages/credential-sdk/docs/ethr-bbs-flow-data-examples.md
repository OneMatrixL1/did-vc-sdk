# BBS Address-Based Recovery Verification - Real Data Examples

This document contains real data captured from an actual BBS credential issuance and verification flow. No mock data is used - all values are generated from actual cryptographic operations.

**Generated**: 2025-11-28T08:08:24.389Z

---

## Step 1: BBS Keypair Generation

Generate a BBS keypair using BLS12-381 curve.

### Input
None (random generation)

### Output

```json
{
  "publicKey": {
    "format": "Uint8Array",
    "length": 96,
    "base58": "rRG1eVcfSpYAr3Dfu4AnpPQSkbKHjzpuqMA4v6oGRLJHABBAEgRXwS1LY3swcSfEfUhFbbdhkaCRAMzsErn2CF8TMyQwWSJtPNnwAHbKKTJopn6Hfn5SKw5rES2NVRPAtrg",
    "hex": "8f75adcfa8ebf0419421398dd5c80c6d41e55fa70f87c68c10ddcdb035ece6eea1efc3988dae95823f6b962c6270cec9158cabf1d7376eea38b1e842e2c3c8c659809f8e5eb36cbd5669f489e82013ab4f14dd8bf1913bea0bbf5338d34d0db5"
  },
  "privateKey": {
    "format": "Uint8Array",
    "length": 32
  },
  "keypairType": "Bls12381BBSKeyPairDock2023"
}
```

### Key Observations
- BBS public key is **96 bytes** (vs 33 bytes for compressed secp256k1)
- Private key is 32 bytes (same as secp256k1)
- Keypair type: `Bls12381BBSKeyPairDock2023`

---

## Step 2: Ethereum Address Derivation from BBS Public Key

Derive an Ethereum address from the BBS public key using keccak256 hash.

### Input

```json
{
  "publicKeyBase58": "rRG1eVcfSpYAr3Dfu4AnpPQSkbKHjzpuqMA4v6oGRLJHABBAEgRXwS1LY3swcSfEfUhFbbdhkaCRAMzsErn2CF8TMyQwWSJtPNnwAHbKKTJopn6Hfn5SKw5rES2NVRPAtrg",
  "publicKeyHex": "8f75adcfa8ebf0419421398dd5c80c6d41e55fa70f87c68c10ddcdb035ece6eea1efc3988dae95823f6b962c6270cec9158cabf1d7376eea38b1e842e2c3c8c659809f8e5eb36cbd5669f489e82013ab4f14dd8bf1913bea0bbf5338d34d0db5",
  "publicKeyLength": 96
}
```

### Derivation Method

```javascript
keccak256(publicKeyBuffer).slice(-20)
```

### Output

```json
{
  "ethereumAddress": "0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "addressWithoutPrefix": "51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "addressLength": 42
}
```

### Key Observations
- Address is derived from keccak256 hash of the 96-byte BBS public key
- Last 20 bytes of the hash become the Ethereum address
- Address is checksummed (mixed case)

---

## Step 3: Create ethr DID

Create a `did:ethr` identifier from the Ethereum address.

### Input

```json
{
  "ethereumAddress": "0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "network": "vietchain"
}
```

### Output

```json
{
  "didWithNetwork": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "didMainnet": "did:ethr:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61"
}
```

### DID Structure

```
did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61
│   │    │         │
│   │    │         └── Ethereum address (derived from BBS public key)
│   │    └── Network identifier (optional, omitted for mainnet)
│   └── DID method
└── DID scheme
```

---

## Step 4: Key Document for Signing

Create the key document used to sign credentials.

```json
{
  "id": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61#keys-1",
  "controller": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "type": "Bls12381BBSVerificationKeyDock2023",
  "keypair": "<Bls12381BBSKeyPairDock2023 instance>"
}
```

### Key Observations
- `id` follows format: `{DID}#keys-1`
- `controller` is the DID itself
- `type` is `Bls12381BBSVerificationKeyDock2023`
- `keypair` contains both public and private keys for signing

---

## Step 5: Unsigned Credential

The credential before signing.

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://ld.truvera.io/security/bbs/v1"
  ],
  "type": [
    "VerifiableCredential",
    "AlumniCredential"
  ],
  "issuer": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "issuanceDate": "2024-01-15T10:30:00.000Z",
  "credentialSubject": {
    "id": "did:example:holder123",
    "alumniOf": "Example University",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science"
    }
  }
}
```

---

## Step 6: Signed Credential with BBS Signature

The credential after signing with BBS signature.

### Full Signed Credential

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://ld.truvera.io/security/bbs/v1"
  ],
  "type": [
    "VerifiableCredential",
    "AlumniCredential"
  ],
  "issuer": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "issuanceDate": "2024-01-15T10:30:00.000Z",
  "credentialSubject": {
    "id": "did:example:holder123",
    "alumniOf": "Example University",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science"
    }
  },
  "cryptoVersion": "0.6.0",
  "credentialSchema": {
    "id": "data:application/json;charset=utf-8,",
    "type": "JsonSchemaValidator2018",
    "version": "0.4.0",
    "details": "..."
  },
  "proof": {
    "@context": [
      {
        "sec": "https://w3id.org/security#",
        "proof": {
          "@id": "sec:proof",
          "@type": "@id",
          "@container": "@graph"
        }
      },
      "https://ld.truvera.io/security/bbs23/v1"
    ],
    "type": "Bls12381BBSSignatureDock2023",
    "created": "2025-11-28T08:08:24Z",
    "verificationMethod": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z2SLyYmozdmd2MWFRXY6RV3zR3A4V8bWtmJqwwmmqEKZqzVQHde1f5PzoaMGJoKs5Xd5KGqBqdCCbva8AHjCkb2MpXthH79xaWk6e1MPTtxDuUM",
    "publicKeyBase58": "rRG1eVcfSpYAr3Dfu4AnpPQSkbKHjzpuqMA4v6oGRLJHABBAEgRXwS1LY3swcSfEfUhFbbdhkaCRAMzsErn2CF8TMyQwWSJtPNnwAHbKKTJopn6Hfn5SKw5rES2NVRPAtrg"
  }
}
```

### Proof Details

```json
{
  "type": "Bls12381BBSSignatureDock2023",
  "verificationMethod": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61#keys-1",
  "proofPurpose": "assertionMethod",
  "created": "2025-11-28T08:08:24Z",
  "proofValue": "z2SLyYmozdmd2MWFRXY6RV3zR3A4V8bWtmJqwwmmqEKZqzVQHde1f5PzoaMGJoKs5Xd5KGqBqdCCbva8AHjCkb2MpXthH79xaWk6e1MPTtxDuUM",
  "proofValueLength": 111,
  "publicKeyBase58": "rRG1eVcfSpYAr3Dfu4AnpPQSkbKHjzpuqMA4v6oGRLJHABBAEgRXwS1LY3swcSfEfUhFbbdhkaCRAMzsErn2CF8TMyQwWSJtPNnwAHbKKTJopn6Hfn5SKw5rES2NVRPAtrg",
  "publicKeyBase58Length": 131,
  "publicKeyBase58DecodedLength": 96
}
```

### Key Observations
- **`publicKeyBase58`** is embedded in the proof - this is the BBS public key
- `proofValue` contains the BBS signature (base58 encoded)
- `verificationMethod` points to the key ID in the DID
- The `publicKeyBase58` decodes to 96 bytes (BBS public key size)

---

## Step 7: Address Verification Process

During verification, the address is derived from the embedded public key and compared with the DID's address.

### Step 7.1: Extract Public Key from Proof

```json
{
  "source": "proof.publicKeyBase58",
  "publicKeyBase58": "rRG1eVcfSpYAr3Dfu4AnpPQSkbKHjzpuqMA4v6oGRLJHABBAEgRXwS1LY3swcSfEfUhFbbdhkaCRAMzsErn2CF8TMyQwWSJtPNnwAHbKKTJopn6Hfn5SKw5rES2NVRPAtrg",
  "decodedLength": 96
}
```

### Step 7.2: Derive Address from Public Key

```json
{
  "method": "bbsPublicKeyToAddress(decodedPublicKey)",
  "derivedAddress": "0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61"
}
```

### Step 7.3: Extract Address from DID

```json
{
  "did": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "method": "did.split(\":\").pop()",
  "extractedAddress": "0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61"
}
```

### Step 7.4: Compare Addresses

```json
{
  "derivedAddressLower": "0x51bd82388f4db7b4206456b22b09a1cd24d30a61",
  "didAddressLower": "0x51bd82388f4db7b4206456b22b09a1cd24d30a61",
  "match": true
}
```

**Result**: `VALID - Public key in proof derives to same address as DID`

---

## Step 8: Minimal DID Document for Purpose Validation

The DID document required for verification. **Note: It does NOT contain the BBS public key.**

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/v2"
  ],
  "id": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "verificationMethod": [
    {
      "id": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61#controller",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
      "blockchainAccountId": "eip155:1:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61"
    }
  ],
  "assertionMethod": [
    "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61#controller",
    "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61#keys-1"
  ],
  "authentication": [
    "did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61#controller"
  ]
}
```

### Key Observations

| Property | Value |
|----------|-------|
| Contains BBS Key | **NO** |
| Contains Secp256k1 Recovery Method | Yes |
| `assertionMethod` authorizes | `#controller` and `#keys-1` |
| Verification Method in Proof | `...#keys-1` |
| Is `#keys-1` authorized | **Yes** (listed in `assertionMethod`) |

**IMPORTANT**: The DID document does NOT contain the BBS public key. The BBS public key comes from the proof itself (`proof.publicKeyBase58`). The DID document only needs to authorize the `verificationMethod` ID in `assertionMethod`.

---

## Step 9: Credential Verification Result

### Result

```json
{
  "verified": true,
  "resultsCount": 1,
  "firstResult": {
    "verified": true,
    "purposeValid": true
  }
}
```

### Verification Steps

1. Parse credential and extract proof
2. Detect `proof.publicKeyBase58` exists
3. Detect `verificationMethod` is ethr DID
4. Create `Bls12381BBSRecoveryMethod2023.fromProof(proof, issuerDID)`
5. In verifier: derive address from embedded public key
6. In verifier: compare derived address with DID address
7. If addresses match: verify BBS signature
8. Validate proof purpose using DID document `assertionMethod`

---

## Step 10: Tampered Credential Verification (Negative Test)

### Modification

```json
{
  "field": "credentialSubject.alumniOf",
  "original": "Example University",
  "tampered": "Fake University"
}
```

### Tampered Credential

```json
{
  "credentialSubject": {
    "id": "did:example:holder123",
    "alumniOf": "Fake University",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science"
    }
  },
  "proof": {
    "...": "...",
    "proofValue": "z2SLyYmozdmd2MWFRXY6RV3zR3A4V8bWtmJqwwmmqEKZqzVQHde1f5PzoaMGJoKs5Xd5KGqBqdCCbva8AHjCkb2MpXthH79xaWk6e1MPTtxDuUM",
    "publicKeyBase58": "rRG1eVcfSpYAr3Dfu4AnpPQSkbKHjzpuqMA4v6oGRLJHABBAEgRXwS1LY3swcSfEfUhFbbdhkaCRAMzsErn2CF8TMyQwWSJtPNnwAHbKKTJopn6Hfn5SKw5rES2NVRPAtrg"
  }
}
```

### Result

```json
{
  "verified": false,
  "expectedVerified": false,
  "testPassed": true
}
```

**Explanation**: BBS signature verification fails because the signed content has been modified. The signature was created over the original data, so changing `alumniOf` invalidates the signature.

---

## Step 11: Wrong Public Key Verification (Negative Test)

### Modification

Replace the public key in the proof with a different BBS public key.

```json
{
  "field": "proof.publicKeyBase58",
  "original": "rRG1eVcfSpYAr3Dfu4AnpPQSkbKHjzpuqMA4v6oGRLJHABBAEgRXwS1LY3swcSfEfUhFbbdhkaCRAMzsErn2CF8TMyQwWSJtPNnwAHbKKTJopn6Hfn5SKw5rES2NVRPAtrg",
  "replaced": "ryXNcUpzccDG8Tave81EWWeWcFPX1zYQxDuLq5XQZcPX7r4eG9HivTdnAbHtsZxKEqPsiFYvLLPbUtYvUv4Zuvu9cPMdhPr3qbbpaAnT1Qr7oKLunQTMhKqNkz2hmeWNhuv"
}
```

### Address Comparison

```json
{
  "addressFromOriginalKey": "0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "addressFromWrongKey": "0x8cD3f94bDaE1934311f09e13E1f214425E2e4719",
  "didAddress": "0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61",
  "originalMatches": true,
  "wrongMatches": false
}
```

### Result

```json
{
  "verified": false,
  "expectedVerified": false,
  "testPassed": true
}
```

**Explanation**: Address derived from the wrong public key (`0x8cD3f94bDaE1934311f09e13E1f214425E2e4719`) does not match the DID address (`0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61`). Verification fails **before even checking the signature** because the address comparison fails first.

---

## Summary: Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              ISSUANCE FLOW                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  1. Generate BBS Keypair                                                        │
│     └── publicKey: 96 bytes                                                     │
│     └── privateKey: 32 bytes                                                    │
│                          │                                                       │
│                          ▼                                                       │
│  2. Derive Address: keccak256(publicKey).slice(-20)                             │
│     └── 0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61                              │
│                          │                                                       │
│                          ▼                                                       │
│  3. Create DID: did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61   │
│                          │                                                       │
│                          ▼                                                       │
│  4. Sign Credential with BBS privateKey                                         │
│     └── proof.proofValue = BBS signature                                        │
│     └── proof.publicKeyBase58 = Base58(publicKey)  ← EMBEDDED                   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                            VERIFICATION FLOW                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  1. Extract publicKeyBase58 from proof                                          │
│     └── Decode Base58 → 96-byte public key                                      │
│                          │                                                       │
│                          ▼                                                       │
│  2. Derive address from public key                                              │
│     └── keccak256(publicKey).slice(-20)                                         │
│     └── 0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61                              │
│                          │                                                       │
│                          ▼                                                       │
│  3. Extract address from issuer DID                                             │
│     └── did:ethr:vietchain:0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61           │
│     └── 0x51bd82388F4DB7B4206456B22B09A1Cd24d30a61                              │
│                          │                                                       │
│                          ▼                                                       │
│  4. Compare addresses (case-insensitive)                                        │
│         ┌────────────────┴────────────────┐                                     │
│         │                                 │                                      │
│      MATCH                            MISMATCH                                  │
│         │                                 │                                      │
│         ▼                                 ▼                                      │
│  5. Verify BBS signature              REJECT                                    │
│     using public key                  (wrong key)                               │
│         │                                                                        │
│         ▼                                                                        │
│  6. Validate proof purpose                                                      │
│     against DID document                                                        │
│         │                                                                        │
│         ▼                                                                        │
│     VERIFIED ✓                                                                  │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Data Sizes

| Data | Size | Encoding |
|------|------|----------|
| BBS Public Key | 96 bytes | Raw binary |
| BBS Public Key (Base58) | 131 characters | Base58 |
| BBS Private Key | 32 bytes | Raw binary |
| BBS Signature | ~80 bytes | Raw binary |
| BBS Signature (Base58) | 111 characters | Base58 |
| Ethereum Address | 20 bytes | Hex (42 chars with 0x) |
| ethr DID (mainnet) | ~50 characters | String |
| ethr DID (with network) | ~60 characters | String |
