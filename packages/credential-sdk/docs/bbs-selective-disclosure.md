# BBS Selective Disclosure with Ethr DIDs

## Overview

BBS (Boneh-Boyen-Shacham) signatures enable **selective disclosure** - the ability to reveal only specific attributes from a credential without exposing the entire document. This is a key privacy feature for verifiable credentials.

## Key Concept: Derived Credentials vs Standard Presentations

Unlike standard credentials that use `signPresentation()` to create verifiable presentations, BBS credentials use a different mechanism:

- **Standard Presentations (secp256k1)**: Bundle credentials and add a holder signature
- **BBS Presentations**: Create **derived credentials** that contain only revealed attributes

## How It Works

### 1. Issue a BBS Credential

First, issue a credential with BBS signatures containing all attributes:

```javascript
import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import Bls12381BBSKeyPairDock2023 from '@docknetwork/credential-sdk/vc/crypto/Bls12381BBSKeyPairDock2023';
import { issueCredential } from '@docknetwork/credential-sdk/vc';
import { keypairToAddress, addressToDID } from '@docknetwork/credential-sdk/modules/ethr-did/utils';

// Initialize WASM for BBS operations
await initializeWasm();

// Create BBS keypair
const issuerKeypair = Bls12381BBSKeyPairDock2023.generate({
  id: 'issuer-key',
  controller: 'temp',
});

// Create ethr DID from BBS public key
const issuerAddress = keypairToAddress(issuerKeypair);
const issuerDID = addressToDID(issuerAddress, 'mainnet');

// Create key document for signing
const issuerKeyDoc = {
  id: `${issuerDID}#keys-bbs`,
  controller: issuerDID,
  type: 'Bls12381BBSVerificationKeyDock2023',
  keypair: issuerKeypair,
};

// Issue credential with multiple attributes
const credential = await issueCredential(issuerKeyDoc, {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://www.w3.org/2018/credentials/examples/v1',
    'https://ld.truvera.io/security/bbs/v1',
  ],
  type: ['VerifiableCredential', 'UniversityDegreeCredential'],
  issuer: issuerDID,
  issuanceDate: '2024-01-01T00:00:00Z',
  credentialSubject: {
    id: 'did:ethr:vietchain:0x...',
    givenName: 'Alice',
    familyName: 'Smith',
    degree: {
      type: 'BachelorDegree',
      name: 'Bachelor of Science and Arts',
      university: 'Example University',
    },
    alumniOf: 'Example University',
    graduationYear: 2020,
  },
});
```

### 2. Create Derived Credential with Selective Disclosure

Use the `Presentation` class to reveal only specific attributes:

```javascript
import Presentation from '@docknetwork/credential-sdk/vc/presentation';

// Create presentation
const presentation = new Presentation();

// Add credential to presentation
await presentation.addCredentialToPresent(credential);

// Reveal only selected attributes
presentation.addAttributeToReveal(0, [
  'credentialSubject.degree.type',
  'credentialSubject.degree.name',
  'credentialSubject.alumniOf',
]);

// Derive credential - only revealed attributes will be present
const derivedCredentials = presentation.deriveCredentials({
  nonce: 'verifier-challenge-abc123',
});

const derivedCred = derivedCredentials[0];
console.log(derivedCred.credentialSubject);
// Output:
// {
//   degree: {
//     type: 'BachelorDegree',
//     name: 'Bachelor of Science and Arts'
//   },
//   alumniOf: 'Example University'
// }
// Note: givenName, familyName, graduationYear are HIDDEN
```

### 3. Verify Derived Credential

The verifier can verify the derived credential normally:

```javascript
import { verifyCredential } from '@docknetwork/credential-sdk/vc';

const result = await verifyCredential(derivedCred);
console.log(result.verified); // true
```

## Privacy Benefits

### Scenario 1: Age Verification

Reveal only that someone is over 18 without revealing their exact birthdate:

```javascript
// Full credential has: birthDate: '1985-03-15'
presentation.addAttributeToReveal(0, ['credentialSubject.ageOver18']);
// Derived credential only shows: ageOver18: true
```

### Scenario 2: Professional Verification

Reveal degree but hide personal information:

```javascript
// Full credential has: givenName, familyName, birthDate, degree, etc.
presentation.addAttributeToReveal(0, [
  'credentialSubject.degree.type',
  'credentialSubject.degree.university',
]);
// Derived credential only shows degree information
```

### Scenario 3: Different Revelations for Different Verifiers

Create multiple derived credentials from the same full credential:

```javascript
// For employer: reveal degree and university
const presentation1 = new Presentation();
await presentation1.addCredentialToPresent(fullCredential);
presentation1.addAttributeToReveal(0, [
  'credentialSubject.degree',
  'credentialSubject.alumniOf',
]);
const employerCred = presentation1.deriveCredentials({ nonce: 'employer-123' })[0];

// For membership: reveal only alumni status
const presentation2 = new Presentation();
await presentation2.addCredentialToPresent(fullCredential);
presentation2.addAttributeToReveal(0, ['credentialSubject.alumniOf']);
const membershipCred = presentation2.deriveCredentials({ nonce: 'member-456' })[0];

// Both are verifiable, both hide personal info, but show different attributes
```

## Attribute Path Syntax

Attributes are specified using dot notation:

```javascript
// Top-level attribute
'credentialSubject.alumniOf'

// Nested attribute
'credentialSubject.degree.type'
'credentialSubject.degree.name'
'credentialSubject.address.city'

// Entire nested object (reveals all subfields)
'credentialSubject.degree'
```

## Automatically Revealed Fields

The `Presentation` class automatically reveals certain required fields:

- `@context` - JSON-LD context
- `type` - Credential type
- `proof.type` - Proof type
- `proof.verificationMethod` - Issuer's verification method
- `issuer` - Issuer DID (if present in credential)

You don't need to explicitly reveal these - they're always included for proper verification.

## Security Guarantees

### Cryptographic Binding

The BBS signature cryptographically binds ALL attributes (even hidden ones):

- **Cannot tamper** with revealed attributes - signature verification fails
- **Cannot add fake attributes** - they won't verify
- **Cannot reveal different attributes** than what was in the original credential

### Verifier Challenge (Nonce)

Always use a unique challenge from the verifier:

```javascript
const derivedCredentials = presentation.deriveCredentials({
  nonce: 'unique-verifier-challenge-abc123',
});
```

This prevents:
- Replay attacks - old presentations can't be reused
- Credential sharing - presentations are bound to specific verification sessions

## Complete Example

```javascript
import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import Bls12381BBSKeyPairDock2023 from '@docknetwork/credential-sdk/vc/crypto/Bls12381BBSKeyPairDock2023';
import Presentation from '@docknetwork/credential-sdk/vc/presentation';
import { issueCredential, verifyCredential } from '@docknetwork/credential-sdk/vc';
import { keypairToAddress, addressToDID } from '@docknetwork/credential-sdk/modules/ethr-did/utils';

await initializeWasm();

// 1. Setup issuer
const issuerKeypair = Bls12381BBSKeyPairDock2023.generate();
const issuerDID = addressToDID(keypairToAddress(issuerKeypair), 'mainnet');
const issuerKeyDoc = {
  id: `${issuerDID}#keys-bbs`,
  controller: issuerDID,
  type: 'Bls12381BBSVerificationKeyDock2023',
  keypair: issuerKeypair,
};

// 2. Issue full credential
const fullCredential = await issueCredential(issuerKeyDoc, {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://www.w3.org/2018/credentials/examples/v1',
    'https://ld.truvera.io/security/bbs/v1',
  ],
  type: ['VerifiableCredential', 'DriverLicense'],
  issuer: issuerDID,
  issuanceDate: '2024-01-01T00:00:00Z',
  credentialSubject: {
    id: 'did:ethr:vietchain:0x...',
    givenName: 'Alice',
    familyName: 'Smith',
    birthDate: '1985-03-15',
    licenseNumber: 'D1234567',
    ageOver18: true,
    ageOver21: true,
  },
});

// 3. Holder creates selective disclosure for verifier
const presentation = new Presentation();
await presentation.addCredentialToPresent(fullCredential);

// Reveal only age verification - hide name, birthdate, license number
presentation.addAttributeToReveal(0, [
  'credentialSubject.ageOver21',
]);

const derivedCred = presentation.deriveCredentials({
  nonce: 'venue-entrance-check-789',
})[0];

// 4. Verifier checks the credential
const result = await verifyCredential(derivedCred);
console.log(result.verified); // true
console.log(derivedCred.credentialSubject);
// { ageOver21: true }
// Name, birthDate, licenseNumber are HIDDEN
```

## Comparison with Standard Presentations

| Feature | Standard VP (secp256k1) | BBS Selective Disclosure |
|---------|-------------------------|--------------------------|
| Method | `signPresentation()` | `Presentation.deriveCredentials()` |
| Holder signature | Yes (over entire VP) | No (derived proof from issuer signature) |
| Selective disclosure | No - all attributes visible | Yes - choose which to reveal |
| Privacy | Low - full credentials exposed | High - minimal disclosure |
| Use case | Bundle multiple credentials | Hide sensitive attributes |
| Proof type | `authentication` | `assertionMethod` (from issuer) |

## Important Notes

### 1. Not for Bundling Multiple Credentials

The current `Presentation.deriveCredentials()` only supports deriving from a single credential:

```javascript
// ✓ Correct - one credential
await presentation.addCredentialToPresent(credential1);

// ✗ Error - multiple credentials not supported for derivation
await presentation.addCredentialToPresent(credential1);
await presentation.addCredentialToPresent(credential2); // Will error
```

For presenting multiple credentials together, use standard `signPresentation()`.

### 2. Schema Compatibility

BBS presentations create derived credentials, not standard VPs. They have:
- `type: 'Bls12381BBSSignatureProofDock2023'` proof
- Embedded `nonce` and `proofValue`
- Modified credential structure

### 3. Network Cache for Tests

When testing, you need to cache the verification method:

```javascript
// In tests - cache the key document
networkCache[`${issuerDID}#keys-bbs`] = {
  '@context': 'https://ld.truvera.io/security/bbs/v1',
  id: `${issuerDID}#keys-bbs`,
  type: 'Bls12381BBSVerificationKeyDock2023',
  controller: issuerDID,
  publicKeyBase58: credential.proof.publicKeyBase58,
};
```

## See Also

- [BBS Recovery Verification](./ethr-bbs-recovery-verification.md) - How BBS works with ethr DIDs
- [Test Examples](../tests/ethr-vc-issuance-bbs.test.js) - Complete working examples
- [CTO Report](./cto-report-bbs-ethr-did.md) - Architecture and design decisions
