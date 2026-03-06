# VPRequest v2.0 — Migration Guide

## Summary

`VPRequest` has been reworked from unsigned JSON with a nested `VerifierInfo` object into a VP-like signed structure with flat verifier fields and an optional `proof`. This mirrors how `VerifiablePresentation` works — the verifier now "presents" their request.

## What Changed

### VPRequest structure (before → after)

```diff
 interface VPRequest {
+  '@context'?: string[];
+  type: ['VerifiablePresentationRequest'];
   id: string;
   version: string;              // default: '1.0' → '2.0'
   name: LocalizableString;
   nonce: string;
-  verifier: VerifierInfo;       // nested object
+  verifier: string;             // DID string (was VerifierInfo.id)
+  verifierName: LocalizableString;  // was VerifierInfo.name
+  verifierUrl: string;              // was VerifierInfo.url
+  verifierCredentials?: PresentedCredential[];  // was VerifierInfo.credentials
   createdAt: string;
   expiresAt: string;
   rules: DocumentRequestNode;
+  proof?: VerifierRequestProof; // NEW — optional verifier signature
 }
```

### Side-by-side: VP (response) vs VPRequest (new)

| VP (response)              | VPRequest (new)                |
|----------------------------|--------------------------------|
| `holder: string`           | `verifier: string`             |
| `verifiableCredential[]`   | `verifierCredentials[]`        |
| `proof: HolderProof`       | `proof?: VerifierRequestProof` |

### New types

**`VerifierRequestProof`** — verifier's signature over the request:

```ts
interface VerifierRequestProof {
  type: string;
  cryptosuite?: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  challenge: string;   // must equal nonce
  domain: string;      // must match verifierUrl hostname
  proofValue: string;
}
```

**`UnsignedVPRequest`** — `Omit<VPRequest, 'proof'>`, used as the payload for signing callbacks.

### Deprecated

**`VerifierInfo`** — still exported for backward compatibility, but should not be used in new code.

---

## Migration Steps

### 1. Reading verifier fields

```diff
- request.verifier.id
+ request.verifier

- request.verifier.name
+ request.verifierName

- request.verifier.url
+ request.verifierUrl

- request.verifier.credentials
+ request.verifierCredentials
```

### 2. Building requests (no change needed)

`setVerifier()` still accepts the same `{ id, name, url }` shape:

```ts
new VPRequestBuilder('req-1')
  .setVerifier({ id: 'did:web:example', name: 'Example', url: 'https://example.com' })
  .addDocumentRequest(docReq)
  .build();
```

`addVerifierCredential()` no longer requires `setVerifier()` to be called first.

### 3. Signed requests (new)

Use `buildSigned()` to attach a verifier proof. The method handles the signing ceremony internally using `AssertionProofPurpose`:

```ts
import type { KeyDoc } from '@1matrix/presentation-exchange';

const keyDoc: KeyDoc = {
  id: 'did:web:example#key-1',
  type: 'EcdsaSecp256k1VerificationKey2019',
  keypair: myKeypair,       // crypto keypair instance
  controller: 'did:web:example',
};

const signedRequest = await new VPRequestBuilder('req-1')
  .setVerifier({ id: 'did:web:example', name: 'Example', url: 'https://example.com' })
  .addDocumentRequest(docReq)
  .buildSigned(keyDoc, resolver);
```

The proof `domain` is derived from `verifierUrl` hostname and `challenge` from the request `nonce`.

Proof is **optional** — unsigned requests still work for dev/testing.

### 4. Verifier credential error messages

Error messages from `verifyVPRequest()` changed:

```diff
- "verifier.id"             → "verifier"
- "verifier.url"            → "verifierUrl"
- "verifier.credentials[i]" → "verifierCredentials[i]"
```

### 5. Request validation now checks proof envelope

If `proof` is present on a VPRequest, `verifyVPRequest()` validates:
- `verificationMethod` is present
- `proofPurpose === 'assertionMethod'`
- `challenge === nonce`
- `domain` matches `verifierUrl` hostname

Cryptographic proof verification remains the caller's responsibility (same pattern as VP).

---

## Version

Default builder version bumped from `'1.0'` to `'2.0'`.
