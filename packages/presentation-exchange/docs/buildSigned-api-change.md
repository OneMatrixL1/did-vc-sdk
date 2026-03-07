# `buildSigned` API Change

## What changed

`VPRequestBuilder.buildSigned()` no longer takes a callback. It now accepts a `KeyDoc` and optional resolver directly and handles the entire signing ceremony internally.

### Before

```ts
const signed = await builder.buildSigned(async (unsigned) => {
  const suite = getSuiteFromKeyDoc(keyDoc);
  const purpose = new AuthenticationProofPurpose({ domain, challenge });
  const vp = { '@context': [...], type: ['VerifiablePresentation'], ...unsigned };
  const result = await signPresentation(vp, keyDoc, challenge, domain, resolver, true, purpose, false);
  return result.proof;
});
```

### After

```ts
const signed = await builder.buildSigned(keyDoc, resolver);
```

## Why

The callback approach was error-prone. did-app was signing with `AuthenticationProofPurpose` instead of `AssertionProofPurpose`, which caused `verifyVPRequest()` to reject the proof. The signing logic is now internal to presentation-exchange so consumers can't get it wrong.

## What `buildSigned` does internally

1. Calls `build()` to get the unsigned VPRequest
2. Wraps it as a VP-like LD document (`@context`, `type: ['VerifiablePresentation']`, `holder`)
3. Signs with `signPresentation()` using `AssertionProofPurpose({ domain, challenge })`
   - `domain` = hostname from `verifierUrl`
   - `challenge` = `nonce`
   - `addSuiteContext = false`
4. Extracts the proof and attaches it to the VPRequest

## `KeyDoc` interface

```ts
import type { KeyDoc } from '@1matrix/presentation-exchange';

interface KeyDoc {
  id: string;           // e.g. 'did:ethr:0x...#controller'
  type: string;         // e.g. 'EcdsaSecp256k1VerificationKey2019'
  keypair: unknown;     // crypto keypair instance
  controller: string;   // DID
}
```

This is the same shape credential-sdk's `signPresentation` expects for its `keyDoc` parameter.

## Migration in did-app

Find all call sites of `buildSigned(async (unsigned) => { ... })` and replace with:

```ts
// Old
const signed = await vpRequestBuilder.buildSigned(async (unsigned) => {
  // ... manual signing logic ...
  return proof;
});

// New
const signed = await vpRequestBuilder.buildSigned(keyDoc, resolver);
```

Remove any imports of `jsonld-signatures`, `AuthenticationProofPurpose`, or `AssertionProofPurpose` that were only used for VPRequest signing.
