# EcdsaSecp256k1Signature2020 Context Review

**Date:** 2025-11-25
**File:** `packages/credential-sdk/src/vc/contexts/credential-v1-updated.json` (lines 166-214)

## Summary

Reviewed the `EcdsaSecp256k1Signature2020` JSON-LD context definition against the W3C specification at `https://w3id.org/security/suites/secp256k1-2020/v1`.

## Differences Found

| Field | W3C Spec | Our SDK | Impact |
|-------|----------|---------|--------|
| `proofValue` | `@type: "sec:multibase"` | No type | LOW |
| `jws` | Not included | Included | LOW |
| `proofPurpose` methods | 5 methods | 2 methods | LOW |

### 1. `proofValue` Missing Type Annotation

**W3C Spec:**
```json
"proofValue": {
  "@id": "https://w3id.org/security#proofValue",
  "@type": "sec:multibase"
}
```

**Our SDK:**
```json
"proofValue": "sec:proofValue"
```

**Impact:** LOW - The SDK correctly encodes proofValue with multibase base58btc header (`z` prefix) in `CustomLinkedDataSignature.encodeProofValue()`. The type annotation is informational for JSON-LD processors but doesn't affect signature creation/verification.

### 2. `jws` Field Included (Not in W3C Spec)

**Our SDK includes:**
```json
"jws": "sec:jws"
```

**Impact:** LOW - This is **intentional**. The SDK supports both proof formats:
- `proofValue` (multibase) - when `useProofValue: true`
- `jws` (detached JWS) - when `useProofValue: false` (default)

See `CustomLinkedDataSignature.js:177-192` for the implementation. The `jws` field provides backwards compatibility with older jsonld-signature implementations.

### 3. Missing Proof Purpose Methods

**W3C Spec has 5 methods:**
- `assertionMethod`
- `authentication`
- `capabilityInvocation`
- `capabilityDelegation`
- `keyAgreement`

**Our SDK has 2 methods:**
- `assertionMethod`
- `authentication`

**Impact:** LOW - The SDK currently only uses `assertionMethod` for credential issuance (see `presentation.js:215`). The missing methods (`capabilityInvocation`, `capabilityDelegation`, `keyAgreement`) are not used by the SDK.

Note: These methods ARE defined in `did-v1-updated.json` and `security_context.js`, so DID documents will include them. The omission is only in the signature suite's scoped context.

## Does This Affect the SDK?

### Internal Functionality: NO

The SDK works correctly because:
1. Signature creation/verification uses programmatic encoding, not JSON-LD type coercion
2. The `jws` field is intentionally supported for flexibility
3. Only `assertionMethod` proof purpose is used currently

### External Interoperability: MINIMAL RISK

| Scenario | Risk |
|----------|------|
| Verifying our credentials with strict W3C tools | LOW - proofValue encoding is correct |
| Using capabilityInvocation/Delegation | N/A - Not supported anyway |
| Consuming credentials from other W3C implementations | LOW - We accept both jws and proofValue |

## Recommendation

**No immediate changes required.** The context works correctly for the SDK's use case.

**Optional improvements for strict W3C compliance:**
1. Add `@type: "sec:multibase"` to proofValue (cosmetic)
2. Add missing proof purpose methods to the signature context (future-proofing)

## References

- W3C Spec: https://w3id.org/security/suites/secp256k1-2020/v1 (redirects to https://ns.did.ai/suites/secp256k1-2020/v1)
- Implementation: `packages/credential-sdk/src/vc/crypto/EcdsaSecp256k1Signature2020.js`
- Base class: `packages/credential-sdk/src/vc/crypto/common/CustomLinkedDataSignature.js`
