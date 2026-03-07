# Presentation Exchange — Integration Guide

> Branch: `feature/audit-nation-id-security`
> Base: `master` — 8 commits ahead
> Last updated: 2026-03-06

Quick-start reference for agents and developers integrating with the `presentation-exchange` package. For architecture diagrams see [design.md](./design.md). For a full CCCD scenario see [cccd-use-case.md](./cccd-use-case.md).

---

## What This Branch Adds (over master)

| Commit | What changed |
|--------|-------------|
| `c2f40c07` | Migrated CCCD credential system into `credential-sdk/src/icao/`, TypeScript audit |
| `750a1591` | Improved TypeScript handling across both packages |
| `4503eb97` | Resolved all ESLint errors in presentation-exchange |
| `54fa7f7f` | Added design.md and cccd-use-case.md docs |
| `c92c6841` | Moved ICAO schema resolver into presentation-exchange (was in credential-sdk) |
| `ab2adad0` | Integrated BBS+ selective disclosure into presentation-exchange |
| `4cd7d868` | Enabled ICAO DG-level selective disclosure, guarded empty DG hashes in SODVerifier |
| `6035478a` | Simplified `credentialSubject` type (single Record, not array), expanded test coverage |

---

## Package Map

```
packages/
├── credential-sdk/          # Core VC primitives, crypto, ICAO/SOD verification
│   └── src/icao/
│       ├── credentials/     # issueCredential() for CCCD (SOD-backed)
│       ├── icao-profile/    # Document profiles, field-to-DG mappings
│       ├── sod-verifier.ts  # SOD signature + per-DG hash verification
│       └── ...
│
└── presentation-exchange/   # Request ↔ match ↔ resolve ↔ verify orchestration
    ├── src/
    │   ├── builder/         # VPRequestBuilder, DocumentRequestBuilder
    │   ├── resolver/        # matchCredentials(), resolvePresentation()
    │   ├── resolvers/       # Schema resolvers (JSON, ICAO, BBS+)
    │   ├── verifier/        # verifyPresentationStructure()
    │   ├── types/           # All shared TypeScript interfaces
    │   └── index.ts         # Public API re-exports
    └── docs/
```

---

## Integration Flow (5 Steps)

```
Verifier                    Holder Wallet                  Verifier
   │                             │                            │
   │  1. Build VPRequest         │                            │
   │────────────────────────────>│                            │
   │                             │                            │
   │         2. matchCredentials(rules, creds)                │
   │                             │                            │
   │         3. resolvePresentation(request, creds, picks)    │
   │                   ↳ deriveCredential (selective)          │
   │                   ↳ signPresentation (holder proof)      │
   │                             │                            │
   │                             │  4. Submit VP              │
   │                             │───────────────────────────>│
   │                             │                            │
   │                             │  5. verifyPresentation     │
   │                             │     Structure + crypto     │
```

---

## Step-by-Step Code

### Step 1 — Verifier builds a VPRequest

```typescript
import { VPRequestBuilder, DocumentRequestBuilder } from '@1matrix/presentation-exchange';

const vpRequest = new VPRequestBuilder('req-kyc-001', 'random-nonce-xyz')
  .setName('Identity Verification')
  .setVerifier({ id: 'did:web:bank.vn', name: 'Bank', url: 'https://bank.vn' })
  .setExpiresAt('2099-12-31T23:59:59Z')
  .addDocumentRequest(
    new DocumentRequestBuilder('dr-cccd', 'CCCDCredential')
      .setSchemaType('ICAO9303SOD')          // or 'JsonSchema' for standard VCs
      .setDisclosureMode('selective')         // 'selective' (default) | 'full'
      .disclose('c-name', 'fullName',        { purpose: 'Full name' })
      .disclose('c-dob',  'dateOfBirth',     { purpose: 'Date of birth' })
      .disclose('c-photo','photo',           { purpose: 'Photo', optional: true })
  )
  .build();
```

**Key points:**
- `schemaType` selects which `SchemaResolver` processes the credential
- `disclose(conditionID, field, opts)` — field format depends on schemaType:
  - `JsonSchema` → JSONPath: `$.credentialSubject.name`
  - `ICAO9303SOD` → profile field ID: `fullName`, `dateOfBirth`, `photo`
- `optional: true` means the field is nice-to-have, not required for matching
- Rules can be nested with AND/OR via `addLogicalGroup()`

### Step 2 — Holder matches credentials

```typescript
import { matchCredentials } from '@1matrix/presentation-exchange';
import type { DocumentRequestMatch } from '@1matrix/presentation-exchange';

const matchResult = matchCredentials(vpRequest.rules, holderCredentials);
// matchResult mirrors the request tree with satisfied/candidates info

if (matchResult.type === 'DocumentRequest') {
  const match = matchResult as DocumentRequestMatch;
  console.log(match.satisfied);                    // true if any candidate is fullyQualified
  console.log(match.candidates[0].disclosedFields); // ['fullName', 'dateOfBirth', 'photo']
  console.log(match.candidates[0].missingFields);   // [] (empty = fully qualified)
}
```

**`CandidateCredential` fields:**
| Field | Description |
|-------|-------------|
| `credential` | The original MatchableCredential |
| `index` | Index in the input array |
| `disclosedFields` | Fields the resolver can extract |
| `missingFields` | Required fields that couldn't be resolved |
| `fullyQualified` | `true` if no missing fields and no unsatisfiable ZKPs |

### Step 3 — Holder resolves and signs VP

```typescript
import { resolvePresentation } from '@1matrix/presentation-exchange';

const vp = await resolvePresentation(
  vpRequest,
  holderCredentials,
  [{ docRequestID: 'dr-cccd', credentialIndex: 0 }],  // user picks
  {
    holder: 'did:ethr:vietchain:0xABC...',
    signPresentation: async (unsigned) => {
      // Sign the unsigned VP with your key (any proof suite)
      // Return a HolderProof object
      return {
        type: 'EcdsaSecp256k1Signature2019',
        verificationMethod: 'did:ethr:...#keys-1',
        proofPurpose: 'authentication',
        challenge: vpRequest.nonce,
        domain: 'bank.vn',
        proofValue: '...',
      };
    },
  },
);
```

**What happens inside `resolvePresentation`:**

| Disclosure Mode | Behavior |
|-----------------|----------|
| `'full'` | Credential passed verbatim (no stripping) |
| `'selective'` | Calls `SchemaResolver.deriveCredential()` with only the requested fields |
| `'selective'` + BBS+ proof | Auto-wraps with `createBBSResolver()` → produces derived BBS proof |
| `'selective'` + ICAO | Strips unneeded DGs (e.g., keeps dg13+dg2, drops dg1) |

### Step 4 — Verifier validates VP structure

```typescript
import { verifyPresentationStructure } from '@1matrix/presentation-exchange';

const result = verifyPresentationStructure(vpRequest, vp);
// result.valid === true
// result.errors === []   (or list of structural violations)
```

Checks: nonce matches, domain matches, all required docRequests covered, credential types match.

### Step 5 — Verifier verifies crypto + reads fields

Crypto verification is the **caller's responsibility** (presentation-exchange is proof-suite agnostic):

```typescript
// Standard VC/VP proofs (EcdsaSecp256k1, Ed25519, BBS+):
import { verifyPresentation } from '@1matrix/credential-sdk/vc';
const cryptoResult = await verifyPresentation(vp, {
  challenge: vpRequest.nonce,
  domain: 'bank.vn',
});

// ICAO credentials with ICAO9303SODSignature proof:
// The SODVerifier checks per-DG hashes against the SOD.
// Partial DGs (from selective disclosure) are supported —
// missing DGs are simply skipped during verification.
```

Read disclosed fields using the schema resolver:

```typescript
import { createICAOSchemaResolver } from '@1matrix/presentation-exchange';

const resolver = createICAOSchemaResolver();
const cred = vp.verifiableCredential[0];

const name = resolver.resolveField(cred, 'fullName');
// { found: true, value: 'NGUYEN VAN A' }

const photo = resolver.resolveField(cred, 'photo');
// { found: true, value: '<base64 jpeg>' }

// Field from a stripped DG returns found: false
const mrzDob = resolver.resolveField(cred, 'mrzDateOfBirth');
// { found: false, value: undefined }
```

---

## Schema Resolvers

Resolvers are registered by `schemaType` and handle field resolution + credential derivation.

| Schema Type | Resolver | Field Format | Selective Disclosure |
|-------------|----------|-------------|---------------------|
| `JsonSchema` | `jsonSchemaResolver` | JSONPath (`$.credentialSubject.name`) | Strips unrequested fields from subject |
| `ICAO9303SOD` | `createICAOSchemaResolver()` | Profile field ID (`fullName`, `photo`) | Strips unrequested DG blobs (dg1, dg2, dg13...) |
| BBS+ (auto) | `createBBSResolver(inner)` | Delegates to inner resolver | Produces derived BBS proof via `Presentation` class |

### Adding a custom resolver

```typescript
import type { SchemaResolver } from '@1matrix/presentation-exchange';

const myResolver: SchemaResolver = {
  type: 'MyCustomSchema',

  resolveField(credential, field) {
    // Return { found: boolean, value: unknown }
  },

  async deriveCredential(credential, disclosedFields, options?) {
    // Return PresentedCredential with only disclosed data
  },
};

// Pass custom resolvers at match + resolve time:
matchCredentials(rules, creds, { MyCustomSchema: myResolver });
resolvePresentation(request, creds, selections, {
  holder: '...',
  resolvers: { MyCustomSchema: myResolver },
  signPresentation: async (unsigned) => { ... },
});
```

---

## ICAO Selective Disclosure — How It Works

ICAO credentials store data as binary Data Group (DG) blobs in `credentialSubject`:

```
credentialSubject: {
  id:   'did:vbsn:cccd:...',
  dg1:  '<base64>',   // MRZ (machine-readable zone)
  dg2:  '<base64>',   // Biometric photo
  dg13: '<base64>',   // Vietnamese proprietary TLV (name, DOB, address...)
  dg14: '<base64>',   // Security info
  dg15: '<base64>',   // Active Auth public key
}
```

The `ICAO9303SODSignature` proof contains a government-signed SOD with **per-DG hashes**. This enables DG-level selective disclosure:

1. **Profile lookup** — `VN_CCCD_2024` maps field IDs to DG sources:
   - `fullName` → `dg13`, `dateOfBirth` → `dg13`, `photo` → `dg2`, `documentType` → `dg1`

2. **`getRequiredDGs(profile, fields)`** — Computes the minimal set of DGs needed:
   - Request `[fullName, dateOfBirth, photo]` → needs `[dg13, dg2]`

3. **`deriveCredential()`** — Builds a new `credentialSubject` with only required DGs:
   - Keeps: `dg13`, `dg2`, `id`
   - Strips: `dg1`, `dg14`, `dg15`, `com`

4. **SOD verification** — `SODVerifier.verifyDGHashes()` checks only present DGs:
   - Missing DGs are skipped (not failures)
   - Guard: `dgHashes.length > 0` prevents vacuous truth when zero DGs match

```
Full credential:      dg1 + dg2 + dg13 + dg14 + dg15
                          ↓ selective disclosure
Derived credential:         dg2 + dg13
                          ↓ SOD verification
SOD checks:                 hash(dg2) ✓   hash(dg13) ✓   (dg1,dg14,dg15 skipped)
```

---

## Key Type Signatures

```typescript
// Core types — import from '@1matrix/presentation-exchange'

interface MatchableCredential {
  type: readonly string[] | string[];
  issuer: string | { id: string; name?: string };
  credentialSubject: Record<string, unknown>;     // Always a single object (not array)
  proof?: CredentialProof | CredentialProof[];
  [key: string]: unknown;
}

interface VPRequest {
  id: string;
  version: string;
  name: LocalizableString;
  nonce: string;
  verifier: VerifierInfo;
  createdAt: string;
  expiresAt: string;
  rules: DocumentRequestNode;                     // Recursive AND/OR tree
}

interface VerifiablePresentation {
  '@context': string[];
  type: ['VerifiablePresentation'];
  holder: string;
  verifiableCredential: PresentedCredential[];
  presentationSubmission: SubmissionEntry[];       // Maps docRequestID → credential index
  proof: HolderProof;
}

interface SchemaResolver {
  readonly type: string;
  resolveField(cred: MatchableCredential, field: string): { found: boolean; value: unknown };
  deriveCredential(cred: MatchableCredential, fields: string[], opts?: DeriveOptions): Promise<PresentedCredential>;
}

// Functions
function matchCredentials(rules: DocumentRequestNode, creds: MatchableCredential[], resolvers?: SchemaResolverMap): RuleTreeMatch;
function resolvePresentation(request: VPRequest, creds: MatchableCredential[], selections: CredentialSelection[], options: ResolveOptions): Promise<VerifiablePresentation>;
function verifyPresentationStructure(request: VPRequest, vp: VerifiablePresentation): { valid: boolean; errors: string[] };
```

---

## Test Coverage

| Test File | What it covers |
|-----------|---------------|
| `schema-resolver.test.ts` | JSON + ICAO resolvers, field resolution, selective derivation, full CCCD flow (5 steps) |
| `cccd-e2e.test.ts` | Real secp256k1 crypto: issue VC → match → resolve (selective) → sign VP → verify structure → read fields. Asserts dg1 stripped, dg13+dg2 kept, MRZ fields absent. |
| `bbs-selective-disclosure.test.ts` | BBS+ derivation through PE: issue BBS VC → match → resolve (selective) → verify derived BBS proof |
| `full-disclosure.test.ts` | Full disclosure mode (credential passed verbatim) |
| `matcher.test.ts` | Matching logic: type filtering, issuer filtering, AND/OR trees |
| `school-enrollment-e2e.test.ts` | Multi-credential E2E with JsonSchema resolver |

---

## Important Notes for Integration

1. **`credentialSubject` is always a single `Record<string, unknown>`** — never an array. This was simplified on this branch.

2. **BBS+ is auto-detected** — If a credential's proof type is `Bls12381BBSSignatureDock2023`, `resolvePresentation` automatically wraps the resolver with `createBBSResolver`. No extra config needed.

3. **ICAO profile detection** — The ICAO resolver detects the profile from `credential.proof.dgProfile` (set during issuance) or falls back to matching `credential.type` against registered profiles. Pass a specific profile to `createICAOSchemaResolver(profile)` to override.

4. **Crypto verification is not in presentation-exchange** — `verifyPresentationStructure` only checks structure. Crypto verification (VP proof, VC proof, SOD) lives in `credential-sdk`.

5. **SODVerifier now guards against empty DG matches** — `dgHashes.length > 0` ensures a credential with zero matching DGs cannot pass verification via `[].every(...)` returning `true`.

6. **Selective disclosure + EcdsaSecp256k1** — Selective disclosure modifies `credentialSubject`, which invalidates standard JSON-LD signatures (EcdsaSecp256k1, Ed25519). Only use selective disclosure with proof types that support it: `BBS+` (derived proofs) or `ICAO9303SODSignature` (per-DG hashes via SOD).
