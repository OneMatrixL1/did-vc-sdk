# Presentation Exchange — Design Overview

A library for requesting, matching, assembling, and verifying Verifiable Presentations.
Supports selective disclosure and zero-knowledge proofs over recursive AND/OR rule trees.

---

## System Flow

```mermaid
sequenceDiagram
    participant V as Verifier
    participant H as Holder
    participant W as Wallet / App

    V->>V: Build VPRequest (rules tree)
    V->>H: Send VPRequest

    H->>W: matchCredentials(rules, credentials)
    W->>H: RuleTreeMatch (candidates per DocumentRequest)

    H->>W: CredentialSelection[]
    W->>W: resolvePresentation(request, credentials, selections, options)
    W->>W: deriveCredential() [optional — BBS+, ZKP]
    W->>W: signPresentation()
    W->>H: VerifiablePresentation

    H->>V: Submit VerifiablePresentation
    V->>V: verifyPresentationStructure(request, vp)
    V->>V: verify cryptographic proof [caller's responsibility]
```

---

## Architecture

```mermaid
graph TD
    subgraph Types
        T1[request.ts<br/>VPRequest · DocumentRequest<br/>conditions · proof systems]
        T2[response.ts<br/>VerifiablePresentation<br/>PresentedCredential · proofs]
        T3[matching.ts<br/>RuleTreeMatch<br/>CandidateCredential]
        T4[credential.ts<br/>MatchableCredential]
    end

    subgraph Builders
        B1[VPRequestBuilder]
        B2[DocumentRequestBuilder]
        B1 -->|produces| T1
        B2 -->|produces| T1
    end

    subgraph Resolver
        R1[matcher.ts<br/>matchCredentials]
        R2[resolver.ts<br/>resolvePresentation]
        R3[field-extractor.ts]
        R4[tree-evaluator.ts]
        R1 --> R3
        R1 --> R4
        R2 --> R3
    end

    subgraph Verifier
        V1[structural-verifier.ts<br/>verifyPresentationStructure]
    end

    T1 --> R1
    T4 --> R1
    R1 -->|RuleTreeMatch| T3
    T3 -->|CredentialSelection| R2
    T1 --> R2
    R2 -->|VerifiablePresentation| T2
    T1 --> V1
    T2 --> V1
```

---

## Request Tree Structure

VPRequests use a recursive AND/OR tree of `DocumentRequest` leaf nodes.

```mermaid
graph TD
    Root["VPRequest<br/>(nonce, verifier, expiresAt)"]
    Root --> Rules

    Rules["rules: DocumentRequestNode<br/>(AND)"]
    Rules --> DR1["DocumentRequest<br/>docType: CCCDCredential<br/>disclosureMode: selective"]
    Rules --> OR["(OR)"]
    OR --> DR2["DocumentRequest<br/>docType: PassportCredential"]
    OR --> DR3["DocumentRequest<br/>docType: DriverLicenseCredential"]

    DR1 --> C1["DiscloseCondition<br/>$.credentialSubject.name"]
    DR1 --> C2["DiscloseCondition<br/>$.credentialSubject.dob"]
    DR1 --> C3["ZKPCondition<br/>circuit: age_gt_18<br/>system: groth16"]
```

---

## Credential Matching

`matchCredentials` evaluates the rules tree against a credential set and produces a mirror tree of match results.

```mermaid
flowchart LR
    Creds["MatchableCredential[]"]
    Rules["DocumentRequestNode"]

    Creds --> M["matchCredentials()"]
    Rules --> M

    M --> Tree["RuleTreeMatch"]

    Tree --> LRM["LogicalRuleMatch<br/>satisfied: bool"]
    Tree --> DRM["DocumentRequestMatch<br/>satisfied: bool"]

    DRM --> CC["CandidateCredential[]<br/>disclosedFields<br/>missingFields<br/>satisfiableZKPs<br/>unsatisfiableZKPs<br/>fullyQualified"]
```

Each `CandidateCredential` filters by:
1. **docType** — credential must have at least one matching type
2. **issuer** — if specified, issuer DID must be in the allowed list
3. **fields** — JSONPath resolution of each `DiscloseCondition`
4. **ZKP inputs** — all `privateInputs` paths must resolve in the credential

---

## Presentation Assembly

```mermaid
flowchart TD
    Sel["CredentialSelection[]<br/>(docRequestID → credentialIndex)"]
    Opts["ResolveOptions<br/>holder · signPresentation()<br/>deriveCredential() [optional]"]

    Sel --> Resolve["resolvePresentation()"]
    Opts --> Resolve

    Resolve --> Validate["Validate selections<br/>against rules"]
    Validate --> Mode{disclosureMode}

    Mode -->|full| Full["credentialToFull()<br/>pass verbatim"]
    Mode -->|selective + deriveCredential| Derive["deriveCredential()<br/>BBS+ / ZKP"]
    Mode -->|selective| Select["credentialToSelective()<br/>JSONPath field extraction"]

    Full --> Assemble
    Derive --> Assemble
    Select --> Assemble

    Assemble["Build UnsignedPresentation<br/>+ presentationSubmission map"]
    Assemble --> Sign["signPresentation()"]
    Sign --> VP["VerifiablePresentation"]
```

---

## Modules

| Module | File | Responsibility |
|---|---|---|
| **Types** | `types/request.ts` | VPRequest, DocumentRequest, condition nodes, proof systems |
| | `types/response.ts` | VerifiablePresentation, PresentedCredential, HolderProof, CredentialProof |
| | `types/matching.ts` | RuleTreeMatch, CandidateCredential, CredentialSelection |
| | `types/credential.ts` | MatchableCredential structural supertype |
| | `types/localization.ts` | LocalizableString for multilingual names/purposes |
| **Builders** | `builder/request-builder.ts` | Fluent API for VPRequest (auto-generates nonce, timestamps) |
| | `builder/document-request-builder.ts` | Fluent API for DocumentRequest with `disclose()` and `zkp()` |
| **Resolver** | `resolver/matcher.ts` | Match credentials to request tree → RuleTreeMatch |
| | `resolver/resolver.ts` | Assemble and sign VerifiablePresentation |
| | `resolver/field-extractor.ts` | Walk condition tree, collect DiscloseConditions and ZKPConditions |
| | `resolver/tree-evaluator.ts` | Generic AND/OR tree evaluator (reusable) |
| **Verifier** | `verifier/structural-verifier.ts` | Validate VP structure against request (nonce, domain, coverage, types) |
| **Utils** | `utils/jsonpath.ts` | Minimal `$.a.b.c` JSONPath resolver |
| | `utils/localization.ts` | Resolve LocalizableString to plain string with language fallback |

---

## Key Design Decisions

**Recursive AND/OR trees** — Both request rules and credential conditions are recursive logical trees, enabling complex multi-credential policies (e.g. "passport AND (CCCD OR driver's license)").

**Disclosure modes** — `selective` extracts only requested fields; `full` passes the credential verbatim. Useful for trusted-verifier flows where no privacy filtering is needed.

**Pluggable derivation** — `deriveCredential` callback decouples the library from any specific selective-disclosure cryptography (BBS+, CL, SD-JWT). The library handles orchestration; the caller provides the crypto.

**Structural verification only** — `verifyPresentationStructure` checks nonce, domain, coverage, and credential types. Cryptographic proof verification is left to the caller to avoid coupling to specific proof suites.

**JSONPath scope** — Only `$.a.b.c` dot-notation is supported. Wildcards, filters, and bracket notation are out of scope.
