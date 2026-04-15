# ZKP Domain-Scoped Proof System

## 1. Architecture Overview

```mermaid
graph TB
    subgraph "App Layer (did-app)"
        CS[CredentialService]
        BP[build-presentation]
        PG[proof-generation.ts<br/>wiring layer]
    end

    subgraph "SDK Layer (presentation-exchange)"
        PS[ICAO9303ProofSystem<br/>orchestrator]
        WB[witness-builder]
        SP[sod-parser]
        DP[dg13-parser]
        DOM[domain]
        STORE[ProofStore]
        RES[resolvePresentation]
    end

    subgraph "Injected by App"
        ZKP[ZKPProvider<br/>native-zkp-prover]
        HASH[Poseidon2Hasher]
        MTB[MerkleTreeBuilder]
    end

    CS -->|"after save"| PG
    BP -->|"before share"| PG
    PG -->|"creates"| PS
    PS --> WB
    WB --> SP
    WB --> DP
    PS --> DOM
    PS --> STORE
    PS -.->|"prove()"| ZKP
    PS -.->|"hash()"| HASH
    PS -.->|"build()"| MTB
    DOM -.->|"hash()"| HASH
    BP -->|"zkpProofs"| RES

    style PS fill:#e1f5fe,stroke:#0288d1
    style ZKP fill:#fff3e0,stroke:#f57c00
    style HASH fill:#fff3e0,stroke:#f57c00
    style MTB fill:#fff3e0,stroke:#f57c00
```

## 2. Proof Chain — Circuit Dependency

```mermaid
graph LR
    SOD["sod-verify<br/>ECDSA signature check"]
    DGM["dg-map<br/>extract DG13 hash"]
    MKL["dg13-merklelize<br/>build Merkle tree"]
    PRED["predicate circuits<br/>date-gt, date-lt, etc."]
    REVEAL["dg13-field-reveal<br/>disclose single field"]

    SOD -->|"econtent_binding"| DGM
    DGM -->|"dg_binding"| MKL
    MKL -->|"commitment"| PRED
    MKL -->|"commitment"| REVEAL

    SOD -.->|"same salt"| DGM
    DGM -.->|"same salt"| MKL
    MKL -.->|"same salt"| PRED

    style SOD fill:#c8e6c9,stroke:#388e3c
    style DGM fill:#c8e6c9,stroke:#388e3c
    style MKL fill:#c8e6c9,stroke:#388e3c
    style PRED fill:#fff9c4,stroke:#fbc02d
    style REVEAL fill:#fff9c4,stroke:#fbc02d
```

**Chain proofs** (green) are pre-computed at import time.
**On-demand proofs** (yellow) are generated per VP request.

## 3. Credential Import Flow

```mermaid
sequenceDiagram
    participant User
    participant NFC as NFC Scanner
    participant CS as CredentialService
    participant SDK as credential-sdk
    participant Store as VC Storage
    participant PG as proof-generation
    participant PS as ICAO9303ProofSystem
    participant Plugin as NativeZkpProver

    User->>NFC: Scan CCCD
    NFC->>CS: IDCardData (SOD, DG1, DG2, DG13...)
    CS->>SDK: issueCCCDCredential(sod, dgs)
    SDK-->>CS: W3C VerifiableCredential
    CS->>Store: saveCredential(vc)
    Store-->>CS: credentialId

    Note over CS,Plugin: Fire-and-forget (non-blocking)

    CS--)PG: generateDefaultDomainProofs(vc, id)
    PG->>PS: deriveDomain("1matrix")
    PS->>Plugin: poseidon2Hash(pack("1matrix"))
    Plugin-->>PS: domain hash

    PG->>PS: generateChainProofs(vc, domain)

    PS->>PS: buildSODWitnessData(sod)
    PS->>Plugin: prove("sod-verify", inputs)
    Plugin-->>PS: {proofValue, econtent_binding}

    PS->>Plugin: prove("dg-map", inputs + econtent_binding)
    Plugin-->>PS: {proofValue, dg_binding}

    PS->>PS: buildDG13WitnessData(dg13)
    PS->>Plugin: buildMerkleTree(fields, salt)
    Plugin-->>PS: {root, commitment, leaves, siblings}

    PS->>Plugin: prove("dg13-merklelize", inputs)
    Plugin-->>PS: {proofValue, binding, identity, commitment}

    PS->>PS: assert dg_binding == binding
    PS->>Store: save DomainProofSet
```

## 4. P2P Sharing Flow (Quick Share — Same Domain)

```mermaid
sequenceDiagram
    participant Verifier
    participant Prover as Prover App
    participant BP as build-presentation
    participant PG as proof-generation
    participant PS as ProofStore
    participant SDK as resolvePresentation

    Verifier->>Prover: VPRequest (via WebRTC)
    Prover->>BP: buildPresentation(request, credential)

    BP->>BP: extract ZKP conditions from request
    BP->>PG: getOrGenerateProofs(vc, id, "1matrix")
    PG->>PS: get(credentialId, domainHash)
    PS-->>PG: cached DomainProofSet

    Note over BP: Map chain proofs to conditionIDs

    BP->>SDK: resolvePresentation(request, cred, {zkpProofs})
    SDK->>SDK: deriveCredential (selective disclosure)
    SDK->>SDK: attach ZKP proofs to derived credential
    SDK->>SDK: sign VP envelope
    SDK-->>BP: VerifiablePresentation

    BP-->>Prover: VP with ZKP proofs
    Prover->>Verifier: VPResponse (via WebRTC)
```

## 5. P2P Sharing Flow (New Domain)

```mermaid
sequenceDiagram
    participant Prover as Prover App
    participant PG as proof-generation
    participant PS as ICAO9303ProofSystem
    participant Plugin as NativeZkpProver
    participant Store as ProofStore

    Prover->>PG: getOrGenerateProofs(vc, id, "partner-domain")
    PG->>Store: get(credentialId, partnerHash)
    Store-->>PG: null (not cached)

    PG->>PS: generateChainProofs(vc, partnerDomain)

    Note over PS,Plugin: Full chain regeneration<br/>(sod-verify → dg-map → dg13-merklelize)
    PS->>Plugin: prove("sod-verify", {..., salt: partnerHash})
    Plugin-->>PS: proof + econtent_binding
    PS->>Plugin: prove("dg-map", {...})
    Plugin-->>PS: proof + dg_binding
    PS->>Plugin: buildMerkleTree(fields, partnerHash)
    Plugin-->>PS: tree
    PS->>Plugin: prove("dg13-merklelize", {...})
    Plugin-->>PS: proof + binding + commitment

    PS->>Store: save(DomainProofSet)
    PS-->>PG: DomainProofSet
```

## 6. Data Model — Class Diagram

```mermaid
classDiagram
    class Domain {
        +name: string
        +hash: string
    }

    class ChainProof {
        +circuitId: string
        +proofValue: string
        +publicInputs: Record
        +publicOutputs: Record
    }

    class CachedMerkleTree {
        +root: string
        +commitment: string
        +leaves: string[32]
        +siblings: string[32][5]
    }

    class DomainProofSet {
        +domain: Domain
        +credentialId: string
        +createdAt: string
        +sodVerify: ChainProof
        +dgMap: ChainProof
        +dg13Merklelize: ChainProof
        +merkleTree: CachedMerkleTree
    }

    class ZKPProvider {
        <<interface>>
        +prove(params): Promise~ZKPProveResult~
    }

    class Poseidon2Hasher {
        <<interface>>
        +hash(inputs, len): Promise~string~
    }

    class MerkleTreeBuilder {
        <<interface>>
        +build(fields, salt): Promise~CachedMerkleTree~
    }

    class ProofStore {
        <<interface>>
        +save(proofSet): Promise~void~
        +get(credId, domainHash): Promise~DomainProofSet~
        +listDomains(credId): Promise~Domain[]~
        +deleteAll(credId): Promise~void~
    }

    class ICAO9303ProofSystem {
        -zkp: ZKPProvider
        -hasher: Poseidon2Hasher
        -merkle: MerkleTreeBuilder
        -store: ProofStore
        +deriveDomain(name): Promise~Domain~
        +generateChainProofs(cred, id, domain): Promise~DomainProofSet~
        +getOrGenerateProofs(cred, id, domain): Promise~DomainProofSet~
        +generatePredicateProof(proofSet, circuitId, tagId, extra): Promise~ChainProof~
        +generateFieldRevealProof(proofSet, tagId): Promise~ChainProof~
        +deleteProofs(credId): Promise~void~
    }

    DomainProofSet --> Domain
    DomainProofSet --> "3" ChainProof
    DomainProofSet --> CachedMerkleTree
    ICAO9303ProofSystem --> ZKPProvider
    ICAO9303ProofSystem --> Poseidon2Hasher
    ICAO9303ProofSystem --> MerkleTreeBuilder
    ICAO9303ProofSystem --> ProofStore
    ICAO9303ProofSystem ..> DomainProofSet : creates
```

## 7. Module Dependency Graph

```mermaid
graph BT
    types[types.ts]
    domain[domain.ts]
    sod[sod-parser.ts]
    dg13[dg13-parser.ts]
    wb[witness-builder.ts]
    store[proof-store.ts]
    ps[icao9303-proof-system.ts]
    idx[index.ts]
    resolver[resolver.ts]

    domain --> types
    store --> types
    sod --> |"standalone"| sod
    dg13 --> |"standalone"| dg13
    wb --> sod
    wb --> dg13
    ps --> types
    ps --> domain
    ps --> wb
    idx --> types
    idx --> domain
    idx --> sod
    idx --> dg13
    idx --> wb
    idx --> store
    idx --> ps
    resolver -.->|"zkpProofs option"| types

    style ps fill:#e1f5fe,stroke:#0288d1
    style resolver fill:#fce4ec,stroke:#c62828
```

## 8. Binding Chain — Cryptographic Linkage

```mermaid
graph TD
    SOD["e-Passport SOD<br/>(government ECDSA signature)"]
    EC["eContent<br/>(signed hash table)"]
    DG13RAW["DG13 raw bytes<br/>(Vietnamese citizen data)"]

    SODP["sod-verify circuit"]
    DGMP["dg-map circuit"]
    MKLP["dg13-merklelize circuit"]

    EB["econtent_binding<br/>= Poseidon2(eContent_hash, salt)"]
    DB["dg_binding<br/>= Poseidon2(dg13_hash, salt)"]
    MB["binding<br/>= Poseidon2(dg13_hash, salt)"]
    ID["identity<br/>= Poseidon2(immutable_fields, salt)"]
    CM["commitment<br/>= Poseidon2(merkle_root, salt)"]

    SOD --> SODP
    SODP --> EB

    EC --> DGMP
    EB -->|"public input"| DGMP
    DGMP --> DB

    DG13RAW --> MKLP
    MKLP --> MB
    MKLP --> ID
    MKLP --> CM

    DB ===|"MUST EQUAL"| MB

    CM -->|"used by"| PRED["predicate proofs"]
    CM -->|"used by"| REVEAL["field-reveal proofs"]

    style DB fill:#c8e6c9,stroke:#388e3c
    style MB fill:#c8e6c9,stroke:#388e3c
    style PRED fill:#fff9c4,stroke:#fbc02d
    style REVEAL fill:#fff9c4,stroke:#fbc02d
```

## 9. Storage Layout

```mermaid
graph LR
    subgraph "Credential Storage (encrypted)"
        VC["vc_credentials<br/>[StoredCredential, ...]"]
    end

    subgraph "Proof Storage (encrypted, separate keys)"
        IDX1["zkp_proofs_index_cred001<br/>[{name:'1matrix', hash:'0xaaa'},<br/> {name:'partner', hash:'0xbbb'}]"]
        PS1["zkp_proofs_cred001_0xaaa<br/>DomainProofSet (1matrix)"]
        PS2["zkp_proofs_cred001_0xbbb<br/>DomainProofSet (partner)"]
        IDX2["zkp_proofs_index_cred002<br/>[{name:'1matrix', hash:'0xaaa'}]"]
        PS3["zkp_proofs_cred002_0xaaa<br/>DomainProofSet (1matrix)"]
    end

    IDX1 --> PS1
    IDX1 --> PS2
    IDX2 --> PS3

    style VC fill:#e8eaf6,stroke:#3f51b5
    style PS1 fill:#e8f5e9,stroke:#4caf50
    style PS2 fill:#e8f5e9,stroke:#4caf50
    style PS3 fill:#e8f5e9,stroke:#4caf50
```

## 10. State Machine — Proof Generation Phases

```mermaid
stateDiagram-v2
    [*] --> idle

    idle --> sod_verify: generateChainProofs()
    sod_verify --> dg_map: econtent_binding obtained
    dg_map --> merkle_tree: dg_binding obtained
    merkle_tree --> dg13_merklelize: tree built
    dg13_merklelize --> complete: binding verified
    dg13_merklelize --> error: binding mismatch

    sod_verify --> error: prove() failed
    dg_map --> error: prove() failed
    merkle_tree --> error: build() failed

    complete --> [*]
    error --> [*]
```

## 11. Domain Unlinkability

```mermaid
graph LR
    subgraph "Same credential, different domains"
        CRED["CCCD Credential<br/>(same SOD, same DG13)"]
    end

    subgraph "Domain: 1matrix"
        S1["salt = poseidon2('1matrix')"]
        B1["binding_A = poseidon2(dg13_hash, salt_A)"]
        C1["commitment_A = poseidon2(root_A, salt_A)"]
    end

    subgraph "Domain: partner"
        S2["salt = poseidon2('partner')"]
        B2["binding_B = poseidon2(dg13_hash, salt_B)"]
        C2["commitment_B = poseidon2(root_B, salt_B)"]
    end

    CRED --> S1
    CRED --> S2
    S1 --> B1
    S1 --> C1
    S2 --> B2
    S2 --> C2

    B1 -.-x|"cannot link"| B2
    C1 -.-x|"cannot link"| C2

    style B1 fill:#c8e6c9
    style B2 fill:#bbdefb
    style C1 fill:#c8e6c9
    style C2 fill:#bbdefb
```

Different domains produce completely different bindings and commitments from the same underlying credential data, making cross-provider tracking impossible.
