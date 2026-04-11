# ZKP Merkle Selective Disclosure

Architecture overview of the ZKP Merkle selective disclosure feature added in `feat/zkp-selective-disclosure`.

---

## Flow Diagram

```mermaid
flowchart TD
    subgraph Request["VPRequest (Verifier side)"]
        DR["DocumentRequest<br/>─────────────<br/>disclosureMode: zkp-only<br/>conditions:"]
        DC["DiscloseCondition<br/>merkleDisclosure: { commitmentRef }"]
        ZC["ZKPCondition<br/>circuitId, proofSystem<br/>publicInputs, dependsOn"]
        DR --> DC
        DR --> ZC
    end

    subgraph Match["matchCredentials (Holder side)"]
        M["checkFieldCoverage<br/>─────────────────<br/>disclose → resolveField()<br/>zkp → always satisfiable<br/>(no privateInputs anymore)"]
    end

    subgraph Resolve["resolvePresentation"]
        direction TB
        RM{"isZKPMode?<br/>merkleDisclosure exists<br/>or zkp-only"}
        RN["normal path<br/>deriveCredential(fields)"]
        RZ["ZKP path<br/>deriveCredentialWithZKP()"]
        RM -- no --> RN
        RM -- yes: needs ZKPSchemaResolver --> RZ
    end

    subgraph ZKPResolver["ZKPSchemaResolver (ICAO9303SOD-ZKP)"]
        direction TB
        ZR1["for each ZKPCondition<br/>→ provider.prove(merkleWitness)<br/>→ ZKPProof"]
        ZR2["for each merkleDisclose<br/>→ fieldIdToLeafIndex()<br/>→ extractSiblingsForLeaf()<br/>→ MerkleDisclosureProof"]
        ZR1 --> ZR2
    end

    subgraph VP["PresentedCredential.proof[]"]
        P1["ZKPProof<br/>{ conditionID, circuitId<br/>publicInputs, publicOutputs<br/>proofValue, dependsOn }"]
        P2["MerkleDisclosureProof<br/>{ conditionID, fieldIndex<br/>fieldValue, leafPreimage<br/>siblings, commitment, dependsOn }"]
    end

    subgraph Verify["verifyVPResponse (Verifier)"]
        direction TB
        V1["structural check"]
        V2["crypto check<br/>(credential-sdk)"]
        V3["verifyZKPProofs()"]
        V3A["ZKPProof<br/>→ provider.verify()<br/>→ check circuitId match<br/>→ check dependsOn"]
        V3B["MerkleDisclosureProof<br/>→ verifyMerkleInclusion()<br/>  Poseidon2 tree walk<br/>→ verifyFieldValue()<br/>→ check dependsOn"]
        V1 --> V2 --> V3
        V3 --> V3A & V3B
    end

    subgraph NewPkg["@1matrix/zkp-provider"]
        WP["createWasmZKPProvider()<br/>UltraHonkBackend (lazy)<br/>noir.execute + generateProof"]
        PH["createPoseidon2Hasher()<br/>BarretenbergSync BN254"]
        BC["Bundled circuits<br/>sod-validate<br/>dg13-merklelize<br/>date-gt/lt/gte/lte/inrange"]
        WP --> BC
    end

    DR --> M
    M --> Resolve
    Resolve --> ZKPResolver
    ZKPResolver --> VP
    VP --> Verify
    NewPkg -- ZKPProvider --> ZKPResolver
    NewPkg -- Poseidon2Hasher --> V3B
```

---

## Key Design Decisions

**`privateInputs` removed from `ZKPCondition`**
Private inputs are never part of the protocol request. The verifier has no business knowing what credential fields feed into a ZKP. Satisfiability is checked at prove time, not match time — `matchCredentials` now marks all ZKP conditions as satisfiable.

**`isZKPMode` only triggers on Merkle conditions**
Plain ZKP predicate conditions (e.g. age proof on a `JsonSchema` credential) do not require a `ZKPSchemaResolver`. Only Merkle disclosure conditions and `zkp-only` mode require it. This keeps non-ICAO schemas working normally alongside ZKP predicates.

**`dependsOn` proof chaining**
Proofs reference each other by `conditionID`. The typical chain for CCCD:
```
sod-validate (ZKPProof)
  └─ dg13-merklelize (ZKPProof, dependsOn: { commitment: "c-sod" })
       └─ fullName (MerkleDisclosureProof, dependsOn: { commitment: "c-dg13" })
       └─ dateOfBirth (MerkleDisclosureProof, dependsOn: { commitment: "c-dg13" })
```
The verifier checks that `commitment` values match across linked proofs, preventing substitution attacks.

**`ZKPProvider` and `Poseidon2Hasher` are injected interfaces**
`presentation-exchange` has no hard dependency on `@aztec/bb.js`. The `@1matrix/zkp-provider` package provides the production implementation; tests use lightweight deterministic stubs.

---

## New Files

| File | Purpose |
|------|---------|
| `src/types/merkle.ts` | `MerkleWitnessData`, `MerkleFieldData`, `MerkleDisclosureProof` |
| `src/types/zkp-provider.ts` | `ZKPProvider`, `ZKPProveParams`, `ZKPVerifyParams`, `Poseidon2Hasher` |
| `src/resolvers/zkp-field-mapping.ts` | DG13 field ID → Merkle leaf index mapping |
| `src/resolvers/zkp-icao-schema-resolver.ts` | `ZKPSchemaResolver`, `createZKPICAOSchemaResolver()` |
| `src/verifier/zkp-verifier.ts` | `verifyZKPProofs()`, `verifyMerkleInclusion()` |
| `packages/zkp-provider/` | Production WASM provider + bundled Noir circuits |


```
const request = new VPRequestBuilder('enrollment')
    .addDocumentRequest(
      new DocumentRequestBuilder('parent', 'CCCDCredential')
        .setSchemaType('ICAO9303SOD')
        .program("program-output-1-var", new ICAO9303ZKPData) -> Will generate a new proof for VP
        .zkp("firstname-reveal-dg13-var", "dg13-profile-disclose")
        .zkp("zk-sod-verification-1", {
          circuitId: "sod-verification",
          privateInputs: {
            // Example
            eContent: "$proof.["ICAO9303SOD"].data", // JSON path to W3C VC
            signature: ""
          },
          publicInputs: {
            // Example
          }
        })
        .run('sod-validate').as('sod')
        .run('icao-merklelize', { dataGroup: 'dg13' }).as('dg13')
        .disclose('c1', 'dg13.fullName')
        .build()
    )
    .addDocumentRequest(
      new DocumentRequestBuilder('child', 'CCCDCredential')
        .setSchemaType('ICAO9303SOD')
        .run('sod-validate').as('sod')
        .run('icao-merklelize', { dataGroup: 'dg13' }).as('dg13')
        .disclose('c2', 'dg13.fullName')
        .zkp('c3', {
          circuitId: 'field-equals',
          fieldId: 'dg13.fatherName',
          publicInputs: {
            ref: 'parent.dg13.fullName',          // ← cross-doc variable
          },
        })
        .build()
    )
    .build();
```