# @1matrix/nid-contracts — National ID Registry

On-chain registry for Vietnamese CCCD (Citizen ID Card) identity proofs. Verifies a chain of 3 UltraHonk ZK proofs, stores identity→DID bindings, and emits DSC certificate path events for off-chain PKI verification.

## Deployed Addresses

| Contract | Address | Chain |
|---|---|---|
| **NationalIDRegistry** | `0x3f66f96D5fb1C1bd3d67DACdf24140cB50D60758` | VNIDChain testnet (84005) |
| UniversalHonkVerifier | `0x81CD798a9a2219b9bC7bCfC2019729Bd07eb82cc` | VNIDChain testnet (84005) |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                NationalIDRegistry                    │
│                                                     │
│  register(3 VKs, 3 proofs, public I/O, did, caPath) │
│     │                                               │
│     ├─ verify sod-validate proof ──────────────┐    │
│     ├─ verify dg-bridge proof ─────────────┐   │    │
│     ├─ verify unique-identity proof ───┐   │   │    │
│     │                                  ▼   ▼   ▼    │
│     │                        UniversalHonkVerifier   │
│     │                        (deployed, immutable)   │
│     │                                               │
│     ├─ store nid[dsc][domain][identity] = did       │
│     ├─ count[dsc][domain]++                         │
│     └─ emit DSCFirstSeen (once per DSC)             │
└─────────────────────────────────────────────────────┘
```

## ZK Proof Chain

Three circuits are verified on-chain. Each proof is generated off-chain from CCCD NFC chip data using UltraHonk (Noir/Barretenberg) over BN254.

```
sod-validate ─── eContentBinding ───► dg-bridge ─── dgBinding ───► unique-identity
     │                                    │                              │
     ▼                                    ▼                              ▼
 dscPubKeyHash                      dgNumber=13                      identity
```

### Circuit Details

| # | Circuit | What it proves | Public Inputs | Public Outputs |
|---|---------|----------------|---------------|----------------|
| 1 | **sod-validate** | ECDSA signature on SOD is valid (DSC signed the document) | `domain` | `eContentBinding`, `dscPubKeyHash` |
| 2 | **dg-bridge** | Links SOD to a specific data group (DG13) | `domain`, `eContentBinding`, `dgNumber` | `dgBinding` |
| 3 | **unique-identity** | Extracts unique identity hash from DG13 personal data | `domain` | `dgBinding`, `identity` |

### Chain Binding (Soundness)

The contract enforces proof chain integrity by passing **the same intermediate values** to multiple verifier calls:

- `eContentBinding` — output of sod-validate, fed as input to dg-bridge
- `dgBinding` — output of dg-bridge, fed as input to unique-identity
- `domain` — shared across all 3 proofs (scoped to "1matrix" domain)
- `dgNumber` — hardcoded to `13` in the contract (prevents bridging to wrong data group)

If any value is tampered, the corresponding proof verification fails.

### VK Hash Security

The contract stores **immutable VK hashes** per circuit (set at deployment). The `UniversalHonkVerifier` binds the VK hash into the Fiat-Shamir transcript, so:
- Wrong VK hash → wrong challenges → proof fails
- Right VK hash but wrong VK struct → proof fails
- No admin can change VK hashes after deployment

## Storage

```solidity
// Core mapping: DSC → Domain → Identity → DID address
mapping(bytes32 => mapping(bytes32 => mapping(bytes32 => address))) public nid;

// Count of registered identities per DSC + domain
mapping(bytes32 => mapping(bytes32 => uint256)) public count;

// Whether DSCFirstSeen event has been emitted for this DSC
mapping(bytes32 => bool) public dscSeen;
```

### Key Types

| Field | Type | Description |
|---|---|---|
| `dscPubKeyHash` | `bytes32` | Poseidon2 hash of DSC public key (proven in sod-validate) |
| `domain` | `bytes32` | BN254 field: `poseidon2(pack("1matrix"))` |
| `identity` | `bytes32` | Poseidon2 hash of immutable personal fields (unique per person per domain) |
| `did` | `address` | Projected ID (pId) from `ethr-did-registry`: `keccak256(secp256k1Addr ++ bbsAddr)[-20:]` |

## Events

```solidity
// Emitted on every successful registration
event IdentityRegistered(
    bytes32 indexed dscPubKeyHash,
    bytes32 indexed domain,
    bytes32 indexed identity,
    address did
);

// Emitted once per unique DSC — for off-chain CA verification
event DSCFirstSeen(
    bytes32 indexed dscPubKeyHash,
    bytes caPath    // X.509 cert chain: DSC → intermediate → CA root
);
```

### DSC Whitelist Flow (CA Path)

The CA Root → DSC certificate chain **cannot** be verified on-chain (too expensive). Instead:

1. User registers with ZK proofs → `dscPubKeyHash` proven in circuit
2. User provides `caPath` (raw X.509 cert chain) as calldata
3. Contract emits `DSCFirstSeen(dscPubKeyHash, caPath)` — **once per unique DSC**
4. Off-chain indexers read events and verify CA certificate chains against ICAO PKD
5. Verified DSCs are added to a trusted whitelist
6. Whitelist can later be published on-chain (merkle root or mapping)

"Low number" of DSCs — one per country/issuing authority, so this event is rare.

## Gas Costs

| Operation | Gas |
|---|---|
| sod-validate verification | ~2,280,000 |
| dg-bridge verification | ~2,156,000 |
| unique-identity verification | ~2,218,000 |
| Storage + events | ~70,000 |
| **Total `register()`** | **~6,724,000** |

## Integration

### From DomainProofSet (did-app)

The `ICAO9303ProofSystem` generates a `DomainProofSet` containing all data needed:

```typescript
// Map DomainProofSet → register() call
const tx = await registry.register(
  sodValidateVk,                                        // VK struct (from AllVks.sol)
  dgBridgeVk,                                           // VK struct
  uniqueIdentityVk,                                     // VK struct
  base64ToHex(proofSet.sodValidate.proofValue),         // proof bytes
  base64ToHex(proofSet.dgBridge.proofValue),            // proof bytes
  base64ToHex(proofSet.uniqueIdentity.proofValue),      // proof bytes (need unique-identity proof)
  proofSet.domain.hash,                                 // domain
  proofSet.sodValidate.publicOutputs.eContentBinding,   // eContentBinding
  proofSet.sodValidate.publicOutputs.dscPubKeyHash,     // dscPubKeyHash
  proofSet.dgBridge.publicOutputs.dgBinding,            // dgBinding
  proofSet.uniqueIdentity.publicOutputs.identity,       // identity
  pId,                                                  // DID address (from ethr-did-registry)
  caPathBytes,                                          // CA cert chain (DER encoded)
);
```

### Query

```typescript
// Check if identity is registered
const did = await registry.getNID(dscPubKeyHash, domain, identity);

// Count registrations under a DSC + domain
const count = await registry.getCount(dscPubKeyHash, domain);
```

## Development

```bash
cd packages/did-vc-sdk/packages/contracts

# Install
npm install --no-workspaces

# Compile
node_modules/.bin/hardhat compile

# Test (forks VNIDChain testnet — requires network access)
node_modules/.bin/hardhat test

# Deploy
node_modules/.bin/hardhat run scripts/deploy.ts --network vnidchainTestnet
```

### Dependencies

- **Hardhat** — build, test, deploy
- **VNIDChain testnet** — tests fork the live chain to use the real `UniversalHonkVerifier`
- **did-circuits** — source of VKs, proofs, and verifier contract (`/Users/gianglongtran/workspace/1matrix/did-circuits`)

### VK Hashes (immutable after deployment)

| Circuit | VK Hash |
|---|---|
| sod-validate | `0x02784cbb85651ead1623f47f8d625f279e3bfe7b70c2e5cce5b00f72a2f765fd` |
| dg-bridge | `0x0567502a030452f67c179eee03a5d54f250c6890d106647ed652d9dd7e3025ca` |
| unique-identity | `0x2a5d9f27a48ba0efb2f3d27ea36fe59dfa5efae681db6d74e1c82f99827810c2` |

## Security Model

| Concern | Mitigation |
|---|---|
| Proof forgery | UltraHonk verification on BN254 — cryptographically sound |
| VK substitution | Immutable VK hashes set at deployment; no admin can change them |
| Cross-circuit replay | Chain binding: shared `eContentBinding`/`dgBinding`/`domain` across proofs |
| Wrong data group | `dgNumber` hardcoded to `13` — cannot bridge to DG1, DG2, etc. |
| Double registration | `nid[dsc][domain][identity]` checked before storing |
| DSC trust | CA path emitted as event; off-chain verification builds whitelist |
| Admin abuse | **No admin.** All state is permissionless. Redeploy if circuits change. |
| DID format | `address` (pId) — consistent with `ethr-did-registry` dual-address pattern |
