/**
 * Domain-scoped ZKP proof system types.
 *
 * All proving, hashing, and storage implementations are injected by the app.
 * The SDK only defines interfaces and orchestration logic.
 */

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/** A named domain with its Poseidon2 hash. */
export interface Domain {
  /** Human-readable name, e.g. "1matrix". */
  readonly name: string;
  /** Hex-encoded BN254 field element: poseidon2(pack(name)). */
  readonly hash: string;
}

// ---------------------------------------------------------------------------
// Proof data
// ---------------------------------------------------------------------------

/** A single circuit proof with its public I/O. */
export interface ChainProof {
  readonly circuitId: string;
  readonly proofValue: string;
  readonly publicInputs: Record<string, unknown>;
  readonly publicOutputs: Record<string, unknown>;
}

/** Per-leaf packed data needed for predicate proofs. */
export interface LeafData {
  readonly length: string;
  readonly data: readonly [string, string, string, string];
}

/** Cached Poseidon2 Merkle tree (16 leaves, depth 4). */
export interface CachedMerkleTree {
  readonly root: string;
  readonly commitment: string;
  readonly leaves: readonly string[];
  /** siblings[leafIndex] = 4-element path from leaf to root. */
  readonly siblings: readonly (readonly string[])[];
  /** Packed leaf data for each field (needed for predicate proofs). */
  readonly leafData: readonly LeafData[];
}

/**
 * Complete set of chain proofs for one (credential, domain) pair.
 *
 * Chain: sod-validate → dg-bridge → dg13-merklelize, all sharing the same domain.
 */
export interface DomainProofSet {
  readonly domain: Domain;
  readonly credentialId: string;
  readonly createdAt: string;

  /** SOD signature verification. publicOutputs: eContentBinding, dscPubKeyHash. */
  readonly sodValidate: ChainProof;
  /** DG hash extraction. publicOutputs.dgBinding must equal dg13Merklelize dgBinding. */
  readonly dgBridge: ChainProof;
  /** DG13 Merkle tree. publicOutputs: dgBinding, identity, commitment. */
  readonly dg13Merklelize: ChainProof;
  /** DID delegation proof (optional — requires DG15 + Active Auth). */
  readonly didDelegate?: ChainProof;

  /** Full Merkle tree for on-demand predicate proofs. */
  readonly merkleTree: CachedMerkleTree;
}

// ---------------------------------------------------------------------------
// Dependency-injection interfaces (app provides implementations)
// ---------------------------------------------------------------------------

/** Prove/verify ZKP circuits (native plugin or WASM). */
export interface ZKPProvider {
  prove(params: ZKPProveParams): Promise<ZKPProveResult>;
}

export interface ZKPProveParams {
  circuitId: string;
  privateInputs: Record<string, unknown>;
  publicInputs: Record<string, unknown>;
}

export interface ZKPProveResult {
  proofValue: string;
  publicOutputs: Record<string, unknown>;
}

/** Poseidon2 hash over BN254 field elements. */
export interface Poseidon2Hasher {
  hash(inputs: string[], len: number): Promise<string>;
}

/** Build a Poseidon2 Merkle tree (16 leaves, depth 4). */
export interface MerkleTreeBuilder {
  build(fields: MerkleLeafInput[], domain: string): Promise<CachedMerkleTree>;
}

export interface MerkleLeafInput {
  tagId: number;
  length: number;
  packedFields: [string, string, string, string];
}

/** Persistent storage for DomainProofSets. */
export interface ProofStore {
  save(proofSet: DomainProofSet): Promise<void>;
  get(credentialId: string, domainHash: string): Promise<DomainProofSet | null>;
  listDomains(credentialId: string): Promise<Domain[]>;
  deleteAll(credentialId: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Progress reporting
// ---------------------------------------------------------------------------

export type ProofGenPhase =
  | 'idle'
  | 'sod-validate'
  | 'dg-bridge'
  | 'merkle-tree'
  | 'dg13-merklelize'
  | 'did-delegate'
  | 'complete'
  | 'error';
