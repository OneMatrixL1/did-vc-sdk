/**
 * Domain-scoped ZKP proof system types.
 *
 * All proving, hashing, and storage implementations are injected by the app.
 * The SDK only defines interfaces and orchestration logic.
 */

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/** A named domain with its Poseidon2 hash (used as circuit "salt"). */
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

/** Cached Poseidon2 Merkle tree (32 leaves, depth 5). */
export interface CachedMerkleTree {
  readonly root: string;
  readonly commitment: string;
  readonly leaves: readonly string[];
  /** siblings[leafIndex] = 5-element path from leaf to root. */
  readonly siblings: readonly (readonly string[])[];
}

/**
 * Complete set of chain proofs for one (credential, domain) pair.
 *
 * Chain: sod-verify → dg-map → dg13-merklelize, all sharing the same salt.
 */
export interface DomainProofSet {
  readonly domain: Domain;
  readonly credentialId: string;
  readonly createdAt: string;

  /** SOD signature verification. publicOutputs.econtent_binding links to dgMap. */
  readonly sodVerify: ChainProof;
  /** DG hash extraction. publicOutputs.dg_binding must equal dg13Merklelize binding. */
  readonly dgMap: ChainProof;
  /** DG13 Merkle tree. publicOutputs: binding, identity, commitment. */
  readonly dg13Merklelize: ChainProof;

  /** Full Merkle tree for on-demand predicate/field-reveal proofs. */
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

/** Build a Poseidon2 Merkle tree (32 leaves, depth 5). */
export interface MerkleTreeBuilder {
  build(fields: MerkleLeafInput[], salt: string): Promise<CachedMerkleTree>;
}

export interface MerkleLeafInput {
  tagId: number;
  length: number;
  packedFields: [string, string, string, string];
  packedHash: string;
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
  | 'sod-verify'
  | 'dg-map'
  | 'merkle-tree'
  | 'dg13-merklelize'
  | 'complete'
  | 'error';
