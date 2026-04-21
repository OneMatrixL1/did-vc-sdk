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
  /** Opaque envelope (base64) — used by SDK-local `ZKPProvider.verify`. */
  readonly proofValue: string;
  /** Raw proof bytes as 0x-hex — feed directly to on-chain verifiers. */
  readonly proofBytes: string;
  /** Ordered bytes32 hex public signals — the `publicInputs` array on-chain verifiers expect. */
  readonly publicSignals: readonly string[];
  /** Circuit input map keyed by Noir parameter name. */
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
  /** Unique identity (on-chain registration slot). publicOutputs: dgBinding, identity. */
  readonly uniqueIdentity: ChainProof;
  /**
   * Holder-binding proof: Active Authentication signature bound to the holder DID.
   * Present only when scan-time data (DG15 + aaSignature) and the holder DID were
   * supplied to `generateChainProofs`. Verifiers that set `requireHolderBinding`
   * require this proof; others ignore its absence. publicOutputs: dgBinding.
   */
  readonly didDelegate?: ChainProof;
  /**
   * DG15 bridge proof — binds DG15 hash into SOD via dg-bridge with dgNumber=15.
   * Present only when didDelegate is present (same prerequisites). Its
   * `publicOutputs.dgBinding` must match `didDelegate.publicOutputs.dgBinding`
   * so the on-chain registry can chain DG15 ← SOD ← delegate(did).
   */
  readonly dgBridge15?: ChainProof;

  /** Full Merkle tree for on-demand predicate proofs. */
  readonly merkleTree: CachedMerkleTree;
}

// ---------------------------------------------------------------------------
// Dependency-injection interfaces (app provides implementations)
// ---------------------------------------------------------------------------

/** Prove/verify ZKP circuits (native plugin or WASM). */
export interface ZKPProvider {
  prove(params: ZKPProveParams): Promise<ZKPProveResult>;
  verify?(params: ZKPVerifyParams): Promise<boolean>;
}

export interface ZKPVerifyParams {
  circuitId: string;
  proofValue: string;
  publicInputs: Record<string, unknown>;
  publicOutputs: Record<string, unknown>;
}

export interface ZKPProveParams {
  circuitId: string;
  privateInputs: Record<string, unknown>;
  publicInputs: Record<string, unknown>;
}

export interface ZKPProveResult {
  /**
   * Opaque envelope: base64 of [numPub(4 BE) | publicInputs(32*n) | proofBytes].
   * Used for SDK-local round-trip verification (noir_rs verify_ultra_honk expects this layout).
   */
  proofValue: string;
  /** Raw proof bytes as 0x-prefixed hex. Feed this directly to on-chain verifiers. */
  proofBytes: string;
  /** Public signals: ordered bytes32 (0x-hex) values — the `publicInputs` parameter on-chain verifiers expect. */
  publicSignals: string[];
  publicOutputs: Record<string, unknown>;
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
  | 'unique-identity'
  | 'dg-bridge-15'
  | 'did-delegate'
  | 'complete'
  | 'error';
