// Types & interfaces
export type {
  Domain,
  ChainProof,
  LeafData,
  CachedMerkleTree,
  DomainProofSet,
  ZKPProvider,
  ZKPProveParams,
  ZKPProveResult,
  ZKPVerifyParams,
  Poseidon2Hasher,
  MerkleTreeBuilder,
  MerkleLeafInput,
  ProofStore,
  ProofGenPhase,
} from './types.js';

// Domain
export { DEFAULT_DOMAIN_NAME, deriveDomain, packStringToFieldHex } from './domain.js';

// Proof system orchestrator
export { ICAO9303ProofSystem } from './icao9303-proof-system.js';
export type { ICAO9303ProofSystemConfig, DelegationData } from './icao9303-proof-system.js';

// Proof stores
export { MemoryProofStore, LocalStorageProofStore } from './proof-store.js';

// Witness builders (for advanced usage / custom proof generation)
export {
  buildSodValidateInputs,
  buildDgBridgeInputs,
  buildDg13MerklelizeInputs,
  buildPredicateInputs,
  buildDIDDelegateInputs,
  buildDG15WitnessData,
} from './witness-builder.js';
export type {
  CircuitInputs,
  SodValidateInputs,
  DgBridgeInputs,
  Dg13MerklelizeInputs,
  PredicateInputs,
  DIDDelegateInputs,
  DG15WitnessData,
} from './witness-builder.js';

// SOD parser (for advanced usage)
export { buildSODWitnessData } from './sod-parser.js';
export type { SODWitnessData } from './sod-parser.js';

// DG13 parser (for advanced usage)
export { buildDG13WitnessData } from './dg13-parser.js';
export type { DG13WitnessData } from './dg13-parser.js';
