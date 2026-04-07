export { createWasmZKPProvider } from './provider.js';

export type { ZKPProvider, ZKPProveParams, ZKPProveResult, ZKPVerifyParams, WasmProviderConfig } from './provider.js';

export { createPoseidon2Hasher } from './poseidon2.js';

export type { Poseidon2Hasher } from './poseidon2.js';

export { loadCircuit, loadVerificationKey, getAvailableCircuits } from './circuits.js';

export type { CircuitArtifact } from './circuits.js';

export { buildMerkleTree, TREE_DEPTH, TREE_LEAVES } from './merkle-tree.js';

export type { MerkleTree, LeafInput } from './merkle-tree.js';
