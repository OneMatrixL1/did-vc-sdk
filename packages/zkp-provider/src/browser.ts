/**
 * Browser entry point for @1matrix/zkp-provider.
 *
 * Same as index.ts but WITHOUT circuits.ts (which uses Node.js fs).
 * Circuits must be passed via config.circuits to createWasmZKPProvider().
 */

export { createWasmZKPProviderBrowser as createWasmZKPProvider } from './provider-browser.js';

export type { ZKPProvider, ZKPProveParams, ZKPProveResult, ZKPVerifyParams, WasmProviderConfig } from './provider.js';

export { createPoseidon2Hasher } from './poseidon2.js';

export type { Poseidon2Hasher } from './poseidon2.js';

export { buildMerkleTree, TREE_DEPTH, TREE_LEAVES } from './merkle-tree.js';

export type { MerkleTree, LeafInput } from './merkle-tree.js';
