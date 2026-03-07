import type { KeyDoc } from '../types/request.js';

export type KeySystem = 'secp256k1' | 'bbs';

interface KeyTypeConfig {
  defaultFragment: string;
  resolveType: (fragment: string) => string;
}

const KEY_SYSTEMS: Record<KeySystem, KeyTypeConfig> = {
  secp256k1: {
    defaultFragment: 'controller',
    resolveType: (fragment) =>
      fragment === 'controller'
        ? 'EcdsaSecp256k1RecoveryMethod2020'
        : 'EcdsaSecp256k1VerificationKey2019',
  },
  bbs: {
    defaultFragment: 'keys-1',
    resolveType: () => 'Bls12381BBS23VerificationKeyDock2023',
  },
};

/**
 * Create a KeyDoc for signing.
 *
 * @param did      The DID (e.g. `did:ethr:vietchain:0x...`)
 * @param keypair  Crypto keypair instance (library-specific)
 * @param system   Key system: `'secp256k1'` or `'bbs'`
 * @param fragment Verification method fragment (default: `'controller'` for secp256k1, `'keys-1'` for bbs)
 *
 * @example
 * // Owner key (recovery-based, no public key needed)
 * createKeyDoc(did, keypair, 'secp256k1')
 * // → { id: 'did:ethr:...#controller', type: 'EcdsaSecp256k1RecoveryMethod2020', ... }
 *
 * // Added key on-chain
 * createKeyDoc(did, keypair, 'secp256k1', 'key-1')
 * // → { id: 'did:ethr:...#key-1', type: 'EcdsaSecp256k1VerificationKey2019', ... }
 *
 * // BBS key
 * createKeyDoc(did, keypair, 'bbs')
 * // → { id: 'did:...#keys-1', type: 'Bls12381BBS23VerificationKeyDock2023', ... }
 */
export function createKeyDoc(
  did: string,
  keypair: unknown,
  system: KeySystem,
  fragment?: string,
): KeyDoc {
  const config = KEY_SYSTEMS[system];
  const frag = fragment ?? config.defaultFragment;

  return {
    id: `${did}#${frag}`,
    controller: did,
    type: config.resolveType(frag),
    keypair,
  };
}
