/**
 * Shared utilities for use-case tests
 *
 * Common patterns for:
 * - Issuer (BBS keypair) setup
 * - Holder (Secp256k1 keypair) setup
 * - Credential issuance and derivation
 * - VP creation and verification
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import {
  issueCredential,
  VerifiablePresentation,
  Presentation,
} from '../../src/vc';
import Bls12381BBSKeyPairDock2023 from '../../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import {
  Bls12381BBS23DockVerKeyName,
  EcdsaSecp256k1RecoveryMethod2020Name,
} from '../../src/vc/crypto/constants';
import { Secp256k1Keypair } from '../../src/keypairs';
import {
  EthrDIDModule,
  addressToDID,
  keypairToAddress,
  verifyPresentationOptimistic,
} from '../../src/modules/ethr-did';

// =============================================================================
// Constants
// =============================================================================

export const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';
export const BBS_V1 = 'https://ld.truvera.io/security/bbs23/v1';
export const VIETCHAIN_NETWORK = 'vietchain';
export const VIETCHAIN_CHAIN_ID = 84005;

export const NETWORK_CONFIG = {
  name: VIETCHAIN_NETWORK,
  rpcUrl: 'https://rpc.vietcha.in',
  registry: '0xF0889fb2473F91c068178870ae2e1A0408059A03',
  chainId: VIETCHAIN_CHAIN_ID,
};

// =============================================================================
// Keypair and DID Helpers
// =============================================================================

/**
 * Creates a BBS issuer keypair and key document
 */
export function createBBSIssuer(keyId = 'issuer-key') {
  const keypair = Bls12381BBSKeyPairDock2023.generate({
    id: keyId,
    controller: 'temp',
  });
  const did = addressToDID(keypairToAddress(keypair), VIETCHAIN_NETWORK);
  const keyDoc = {
    id: `${did}#keys-bbs`,
    controller: did,
    type: Bls12381BBS23DockVerKeyName,
    keypair,
  };
  return { keypair, did, keyDoc };
}

/**
 * Creates a Secp256k1 holder keypair and key document
 */
export function createSecp256k1Holder() {
  const keypair = Secp256k1Keypair.random();
  const did = addressToDID(keypairToAddress(keypair), VIETCHAIN_NETWORK);
  const publicKeyBytes = keypair.publicKey().secp256k1.bytes;
  const keyDoc = {
    id: `${did}#controller`,
    controller: did,
    type: EcdsaSecp256k1RecoveryMethod2020Name,
    keypair,
    publicKeyBase58: b58.encode(publicKeyBytes),
  };
  return { keypair, did, keyDoc };
}

/**
 * Creates an EthrDIDModule verifier
 */
export function createVerifier() {
  return new EthrDIDModule({
    networks: [NETWORK_CONFIG],
  });
}

// =============================================================================
// Credential Helpers
// =============================================================================

/**
 * Issues a credential with BBS signature
 */
export async function issueCredentialWithBBS(issuerKeyDoc, unsignedCredential) {
  return issueCredential(issuerKeyDoc, unsignedCredential);
}

/**
 * Derives a credential with selective disclosure
 */
export function deriveCredential(credential, revealFields, nonce) {
  const presentation = new Presentation();
  presentation.addCredentialToPresent(credential);
  presentation.addAttributeToReveal(0, revealFields);
  const derivedCredentials = presentation.deriveCredentials({ nonce });
  return derivedCredentials[0];
}

/**
 * Creates and signs a Verifiable Presentation
 */
export async function createSignedVP({
  derivedCredential,
  holderDID,
  holderKeyDoc,
  challenge,
  domain,
  contexts = [],
}) {
  const vp = new VerifiablePresentation(`urn:uuid:vp-${Date.now()}`);
  vp.addContext(BBS_V1);
  contexts.forEach((ctx) => vp.addContext(ctx));
  vp.setHolder(holderDID);
  vp.addCredential(derivedCredential);
  await vp.sign(holderKeyDoc, challenge, domain);
  return vp;
}

/**
 * Verifies a VP using optimistic verification
 */
export async function verifyVP(vpJson, verifierModule, challenge, domain) {
  return verifyPresentationOptimistic(vpJson, {
    module: verifierModule,
    challenge,
    domain,
  });
}

// =============================================================================
// Test Setup Helper
// =============================================================================

/**
 * Initializes WASM - call this in beforeAll
 */
export async function initWasm() {
  await initializeWasm();
}

/**
 * Creates a complete test setup with issuer, holder, and verifier
 */
export async function createTestSetup() {
  await initWasm();

  const issuer = createBBSIssuer();
  const holder = createSecp256k1Holder();
  const verifier = createVerifier();

  return { issuer, holder, verifier };
}
