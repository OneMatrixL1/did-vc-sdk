/**
 * Unit tests for verifyCredentialOptimistic()
 *
 * Tests the optimistic verification helper that tries optimistic resolution first,
 * then falls back to blockchain if verification fails.
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import { issueCredential } from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import {
  EthrDIDModule,
  keypairToAddress,
  addressToDID,
  verifyCredentialOptimistic,
} from '../src/modules/ethr-did';
import mockFetch from './mocks/fetch';

// Context URLs
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';
const VIETCHAIN_NETWORK = 'vietchain';
const VIETCHAIN_CHAIN_ID = 84005;

// Network configuration
const networkConfig = {
  name: VIETCHAIN_NETWORK,
  rpcUrl: 'https://rpc.vietcha.in',
  registry: '0xF0889fb2473F91c068178870ae2e1A0408059A03',
  chainId: VIETCHAIN_CHAIN_ID,
};

// Enable mock fetch
mockFetch();

describe('verifyCredentialOptimistic()', () => {
  let bbsKeypair;
  let ethrDID;
  let keyDoc;
  let signedCredential;
  let module;

  beforeAll(async () => {
    await initializeWasm();

    // Create BBS keypair and derive ethr DID
    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'verify-optimistic-test-key',
      controller: 'temp',
    });

    const address = keypairToAddress(bbsKeypair);
    ethrDID = addressToDID(address, VIETCHAIN_NETWORK);

    keyDoc = {
      id: `${ethrDID}#keys-bbs`,
      controller: ethrDID,
      type: Bls12381BBS23DockVerKeyName,
      keypair: bbsKeypair,
    };

    // Create module
    module = new EthrDIDModule({
      networks: [networkConfig],
    });

    const holderBbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'holder-verify-optimistic-test-key',
      controller: 'temp',
    });

    // Issue credential
    const unsignedCredential = {
      '@context': [
        CREDENTIALS_V1_CONTEXT,
        CREDENTIALS_EXAMPLES_CONTEXT,
        BBS_V1_CONTEXT,
      ],
      type: ['VerifiableCredential'],
      issuer: ethrDID,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: addressToDID(keypairToAddress(holderBbsKeypair), VIETCHAIN_NETWORK),
        alumniOf: 'Optimistic Verification University',
      },
    };

    signedCredential = await issueCredential(keyDoc, unsignedCredential);
  });

  describe('Basic functionality', () => {
    test('throws if module is not provided', async () => {
      await expect(
        verifyCredentialOptimistic(signedCredential, {}),
      ).rejects.toThrow('module is required');
    });

    test('verifies valid credential', async () => {
      const result = await verifyCredentialOptimistic(signedCredential, { module });

      expect(result.verified).toBe(true);
    });

    test('fails verification for tampered credential', async () => {
      const tampered = {
        ...signedCredential,
        credentialSubject: {
          ...signedCredential.credentialSubject,
          alumniOf: 'Fake University',
        },
      };

      const result = await verifyCredentialOptimistic(tampered, { module });

      expect(result.verified).toBe(false);
    });

    test('fails verification for wrong public key', async () => {
      const wrongKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'wrong-key',
        controller: 'temp',
      });
      const wrongPublicKey = b58.encode(new Uint8Array(wrongKeypair.publicKeyBuffer));

      const tampered = {
        ...signedCredential,
        proof: {
          ...signedCredential.proof,
          publicKeyBase58: wrongPublicKey,
        },
      };

      const result = await verifyCredentialOptimistic(tampered, { module });

      expect(result.verified).toBe(false);
    });
  });

  describe('Pass-through options', () => {
    test('passes additional options to verifyCredential', async () => {
      // Test that extra options like skipRevocationCheck are passed through
      const result = await verifyCredentialOptimistic(signedCredential, {
        module,
        skipRevocationCheck: true,
        skipSchemaCheck: true,
      });

      expect(result.verified).toBe(true);
    });
  });
});
