/**
 * Test BBS verification with REAL EthrDIDModule resolver (no mocks)
 *
 * This test verifies that the resolver properly adds #keys-1 to assertionMethod
 * so BBS credentials can be verified without on-chain key registration.
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import { issueCredential, verifyCredential } from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import { EthrDIDModule } from '../src/modules/ethr-did';
import { keypairToAddress, addressToDID } from '../src/modules/ethr-did/utils';

// Do NOT import mockFetch - we want real resolution!

const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';

// Network config from environment
const networkConfig = {
  name: process.env.ETHR_NETWORK || 'vietchain',
  rpcUrl: process.env.ETHR_NETWORK_RPC_URL,
  registry: process.env.ETHR_REGISTRY_ADDRESS || '0xF0889fb2473F91c068178870ae2e1A0408059A03',
};

describe('BBS Verification with Real EthrDIDModule Resolver', () => {
  let module;
  let bbsKeypair;
  let ethrDID;
  let keyDoc;
  let signedCredential;

  beforeAll(async () => {
    if (!process.env.ETHR_NETWORK_RPC_URL) {
      console.log('Skipping test - ETHR_NETWORK_RPC_URL not set');
      return;
    }

    await initializeWasm();

    // Create EthrDIDModule
    module = new EthrDIDModule({
      networks: [networkConfig],
      defaultNetwork: networkConfig.name,
    });

    // Generate BBS keypair and DID
    bbsKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'real-resolver-test',
      controller: 'temp',
    });

    const address = keypairToAddress(bbsKeypair);
    ethrDID = addressToDID(address, networkConfig.name);

    keyDoc = {
      id: `${ethrDID}#keys-1`,
      controller: ethrDID,
      type: Bls12381BBS23DockVerKeyName,
      keypair: bbsKeypair,
    };

    // Issue credential
    const unsignedCredential = {
      '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
      type: ['VerifiableCredential'],
      issuer: ethrDID,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: 'did:example:holder',
        name: 'Test with Real Resolver',
      },
    };

    signedCredential = await issueCredential(keyDoc, unsignedCredential);
  });

  test('resolver adds #keys-1 to assertionMethod', async () => {
    if (!process.env.ETHR_NETWORK_RPC_URL) {
      console.log('Skipping - no RPC URL');
      return;
    }

    // Get document using real resolver
    const document = await module.getDocument(ethrDID);

    console.log('Resolved DID document:');
    console.log(JSON.stringify(document, null, 2));

    // Check that #keys-1 is in assertionMethod
    const bbsKeyId = `${ethrDID}#keys-1`;
    expect(document.assertionMethod).toContain(bbsKeyId);
  }, 30000);

  test('verifies BBS credential with real resolver (no mock)', async () => {
    if (!process.env.ETHR_NETWORK_RPC_URL) {
      console.log('Skipping - no RPC URL');
      return;
    }

    console.log('Signed credential proof:');
    console.log(JSON.stringify(signedCredential.proof, null, 2));

    // Verify using real resolver
    const result = await verifyCredential(signedCredential, {
      resolver: module,
    });

    console.log('Verification result:');
    console.log(JSON.stringify({
      verified: result.verified,
      error: result.error?.message,
      purposeValid: result.results?.[0]?.purposeResult?.valid,
    }, null, 2));

    expect(result.verified).toBe(true);
  }, 30000);
});
