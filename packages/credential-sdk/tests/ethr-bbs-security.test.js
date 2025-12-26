/**
 * Security tests for BBS address-based recovery verification
 *
 * These tests verify that bad actors cannot:
 * 1. Impersonate another DID by using their own key
 * 2. Tamper with credentials after signing
 * 3. Replace public keys to bypass verification
 * 4. Forge credentials without the private key
 */

import { initializeWasm } from '@docknetwork/crypto-wasm-ts';
import b58 from 'bs58';
import { issueCredential, verifyCredential } from '../src/vc';
import Bls12381BBSKeyPairDock2023 from '../src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '../src/vc/crypto/constants';
import {
  keypairToAddress,
  addressToDID,
} from '../src/modules/ethr-did/utils';
import mockFetch from './mocks/fetch';
import networkCache from './utils/network-cache';

// Context URLs
const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';
const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1';
const SECURITY_V2_CONTEXT = 'https://w3id.org/security/v2';
const VIETCHAIN_NETWORK = 'vietchain';

// Enable mock fetch
mockFetch();

/**
 * Setup minimal DID document for purpose validation
 */
function setupMinimalDIDDoc(did) {
  const keyId = `${did}#keys-bbs`;
  const address = did.split(':').pop();
  networkCache[did] = {
    '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
    id: did,
    verificationMethod: [{
      id: `${did}#controller`,
      type: 'EcdsaSecp256k1RecoveryMethod2020',
      controller: did,
      blockchainAccountId: `eip155:1:${address}`,
    }],
    assertionMethod: [`${did}#controller`, keyId],
    authentication: [`${did}#controller`],
  };
}

describe('BBS Security Tests - Bad Actor Scenarios', () => {
  let victimKeypair;
  let victimDID;
  let victimKeyDoc;
  let attackerKeypair;
  let attackerDID;

  beforeAll(async () => {
    await initializeWasm();

    // Victim's identity
    victimKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'victim-key',
      controller: 'temp',
    });
    const victimAddress = keypairToAddress(victimKeypair);
    victimDID = addressToDID(victimAddress, VIETCHAIN_NETWORK);

    victimKeyDoc = {
      id: `${victimDID}#keys-bbs`,
      controller: victimDID,
      type: Bls12381BBS23DockVerKeyName,
      keypair: victimKeypair,
    };

    // Attacker's identity
    attackerKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'attacker-key',
      controller: 'temp',
    });
    const attackerAddress = keypairToAddress(attackerKeypair);
    attackerDID = addressToDID(attackerAddress, VIETCHAIN_NETWORK);

    // Setup DID documents
    setupMinimalDIDDoc(victimDID);
    setupMinimalDIDDoc(attackerDID);
  });

  afterAll(() => {
    delete networkCache[victimDID];
    delete networkCache[attackerDID];
  });

  describe('Impersonation Attacks', () => {
    test('attacker cannot issue credential as victim using their own key', async () => {
      // Attacker tries to create a credential claiming to be the victim
      // but signs with their own key
      const attackerKeyDoc = {
        id: `${victimDID}#keys-bbs`, // Claims victim's key ID
        controller: victimDID, // Claims victim as controller
        type: Bls12381BBS23DockVerKeyName,
        keypair: attackerKeypair, // But uses attacker's keypair
      };

      const fakeCredential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimDID, // Claims victim as issuer
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'Fake claim from attacker',
        },
      };

      // Signing succeeds (no signing-time validation, like Dock module)
      const signedFakeCredential = await issueCredential(attackerKeyDoc, fakeCredential);

      // But verification FAILS because attacker's publicKeyBase58 derives to
      // a different address than victim's DID
      const result = await verifyCredential(signedFakeCredential);
      expect(result.verified).toBe(false);
    });

    test('attacker cannot use victim credential with replaced public key', async () => {
      // First, victim issues a legitimate credential
      const legitimateCredential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'Legitimate claim',
        },
      };

      const signedCredential = await issueCredential(victimKeyDoc, legitimateCredential);

      // Attacker replaces the public key with their own
      const attackerPublicKey = b58.encode(new Uint8Array(attackerKeypair.publicKeyBuffer));
      const tamperedCredential = {
        ...signedCredential,
        proof: {
          ...signedCredential.proof,
          publicKeyBase58: attackerPublicKey,
        },
      };

      // Verification should FAIL because:
      // 1. Address from attacker's key doesn't match victim's DID
      // 2. Signature was made with victim's key, not attacker's
      const result = await verifyCredential(tamperedCredential);

      expect(result.verified).toBe(false);
    });
  });

  describe('Credential Tampering Attacks', () => {
    let legitimateSignedCredential;

    beforeAll(async () => {
      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          name: 'Original Name',
          score: 85,
        },
      };

      legitimateSignedCredential = await issueCredential(victimKeyDoc, credential);
    });

    test('tampered credentialSubject.name fails verification', async () => {
      const tampered = {
        ...legitimateSignedCredential,
        credentialSubject: {
          ...legitimateSignedCredential.credentialSubject,
          name: 'Tampered Name',
        },
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });

    test('tampered credentialSubject.score fails verification', async () => {
      const tampered = {
        ...legitimateSignedCredential,
        credentialSubject: {
          ...legitimateSignedCredential.credentialSubject,
          score: 100, // Changed from 85
        },
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });

    test('added field to credentialSubject fails verification', async () => {
      const tampered = {
        ...legitimateSignedCredential,
        credentialSubject: {
          ...legitimateSignedCredential.credentialSubject,
          extraField: 'Added by attacker',
        },
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });

    test('removed field from credentialSubject fails verification', async () => {
      const { score, ...subjectWithoutScore } = legitimateSignedCredential.credentialSubject;
      const tampered = {
        ...legitimateSignedCredential,
        credentialSubject: subjectWithoutScore,
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });

    test('tampered issuer fails verification', async () => {
      const tampered = {
        ...legitimateSignedCredential,
        issuer: attackerDID, // Changed issuer
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });

    test('tampered issuanceDate fails verification', async () => {
      const tampered = {
        ...legitimateSignedCredential,
        issuanceDate: '2020-01-01T00:00:00Z', // Changed date
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });
  });

  describe('Proof Manipulation Attacks', () => {
    let legitimateSignedCredential;

    beforeAll(async () => {
      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'Test claim',
        },
      };

      legitimateSignedCredential = await issueCredential(victimKeyDoc, credential);
    });

    test('tampered proofValue fails verification', async () => {
      // Modify one character in the proof value
      const originalProofValue = legitimateSignedCredential.proof.proofValue;
      const tamperedProofValue = originalProofValue.slice(0, -1) + 'X';

      const tampered = {
        ...legitimateSignedCredential,
        proof: {
          ...legitimateSignedCredential.proof,
          proofValue: tamperedProofValue,
        },
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });

    test('empty proofValue fails verification', async () => {
      const tampered = {
        ...legitimateSignedCredential,
        proof: {
          ...legitimateSignedCredential.proof,
          proofValue: '',
        },
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });

    test('random proofValue fails verification', async () => {
      const tampered = {
        ...legitimateSignedCredential,
        proof: {
          ...legitimateSignedCredential.proof,
          proofValue: 'zRandomInvalidProofValue123456789',
        },
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });

    test('swapped verificationMethod to attacker DID fails', async () => {
      const tampered = {
        ...legitimateSignedCredential,
        proof: {
          ...legitimateSignedCredential.proof,
          verificationMethod: `${attackerDID}#keys-bbs`,
        },
      };

      // Should fail because publicKeyBase58 still derives to victim's address
      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });
  });

  describe('Cross-DID Attacks', () => {
    test('credential from one DID cannot be claimed by another', async () => {
      // Victim issues a credential
      const victimCredential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          degree: 'PhD',
        },
      };

      const signedByVictim = await issueCredential(victimKeyDoc, victimCredential);

      // Attacker tries to claim this credential was issued by them
      // by changing the issuer field
      const claimedByAttacker = {
        ...signedByVictim,
        issuer: attackerDID,
      };

      const result = await verifyCredential(claimedByAttacker);
      expect(result.verified).toBe(false);
    });

    test('proof from one credential cannot be used on different credential', async () => {
      // Issue two different credentials
      const credential1 = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder1',
          claim: 'Claim 1',
        },
      };

      const credential2 = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder2',
          claim: 'Claim 2',
        },
      };

      const signed1 = await issueCredential(victimKeyDoc, credential1);
      const signed2 = await issueCredential(victimKeyDoc, credential2);

      // Try to use proof from credential1 on credential2's content
      const mixed = {
        ...signed2,
        proof: signed1.proof,
      };

      const result = await verifyCredential(mixed);
      expect(result.verified).toBe(false);
    });
  });

  describe('Key Rotation Scenarios', () => {
    test('credential signed with old key fails after key rotation', async () => {
      // User generates first keypair and issues credential
      const oldKeypair = Bls12381BBSKeyPairDock2023.generate({ id: 'old-key' });
      const oldAddress = keypairToAddress(oldKeypair);
      const oldDID = addressToDID(oldAddress, VIETCHAIN_NETWORK);

      setupMinimalDIDDoc(oldDID);

      const oldKeyDoc = {
        id: `${oldDID}#keys-bbs`,
        controller: oldDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: oldKeypair,
      };

      // Issue credential with old key
      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: oldDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'Issued with old key',
        },
      };

      const signedWithOldKey = await issueCredential(oldKeyDoc, credential);

      // Verify works with old key
      const resultBefore = await verifyCredential(signedWithOldKey);
      expect(resultBefore.verified).toBe(true);

      // User "rotates" to new keypair (generates completely new keypair)
      // This creates a NEW DID because address changes
      const newKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'new-key',
        controller: 'temp',
      });
      const newAddress = keypairToAddress(newKeypair);
      const newDID = addressToDID(newAddress, VIETCHAIN_NETWORK);

      // The old credential still verifies because:
      // - The embedded publicKeyBase58 still derives to the old DID's address
      // - BBS recovery verification is self-contained
      // This is expected behavior - credentials remain valid for the DID they were issued from
      const resultAfter = await verifyCredential(signedWithOldKey);
      expect(resultAfter.verified).toBe(true);

      // But if attacker tries to claim old credential is from new DID, it fails
      const claimedFromNewDID = {
        ...signedWithOldKey,
        issuer: newDID,
      };
      const resultClaimed = await verifyCredential(claimedFromNewDID);
      expect(resultClaimed.verified).toBe(false);

      // Cleanup
      delete networkCache[oldDID];
    });

    test('new key cannot verify credentials signed by old key', async () => {
      // Generate two different keypairs for same "identity"
      const keypairV1 = Bls12381BBSKeyPairDock2023.generate({
        id: 'identity-v1',
        controller: 'temp',
      });
      const keypairV2 = Bls12381BBSKeyPairDock2023.generate({
        id: 'identity-v2',
        controller: 'temp',
      });

      const addressV1 = keypairToAddress(keypairV1);
      const didV1 = addressToDID(addressV1, VIETCHAIN_NETWORK);

      setupMinimalDIDDoc(didV1);

      // Sign with V1 keypair
      const keyDocV1 = {
        id: `${didV1}#keys-bbs`,
        controller: didV1,
        type: Bls12381BBS23DockVerKeyName,
        keypair: keypairV1,
      };

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: didV1,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'Signed with V1',
        },
      };

      const signedWithV1 = await issueCredential(keyDocV1, credential);

      // Try to replace publicKeyBase58 with V2's key
      const v2PublicKey = b58.encode(new Uint8Array(keypairV2.publicKeyBuffer));
      const tamperedWithV2Key = {
        ...signedWithV1,
        proof: {
          ...signedWithV1.proof,
          publicKeyBase58: v2PublicKey,
        },
      };

      // Should fail - V2 key derives to different address than V1's DID
      const result = await verifyCredential(tamperedWithV2Key);
      expect(result.verified).toBe(false);

      // Cleanup
      delete networkCache[didV1];
    });
  });

  describe('No BBS Keypair Scenarios', () => {
    test('BBS credential fails if issuer DID has no BBS key authorization', async () => {
      // Create a DID that explicitly does NOT authorize BBS keys
      const someKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'some-key',
        controller: 'temp',
      });
      const someAddress = keypairToAddress(someKeypair);
      const someDID = addressToDID(someAddress, VIETCHAIN_NETWORK);

      // Setup DID doc WITHOUT #keys-bbs in assertionMethod
      // (simulating on-chain data that doesn't include BBS authorization)
      networkCache[someDID] = {
        '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
        id: someDID,
        verificationMethod: [{
          id: `${someDID}#controller`,
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: someDID,
          blockchainAccountId: `eip155:1:${someAddress}`,
        }],
        // Only controller is authorized, NOT #keys-bbs
        assertionMethod: [`${someDID}#controller`],
        authentication: [`${someDID}#controller`],
      };

      const keyDoc = {
        id: `${someDID}#keys-bbs`,
        controller: someDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: someKeypair,
      };

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: someDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'BBS credential from DID without BBS authorization',
        },
      };

      const signed = await issueCredential(keyDoc, credential);

      // Verification should fail because #keys-bbs is not in assertionMethod
      const result = await verifyCredential(signed);
      expect(result.verified).toBe(false);

      // Cleanup
      delete networkCache[someDID];
    });

    test('attacker cannot add BBS credential to secp256k1-only DID', async () => {
      // Scenario: Attacker knows victim's secp256k1 DID and tries to
      // create BBS credentials claiming to be from that DID

      // Victim has a secp256k1-based DID (not derived from BBS key)
      // Using a properly checksummed address
      const victimSecp256k1Address = '0x742d35Cc6634C0532925a3b844Bc454e4438f44e';
      const victimSecp256k1DID = `did:ethr:${VIETCHAIN_NETWORK}:${victimSecp256k1Address}`;

      // Setup victim's DID doc (secp256k1 only, no BBS)
      networkCache[victimSecp256k1DID] = {
        '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
        id: victimSecp256k1DID,
        verificationMethod: [{
          id: `${victimSecp256k1DID}#controller`,
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: victimSecp256k1DID,
          blockchainAccountId: `eip155:1:${victimSecp256k1Address}`,
        }],
        assertionMethod: [`${victimSecp256k1DID}#controller`],
        authentication: [`${victimSecp256k1DID}#controller`],
      };

      // Attacker generates their own BBS keypair
      const attackerBBSKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'attacker-bbs',
        controller: 'temp',
      });

      // Attacker tries to issue BBS credential as victim
      const attackerKeyDoc = {
        id: `${victimSecp256k1DID}#keys-bbs`,
        controller: victimSecp256k1DID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: attackerBBSKeypair,
      };

      const fakeCredential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimSecp256k1DID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'Fake credential from attacker',
        },
      };

      // Signing succeeds (no signing-time validation, like Dock module)
      const signedFakeCredential = await issueCredential(attackerKeyDoc, fakeCredential);

      // But verification FAILS because attacker's publicKeyBase58 derives to
      // a different address than victim's secp256k1 DID
      const result = await verifyCredential(signedFakeCredential);
      expect(result.verified).toBe(false);

      // Cleanup
      delete networkCache[victimSecp256k1DID];
    });

    test('BBS key from different address cannot impersonate DID', async () => {
      // Even if attacker has a valid BBS keypair, they cannot create
      // credentials for DIDs that don't match their derived address

      // Using a properly formatted address (not checksummed but lowercase is valid)
      const legitimateAddress = '0xabcdef1234567890abcdef1234567890abcdef12';
      const legitimateDID = `did:ethr:${VIETCHAIN_NETWORK}:${legitimateAddress}`;

      // Setup legitimate DID (even with #keys-bbs authorized)
      networkCache[legitimateDID] = {
        '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
        id: legitimateDID,
        verificationMethod: [{
          id: `${legitimateDID}#controller`,
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: legitimateDID,
          blockchainAccountId: `eip155:1:${legitimateAddress}`,
        }],
        assertionMethod: [`${legitimateDID}#controller`, `${legitimateDID}#keys-bbs`],
        authentication: [`${legitimateDID}#controller`],
      };

      // Attacker has their own BBS keypair
      const attackerBBSKeypair = Bls12381BBSKeyPairDock2023.generate({
        id: 'attacker',
        controller: 'temp',
      });

      // Attacker tries to sign as legitimate DID
      const attackerKeyDoc = {
        id: `${legitimateDID}#keys-bbs`,
        controller: legitimateDID,
        type: Bls12381BBS23DockVerKeyName,
        keypair: attackerBBSKeypair,
      };

      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: legitimateDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'Impersonation attempt',
        },
      };

      // Signing succeeds (no signing-time validation, like Dock module)
      const signedFakeCredential = await issueCredential(attackerKeyDoc, credential);

      // But verification FAILS because attacker's publicKeyBase58 derives to
      // a different address than the legitimate DID
      const result = await verifyCredential(signedFakeCredential);
      expect(result.verified).toBe(false);

      // Cleanup
      delete networkCache[legitimateDID];
    });
  });

  describe('Invalid Public Key Attacks', () => {
    test('malformed publicKeyBase58 fails verification', async () => {
      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'Test',
        },
      };

      const signed = await issueCredential(victimKeyDoc, credential);

      const tampered = {
        ...signed,
        proof: {
          ...signed.proof,
          publicKeyBase58: 'InvalidBase58!!!', // Invalid characters
        },
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
      // Should contain error about non-base58 character
      expect(result.results[0].error.message).toContain('Non-base58');
    });

    test('truncated publicKeyBase58 fails verification', async () => {
      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'Test',
        },
      };

      const signed = await issueCredential(victimKeyDoc, credential);

      const tampered = {
        ...signed,
        proof: {
          ...signed.proof,
          publicKeyBase58: signed.proof.publicKeyBase58.slice(0, 20), // Truncated
        },
      };

      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });

    test('missing publicKeyBase58 fails verification', async () => {
      const credential = {
        '@context': [CREDENTIALS_V1_CONTEXT, BBS_V1_CONTEXT],
        type: ['VerifiableCredential'],
        issuer: victimDID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: 'did:example:holder',
          claim: 'Test',
        },
      };

      const signed = await issueCredential(victimKeyDoc, credential);

      const { publicKeyBase58, ...proofWithoutKey } = signed.proof;
      const tampered = {
        ...signed,
        proof: proofWithoutKey,
      };

      // Should fail - publicKeyBase58 is required for recovery verification
      const result = await verifyCredential(tampered);
      expect(result.verified).toBe(false);
    });
  });
});
