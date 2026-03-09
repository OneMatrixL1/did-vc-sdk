/**
 * Test: VP proof is verified BEFORE credential verification.
 *
 * Exercises the fix for the original SDK bug where verifyPresentationCredentials
 * ran first, mutating the presentation via JSON-LD expansion, which caused
 * jsigs.verify to fail with "Invalid signature."
 *
 * This test creates a real signed VP with an embedded signed credential and
 * verifies both the holder proof and credential proof succeed via
 * verifyPresentation (proof-first order).
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import b58 from 'bs58';

// credential-sdk
import { Secp256k1Keypair } from '@1matrix/credential-sdk/keypairs';
import { addressToDID, keypairToAddress } from '@1matrix/credential-sdk/src/modules/ethr-did/utils.js';
import {
  issueCredential,
  signPresentation,
  verifyPresentation,
} from '@1matrix/credential-sdk/vc';
import { EcdsaSecp256k1VerKeyName } from '@1matrix/credential-sdk/vc-crypto-constants';
import networkCache from '../../../credential-sdk/tests/utils/network-cache';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_V1 = 'https://www.w3.org/2018/credentials/examples/v1';
const SECURITY_V2 = 'https://w3id.org/security/v2';
const DID_V1 = 'https://www.w3.org/ns/did/v1';
const VIETCHAIN = 'vietchain';

// ---------------------------------------------------------------------------
// DID registration helpers
// ---------------------------------------------------------------------------

type KeyDoc = {
  id: string;
  controller: string;
  type: string;
  publicKey: ReturnType<InstanceType<typeof Secp256k1Keypair>['publicKey']>;
  keypair: InstanceType<typeof Secp256k1Keypair>;
};

function registerDID(keypair: InstanceType<typeof Secp256k1Keypair>, did: string): KeyDoc {
  // eslint-disable-next-line no-underscore-dangle
  const publicKeyBytes = keypair._publicKey();
  const publicKeyBase58 = b58.encode(publicKeyBytes);
  const keyId = `${did}#keys-1`;

  const cache = networkCache as Record<string, unknown>;

  cache[keyId] = {
    '@context': SECURITY_V2,
    id: keyId,
    type: EcdsaSecp256k1VerKeyName,
    controller: did,
    publicKeyBase58,
  };

  cache[did] = {
    '@context': [DID_V1, SECURITY_V2],
    id: did,
    verificationMethod: [
      { id: keyId, type: EcdsaSecp256k1VerKeyName, controller: did, publicKeyBase58 },
    ],
    assertionMethod: [keyId],
    authentication: [keyId],
  };

  return {
    id: keyId,
    controller: did,
    type: EcdsaSecp256k1VerKeyName,
    publicKey: keypair.publicKey(),
    keypair,
  };
}

function cleanupDID(did: string): void {
  const cache = networkCache as Record<string, unknown>;
  Object.keys(cache).forEach((key) => {
    if (key === did || key.startsWith(`${did}#`)) {
      delete cache[key];
    }
  });
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('verifyPresentation: proof-before-credentials order', () => {
  let issuerKeyDoc: KeyDoc;
  let issuerDID: string;
  let holderKeyDoc: KeyDoc;
  let holderDID: string;
  let signedCredential: Record<string, unknown>;
  let signedVP: Record<string, unknown>;

  const testChallenge = 'challenge-proof-order-test';
  const testDomain = 'test.example.com';
  const registeredDIDs: string[] = [];

  beforeAll(async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => {
        const cached = (networkCache as Record<string, unknown>)[url];
        if (cached) {
          return Promise.resolve(
            new Response(JSON.stringify(cached), {
              status: 200,
              headers: { 'Content-type': 'application/json' },
            }),
          );
        }
        throw new Error(`[verify-vp-proof-order] Unmocked URL: ${url}`);
      }),
    );

    // Create issuer
    const issuerKeypair = new Secp256k1Keypair(
      '1111111111111111111111111111111111111111111111111111111111111111',
    );
    issuerDID = addressToDID(keypairToAddress(issuerKeypair), VIETCHAIN);
    issuerKeyDoc = registerDID(issuerKeypair, issuerDID);
    registeredDIDs.push(issuerDID);

    // Create holder
    const holderKeypair = new Secp256k1Keypair(
      '2222222222222222222222222222222222222222222222222222222222222222',
    );
    holderDID = addressToDID(keypairToAddress(holderKeypair), VIETCHAIN);
    holderKeyDoc = registerDID(holderKeypair, holderDID);
    registeredDIDs.push(holderDID);

    // Issue credential
    signedCredential = await issueCredential(issuerKeyDoc, {
      '@context': [CREDENTIALS_V1, CREDENTIALS_EXAMPLES_V1],
      type: ['VerifiableCredential'],
      issuer: issuerDID,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: holderDID,
        alumniOf: 'Proof Order University',
      },
    });

    // Sign presentation containing the credential
    signedVP = await signPresentation(
      {
        '@context': [CREDENTIALS_V1],
        type: ['VerifiablePresentation'],
        verifiableCredential: [signedCredential],
        holder: holderDID,
      },
      holderKeyDoc,
      testChallenge,
      testDomain,
    );
  });

  afterAll(() => {
    registeredDIDs.forEach(cleanupDID);
    vi.restoreAllMocks();
  });

  it('verifies VP with embedded credentials (proof + credentials both pass)', async () => {
    const result = await verifyPresentation(signedVP, {
      challenge: testChallenge,
      domain: testDomain,
    }) as {
      verified: boolean;
      presentationResult: { verified: boolean };
      credentialResults: Array<{ verified: boolean }>;
      error?: Error;
    };

    expect(result.verified).toBe(true);
    expect(result.presentationResult.verified).toBe(true);
    expect(result.credentialResults).toHaveLength(1);
    expect(result.credentialResults[0].verified).toBe(true);
  }, 30000);

  it('fails when VP proof challenge does not match', async () => {
    const result = await verifyPresentation(signedVP, {
      challenge: 'wrong-challenge',
      domain: testDomain,
    }) as { verified: boolean };

    expect(result.verified).toBe(false);
  }, 30000);

  it('fails when credential inside VP is tampered', async () => {
    const tamperedVP = {
      ...signedVP,
      verifiableCredential: [{
        ...(signedVP as { verifiableCredential: Record<string, unknown>[] }).verifiableCredential[0],
        credentialSubject: {
          id: holderDID,
          alumniOf: 'Fake University',
        },
      }],
    };

    const result = await verifyPresentation(tamperedVP, {
      challenge: testChallenge,
      domain: testDomain,
    }) as { verified: boolean };

    expect(result.verified).toBe(false);
  }, 30000);

  it('requires challenge param (no unsignedPresentation bypass)', async () => {
    const result = await verifyPresentation(signedVP, {}) as {
      verified: boolean;
      error?: Error;
    };

    expect(result.verified).toBe(false);
    expect(result.error?.message).toMatch(/challenge/i);
  }, 30000);

  it('verifies VP with multiple credentials', async () => {
    // Issue a second credential
    const secondCredential = await issueCredential(issuerKeyDoc, {
      '@context': [CREDENTIALS_V1, CREDENTIALS_EXAMPLES_V1],
      type: ['VerifiableCredential'],
      issuer: issuerDID,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: holderDID,
        degree: 'Masters of Science',
      },
    });

    const multiVP = await signPresentation(
      {
        '@context': [CREDENTIALS_V1],
        type: ['VerifiablePresentation'],
        verifiableCredential: [signedCredential, secondCredential],
        holder: holderDID,
      },
      holderKeyDoc,
      'multi-cred-challenge',
      testDomain,
    );

    const result = await verifyPresentation(multiVP, {
      challenge: 'multi-cred-challenge',
      domain: testDomain,
    }) as {
      verified: boolean;
      presentationResult: { verified: boolean };
      credentialResults: Array<{ verified: boolean }>;
    };

    expect(result.verified).toBe(true);
    expect(result.presentationResult.verified).toBe(true);
    expect(result.credentialResults).toHaveLength(2);
    expect(result.credentialResults[0].verified).toBe(true);
    expect(result.credentialResults[1].verified).toBe(true);
  }, 30000);
});
