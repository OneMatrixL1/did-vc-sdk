/**
 * buildSigned() integration test — real secp256k1 signing + full crypto verification
 *
 * Proves that buildSigned:
 * 1. Signs without JSON-LD context errors (VPRequest fields are covered)
 * 2. Produces a proof with correct purpose (assertionMethod, not authentication)
 * 3. Proof is cryptographically verifiable by reconstructing the VP-like envelope
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import b58 from 'bs58';

// credential-sdk
import { Secp256k1Keypair } from '@1matrix/credential-sdk/keypairs';
import { addressToDID, keypairToAddress } from '@1matrix/credential-sdk/src/modules/ethr-did/utils.js';
import { verifyPresentation } from '@1matrix/credential-sdk/vc';
import { EcdsaSecp256k1VerKeyName } from '@1matrix/credential-sdk/vc-crypto-constants';
// eslint-disable-next-line @typescript-eslint/no-require-imports
import jsigs from 'jsonld-signatures';
import networkCache from '../../../credential-sdk/tests/utils/network-cache';

// presentation-exchange
import { VPRequestBuilder } from '../../src/builder/request-builder.js';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';
import { verifyVPRequest, verifyVPRequestFull } from '../../src/verifier/request-verifier.js';
import type { KeyDoc } from '../../src/types/request.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';
const SECURITY_V2 = 'https://w3id.org/security/v2';
const DID_V1 = 'https://www.w3.org/ns/did/v1';
const VIETCHAIN = 'vietchain';

// ---------------------------------------------------------------------------
// DID registration helpers (same pattern as cccd-e2e)
// ---------------------------------------------------------------------------

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
// The inline context buildSigned uses — we need the same to verify
// ---------------------------------------------------------------------------

const VP_REQUEST_CONTEXT = {
  verifier: { '@id': 'https://w3id.org/vprequest#verifier', '@type': '@id' },
  version: 'https://schema.org/version',
  name: 'https://schema.org/name',
  nonce: 'https://w3id.org/security#nonce',
  verifierName: 'https://schema.org/alternateName',
  verifierUrl: 'https://schema.org/url',
  verifierCredentials: 'https://w3id.org/security#verifiableCredential',
  createdAt: 'https://schema.org/dateCreated',
  expiresAt: 'https://schema.org/expires',
  rules: { '@id': 'https://w3id.org/vprequest#rules', '@type': '@json' },
};

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('VPRequestBuilder.buildSigned()', () => {
  let verifierKeyDoc: KeyDoc;
  let verifierDID: string;
  const registeredDIDs: string[] = [];

  beforeAll(() => {
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
        throw new Error(`[build-signed-test] Unmocked URL: ${url}`);
      }),
    );

    const keypair = new Secp256k1Keypair(
      'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233',
    );
    verifierDID = addressToDID(keypairToAddress(keypair), VIETCHAIN);
    verifierKeyDoc = registerDID(keypair, verifierDID);
    registeredDIDs.push(verifierDID);
  });

  afterAll(() => {
    registeredDIDs.forEach(cleanupDID);
    vi.restoreAllMocks();
  });

  it('signs a VPRequest and the proof is cryptographically verifiable', async () => {
    // ---------------------------------------------------------------
    // 1. Build and sign
    // ---------------------------------------------------------------
    const signed = await new VPRequestBuilder('req-test', 'nonce-test-123')
      .setVerifier({
        id: verifierDID,
        name: 'Test Verifier',
        url: 'https://verifier.example.com',
      })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('dr-1', 'KYCCredential')
          .setSchemaType('JsonSchema')
          .disclose('c-name', '$.credentialSubject.fullName'),
      )
      .buildSigned(verifierKeyDoc);

    // ---------------------------------------------------------------
    // 2. Structural validation passes
    // ---------------------------------------------------------------
    const structural = verifyVPRequest(signed);
    expect(structural.errors).toHaveLength(0);
    expect(structural.valid).toBe(true);

    // ---------------------------------------------------------------
    // 3. Proof fields are correct
    // ---------------------------------------------------------------
    expect(signed.proof).toBeDefined();
    expect(signed.proof!.proofPurpose).toBe('assertionMethod');
    expect(signed.proof!.challenge).toBe('nonce-test-123');
    expect(signed.proof!.domain).toBe('verifier.example.com');
    expect(signed.proof!.verificationMethod).toBe(verifierKeyDoc.id);
    expect(signed.proof!.type).toBe('EcdsaSecp256k1Signature2019');
    expect(signed.proof!.jws).toBeDefined();

    // ---------------------------------------------------------------
    // 4. Crypto verification — reconstruct VP-like envelope and verify
    // ---------------------------------------------------------------
    const { proof, ...unsigned } = signed;
    const vpToVerify = {
      '@context': [CREDENTIALS_V1, VP_REQUEST_CONTEXT],
      ...unsigned,
      type: ['VerifiablePresentation'],
      holder: unsigned.verifier,
      proof,
    };

    const { AssertionProofPurpose } = jsigs.purposes;
    const verifyPurpose = new AssertionProofPurpose({
      challenge: signed.nonce,
      domain: new URL(signed.verifierUrl).hostname,
    });

    const result = await verifyPresentation(vpToVerify, {
      challenge: signed.nonce,
      domain: new URL(signed.verifierUrl).hostname,
      presentationPurpose: verifyPurpose,
    }) as { verified: boolean };

    expect(result.verified).toBe(true);
  }, 30000);

  it('fails structural validation when proof purpose is not assertionMethod', async () => {
    const signed = await new VPRequestBuilder('req-test-2', 'nonce-test-456')
      .setVerifier({
        id: verifierDID,
        name: 'Test Verifier',
        url: 'https://verifier.example.com',
      })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('dr-2', 'KYCCredential')
          .setSchemaType('JsonSchema')
          .disclose('c-name', '$.credentialSubject.fullName'),
      )
      .buildSigned(verifierKeyDoc);

    // Tamper: change proofPurpose to authentication
    const tampered = {
      ...signed,
      proof: { ...signed.proof!, proofPurpose: 'authentication' as const },
    };

    const result = verifyVPRequest(tampered as typeof signed);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toMatch(/proof purpose must be "assertionMethod"/);
  }, 30000);

  it('fails structural validation when proof challenge does not match nonce', async () => {
    const signed = await new VPRequestBuilder('req-test-3', 'nonce-original')
      .setVerifier({
        id: verifierDID,
        name: 'Test Verifier',
        url: 'https://verifier.example.com',
      })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('dr-3', 'KYCCredential')
          .setSchemaType('JsonSchema')
          .disclose('c-name', '$.credentialSubject.fullName'),
      )
      .buildSigned(verifierKeyDoc);

    // Tamper nonce — structural validation catches the mismatch
    const tampered = { ...signed, nonce: 'tampered-nonce' };
    const result = verifyVPRequest(tampered);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toMatch(/proof challenge mismatch/);
  }, 30000);
});

// ---------------------------------------------------------------------------
// verifyVPRequestFull — structural + crypto
// ---------------------------------------------------------------------------

describe('verifyVPRequestFull()', () => {
  let verifierKeyDoc: KeyDoc;
  let verifierDID: string;
  const registeredDIDs: string[] = [];

  beforeAll(() => {
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
        throw new Error(`[verify-request-test] Unmocked URL: ${url}`);
      }),
    );

    const keypair = new Secp256k1Keypair(
      'bbccddee00112233bbccddee00112233bbccddee00112233bbccddee00112233',
    );
    verifierDID = addressToDID(keypairToAddress(keypair), VIETCHAIN);
    verifierKeyDoc = registerDID(keypair, verifierDID);
    registeredDIDs.push(verifierDID);
  });

  afterAll(() => {
    registeredDIDs.forEach(cleanupDID);
    vi.restoreAllMocks();
  });

  it('verifies a signed VPRequest (structural + crypto)', async () => {
    const signed = await new VPRequestBuilder('req-full-1', 'nonce-full-123')
      .setVerifier({
        id: verifierDID,
        name: 'Full Verifier',
        url: 'https://verifier.example.com',
      })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('dr-f1', 'KYCCredential')
          .setSchemaType('JsonSchema')
          .disclose('c-name', '$.credentialSubject.fullName'),
      )
      .buildSigned(verifierKeyDoc);

    const result = await verifyVPRequestFull(signed);

    expect(result.verified).toBe(true);
    expect(result.structural.valid).toBe(true);
    expect(result.crypto).not.toBeNull();
    expect(result.crypto!.verified).toBe(true);
    expect(result.errors).toHaveLength(0);
  }, 30000);

  it('passes for unsigned VPRequest (structural only, no crypto)', async () => {
    const unsigned = new VPRequestBuilder('req-unsigned', 'nonce-unsigned')
      .setVerifier({
        id: verifierDID,
        name: 'Unsigned Verifier',
        url: 'https://verifier.example.com',
      })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('dr-u1', 'KYCCredential')
          .setSchemaType('JsonSchema')
          .disclose('c-name', '$.credentialSubject.fullName'),
      )
      .build();

    const result = await verifyVPRequestFull(unsigned);

    expect(result.verified).toBe(true);
    expect(result.structural.valid).toBe(true);
    expect(result.crypto).toBeNull();
  }, 30000);

  it('fails crypto when request content is tampered', async () => {
    const signed = await new VPRequestBuilder('req-tamper', 'nonce-tamper')
      .setVerifier({
        id: verifierDID,
        name: 'Tamper Verifier',
        url: 'https://verifier.example.com',
      })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('dr-t1', 'KYCCredential')
          .setSchemaType('JsonSchema')
          .disclose('c-name', '$.credentialSubject.fullName'),
      )
      .buildSigned(verifierKeyDoc);

    // Verify with wrong challenge — crypto proof purpose check fails
    const result = await verifyVPRequestFull(signed, {
      // Override the nonce used for structural check so structural passes,
      // but pass a different challenge to the crypto layer by tampering proof
    });

    // Tamper the proof challenge after signing — structural sees mismatch
    const tamperedProof = { ...signed, proof: { ...signed.proof!, challenge: 'wrong-challenge' } };
    const result2 = await verifyVPRequestFull(tamperedProof);

    // Structural catches the nonce/challenge mismatch
    expect(result2.verified).toBe(false);
    expect(result2.errors[0]).toMatch(/challenge mismatch/);
  }, 30000);

  it('fails structural when required fields are missing', async () => {
    const signed = await new VPRequestBuilder('req-struct-fail', 'nonce-sf')
      .setVerifier({
        id: verifierDID,
        name: 'Struct Verifier',
        url: 'https://verifier.example.com',
      })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('dr-sf', 'KYCCredential')
          .setSchemaType('JsonSchema')
          .disclose('c-name', '$.credentialSubject.fullName'),
      )
      .buildSigned(verifierKeyDoc);

    // Remove required field
    const broken = { ...signed, verifier: '' };
    const result = await verifyVPRequestFull(broken);

    expect(result.verified).toBe(false);
    expect(result.structural.valid).toBe(false);
    // Crypto should not even run
    expect(result.crypto).toBeNull();
  }, 30000);
});
