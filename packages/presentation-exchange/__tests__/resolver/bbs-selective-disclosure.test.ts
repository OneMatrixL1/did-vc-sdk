/**
 * BBS+ Selective Disclosure E2E Test
 *
 * Verifies the full flow of BBS+ selective disclosure through PE:
 *   1. Issue a BBS-signed credential (Bls12381BBSSignatureDock2023)
 *   2. Build VPRequest with schemaType: 'JsonSchema', disclosureMode: 'selective'
 *   3. matchCredentials() → satisfied
 *   4. resolvePresentation() → auto-detects BBS → BBS derivation
 *   5. Assert derived credential proof.type = 'Bls12381BBSSignatureProofDock2023'
 *   6. Assert disclosed fields present, hidden fields absent
 *   7. verifyCredential(derivedCred) → { verified: true }
 *   8. Tamper test: modify revealed field → verification fails
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { initializeWasm } from '@1matrix/credential-sdk/crypto';
import Bls12381BBSKeyPairDock2023 from '@1matrix/credential-sdk/src/vc/crypto/Bls12381BBSKeyPairDock2023';
import { Bls12381BBS23DockVerKeyName } from '@1matrix/credential-sdk/vc-crypto-constants';
import { Secp256k1Keypair } from '@1matrix/credential-sdk/keypairs';
import {
  addressToDID,
  keypairToAddress,
} from '@1matrix/credential-sdk/src/modules/ethr-did/utils.js';
import {
  issueCredential as sdkIssueCredential,
  verifyCredential as sdkVerifyCredential,
} from '@1matrix/credential-sdk/vc';
import networkCache from '../../../credential-sdk/tests/utils/network-cache';

import { matchCredentials } from '../../src/resolver/matcher.js';
import { resolvePresentation } from '../../src/resolver/resolver.js';
import { verifyPresentationStructure } from '../../src/verifier/structural-verifier.js';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';
import { VPRequestBuilder } from '../../src/builder/request-builder.js';
import type { DocumentRequestMatch } from '../../src/types/matching.js';
import type { HolderProof } from '../../src/types/response.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CREDENTIALS_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const CREDENTIALS_EXAMPLES_CONTEXT = 'https://www.w3.org/2018/credentials/examples/v1';
const BBS_V1_CONTEXT = 'https://ld.truvera.io/security/bbs/v1';
const SECURITY_V2_CONTEXT = 'https://w3id.org/security/v2';
const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1';
const VIETCHAIN_NETWORK = 'vietchain';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function registerBBSDID(
  keypair: InstanceType<typeof Bls12381BBSKeyPairDock2023>,
  did: string,
) {
  const keyId = `${did}#keys-bbs`;
  const address = did.split(':').pop();
  const cache = networkCache as Record<string, unknown>;

  cache[did] = {
    '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
    id: did,
    verificationMethod: [
      {
        id: `${did}#controller`,
        type: 'EcdsaSecp256k1RecoveryMethod2020',
        controller: did,
        blockchainAccountId: `eip155:1:${address}`,
      },
    ],
    assertionMethod: [`${did}#controller`, keyId],
    authentication: [`${did}#controller`],
  };

  return {
    id: keyId,
    controller: did,
    type: Bls12381BBS23DockVerKeyName,
    keypair,
  };
}

function cacheVerificationMethod(credential: Record<string, unknown>) {
  const proof = credential.proof as Record<string, unknown>;
  const verificationMethod = proof.verificationMethod as string;
  const cache = networkCache as Record<string, unknown>;

  cache[verificationMethod] = {
    '@context': BBS_V1_CONTEXT,
    id: verificationMethod,
    type: 'Bls12381BBSVerificationKeyDock2023',
    controller: credential.issuer,
    publicKeyBase58: proof.publicKeyBase58,
  };
}

function registerSecp256k1DID(
  keypair: InstanceType<typeof Secp256k1Keypair>,
  did: string,
) {
  // eslint-disable-next-line no-underscore-dangle
  const publicKeyBytes = keypair._publicKey();
  const b58 = require('bs58');
  const publicKeyBase58 = b58.encode(publicKeyBytes);
  const keyId = `${did}#keys-1`;
  const cache = networkCache as Record<string, unknown>;

  cache[keyId] = {
    '@context': SECURITY_V2_CONTEXT,
    id: keyId,
    type: 'EcdsaSecp256k1VerificationKey2019',
    controller: did,
    publicKeyBase58,
  };

  cache[did] = {
    '@context': [DID_V1_CONTEXT, SECURITY_V2_CONTEXT],
    id: did,
    verificationMethod: [
      { id: keyId, type: 'EcdsaSecp256k1VerificationKey2019', controller: did, publicKeyBase58 },
    ],
    assertionMethod: [keyId],
    authentication: [keyId],
  };

  return {
    id: keyId,
    controller: did,
    type: 'EcdsaSecp256k1VerificationKey2019',
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

describe('BBS+ selective disclosure through PE', () => {
  let issuerKeyDoc: ReturnType<typeof registerBBSDID>;
  let issuerDID: string;
  let holderDID: string;

  const registeredDIDs: string[] = [];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let signedVC: any;

  beforeAll(async () => {
    await initializeWasm();

    // Mock fetch for DID resolution
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
        throw new Error(`[bbs-sd-e2e] Unmocked URL: ${url}`);
      }),
    );

    // Create BBS issuer
    const issuerKeypair = Bls12381BBSKeyPairDock2023.generate({
      id: 'bbs-issuer',
      controller: 'temp',
    });
    const issuerAddress = keypairToAddress(issuerKeypair);
    issuerDID = addressToDID(issuerAddress, VIETCHAIN_NETWORK);
    issuerKeyDoc = registerBBSDID(issuerKeypair, issuerDID);
    registeredDIDs.push(issuerDID);

    // Create holder (secp256k1 for VP signing)
    const holderKeypair = new Secp256k1Keypair(
      'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
    );
    holderDID = addressToDID(keypairToAddress(holderKeypair), VIETCHAIN_NETWORK);
    registerSecp256k1DID(holderKeypair, holderDID);
    registeredDIDs.push(holderDID);

    // Issue BBS-signed credential
    const unsignedVC = {
      '@context': [CREDENTIALS_V1_CONTEXT, CREDENTIALS_EXAMPLES_CONTEXT, BBS_V1_CONTEXT],
      type: ['VerifiableCredential', 'AlumniCredential'],
      issuer: issuerDID,
      issuanceDate: '2026-01-01T00:00:00Z',
      credentialSubject: {
        id: holderDID,
        givenName: 'Alice',
        familyName: 'Smith',
        alumniOf: 'Example University',
        graduationYear: 2020,
      },
    };

    signedVC = await sdkIssueCredential(issuerKeyDoc, unsignedVC);

    // Cache verification method so Presentation class can resolve it
    cacheVerificationMethod(signedVC);
  }, 60000);

  afterAll(() => {
    registeredDIDs.forEach(cleanupDID);
    vi.restoreAllMocks();
  });

  it('issues a BBS-signed credential with correct proof type', () => {
    expect(signedVC.proof).toBeDefined();
    expect(signedVC.proof.type).toBe('Bls12381BBSSignatureDock2023');
    expect(signedVC.proof.verificationMethod).toBe(issuerKeyDoc.id);
  });

  it('resolvePresentation auto-detects BBS and produces derived proof', async () => {
    // Build VPRequest asking for selective disclosure
    const vpRequest = new VPRequestBuilder('req-bbs-sd', 'nonce-bbs-123')
      .setName('BBS Selective Disclosure Test')
      .setVerifier({
        id: 'did:web:verifier.example',
        name: 'Test Verifier',
        url: 'https://verifier.example',
      })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('dr-alumni', 'AlumniCredential')
          .setSchemaType('JsonSchema')
          .setDisclosureMode('selective')
          .disclose('c-alumni', '$.credentialSubject.alumniOf', { purpose: 'University' })
          .disclose('c-grad', '$.credentialSubject.graduationYear', { purpose: 'Graduation year' }),
      )
      .build();

    // Match credentials
    const matchResult = matchCredentials(vpRequest.rules, [signedVC]);
    const match = matchResult as DocumentRequestMatch;
    expect(match.satisfied).toBe(true);
    expect(match.candidates[0].fullyQualified).toBe(true);

    // Resolve presentation — BBS auto-detection should kick in
    const vp = await resolvePresentation(
      vpRequest,
      [signedVC],
      [{ docRequestID: 'dr-alumni', credentialIndex: 0 }],
      {
        holder: holderDID,
        signPresentation: async () => ({
          type: 'EcdsaSecp256k1Signature2019',
          cryptosuite: '',
          verificationMethod: `${holderDID}#keys-1`,
          proofPurpose: 'authentication' as const,
          challenge: 'nonce-bbs-123',
          domain: 'verifier.example',
          proofValue: 'mock-holder-sig',
        }),
      },
    );

    // VP structure checks
    expect(vp.type).toContain('VerifiablePresentation');
    expect(vp.holder).toBe(holderDID);
    expect(vp.verifiableCredential).toHaveLength(1);
    expect(vp.presentationSubmission).toHaveLength(1);

    const derivedCred = vp.verifiableCredential[0];

    // Derived proof type must be the BBS proof type, not the original signature type
    expect(derivedCred.proof).toBeDefined();
    const proof = derivedCred.proof as Record<string, unknown>;
    expect(proof.type).toBe('Bls12381BBSSignatureProofDock2023');

    // Disclosed fields must be present
    expect(derivedCred.credentialSubject.alumniOf).toBe('Example University');
    expect(derivedCred.credentialSubject.graduationYear).toBe(2020);

    // Hidden fields must be absent (cryptographically not revealed)
    expect(derivedCred.credentialSubject.givenName).toBeUndefined();
    expect(derivedCred.credentialSubject.familyName).toBeUndefined();

    // Essential metadata preserved
    expect(derivedCred.issuer).toBe(issuerDID);
    expect(derivedCred.type).toContain('VerifiableCredential');
    expect(derivedCred.type).toContain('AlumniCredential');

    // Structural verification
    const structResult = verifyPresentationStructure(vpRequest, vp);
    expect(structResult.valid).toBe(true);
    expect(structResult.errors).toHaveLength(0);

    // Cryptographic verification of the derived credential
    const verifyResult = await sdkVerifyCredential(derivedCred);
    expect(verifyResult.verified).toBe(true);
  }, 60000);

  it('tampering a revealed field causes verification to fail', async () => {
    const vpRequest = new VPRequestBuilder('req-bbs-tamper', 'nonce-tamper')
      .setName('Tamper Test')
      .setVerifier({
        id: 'did:web:verifier.example',
        name: 'Test Verifier',
        url: 'https://verifier.example',
      })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('dr-tamper', 'AlumniCredential')
          .setSchemaType('JsonSchema')
          .setDisclosureMode('selective')
          .disclose('c-alumni', '$.credentialSubject.alumniOf', { purpose: 'University' }),
      )
      .build();

    const vp = await resolvePresentation(
      vpRequest,
      [signedVC],
      [{ docRequestID: 'dr-tamper', credentialIndex: 0 }],
      {
        holder: holderDID,
        signPresentation: async () => ({
          type: 'EcdsaSecp256k1Signature2019',
          cryptosuite: '',
          verificationMethod: `${holderDID}#keys-1`,
          proofPurpose: 'authentication' as const,
          challenge: 'nonce-tamper',
          domain: 'verifier.example',
          proofValue: 'mock-holder-sig',
        }),
      },
    );

    const derivedCred = vp.verifiableCredential[0];

    // Tamper with a revealed field
    const tampered = {
      ...derivedCred,
      credentialSubject: {
        ...derivedCred.credentialSubject,
        alumniOf: 'Fake University',
      },
    };

    const verifyResult = await sdkVerifyCredential(tampered);
    expect(verifyResult.verified).toBe(false);
  }, 60000);
}, 120000);
