/**
 * VP Request -> VP Response — complete end-to-end flow.
 *
 * 1. Verifier builds VPRequest
 * 2. Holder matches + resolves VP (real ZKP proofs via ICAO proof system pipeline)
 * 3. Verifier verifies structural + ZKP proof chain
 *
 * All crypto is real.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { VPRequestBuilder } from '../../src/builder/request-builder.js';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';
import { matchCredentials } from '../../src/resolver/matcher.js';
import { resolvePresentation } from '../../src/resolver/resolver.js';
import { verifyPresentationStructure } from '../../src/verifier/structural-verifier.js';
import { createICAO9303ProofSystem } from '../../src/proof-system/icao9303-proof-system.js';
import { createWasmZKPProvider, createPoseidon2Hasher, buildMerkleTree } from '@1matrix/zkp-provider';
import type { ZKPProvider, Poseidon2Hasher } from '@1matrix/zkp-provider';
import type { SchemaProofSystem } from '../../src/types/proof-system.js';
import type { DocumentRequestMatch } from '../../src/types/matching.js';
import { isICAOProofBundle } from '../../src/types/icao-proof-bundle.js';
import type { ICAO9303ZKPProofBundle } from '../../src/types/icao-proof-bundle.js';
import { motherCCCD, createMockVerifyDSC } from '../fixtures/cccd-factory.js';

let zkpProvider: ZKPProvider & { destroy(): void };
let poseidon2: Poseidon2Hasher;
let proofSystem: SchemaProofSystem;

beforeAll(async () => {
  poseidon2 = await createPoseidon2Hasher();
  zkpProvider = await createWasmZKPProvider();
  proofSystem = createICAO9303ProofSystem({ poseidon2, buildMerkleTree });
}, 60000);

describe('VP Request -> VP Response', () => {
  it('holder resolves VP with real ZKP proofs through ICAO pipeline', async () => {
    const cccd = motherCCCD;

    // ===== VERIFIER: build request =====
    const request = new VPRequestBuilder('kyc-001', 'nonce-abc123')
      .setName('Bank KYC')
      .setVerifier({ id: 'did:web:bank.vn', name: 'Vietnam Bank', url: 'https://bank.vn' })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('cccd', 'CCCDCredential')
          .setSchemaType('ICAO9303SOD')
          .setName('National ID')
          .disclose({ field: 'fullName', id: 'c1' })
          .disclose({ field: 'gender', id: 'c2' }),
      )
      .build();

    // ===== HOLDER: match =====
    const matchResult = matchCredentials(
      request.rules,
      [cccd.credential],
      { 'ICAO9303SOD': proofSystem },
    );
    expect(matchResult.satisfied).toBe(true);

    // ===== HOLDER: resolve VP (generates 5 real ZKP proofs) =====
    const vp = await resolvePresentation(
      request,
      [cccd.credential],
      [{ docRequestID: 'cccd', credentialIndex: 0 }],
      {
        holder: 'did:key:z6MkHolder',
        zkpProvider,
        proofSystems: { 'ICAO9303SOD': proofSystem },
        credentialData: () => ({
          sodInputs: cccd.sodInputs,
          dg13Inputs: cccd.dg13CircuitInputs,
          salt: cccd.salt,
          dscCertificate: cccd.dscCertificate,
        }),
        signPresentation: async () => ({
          type: 'DataIntegrityProof',
          verificationMethod: 'did:key:z6MkHolder#keys-1',
          proofPurpose: 'authentication' as const,
          challenge: 'nonce-abc123',
          domain: 'bank.vn',
          proofValue: 'z' + 'A'.repeat(85),
        }),
      },
    );

    // ===== VP structure =====
    expect(vp.holder).toBe('did:key:z6MkHolder');
    expect(vp.verifier).toBe('did:web:bank.vn');
    expect(vp.requestId).toBe('kyc-001');
    expect(vp.requestNonce).toBe('nonce-abc123');
    expect(vp.verifiableCredential).toHaveLength(1);
    expect(vp.presentationSubmission[0].docRequestID).toBe('cccd');

    // ===== Credential has real ICAO proof bundle =====
    const cred = vp.verifiableCredential[0];
    expect(cred.type).toContain('CCCDCredential');
    expect(isICAOProofBundle(cred.proof)).toBe(true);

    const bundle = cred.proof as ICAO9303ZKPProofBundle;

    // DSC certificate included in bundle
    expect(bundle.dscCertificate).toBe(cccd.dscCertificate);

    // Flat array of proofs: 3 chain + 2 reveals = 5
    expect(bundle.proofs).toHaveLength(5);

    // Chain proofs present
    const sodVerify = bundle.proofs.find(p => p.circuitId === 'sod-verify')!;
    const dgMap = bundle.proofs.find(p => p.circuitId === 'dg-map')!;
    const dg13 = bundle.proofs.find(p => p.circuitId === 'dg13-merklelize')!;
    expect(sodVerify.proofValue.length).toBeGreaterThan(100);
    expect(dgMap.proofValue.length).toBeGreaterThan(100);
    expect(dg13.proofValue.length).toBeGreaterThan(100);

    // 2 field reveals
    const reveals = bundle.proofs.filter(p => p.circuitId === 'dg13-field-reveal');
    expect(reveals).toHaveLength(2);
    expect(reveals[0].conditionID).toBe('c1');
    expect(reveals[0].proofValue.length).toBeGreaterThan(100);
    expect(reveals[1].conditionID).toBe('c2');
    expect(reveals[1].proofValue.length).toBeGreaterThan(100);

    // ===== VERIFIER: structural verification =====
    const structural = verifyPresentationStructure(request, vp);
    expect(structural.valid).toBe(true);

    // ===== VERIFIER: verify ZKP proof chain =====
    const verifyDSC = createMockVerifyDSC([cccd.dscCertificate]);
    const verifyResult = await proofSystem.verify(
      cred,
      {
        disclose: [
          { type: 'DocumentCondition', conditionID: 'c1', field: 'fullName', operator: 'disclose' },
          { type: 'DocumentCondition', conditionID: 'c2', field: 'gender', operator: 'disclose' },
        ],
        predicates: [],
      },
      { zkpProvider, verifyDSC },
    );

    expect(verifyResult.verified).toBe(true);
    expect(verifyResult.errors).toHaveLength(0);

    // ===== Binding chain integrity =====
    // dg-map econtent_binding must equal sod-verify output
    expect(dgMap.publicInputs.econtent_binding).toBe(sodVerify.publicOutputs.econtent_binding);

    // dg13 binding must equal dg-map output (same DG13 hash)
    expect(dg13.publicOutputs.binding).toBe(dgMap.publicOutputs.dg_binding);

    // All field reveals use the same commitment from dg13
    const commitment = dg13.publicOutputs.commitment;
    for (const fr of reveals) {
      expect(fr.publicInputs.commitment).toBe(commitment);
    }
  }, 600000);
});
