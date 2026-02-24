import { describe, it, expect } from 'vitest';
import { VPRequestBuilder } from '../../src/builder/request-builder.js';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';
import { matchCredentials } from '../../src/resolver/matcher.js';
import { resolvePresentation } from '../../src/resolver/resolver.js';
import { verifyPresentationStructure } from '../../src/verifier/structural-verifier.js';
import {
  parentCredential,
  childCredential,
} from '../fixtures/school-enrollment.js';
import type { DocumentRequestMatch, LogicalRuleMatch } from '../../src/types/matching.js';

describe('School Enrollment E2E', () => {
  it('builds request → matches → resolves VP → verifies structure', async () => {
    // 1. Build request
    const request = new VPRequestBuilder('req-e2e', 'test-nonce')
      .setName('School Enrollment')
      .setVerifier({
        id: 'did:web:school.vn',
        name: 'ABC School',
        url: 'https://school.vn',
      })
      .setExpiresAt('2099-12-31T23:59:59Z')
      .addDocumentRequest(
        new DocumentRequestBuilder('parent', 'CCCDCredential')
          .setName('Parent ID')
          .disclose('c1', '$.credentialSubject.fullName')
          .zkp('c2', {
            circuitId: 'numeric-range',
            proofSystem: 'groth16',
            privateInputs: { value: '$.credentialSubject.dateOfBirth' },
            publicInputs: { max: 20080209, inputFormat: 'dd/mm/yyyy' },
            purpose: 'Prove parent is 18+',
          }),
      )
      .addDocumentRequest(
        new DocumentRequestBuilder('child', 'CCCDCredential')
          .setName('Child ID')
          .disclose('c3', '$.credentialSubject.fullName')
          .disclose('c4', '$.credentialSubject.dateOfBirth'),
      )
      .build();

    expect(request.id).toBe('req-e2e');
    expect(request.rules.type).toBe('Logical');

    // 2. Match credentials
    const credentials = [parentCredential, childCredential];
    const matchResult = matchCredentials(request.rules, credentials);

    expect(matchResult.satisfied).toBe(true);
    const logical = matchResult as LogicalRuleMatch;
    const parentMatch = logical.values[0] as DocumentRequestMatch;
    const childMatch = logical.values[1] as DocumentRequestMatch;

    expect(parentMatch.satisfied).toBe(true);
    expect(childMatch.satisfied).toBe(true);

    // 3. User selects credentials (parent=index 0, child=index 1)
    const selections = [
      { docRequestID: 'parent', credentialIndex: 0 },
      { docRequestID: 'child', credentialIndex: 1 },
    ];

    // 4. Resolve VP
    const vp = await resolvePresentation(request, credentials, selections, {
      holder: 'did:key:z6MkTest',
      signPresentation: async (unsigned) => ({
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-rdfc-2022',
        verificationMethod: 'did:key:z6MkTest#keys-1',
        proofPurpose: 'authentication',
        challenge: request.nonce,
        domain: 'school.vn',
        proofValue: 'mock-signature',
      }),
    });

    expect(vp.type).toEqual(['VerifiablePresentation']);
    expect(vp.holder).toBe('did:key:z6MkTest');
    expect(vp.verifiableCredential).toHaveLength(2);
    expect(vp.presentationSubmission).toHaveLength(2);

    // Parent credential should have selective disclosure (only fullName)
    expect(vp.verifiableCredential[0].credentialSubject.fullName).toBe(
      'Nguyen Van A',
    );

    // Child credential should have fullName + dateOfBirth
    expect(vp.verifiableCredential[1].credentialSubject.fullName).toBe(
      'Nguyen Van C',
    );
    expect(vp.verifiableCredential[1].credentialSubject.dateOfBirth).toBe(
      '15/06/2015',
    );

    // 5. Verify structure
    const verification = verifyPresentationStructure(request, vp);
    expect(verification.valid).toBe(true);
    expect(verification.errors).toEqual([]);
  });

  it('rejects VP with wrong nonce', async () => {
    const request = new VPRequestBuilder('req-nonce', 'correct-nonce')
      .setVerifier({
        id: 'did:web:school.vn',
        name: 'Test',
        url: 'https://school.vn',
      })
      .addDocumentRequest(
        new DocumentRequestBuilder('doc1', 'CCCDCredential'),
      )
      .build();

    const vp = await resolvePresentation(
      request,
      [parentCredential],
      [{ docRequestID: 'doc1', credentialIndex: 0 }],
      {
        holder: 'did:key:z6MkTest',
        signPresentation: async () => ({
          type: 'DataIntegrityProof',
          verificationMethod: 'did:key:z6MkTest#keys-1',
          proofPurpose: 'authentication',
          challenge: 'wrong-nonce', // intentionally wrong
          domain: 'school.vn',
          proofValue: 'mock',
        }),
      },
    );

    const result = verifyPresentationStructure(request, vp);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Nonce mismatch'))).toBe(true);
  });
});
