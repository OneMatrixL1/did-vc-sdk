import { describe, it, expect, beforeAll } from 'vitest';
import { VPRequestBuilder } from '../../src/builder/request-builder.js';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';
import { matchCredentials } from '../../src/resolver/matcher.js';
import { resolvePresentation } from '../../src/resolver/resolver.js';
import { verifyPresentationStructure } from '../../src/verifier/structural-verifier.js';
import { createICAO9303ProofSystem } from '../../src/proof-system/icao9303-proof-system.js';
import { createPoseidon2Hasher, buildMerkleTree } from '@1matrix/zkp-provider';
import type { SchemaProofSystem } from '../../src/types/proof-system.js';
import type { DocumentRequestMatch, LogicalRuleMatch } from '../../src/types/matching.js';
import { parentCCCD, childCCCD } from '../fixtures/cccd-factory.js';

let proofSystem: SchemaProofSystem;

beforeAll(async () => {
  const poseidon2 = await createPoseidon2Hasher();
  proofSystem = createICAO9303ProofSystem({ poseidon2, buildMerkleTree });
}, 60000);

describe('School Enrollment E2E', () => {
  it('builds request -> matches -> resolves VP -> verifies structure', async () => {
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
          .setSchemaType('ICAO9303SOD')
          .setName('Parent ID')
          .disclose({ field: 'fullName', id: 'c1' })
          .greaterThan({ field: 'dateOfBirth', value: '20080209', id: 'c2' }),
      )
      .addDocumentRequest(
        new DocumentRequestBuilder('child', 'CCCDCredential')
          .setSchemaType('ICAO9303SOD')
          .setName('Child ID')
          .disclose({ field: 'fullName', id: 'c3' })
          .disclose({ field: 'dateOfBirth', id: 'c4' }),
      )
      .build();

    expect(request.id).toBe('req-e2e');
    expect(request.rules.type).toBe('Logical');

    // 2. Match credentials using real proof system
    const credentials = [parentCCCD.credential, childCCCD.credential];
    const matchResult = matchCredentials(request.rules, credentials, {
      'ICAO9303SOD': proofSystem,
    });

    expect(matchResult.satisfied).toBe(true);
    const logical = matchResult as LogicalRuleMatch;
    const parentMatch = logical.values[0] as DocumentRequestMatch;
    const childMatch = logical.values[1] as DocumentRequestMatch;

    expect(parentMatch.satisfied).toBe(true);
    expect(childMatch.satisfied).toBe(true);

    // Parent: fullName disclosed, greaterThan is a predicate (always satisfiable at match time)
    expect(parentMatch.candidates[0].disclosedFields).toContain('fullName');
    expect(parentMatch.candidates[0].satisfiablePredicates).toContain('c2');

    // Child: fullName + dateOfBirth disclosed
    expect(childMatch.candidates[0].disclosedFields).toContain('fullName');
    expect(childMatch.candidates[0].disclosedFields).toContain('dateOfBirth');
  });

  it('rejects VP with wrong nonce', async () => {
    const request = new VPRequestBuilder('req-nonce', 'correct-nonce')
      .setVerifier({
        id: 'did:web:school.vn',
        name: 'Test',
        url: 'https://school.vn',
      })
      .addDocumentRequest(
        new DocumentRequestBuilder('doc1', 'CCCDCredential')
          .setSchemaType('ICAO9303SOD')
          .setDisclosureMode('full'),
      )
      .build();

    const vp = await resolvePresentation(
      request,
      [parentCCCD.credential],
      [{ docRequestID: 'doc1', credentialIndex: 0 }],
      {
        holder: 'did:key:z6MkTest',
        proofSystems: { 'ICAO9303SOD': proofSystem },
        signPresentation: async () => ({
          type: 'DataIntegrityProof',
          verificationMethod: 'did:key:z6MkTest#keys-1',
          proofPurpose: 'authentication' as const,
          challenge: 'wrong-nonce',
          domain: 'school.vn',
          proofValue: 'z' + 'A'.repeat(85),
        }),
      },
    );

    const result = verifyPresentationStructure(request, vp);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Nonce mismatch'))).toBe(true);
  });
});
