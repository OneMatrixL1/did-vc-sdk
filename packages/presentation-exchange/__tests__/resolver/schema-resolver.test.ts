import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import { jsonSchemaResolver } from '../../src/resolvers/json-schema-resolver.js';
import { createICAOSchemaResolver } from '../../src/resolvers/icao-schema-resolver.js';
import { matchCredentials } from '../../src/resolver/matcher.js';
import { resolvePresentation } from '../../src/resolver/resolver.js';
import { verifyPresentationStructure } from '../../src/verifier/structural-verifier.js';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';
import { VPRequestBuilder } from '../../src/builder/request-builder.js';
import type { DocumentRequestMatch } from '../../src/types/matching.js';
import { parentCredential } from '../fixtures/school-enrollment.js';

// ---------------------------------------------------------------------------
// Helpers — build ICAO DG blobs for testing
// ---------------------------------------------------------------------------

function encodeDG13Field(tagNum: number, value: string): Buffer {
  const strBuf = Buffer.from(value, 'utf-8');
  const intTag = Buffer.from([0x02, 0x01, tagNum]);
  const strTag = Buffer.from([0x0C, strBuf.length]);
  return Buffer.concat([intTag, strTag, strBuf]);
}

function buildDG13(fields: Record<number, string>): string {
  const parts = Object.entries(fields).map(([tag, val]) =>
    encodeDG13Field(Number(tag), val),
  );
  return Buffer.concat(parts).toString('base64');
}

function buildDG2(): string {
  return Buffer.from([
    0x00, 0x00,
    0xFF, 0xD8, 0xFF,
    0xE0, 0x00, 0x10,
    0x4A, 0x46, 0x49, 0x46,
  ]).toString('base64');
}

// ---------------------------------------------------------------------------
// ICAO credential fixture
// ---------------------------------------------------------------------------

const dg13Base64 = buildDG13({
  2: 'NGUYEN VAN A',
  3: '15/03/1985',
  9: '123 Main St, Hanoi',
});

const dg2Base64 = buildDG2();

const icaoCredential = {
  type: ['VerifiableCredential', 'CCCDCredential'] as string[],
  issuer: 'did:web:cccd.gov.vn',
  credentialSubject: {
    id: 'did:vbsn:cccd:test-key',
    dg13: dg13Base64,
    dg2: dg2Base64,
  },
  proof: {
    type: 'DataIntegrityProof',
    dgProfile: 'VN-CCCD-2024',
    proofPurpose: 'assertionMethod',
    created: '2026-01-01T00:00:00Z',
    sod: 'mock-sod',
  },
};

// ---------------------------------------------------------------------------
// JsonSchema resolver tests
// ---------------------------------------------------------------------------

describe('JsonSchemaResolver', () => {
  describe('resolveField', () => {
    it('resolves a JSONPath field from credential', () => {
      const result = jsonSchemaResolver.resolveField(
        parentCredential,
        '$.credentialSubject.fullName',
      );
      expect(result.found).toBe(true);
      expect(result.value).toBe('Nguyen Van A');
    });

    it('returns not-found for missing field', () => {
      const result = jsonSchemaResolver.resolveField(
        parentCredential,
        '$.credentialSubject.nonExistent',
      );
      expect(result.found).toBe(false);
    });
  });

  describe('deriveCredential', () => {
    it('produces a selective credential with only disclosed fields', async () => {
      const presented = await jsonSchemaResolver.deriveCredential(
        parentCredential,
        ['$.credentialSubject.fullName'],
      );

      expect(presented.credentialSubject.fullName).toBe('Nguyen Van A');
      expect(presented.credentialSubject.dateOfBirth).toBeUndefined();
      expect(presented.credentialSubject.documentNumber).toBeUndefined();
    });
  });
});

// ---------------------------------------------------------------------------
// matchCredentials — both schema types work with built-in defaults
// ---------------------------------------------------------------------------

describe('matchCredentials with built-in resolvers', () => {
  it('matches JsonSchema requests without passing resolvers', () => {
    const request = {
      type: 'DocumentRequest' as const,
      docRequestID: 'test',
      docType: ['CCCDCredential'],
      schemaType: 'JsonSchema',
      conditions: [
        {
          type: 'DocumentCondition' as const,
          conditionID: 'c1',
          field: '$.credentialSubject.fullName',
          operator: 'disclose' as const,
        },
      ],
    };

    const result = matchCredentials(request, [parentCredential]);
    const match = result as DocumentRequestMatch;

    expect(match.satisfied).toBe(true);
    expect(match.candidates[0].disclosedFields).toContain('$.credentialSubject.fullName');
  });

  it('matches ICAO9303SOD requests without passing resolvers', () => {
    const request = {
      type: 'DocumentRequest' as const,
      docRequestID: 'dr-cccd',
      docType: ['CCCDCredential'],
      schemaType: 'ICAO9303SOD',
      conditions: [
        {
          type: 'DocumentCondition' as const,
          conditionID: 'c-name',
          field: 'fullName',
          operator: 'disclose' as const,
        },
        {
          type: 'DocumentCondition' as const,
          conditionID: 'c-address',
          field: 'permanentAddress',
          operator: 'disclose' as const,
        },
        {
          type: 'DocumentCondition' as const,
          conditionID: 'c-photo',
          field: 'photo',
          operator: 'disclose' as const,
          optional: true,
        },
      ],
    };

    const result = matchCredentials(request, [icaoCredential]);
    const match = result as DocumentRequestMatch;

    expect(match.satisfied).toBe(true);
    expect(match.candidates).toHaveLength(1);
    expect(match.candidates[0].fullyQualified).toBe(true);
    expect(match.candidates[0].disclosedFields).toContain('fullName');
    expect(match.candidates[0].disclosedFields).toContain('permanentAddress');
    expect(match.candidates[0].disclosedFields).toContain('photo');
  });

  it('marks ICAO credential missing field as not fully qualified', () => {
    const request = {
      type: 'DocumentRequest' as const,
      docRequestID: 'dr-cccd',
      docType: ['CCCDCredential'],
      schemaType: 'ICAO9303SOD',
      conditions: [
        {
          type: 'DocumentCondition' as const,
          conditionID: 'c-name',
          field: 'fullName',
          operator: 'disclose' as const,
        },
        {
          type: 'DocumentCondition' as const,
          conditionID: 'c-mrz',
          field: 'documentType',   // requires dg1 which is not in our credential
          operator: 'disclose' as const,
        },
      ],
    };

    const result = matchCredentials(request, [icaoCredential]);
    const match = result as DocumentRequestMatch;

    expect(match.candidates[0].fullyQualified).toBe(false);
    expect(match.candidates[0].missingFields).toContain('documentType');
    expect(match.candidates[0].disclosedFields).toContain('fullName');
  });

  it('matches ZKP conditions as satisfiable', () => {
    const request = {
      type: 'DocumentRequest' as const,
      docRequestID: 'dr-cccd',
      docType: ['CCCDCredential'],
      schemaType: 'ICAO9303SOD',
      conditions: [
        {
          type: 'DocumentCondition' as const,
          conditionID: 'c-name',
          field: 'fullName',
          operator: 'disclose' as const,
        },
        {
          type: 'DocumentCondition' as const,
          conditionID: 'zkp-age',
          operator: 'zkp' as const,
          circuitId: 'age-gte',
          proofSystem: 'groth16' as const,
          publicInputs: { minAge: 18, currentDate: '2026-03-05' },
        },
      ],
    };

    const result = matchCredentials(request, [icaoCredential]);
    const match = result as DocumentRequestMatch;

    expect(match.candidates[0].satisfiableZKPs).toContain('zkp-age');
  });

  it('throws when resolver for schemaType is not found', () => {
    const request = {
      type: 'DocumentRequest' as const,
      docRequestID: 'test',
      docType: ['CCCDCredential'],
      schemaType: 'UnknownSchema',
      conditions: [
        {
          type: 'DocumentCondition' as const,
          conditionID: 'c1',
          field: 'someField',
          operator: 'disclose' as const,
        },
      ],
    };

    expect(() =>
      matchCredentials(request, [parentCredential]),
    ).toThrow('No SchemaResolver registered for schemaType "UnknownSchema"');
  });
});

// ---------------------------------------------------------------------------
// CCCD full flow: create VPRequest → fulfill → verify
// ---------------------------------------------------------------------------

describe('CCCD full flow: create → fulfill → verify', () => {
  // --- Step 1: Verifier creates VPRequest ---
  const vpRequest = new VPRequestBuilder('req-cccd-kyc', 'nonce-abc-123')
    .setName('CCCD Identity Verification')
    .setVerifier({
      id: 'did:web:gov.vn',
      name: 'Vietnam Gov Portal',
      url: 'https://gov.vn',
    })
    .setExpiresAt('2099-12-31T23:59:59Z')
    .addDocumentRequest(
      new DocumentRequestBuilder('dr-cccd', 'CCCDCredential')
        .setSchemaType('ICAO9303SOD')
        .disclose('c-name', 'fullName', { purpose: 'Full name' })
        .disclose('c-dob', 'dateOfBirth', { purpose: 'Date of birth' })
        .disclose('c-address', 'permanentAddress', { purpose: 'Permanent address' })
        .disclose('c-photo', 'photo', { purpose: 'Portrait photo', optional: true }),
    )
    .build();

  it('Step 1 — verifier builds a valid VPRequest', () => {
    expect(vpRequest.id).toBe('req-cccd-kyc');
    expect(vpRequest.nonce).toBe('nonce-abc-123');
    expect(vpRequest.verifier).toBe('did:web:gov.vn');
    expect(vpRequest.verifierUrl).toBe('https://gov.vn');

    const rule = vpRequest.rules;
    expect(rule.type).toBe('DocumentRequest');
    if (rule.type === 'DocumentRequest') {
      expect(rule.schemaType).toBe('ICAO9303SOD');
      expect(rule.docType).toContain('CCCDCredential');
      expect(rule.conditions).toHaveLength(4);
    }
  });

  it('Step 2 — holder wallet matches CCCD credential against the request', () => {
    const matchResult = matchCredentials(vpRequest.rules, [icaoCredential]);
    const match = matchResult as DocumentRequestMatch;

    expect(match.satisfied).toBe(true);
    expect(match.candidates).toHaveLength(1);
    expect(match.candidates[0].fullyQualified).toBe(true);
    // All required + optional fields resolvable from our DGs
    expect(match.candidates[0].disclosedFields).toContain('fullName');
    expect(match.candidates[0].disclosedFields).toContain('dateOfBirth');
    expect(match.candidates[0].disclosedFields).toContain('permanentAddress');
    expect(match.candidates[0].disclosedFields).toContain('photo');
    expect(match.candidates[0].missingFields).toHaveLength(0);
  });

  let vp: Awaited<ReturnType<typeof resolvePresentation>>;

  it('Step 3 — holder wallet resolves VP (selective disclosure + sign)', async () => {
    vp = await resolvePresentation(
      vpRequest,
      [icaoCredential],
      [{ docRequestID: 'dr-cccd', credentialIndex: 0 }],
      {
        holder: 'did:vbsn:cccd:test-key',
        signPresentation: async () => ({
          type: 'DataIntegrityProof',
          cryptosuite: 'eddsa-rdfc-2022',
          verificationMethod: 'did:vbsn:cccd:test-key#keys-1',
          proofPurpose: 'authentication',
          challenge: vpRequest.nonce,
          domain: 'gov.vn',
          proofValue: 'mock-holder-signature',
        }),
      },
    );

    // VP structure
    expect(vp.type).toContain('VerifiablePresentation');
    expect(vp.holder).toBe('did:vbsn:cccd:test-key');
    expect(vp.verifiableCredential).toHaveLength(1);
    expect(vp.presentationSubmission).toHaveLength(1);
    expect(vp.presentationSubmission[0].docRequestID).toBe('dr-cccd');

    // VP request-response binding fields
    expect(vp.verifier).toBe('did:web:gov.vn');
    expect(vp.requestId).toBe('req-cccd-kyc');
    expect(vp.requestNonce).toBe('nonce-abc-123');

    // Derived credential has only the required DGs (dg13 + dg2), not all original data
    const cred = vp.verifiableCredential[0];
    expect(cred.type).toContain('CCCDCredential');
    expect(cred.issuer).toBe('did:web:cccd.gov.vn');
    expect(cred.credentialSubject.dg13).toBe(dg13Base64);
    expect(cred.credentialSubject.dg2).toBe(dg2Base64);
    expect(cred.credentialSubject.id).toBe('did:vbsn:cccd:test-key');

    // SOD proof preserved for verifier to check
    expect((cred as Record<string, unknown>).proof).toBeDefined();
  });

  it('Step 4 — verifier validates VP structure against original request', () => {
    const result = verifyPresentationStructure(vpRequest, vp);

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('Step 5 — verifier reads disclosed fields from the presented credential', () => {
    const resolver = createICAOSchemaResolver();
    const cred = vp.verifiableCredential[0];

    const fullName = resolver.resolveField(cred, 'fullName');
    expect(fullName.found).toBe(true);
    expect(fullName.value).toBe('NGUYEN VAN A');

    const dob = resolver.resolveField(cred, 'dateOfBirth');
    expect(dob.found).toBe(true);
    expect(dob.value).toBe('15/03/1985');

    const address = resolver.resolveField(cred, 'permanentAddress');
    expect(address.found).toBe(true);
    expect(address.value).toBe('123 Main St, Hanoi');

    const photo = resolver.resolveField(cred, 'photo');
    expect(photo.found).toBe(true);
    expect(typeof photo.value).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// ICAO resolver — resolveField unit tests
// ---------------------------------------------------------------------------

describe('createICAOSchemaResolver', () => {
  const resolver = createICAOSchemaResolver();

  describe('resolveField', () => {
    it('decodes fullName from dg13 blob', () => {
      const result = resolver.resolveField(icaoCredential, 'fullName');
      expect(result.found).toBe(true);
      expect(result.value).toBe('NGUYEN VAN A');
    });

    it('decodes dateOfBirth from dg13 blob', () => {
      const result = resolver.resolveField(icaoCredential, 'dateOfBirth');
      expect(result.found).toBe(true);
      expect(result.value).toBe('15/03/1985');
    });

    it('decodes permanentAddress from dg13 blob', () => {
      const result = resolver.resolveField(icaoCredential, 'permanentAddress');
      expect(result.found).toBe(true);
      expect(result.value).toBe('123 Main St, Hanoi');
    });

    it('returns not-found for unknown field', () => {
      const result = resolver.resolveField(icaoCredential, 'nonExistentField');
      expect(result.found).toBe(false);
      expect(result.value).toBeUndefined();
    });

    it('decodes photo from dg2 blob', () => {
      const result = resolver.resolveField(icaoCredential, 'photo');
      expect(result.found).toBe(true);
      expect(typeof result.value).toBe('string');
    });
  });

  describe('deriveCredential', () => {
    it('includes only dg13 when requesting fullName + permanentAddress', async () => {
      const presented = await resolver.deriveCredential(
        icaoCredential,
        ['fullName', 'permanentAddress'],
      );

      expect(presented.credentialSubject.dg13).toBe(dg13Base64);
      expect(presented.credentialSubject.dg2).toBeUndefined();
      expect(presented.credentialSubject.id).toBe('did:vbsn:cccd:test-key');
    });

    it('includes dg2 when requesting photo', async () => {
      const presented = await resolver.deriveCredential(
        icaoCredential,
        ['photo'],
      );

      expect(presented.credentialSubject.dg2).toBe(dg2Base64);
      expect(presented.credentialSubject.dg13).toBeUndefined();
    });

    it('includes both dg13 and dg2 when requesting fullName + photo', async () => {
      const presented = await resolver.deriveCredential(
        icaoCredential,
        ['fullName', 'photo'],
      );

      expect(presented.credentialSubject.dg13).toBe(dg13Base64);
      expect(presented.credentialSubject.dg2).toBe(dg2Base64);
    });

    it('preserves credential metadata', async () => {
      const presented = await resolver.deriveCredential(
        icaoCredential,
        ['fullName'],
      );

      expect(presented.type).toEqual(['VerifiableCredential', 'CCCDCredential']);
      expect(presented.issuer).toBe('did:web:cccd.gov.vn');
      expect((presented as Record<string, unknown>).proof).toBeDefined();
    });
  });

  describe('profile auto-detection', () => {
    it('detects profile from credential.proof.dgProfile', () => {
      const result = resolver.resolveField(icaoCredential, 'fullName');
      expect(result.found).toBe(true);
    });

    it('detects profile from credential type when dgProfile is missing', () => {
      const credWithoutProfile = {
        ...icaoCredential,
        proof: { type: 'SomeOtherProof' },
      };

      const result = resolver.resolveField(credWithoutProfile, 'fullName');
      expect(result.found).toBe(true);
      expect(result.value).toBe('NGUYEN VAN A');
    });

    it('returns not-found when no profile matches', () => {
      const unknownCred = {
        type: ['UnknownType'] as string[],
        issuer: 'did:web:unknown',
        credentialSubject: { dg13: dg13Base64 },
      };

      const result = resolver.resolveField(unknownCred, 'fullName');
      expect(result.found).toBe(false);
    });
  });
});
