import { describe, it, expect } from 'vitest';
import { verifyVPRequest } from '../../src/verifier/request-verifier.js';
import type { VPRequest, VerifierRequestProof } from '../../src/types/request.js';
import type { PresentedCredential } from '../../src/types/credential.js';

function makeValidRequest(overrides?: Partial<VPRequest>): VPRequest {
  return {
    type: ['VerifiablePresentationRequest'],
    id: 'req-1',
    version: '2.0',
    name: 'Test Request',
    nonce: 'abc123',
    verifier: 'did:example:verifier',
    verifierName: 'Test Verifier',
    verifierUrl: 'https://verifier.example.com',
    createdAt: '2025-01-01T00:00:00Z',
    expiresAt: '2099-12-31T23:59:59Z',
    rules: {
      type: 'DocumentRequest',
      docRequestID: 'doc-1',
      docType: ['VerifiableCredential'],
      schemaType: 'JsonSchema',
      conditions: [],
    },
    ...overrides,
  };
}

describe('verifyVPRequest', () => {
  it('passes for a valid request', () => {
    const result = verifyVPRequest(makeValidRequest());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Required fields
  // -------------------------------------------------------------------------

  it('fails when id is missing', () => {
    const result = verifyVPRequest(makeValidRequest({ id: '' }));
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('VPRequest is missing required field "id"');
  });

  it('fails when nonce is missing', () => {
    const result = verifyVPRequest(makeValidRequest({ nonce: '' }));
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('VPRequest is missing required field "nonce"');
  });

  it('fails when verifier is missing', () => {
    const result = verifyVPRequest(makeValidRequest({ verifier: '' }));
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('VPRequest is missing required field "verifier"');
  });

  it('fails when verifierUrl is missing', () => {
    const result = verifyVPRequest(makeValidRequest({ verifierUrl: '' }));
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('VPRequest is missing required field "verifierUrl"');
  });

  it('fails when rules is missing', () => {
    const result = verifyVPRequest(
      makeValidRequest({ rules: undefined as unknown as VPRequest['rules'] }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('VPRequest is missing required field "rules"');
  });

  // -------------------------------------------------------------------------
  // Expiration
  // -------------------------------------------------------------------------

  it('accepts a request without expiresAt', () => {
    const { expiresAt: _, ...noExpiry } = makeValidRequest();
    const result = verifyVPRequest(noExpiry as any);
    expect(result.valid).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Verifier credentials structure
  // -------------------------------------------------------------------------

  it('passes when verifier has no credentials (optional)', () => {
    const req = makeValidRequest();
    delete req.verifierCredentials;
    const result = verifyVPRequest(req);
    expect(result.valid).toBe(true);
  });

  it('passes when verifier credentials are well-formed', () => {
    const req = makeValidRequest({
      verifierCredentials: [
        {
          type: ['VerifiableCredential', 'BusinessLicense'],
          issuer: 'did:example:issuer',
          credentialSubject: { name: 'Acme Corp' },
        },
      ],
    });
    const result = verifyVPRequest(req);
    expect(result.valid).toBe(true);
  });

  it('fails when a verifier credential has empty type array', () => {
    const req = makeValidRequest({
      verifierCredentials: [
        {
          type: [],
          issuer: 'did:example:issuer',
          credentialSubject: { name: 'Acme' },
        },
      ],
    });
    const result = verifyVPRequest(req);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      'verifierCredentials[0] is missing or has empty "type"',
    );
  });

  it('fails when a verifier credential is missing issuer', () => {
    const req = makeValidRequest({
      verifierCredentials: [
        {
          type: ['VerifiableCredential'],
          issuer: '' as unknown as string,
          credentialSubject: { name: 'Acme' },
        },
      ],
    });
    const result = verifyVPRequest(req);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      'verifierCredentials[0] is missing "issuer"',
    );
  });

  it('fails when a verifier credential is missing credentialSubject', () => {
    const req = makeValidRequest({
      verifierCredentials: [
        {
          type: ['VerifiableCredential'],
          issuer: 'did:example:issuer',
          credentialSubject: undefined as unknown as Record<string, unknown>,
        },
      ],
    });
    const result = verifyVPRequest(req);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      'verifierCredentials[0] is missing "credentialSubject"',
    );
  });

  it('reports multiple errors at once', () => {
    const req = makeValidRequest({
      id: '',
      nonce: '',
      verifier: '',
    });
    const result = verifyVPRequest(req);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(3);
  });

  // -------------------------------------------------------------------------
  // Realistic verifier credentials: BBS+ and ICAO
  // -------------------------------------------------------------------------

  describe('BBS+ verifier credential', () => {
    const bbsCredential: PresentedCredential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://ld.truvera.io/security/bbs/v1',
      ],
      id: 'urn:uuid:bbs-verifier-cred-001',
      type: ['VerifiableCredential', 'GovernmentPortalCredential'],
      issuer: 'did:web:ca.gov.vn',
      issuanceDate: '2026-01-15T00:00:00Z',
      credentialSubject: {
        id: 'did:web:gov.vn',
        name: 'Vietnam Government Portal',
        operatingLicense: 'GOV-2026-001',
      },
      proof: {
        type: 'DataIntegrityProof',
        cryptosuite: 'bbs-2023',
        proofValue: 'z3FXQkNoEg...mock-bbs-proof',
      },
    };

    it('passes with a well-formed BBS+ credential', () => {
      const req = makeValidRequest({ verifierCredentials: [bbsCredential] });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('fails when BBS+ credential is missing issuer', () => {
      const req = makeValidRequest({
        verifierCredentials: [
          { ...bbsCredential, issuer: '' as unknown as string },
        ],
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'verifierCredentials[0] is missing "issuer"',
      );
    });

    it('fails when BBS+ credential has empty type array', () => {
      const req = makeValidRequest({
        verifierCredentials: [{ ...bbsCredential, type: [] }],
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'verifierCredentials[0] is missing or has empty "type"',
      );
    });

    it('fails when BBS+ credential is missing credentialSubject', () => {
      const req = makeValidRequest({
        verifierCredentials: [
          {
            ...bbsCredential,
            credentialSubject: undefined as unknown as Record<string, unknown>,
          },
        ],
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'verifierCredentials[0] is missing "credentialSubject"',
      );
    });
  });

  describe('ICAO verifier credential', () => {
    const icaoCredential: PresentedCredential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://cccd.gov.vn/credentials/v1',
      ],
      id: 'urn:uuid:icao-verifier-cred-001',
      type: ['VerifiableCredential', 'CCCDCredential'],
      issuer: { id: 'did:ethr:vietchain:0xABCD1234', name: 'MoPS Vietnam' },
      issuanceDate: '2026-02-01T00:00:00Z',
      credentialSubject: {
        id: 'did:web:gov.vn',
        dg1: 'SSVOTQ==',
        dg13: 'AgECABICABNOZ3V5ZW4gVmFuIEE=',
        dg2: 'AP/Y/+A=',
      },
      proof: {
        type: 'DataIntegrityProof',
        cryptosuite: 'ecdsa-jcs-2019',
        sodSignature: 'MEUCIQD...mock-sod-sig',
        dgHashes: {
          dg1: 'sha256:abc123',
          dg2: 'sha256:def456',
          dg13: 'sha256:ghi789',
        },
        proofValue: 'z4DAe...mock-proof-value',
      },
    };

    it('passes with a well-formed ICAO credential', () => {
      const req = makeValidRequest({ verifierCredentials: [icaoCredential] });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('passes with object-form issuer ({ id, name })', () => {
      const req = makeValidRequest({ verifierCredentials: [icaoCredential] });
      // Sanity: confirm issuer is object-form
      expect(typeof icaoCredential.issuer).toBe('object');
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(true);
    });

    it('fails when ICAO credential is missing issuer', () => {
      const req = makeValidRequest({
        verifierCredentials: [
          {
            ...icaoCredential,
            issuer: undefined as unknown as string,
          },
        ],
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'verifierCredentials[0] is missing "issuer"',
      );
    });

    it('fails when ICAO credential is missing credentialSubject', () => {
      const req = makeValidRequest({
        verifierCredentials: [
          {
            ...icaoCredential,
            credentialSubject: undefined as unknown as Record<string, unknown>,
          },
        ],
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'verifierCredentials[0] is missing "credentialSubject"',
      );
    });
  });

  describe('mixed verifier credentials', () => {
    const bbsCred: PresentedCredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://ld.truvera.io/security/bbs/v1'],
      type: ['VerifiableCredential', 'BusinessLicense'],
      issuer: 'did:web:chamber-of-commerce.vn',
      credentialSubject: { licenseNumber: 'BIZ-2026-999' },
      proof: { type: 'DataIntegrityProof', cryptosuite: 'bbs-2023', proofValue: 'z...' },
    };

    const icaoCred: PresentedCredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://cccd.gov.vn/credentials/v1'],
      type: ['VerifiableCredential', 'CCCDCredential'],
      issuer: { id: 'did:ethr:vietchain:0x1234ABCD', name: 'MoPS Vietnam' },
      credentialSubject: { dg13: 'AgECABICABNOZ3V5ZW4gVmFuIEE=' },
      proof: {
        type: 'DataIntegrityProof',
        cryptosuite: 'ecdsa-jcs-2019',
        sodSignature: 'MEUCIQD...',
        dgHashes: { dg13: 'sha256:abc' },
      },
    };

    it('passes when all mixed credentials are well-formed', () => {
      const req = makeValidRequest({ verifierCredentials: [bbsCred, icaoCred] });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('reports error with index for the malformed credential only', () => {
      const req = makeValidRequest({
        verifierCredentials: [
          bbsCred,
          { ...icaoCred, issuer: '' as unknown as string },
        ],
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors).toHaveLength(1);
      expect(result.errors).toContain(
        'verifierCredentials[1] is missing "issuer"',
      );
    });

    it('reports errors for multiple malformed credentials', () => {
      const req = makeValidRequest({
        verifierCredentials: [
          { ...bbsCred, type: [] },
          { ...icaoCred, credentialSubject: undefined as unknown as Record<string, unknown> },
        ],
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors).toHaveLength(2);
      expect(result.errors).toContain(
        'verifierCredentials[0] is missing or has empty "type"',
      );
      expect(result.errors).toContain(
        'verifierCredentials[1] is missing "credentialSubject"',
      );
    });
  });

  // -------------------------------------------------------------------------
  // VPRequest proof validation
  // -------------------------------------------------------------------------

  describe('VPRequest proof validation', () => {
    function makeValidProof(overrides?: Partial<VerifierRequestProof>): VerifierRequestProof {
      return {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: 'did:example:verifier#key-1',
        proofPurpose: 'assertionMethod',
        challenge: 'abc123',
        domain: 'verifier.example.com',
        proofValue: 'z3FXQkNoEg...mock-proof',
        ...overrides,
      };
    }

    it('passes with no proof (unsigned request)', () => {
      const req = makeValidRequest();
      delete req.proof;
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(true);
    });

    it('passes with a valid proof', () => {
      const req = makeValidRequest({ proof: makeValidProof() });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('fails when proof is missing verificationMethod', () => {
      const req = makeValidRequest({
        proof: makeValidProof({ verificationMethod: '' }),
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('VPRequest proof is missing "verificationMethod"');
    });

    it('fails when proof purpose is not assertionMethod', () => {
      const req = makeValidRequest({
        proof: makeValidProof({ proofPurpose: 'authentication' as 'assertionMethod' }),
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toMatch(/proof purpose must be "assertionMethod"/);
    });

    it('fails when proof challenge does not match nonce', () => {
      const req = makeValidRequest({
        proof: makeValidProof({ challenge: 'wrong-nonce' }),
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toMatch(/proof challenge mismatch/);
    });

    it('fails when proof domain does not match verifierUrl', () => {
      const req = makeValidRequest({
        proof: makeValidProof({ domain: 'evil.example.com' }),
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toMatch(/proof domain mismatch/);
    });

    it('accepts proof domain matching full verifierUrl', () => {
      const req = makeValidRequest({
        proof: makeValidProof({ domain: 'https://verifier.example.com' }),
      });
      const result = verifyVPRequest(req);
      expect(result.valid).toBe(true);
    });
  });
});
