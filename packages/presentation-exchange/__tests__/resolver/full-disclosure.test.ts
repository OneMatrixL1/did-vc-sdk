import { describe, it, expect } from 'vitest';
import { matchCredentials } from '../../src/resolver/matcher.js';
import { resolvePresentation } from '../../src/resolver/resolver.js';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';
import { VPRequestBuilder } from '../../src/builder/request-builder.js';
import type { DocumentRequestMatch } from '../../src/types/matching.js';
import {
  parentCredential,
  incompleteCredential,
  passportCredential,
} from '../fixtures/school-enrollment.js';

describe('disclosureMode: full', () => {
  const fullRequest = new DocumentRequestBuilder('natid', 'CCCDCredential')
    .setDisclosureMode('full')
    .build();

  it('marks any type-matching credential as fullyQualified regardless of fields', () => {
    // incompleteCredential is missing dateOfBirth — would fail selective mode
    const result = matchCredentials(fullRequest, [incompleteCredential]);
    const match = result as DocumentRequestMatch;

    expect(match.satisfied).toBe(true);
    expect(match.candidates).toHaveLength(1);
    expect(match.candidates[0].fullyQualified).toBe(true);
    expect(match.candidates[0].missingFields).toHaveLength(0);
  });

  it('still filters by docType', () => {
    const result = matchCredentials(fullRequest, [passportCredential]);
    const match = result as DocumentRequestMatch;
    expect(match.satisfied).toBe(false);
    expect(match.candidates).toHaveLength(0);
  });

  it('resolvePresentation passes the full credentialSubject verbatim', async () => {
    const request = new VPRequestBuilder('req-full', 'nonce-full')
      .setVerifier({ id: 'did:web:example', name: 'Example', url: 'https://example.com' })
      .addDocumentRequest(
        new DocumentRequestBuilder('natid', 'CCCDCredential')
          .setDisclosureMode('full'),
      )
      .build();

    const vp = await resolvePresentation(
      request,
      [parentCredential],
      [{ docRequestID: 'natid', credentialIndex: 0 }],
      {
        holder: 'did:key:z6MkTest',
        signPresentation: async () => ({
          type: 'DataIntegrityProof',
          verificationMethod: 'did:key:z6MkTest#keys-1',
          proofPurpose: 'authentication',
          challenge: 'nonce-full',
          domain: 'example.com',
          proofValue: 'mock',
        }),
      },
    );

    const subject = vp.verifiableCredential[0].credentialSubject;

    // All original fields should be present
    expect(subject.fullName).toBe('Nguyen Van A');
    expect(subject.dateOfBirth).toBe('15/03/1985');
    expect(subject.documentNumber).toBe('012345678901');
  });
});
