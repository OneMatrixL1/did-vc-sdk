import { describe, it, expect } from 'vitest';
import { matchCredentials } from '../../src/resolver/matcher.js';
import type { DocumentRequestMatch, LogicalRuleMatch } from '../../src/types/matching.js';
import {
  schoolEnrollmentRequest,
  parentCredential,
  childCredential,
  passportCredential,
  incompleteCredential,
} from '../fixtures/school-enrollment.js';

describe('matchCredentials', () => {
  it('matches school enrollment with two valid CCCDs', () => {
    const result = matchCredentials(
      schoolEnrollmentRequest.rules,
      [parentCredential, childCredential],
    );

    expect(result.satisfied).toBe(true);
    expect(result.type).toBe('Logical');

    const logical = result as LogicalRuleMatch;
    expect(logical.operator).toBe('AND');
    expect(logical.values).toHaveLength(2);

    // Parent match
    const parentMatch = logical.values[0] as DocumentRequestMatch;
    expect(parentMatch.type).toBe('DocumentRequest');
    expect(parentMatch.request.docRequestID).toBe('parent');
    expect(parentMatch.satisfied).toBe(true);
    expect(parentMatch.candidates).toHaveLength(2);

    // Both CCCDs are candidates for parent (type matches)
    const fullyQualified = parentMatch.candidates.filter((c) => c.fullyQualified);
    expect(fullyQualified.length).toBe(2);

    // Child match
    const childMatch = logical.values[1] as DocumentRequestMatch;
    expect(childMatch.type).toBe('DocumentRequest');
    expect(childMatch.request.docRequestID).toBe('child');
    expect(childMatch.satisfied).toBe(true);
    expect(childMatch.candidates).toHaveLength(2);
  });

  it('does not match passport credential against CCCD request', () => {
    const result = matchCredentials(
      schoolEnrollmentRequest.rules,
      [passportCredential],
    );

    expect(result.satisfied).toBe(false);

    const logical = result as LogicalRuleMatch;
    const parentMatch = logical.values[0] as DocumentRequestMatch;
    expect(parentMatch.candidates).toHaveLength(0);
  });

  it('marks incomplete credential as not fully qualified', () => {
    const result = matchCredentials(
      schoolEnrollmentRequest.rules,
      [incompleteCredential],
    );

    const logical = result as LogicalRuleMatch;

    // Parent request: has ZKP on dateOfBirth, missing field
    const parentMatch = logical.values[0] as DocumentRequestMatch;
    expect(parentMatch.candidates).toHaveLength(1);
    expect(parentMatch.candidates[0].fullyQualified).toBe(false);
    expect(parentMatch.candidates[0].unsatisfiableZKPs).toContain('c2');

    // Child request: missing dateOfBirth disclose field
    const childMatch = logical.values[1] as DocumentRequestMatch;
    expect(childMatch.candidates).toHaveLength(1);
    expect(childMatch.candidates[0].fullyQualified).toBe(false);
    expect(childMatch.candidates[0].missingFields).toContain(
      '$.credentialSubject.dateOfBirth',
    );
  });

  it('handles OR rules correctly', () => {
    const orRequest = {
      type: 'Logical' as const,
      operator: 'OR' as const,
      values: [
        {
          type: 'DocumentRequest' as const,
          docRequestID: 'natid',
          docType: ['CCCDCredential'],
          conditions: [],
        },
        {
          type: 'DocumentRequest' as const,
          docRequestID: 'passport',
          docType: ['PassportCredential'],
          conditions: [],
        },
      ],
    };

    // Only passport available — should still satisfy OR
    const result = matchCredentials(orRequest, [passportCredential]);
    expect(result.satisfied).toBe(true);

    const logical = result as LogicalRuleMatch;
    const natidMatch = logical.values[0] as DocumentRequestMatch;
    const passportMatch = logical.values[1] as DocumentRequestMatch;

    expect(natidMatch.satisfied).toBe(false);
    expect(passportMatch.satisfied).toBe(true);
  });

  it('filters by issuer when specified', () => {
    const request = {
      type: 'DocumentRequest' as const,
      docRequestID: 'gov-id',
      docType: ['CCCDCredential'],
      issuer: 'did:web:other-issuer.vn',
      conditions: [],
    };

    const result = matchCredentials(request, [parentCredential]);
    const match = result as DocumentRequestMatch;
    expect(match.candidates).toHaveLength(0);
    expect(match.satisfied).toBe(false);
  });

  it('reports disclosed fields correctly', () => {
    const result = matchCredentials(
      schoolEnrollmentRequest.rules,
      [parentCredential],
    );

    const logical = result as LogicalRuleMatch;
    const parentMatch = logical.values[0] as DocumentRequestMatch;

    expect(parentMatch.candidates[0].disclosedFields).toContain(
      '$.credentialSubject.fullName',
    );
    expect(parentMatch.candidates[0].satisfiableZKPs).toContain('c2');
  });
});
