import { describe, it, expect } from 'vitest';
import { DocumentRequestBuilder } from '../../src/builder/document-request-builder.js';
import { VPRequestBuilder } from '../../src/builder/request-builder.js';
import type { PredicateCondition } from '../../src/types/condition.js';
import type { DiscloseCondition } from '../../src/types/request.js';

describe('DocumentRequestBuilder (object API)', () => {
  it('builds a request with .disclose()', () => {
    const req = new DocumentRequestBuilder('cccd', 'CCCDCredential')
      .setSchemaType('ICAO9303SOD')
      .disclose({ field: 'fullName', id: 'c1' })
      .disclose({ field: 'dateOfBirth', id: 'c2' })
      .build();

    expect(req.conditions).toHaveLength(2);
    const c1 = req.conditions[0] as DiscloseCondition;
    expect(c1.operator).toBe('disclose');
    expect(c1.field).toBe('fullName');
    expect(c1.conditionID).toBe('c1');
  });

  it('defaults conditionID to field name when id omitted', () => {
    const req = new DocumentRequestBuilder('cccd', 'CCCDCredential')
      .setSchemaType('ICAO9303SOD')
      .disclose({ field: 'fullName' })
      .disclose({ field: 'gender' })
      .build();

    const c1 = req.conditions[0] as DiscloseCondition;
    const c2 = req.conditions[1] as DiscloseCondition;
    expect(c1.conditionID).toBe('fullName');
    expect(c1.field).toBe('fullName');
    expect(c2.conditionID).toBe('gender');
    expect(c2.field).toBe('gender');
  });

  it('builds a request with .greaterThan()', () => {
    const req = new DocumentRequestBuilder('cccd', 'CCCDCredential')
      .setSchemaType('ICAO9303SOD')
      .greaterThan({ field: 'dateOfBirth', value: '20060407' })
      .build();

    const c1 = req.conditions[0] as PredicateCondition;
    expect(c1.operator).toBe('greaterThan');
    expect(c1.field).toBe('dateOfBirth');
    expect(c1.conditionID).toBe('dateOfBirth');
    expect(c1.params).toEqual({ value: '20060407' });
  });

  it('builds a request with .inRange()', () => {
    const req = new DocumentRequestBuilder('cccd', 'CCCDCredential')
      .setSchemaType('ICAO9303SOD')
      .inRange({ field: 'dateOfBirth', gte: '19900101', lte: '20061231' })
      .build();

    const c1 = req.conditions[0] as PredicateCondition;
    expect(c1.operator).toBe('inRange');
    expect(c1.conditionID).toBe('dateOfBirth');
    expect(c1.params).toEqual({ gte: '19900101', lte: '20061231' });
  });

  it('builds a request with .equals() using value', () => {
    const req = new DocumentRequestBuilder('cccd', 'CCCDCredential')
      .setSchemaType('ICAO9303SOD')
      .equals({ field: 'nationality', value: 'VN' })
      .build();

    const c1 = req.conditions[0] as PredicateCondition;
    expect(c1.operator).toBe('equals');
    expect(c1.conditionID).toBe('nationality');
    expect(c1.params).toEqual({ value: 'VN' });
  });

  it('builds a request with .equals() using cross-doc ref', () => {
    const req = new DocumentRequestBuilder('child', 'CCCDCredential')
      .setSchemaType('ICAO9303SOD')
      .equals({ field: 'fatherName', ref: 'parent.fullName' })
      .build();

    const c1 = req.conditions[0] as PredicateCondition;
    expect(c1.operator).toBe('equals');
    expect(c1.conditionID).toBe('fatherName');
    expect(c1.params).toEqual({ ref: 'parent.fullName' });
  });

  it('builds a mixed request with disclose + predicates', () => {
    const req = new DocumentRequestBuilder('cccd', 'CCCDCredential')
      .setSchemaType('ICAO9303SOD')
      .disclose({ field: 'fullName' })
      .disclose({ field: 'dateOfBirth' })
      .inRange({ field: 'dateOfBirth', gte: '19900101', lte: '20061231', id: 'c3' })
      .equals({ field: 'fatherName', ref: 'parent.fullName' })
      .build();

    expect(req.conditions).toHaveLength(4);
    expect((req.conditions[0] as DiscloseCondition).operator).toBe('disclose');
    expect((req.conditions[1] as DiscloseCondition).operator).toBe('disclose');
    expect((req.conditions[2] as PredicateCondition).operator).toBe('inRange');
    expect((req.conditions[3] as PredicateCondition).operator).toBe('equals');
  });

  it('no .zkp() or .merkleDisclose() methods exist', () => {
    const builder = new DocumentRequestBuilder('cccd', 'CCCDCredential');
    expect((builder as Record<string, unknown>).zkp).toBeUndefined();
    expect((builder as Record<string, unknown>).merkleDisclose).toBeUndefined();
  });
});

describe('VPRequestBuilder (school enrollment)', () => {
  it('builds a full enrollment request with object API', () => {
    const request = new VPRequestBuilder('enrollment-001')
      .setName('School Enrollment')
      .setVerifier({ id: 'did:web:school.vn', name: 'School', url: 'https://school.vn' })
      .addDocumentRequest(
        new DocumentRequestBuilder('parent', 'CCCDCredential')
          .setSchemaType('ICAO9303SOD')
          .disclose({ field: 'fullName' })
          .greaterThan({ field: 'dateOfBirth', value: '20060407' }),
      )
      .addDocumentRequest(
        new DocumentRequestBuilder('child', 'CCCDCredential')
          .setSchemaType('ICAO9303SOD')
          .disclose({ field: 'fullName' })
          .disclose({ field: 'dateOfBirth' })
          .equals({ field: 'fatherName', ref: 'parent.fullName' }),
      )
      .build();

    expect(request.rules.type).toBe('Logical');
    expect(request.verifier).toBe('did:web:school.vn');

    const rules = request.rules as { type: 'Logical'; values: Array<{ conditions: unknown[] }> };
    expect(rules.values).toHaveLength(2);
    expect(rules.values[0].conditions).toHaveLength(2);
    expect(rules.values[1].conditions).toHaveLength(3);
  });
});
