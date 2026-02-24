import type { VPRequest } from '../../src/types/request.js';
import type { MatchableCredential } from '../../src/types/credential.js';

/**
 * School enrollment example from the protocol spec.
 * Requires: (Parent CCCD + age proof) AND (Child CCCD + name + DOB)
 */
export const schoolEnrollmentRequest: VPRequest = {
  id: 'req-001',
  version: '1.0',
  name: 'School Enrollment',
  nonce: 'nonce-xyz',
  verifier: {
    id: 'did:web:school.vn',
    name: 'ABC School',
    url: 'https://school.vn',
  },
  createdAt: '2026-02-09T10:00:00Z',
  expiresAt: '2026-02-09T10:30:00Z',
  rules: {
    type: 'Logical',
    operator: 'AND',
    values: [
      {
        type: 'DocumentRequest',
        docRequestID: 'parent',
        docType: ['CCCDCredential'],
        name: 'Parent ID',
        conditions: [
          {
            type: 'DocumentCondition',
            conditionID: 'c1',
            field: '$.credentialSubject.fullName',
            operator: 'disclose',
          },
          {
            type: 'DocumentCondition',
            conditionID: 'c2',
            operator: 'zkp',
            circuitId: 'numeric-range',
            proofSystem: 'groth16',
            purpose: 'Prove parent is 18+',
            privateInputs: { value: '$.credentialSubject.dateOfBirth' },
            publicInputs: { max: 20080209, inputFormat: 'dd/mm/yyyy' },
          },
        ],
      },
      {
        type: 'DocumentRequest',
        docRequestID: 'child',
        docType: ['CCCDCredential'],
        name: 'Child ID',
        conditions: [
          {
            type: 'DocumentCondition',
            conditionID: 'c3',
            field: '$.credentialSubject.fullName',
            operator: 'disclose',
          },
          {
            type: 'DocumentCondition',
            conditionID: 'c4',
            field: '$.credentialSubject.dateOfBirth',
            operator: 'disclose',
          },
        ],
      },
    ],
  },
};

/** Parent credential — has fullName + dateOfBirth */
export const parentCredential: MatchableCredential = {
  type: ['VerifiableCredential', 'CCCDCredential'],
  issuer: 'did:web:cccd.gov.vn',
  credentialSubject: {
    fullName: 'Nguyen Van A',
    dateOfBirth: '15/03/1985',
    documentNumber: '012345678901',
  },
};

/** Child credential — has fullName + dateOfBirth */
export const childCredential: MatchableCredential = {
  type: ['VerifiableCredential', 'CCCDCredential'],
  issuer: 'did:web:cccd.gov.vn',
  credentialSubject: {
    fullName: 'Nguyen Van C',
    dateOfBirth: '15/06/2015',
    documentNumber: '098765432109',
  },
};

/** Passport credential — should NOT match CCCDCredential requests */
export const passportCredential: MatchableCredential = {
  type: ['VerifiableCredential', 'PassportCredential'],
  issuer: 'did:web:passport.gov.vn',
  credentialSubject: {
    fullName: 'Nguyen Van B',
    dateOfBirth: '01/01/1990',
    passportNumber: 'B1234567',
  },
};

/** Incomplete credential — missing dateOfBirth */
export const incompleteCredential: MatchableCredential = {
  type: ['VerifiableCredential', 'CCCDCredential'],
  issuer: 'did:web:cccd.gov.vn',
  credentialSubject: {
    fullName: 'Tran Thi D',
  },
};
