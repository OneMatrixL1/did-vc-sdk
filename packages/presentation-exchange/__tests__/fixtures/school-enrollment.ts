import type { VPRequest } from '../../src/types/request.js';
import {
  parentCCCD,
  childCCCD,
  incompleteCCCD,
  passportCredential as passportCred,
} from './cccd-factory.js';

// Re-export credentials from factory
export const parentCredential = parentCCCD.credential;
export const childCredential = childCCCD.credential;
export const passportCredential = passportCred;
export const incompleteCredential = incompleteCCCD.credential;

/**
 * School enrollment example from the protocol spec.
 * Requires: (Parent CCCD + age proof) AND (Child CCCD + name + DOB)
 */
export const schoolEnrollmentRequest: VPRequest = {
  type: ['VerifiablePresentationRequest'],
  id: 'req-001',
  version: '1.0',
  name: 'School Enrollment',
  nonce: 'nonce-xyz',
  verifier: 'did:web:school.vn',
  verifierName: 'ABC School',
  verifierUrl: 'https://school.vn',
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
        schemaType: 'ICAO9303SOD',
        name: 'Parent ID',
        conditions: [
          {
            type: 'DocumentCondition',
            conditionID: 'c1',
            field: 'fullName',
            operator: 'disclose',
          },
          {
            type: 'DocumentCondition',
            conditionID: 'c2',
            operator: 'greaterThan',
            field: 'dateOfBirth',
            params: { value: '20080209' },
          },
        ],
      },
      {
        type: 'DocumentRequest',
        docRequestID: 'child',
        docType: ['CCCDCredential'],
        schemaType: 'ICAO9303SOD',
        name: 'Child ID',
        conditions: [
          {
            type: 'DocumentCondition',
            conditionID: 'c3',
            field: 'fullName',
            operator: 'disclose',
          },
          {
            type: 'DocumentCondition',
            conditionID: 'c4',
            field: 'dateOfBirth',
            operator: 'disclose',
          },
        ],
      },
    ],
  },
};
