/**
 * TESTCASE 4: VC Schema Validation During Credential Creation
 *
 * Scenario:
 * - Create VC with schema validation
 * - Verify VC against schema before issuing
 */

import VerifiableCredential from '../../src/vc/verifiable-credential';
import { Schema } from '../../src/modules/abstract/schema';
import { DockBlobId } from '../../src/types/blob';
import { validateCredentialSchema } from '../../src/vc/schema';
import { expandJSONLD } from '../../src/vc/helpers';
import { expandedSubjectProperty } from '../../src/vc/constants';

// =============================================================================
// KYC Schema Definition
// =============================================================================

const KYC_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  description: 'KYC Credential Schema',
  type: 'object',
  properties: {
    id: { type: 'string' },
    fullName: { type: 'string', minLength: 1 },
    dateOfBirth: { type: 'string' },
    nationality: { type: 'string' },
    idNumber: { type: 'string' },
  },
  required: ['fullName', 'dateOfBirth', 'nationality'],
  additionalProperties: false,
};

// =============================================================================
// JSON-LD Context
// =============================================================================

const KYC_CONTEXT = {
  '@context': {
    '@version': 1.1,
    '@protected': true,
    id: '@id',
    type: '@type',
    kyc: 'https://bank-a.example.com/kyc#',
    KYCCredential: 'kyc:KYCCredential',
    fullName: 'kyc:fullName',
    dateOfBirth: 'kyc:dateOfBirth',
    nationality: 'kyc:nationality',
    idNumber: 'kyc:idNumber',
  },
};

const CREDENTIALS_V1 = 'https://www.w3.org/2018/credentials/v1';

// Schema and field URIs
const KYC_SCHEMA_ID = 'https://bank-a.example.com/schemas/kyc-v1';
const KYC_SCHEMA_TYPE = 'JsonSchemaValidator2018';
const KYC_BASE_URI = 'https://bank-a.example.com/kyc#';

// Test user data
const TEST_USER = {
  id: 'did:example:user123',
  fullName: 'Nguyen Van A',
  dateOfBirth: '1990-05-15',
  nationality: 'Vietnamese',
};

// =============================================================================
// Test Suite
// =============================================================================

describe('TESTCASE 4: VC Schema Validation During Credential Creation', () => {
  const contexts = [CREDENTIALS_V1, KYC_CONTEXT];

  // ===========================================================================
  // Create VC with schema and validate
  // ===========================================================================

  describe('Create VC with schema and validate', () => {
    test('should create VC with all required fields and validate against schema', async () => {
      const vc = new VerifiableCredential('urn:uuid:kyc-valid-001');
      vc.setContext(contexts);
      vc.addType('KYCCredential');
      vc.setSchema(KYC_SCHEMA_ID, KYC_SCHEMA_TYPE);
      vc.addSubject(TEST_USER);

      const isValid = await vc.validateSchema(KYC_SCHEMA);
      expect(isValid).toBe(true);

      const vcJson = vc.toJSON();
      expect(vcJson.credentialSchema.id).toBe(KYC_SCHEMA_ID);
      expect(vcJson.credentialSchema.type).toBe(KYC_SCHEMA_TYPE);
    }, 30000);

    test('should create VC with required and optional fields', async () => {
      const vc = new VerifiableCredential('urn:uuid:kyc-valid-002');
      vc.setContext(contexts);
      vc.addType('KYCCredential');
      vc.setSchema(KYC_SCHEMA_ID, KYC_SCHEMA_TYPE);
      vc.addSubject({
        ...TEST_USER,
        idNumber: 'CCCD123456789',
      });

      const isValid = await vc.validateSchema(KYC_SCHEMA);
      expect(isValid).toBe(true);
    }, 30000);

    test('should validate VC with different user data', async () => {
      const vc = new VerifiableCredential('urn:uuid:kyc-valid-003');
      vc.setContext(contexts);
      vc.addType('KYCCredential');
      vc.addSubject({
        id: 'did:example:user456',
        fullName: 'Tran Thi B',
        dateOfBirth: '1985-12-01',
        nationality: 'Vietnamese',
      });

      const isValid = await vc.validateSchema(KYC_SCHEMA);
      expect(isValid).toBe(true);
    }, 30000);
  });

  // ===========================================================================
  // Schema utilities
  // ===========================================================================

  describe('Schema utilities', () => {
    test('should validate schema structure before use', async () => {
      await expect(Schema.validateSchema(KYC_SCHEMA)).resolves.toBeDefined();
    });

    test('should reject invalid schema structure', async () => {
      const invalidSchema = {
        type: 'invalid-type',
        properties: {},
      };

      await expect(Schema.validateSchema(invalidSchema)).rejects.toThrow();
    });

    test('should create Schema object for on-chain storage', async () => {
      const schema = new Schema(DockBlobId.random());
      await schema.setJSONSchema(KYC_SCHEMA);

      const json = schema.toJSON();
      expect(json.id).toBeDefined();
      expect(json.schema).toBe(KYC_SCHEMA);

      const blob = schema.toBlob();
      expect(blob.id).toBeDefined();
      expect(blob.blob).toBeDefined();
    });

    test('should reject setting invalid schema on Schema object', async () => {
      const schema = new Schema(DockBlobId.random());

      await expect(
        schema.setJSONSchema({ invalidSchema: true }),
      ).rejects.toThrow();
    });
  });

  // ===========================================================================
  // Reject mismatching VC data
  // ===========================================================================

  describe('Reject mismatching VC data', () => {
    let schemaObj;
    let validExpandedCredential;

    beforeAll(async () => {
      schemaObj = new Schema(DockBlobId.random());
      await schemaObj.setJSONSchema(KYC_SCHEMA);

      const validCredential = {
        '@context': contexts,
        type: ['VerifiableCredential', 'KYCCredential'],
        id: 'urn:uuid:kyc-valid',
        credentialSubject: TEST_USER,
      };
      validExpandedCredential = await expandJSONLD(validCredential);
    }, 30000);

    test('should reject VC missing required field (fullName)', async () => {
      // Copy the expanded subject (without [0] - use spread on the array itself)
      const credentialSubject = {
        ...validExpandedCredential[expandedSubjectProperty],
      };
      delete credentialSubject[`${KYC_BASE_URI}fullName`];

      await expect(
        validateCredentialSchema(
          { [expandedSubjectProperty]: credentialSubject },
          schemaObj,
          contexts,
        ),
      ).rejects.toThrow();
    }, 30000);

    test('should reject VC missing required field (dateOfBirth)', async () => {
      const credentialSubject = {
        ...validExpandedCredential[expandedSubjectProperty],
      };
      delete credentialSubject[`${KYC_BASE_URI}dateOfBirth`];

      await expect(
        validateCredentialSchema(
          { [expandedSubjectProperty]: credentialSubject },
          schemaObj,
          contexts,
        ),
      ).rejects.toThrow();
    }, 30000);

    test('should reject VC missing required field (nationality)', async () => {
      const credentialSubject = {
        ...validExpandedCredential[expandedSubjectProperty],
      };
      delete credentialSubject[`${KYC_BASE_URI}nationality`];

      await expect(
        validateCredentialSchema(
          { [expandedSubjectProperty]: credentialSubject },
          schemaObj,
          contexts,
        ),
      ).rejects.toThrow();
    }, 30000);
  });

  // ===========================================================================
  // VC structure validation
  // ===========================================================================

  describe('VC structure validation', () => {
    test('should include credentialSchema in VC JSON', async () => {
      const vc = new VerifiableCredential('urn:uuid:kyc-structure-001');
      vc.setContext(contexts);
      vc.addType('KYCCredential');
      vc.setSchema(KYC_SCHEMA_ID, KYC_SCHEMA_TYPE);
      vc.addSubject(TEST_USER);

      const vcJson = vc.toJSON();

      expect(vcJson['@context']).toBeDefined();
      expect(vcJson.type).toContain('VerifiableCredential');
      expect(vcJson.type).toContain('KYCCredential');
      expect(vcJson.credentialSchema).toEqual({
        id: KYC_SCHEMA_ID,
        type: KYC_SCHEMA_TYPE,
      });
      expect(vcJson.credentialSubject[0].fullName).toBe(TEST_USER.fullName);
    }, 30000);

    test('should validate VC without credentialSchema reference', async () => {
      const vc = new VerifiableCredential('urn:uuid:kyc-no-schema-ref');
      vc.setContext(contexts);
      vc.addType('KYCCredential');
      // No setSchema call - schema validation is done externally
      vc.addSubject({
        id: 'did:example:user789',
        fullName: 'Le Van C',
        dateOfBirth: '1975-06-15',
        nationality: 'Vietnamese',
      });

      // Can still validate against schema even without credentialSchema reference
      const isValid = await vc.validateSchema(KYC_SCHEMA);
      expect(isValid).toBe(true);

      const vcJson = vc.toJSON();
      expect(vcJson.credentialSchema).toBeUndefined();
    }, 30000);
  });
});
