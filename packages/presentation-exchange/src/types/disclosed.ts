import type { DiscloseCondition, ZKPCondition } from './request.js';

// ---------------------------------------------------------------------------
// Predicate result (machine-readable ZKP outcome)
// ---------------------------------------------------------------------------

/**
 * Machine-readable result of a ZKP predicate proof.
 *
 * Contains what was asked (publicInputs from the request condition)
 * and what was proven (publicOutputs from the proof).
 */
export interface PredicateResult {
  circuitId: string;
  /** Public inputs from the request (what was asked) */
  publicInputs: Record<string, unknown>;
  /** Public outputs from the proof (what was proven) */
  publicOutputs: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Disclosed field
// ---------------------------------------------------------------------------

/** How a field was disclosed in the VP response. */
export type DisclosureMethod = 'merkle' | 'dg' | 'predicate';

/**
 * A single disclosed field, matched from a request condition to a response proof.
 */
export interface DisclosedField {
  /** Condition ID from the request that produced this field. */
  conditionID: string;
  /** Profile field ID (e.g. 'fullName', 'photo', 'dateOfBirth'). */
  fieldId: string;
  /** How this field was disclosed. */
  method: DisclosureMethod;
  /**
   * Disclosed value.
   * - `merkle`: decoded UTF-8 string
   * - `dg`: base64 raw data
   * - `predicate`: `null` (proven without revealing)
   */
  value: string | null;
  /** For predicates: machine-readable proof result. */
  predicate: PredicateResult | null;
}

// ---------------------------------------------------------------------------
// Field result (returned by getField helper)
// ---------------------------------------------------------------------------

/** Result returned by `DisclosedDocument.getField()`. Same shape as DisclosedField. */
export type FieldResult = DisclosedField;

// ---------------------------------------------------------------------------
// Disclosed document
// ---------------------------------------------------------------------------

/**
 * Extraction result for a single DocumentRequest in the VPRequest.
 *
 * Contains all disclosed fields matched by conditionID, plus a `getField()`
 * helper for quick lookup by fieldId.
 */
export interface DisclosedDocument {
  /** The docRequestID from the VPRequest rules. */
  docRequestID: string;
  /** Schema type (e.g. 'ICAO9303SOD'). */
  schemaType: string;
  /** All disclosed fields for this document. */
  fields: DisclosedField[];
  /** Holder DID from did-delegate proof (if present). */
  holderDID: string | null;
  /** Whether the full ZKP binding chain verified. */
  chainVerified: boolean;
  /**
   * Quick lookup by fieldId.
   *
   * ```ts
   * const doc = result.documents[0];
   * doc.getField('fullName')   // { method: 'merkle', value: 'TRAN GIANG LONG', ... }
   * doc.getField('photo')      // { method: 'dg', value: 'base64...', ... }
   * doc.getField('dateOfBirth') // { method: 'predicate', value: null, predicate: {...} }
   * ```
   */
  getField(fieldId: string): FieldResult | undefined;
}

// ---------------------------------------------------------------------------
// Extraction result (top-level)
// ---------------------------------------------------------------------------

/**
 * Result of `extractDisclosedFields()`.
 *
 * For single-document requests (most common), use `field()` directly.
 * For multi-document requests, iterate `documents`.
 *
 * ```ts
 * const result = extractDisclosedFields(vpRequest, vp, true);
 *
 * // Quick access (single doc):
 * result.field('fullName')   // { method: 'merkle', value: 'TRAN GIANG LONG', ... }
 * result.field('dateOfBirth') // { method: 'predicate', value: null, predicate: {...} }
 *
 * // Full access:
 * result.documents[0].fields // all fields
 * ```
 */
export interface DisclosedFieldsResult {
  /** Per-document extraction results. */
  documents: DisclosedDocument[];
  /**
   * Shortcut: lookup across all documents by fieldId.
   * Returns the first match. For multi-doc, use `documents[i].getField()`.
   */
  field(fieldId: string): FieldResult | undefined;
}
