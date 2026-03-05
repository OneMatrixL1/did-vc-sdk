/**
 * ICAO Document Profile type definitions
 *
 * Defines how logical field names map to physical DG locations in ICAO 9303 documents.
 * Supports tlv-positional (DG13), mrz (DG1), and biometric (DG2) decode strategies.
 */

export interface LocalizableString {
  en: string;
  vi?: string;
}

// ---------------------------------------------------------------------------
// Decode Strategies
// ---------------------------------------------------------------------------

export interface TLVPositionalDecode {
  method: 'tlv-positional';
  /** Root application tag, e.g. 0x6D for Vietnamese DG13 */
  root: number;
  /** Container SEQUENCE tag, e.g. 0x30 */
  container: number;
}

export interface TLVTaggedDecode {
  method: 'tlv-tagged';
  /** Root application tag */
  root: number;
  /** Optional prefix tag bytes to skip */
  tagPrefix?: number[];
}

export interface MRZDecode {
  method: 'mrz';
  /** MRZ format: TD1 (ID card, 3×30), TD2 (2×36), TD3 (passport, 2×44) */
  format: 'TD1' | 'TD2' | 'TD3';
  /** ASN.1 tag containing the MRZ string, e.g. 0x5F1F */
  mrzTag?: number;
}

export interface BiometricDecode {
  method: 'biometric';
  imageType: 'jpeg' | 'jp2';
}

export type DecodeStrategy =
  | TLVPositionalDecode
  | TLVTaggedDecode
  | MRZDecode
  | BiometricDecode;

// ---------------------------------------------------------------------------
// Source Definition
// ---------------------------------------------------------------------------

export interface SourceDefinition {
  /** Data Group number (e.g. 1, 2, 13) */
  dgNumber: number;
  decode: DecodeStrategy;
}

// ---------------------------------------------------------------------------
// Field Binding
// ---------------------------------------------------------------------------

export interface FieldBinding {
  /** Key into ICAODocumentProfile.sources */
  source: string;
  /**
   * For tlv-positional: INTEGER field ID (tag number in the DG binary, e.g. 2 for fullName in DG13)
   * For mrz: MRZ parsed field name (e.g. 'documentNumber', 'dateOfBirth')
   * For biometric: unused (pass 0)
   */
  at: number | string;
  type: 'string' | 'date' | 'biometric' | 'enum';
  label: LocalizableString;
  encoding?: string;
  /** For multi-value TLV fields (e.g. fatherName/motherName from familyNames sequence) */
  subIndex?: number;
}

// ---------------------------------------------------------------------------
// ICAO Document Profile
// ---------------------------------------------------------------------------

export interface ICAODocumentProfile {
  profileId: string;
  /** Credential type strings that this profile applies to */
  docType: string[];
  /** ICAO standard version, e.g. '9303-11' */
  icaoVersion: string;
  /** Map of source name → SourceDefinition (e.g. 'dg1', 'dg2', 'dg13') */
  sources: Record<string, SourceDefinition>;
  /** Map of logical field ID → FieldBinding */
  fields: Record<string, FieldBinding>;
}
