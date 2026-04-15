/**
 * Circuit witness/input builders.
 *
 * Translates parsed SOD/DG13 data into the exact input format
 * expected by each ZKP circuit.
 */

import { buildSODWitnessData, type SODWitnessData } from './sod-parser.js';
import { buildDG13WitnessData } from './dg13-parser.js';

// ---------------------------------------------------------------------------
// Circuit input types
// ---------------------------------------------------------------------------

export interface CircuitInputs {
  privateInputs: Record<string, unknown>;
  publicInputs: Record<string, unknown>;
}

export interface SodVerifyInputs extends CircuitInputs {
  privateInputs: {
    econtent: number[];
    econtent_len: number;
    signed_attrs: number[];
    signed_attrs_len: number;
    digest_offset: number;
    signature_r: number[];
    signature_s: number[];
  };
  publicInputs: {
    pubkey_x: number[];
    pubkey_y: number[];
    salt: string;
  };
}

export interface DgMapInputs extends CircuitInputs {
  privateInputs: {
    econtent: number[];
    econtent_len: number;
    dg_offset: number;
  };
  publicInputs: {
    salt: string;
    econtent_binding: string;
    dg_number: number;
  };
}

export interface Dg13MerklelizeInputs extends CircuitInputs {
  privateInputs: {
    raw_msg: number[];
    dg_len: number;
    field_offsets: number[];
    field_lengths: number[];
  };
  publicInputs: {
    salt: string;
  };
}

export interface PredicateInputs extends CircuitInputs {
  privateInputs: {
    siblings: string[];
    length: string;
    data: string[];
    packed_hash: string;
    date_bytes?: number[];
  };
  publicInputs: {
    commitment: string;
    salt: string;
    tag_id: string;
    threshold?: number;
    threshold_min?: number;
    threshold_max?: number;
  };
}

export interface FieldRevealInputs extends CircuitInputs {
  privateInputs: {
    siblings: string[];
    length: string;
    data: string[];
    packed_hash: string;
  };
  publicInputs: {
    commitment: string;
    salt: string;
    tag_id: string;
  };
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/**
 * Build inputs for the `sod-verify` circuit.
 *
 * @param sodBase64 - Base64-encoded SOD from credential.proof.sod
 * @param salt - Domain hash (hex field element)
 */
export function buildSodVerifyInputs(
  sodBase64: string,
  salt: string,
): { inputs: SodVerifyInputs; witness: SODWitnessData } {
  const witness = buildSODWitnessData(sodBase64);

  return {
    witness,
    inputs: {
      privateInputs: {
        econtent: witness.econtent,
        econtent_len: witness.econtentLen,
        signed_attrs: witness.signedAttrs,
        signed_attrs_len: witness.signedAttrsLen,
        digest_offset: witness.digestOffset,
        signature_r: witness.signatureR,
        signature_s: witness.signatureS,
      },
      publicInputs: {
        pubkey_x: witness.pubkeyX,
        pubkey_y: witness.pubkeyY,
        salt,
      },
    },
  };
}

/**
 * Build inputs for the `dg-map` circuit.
 *
 * @param witness - SOD witness data (reused from sod-verify step)
 * @param salt - Domain hash
 * @param econtentBinding - Output from sod-verify proof
 */
export function buildDgMapInputs(
  witness: SODWitnessData,
  salt: string,
  econtentBinding: string,
): DgMapInputs {
  return {
    privateInputs: {
      econtent: witness.econtent,
      econtent_len: witness.econtentLen,
      dg_offset: witness.dgOffset,
    },
    publicInputs: {
      salt,
      econtent_binding: econtentBinding,
      dg_number: 13,
    },
  };
}

/**
 * Build inputs for the `dg13-merklelize` circuit.
 *
 * @param dg13Base64 - Base64-encoded DG13 from credential.credentialSubject.dg13
 * @param salt - Domain hash
 */
export function buildDg13MerklelizeInputs(
  dg13Base64: string,
  salt: string,
): Dg13MerklelizeInputs {
  const witness = buildDG13WitnessData(dg13Base64);

  return {
    privateInputs: {
      raw_msg: witness.rawMsg,
      dg_len: witness.dgLen,
      field_offsets: witness.fieldOffsets,
      field_lengths: witness.fieldLengths,
    },
    publicInputs: {
      salt,
    },
  };
}

/**
 * Build inputs for a predicate circuit (date-greaterthan, date-lessthan, etc.).
 *
 * Uses cached Merkle tree data from a DomainProofSet.
 *
 * @param commitment - DG13 commitment from dg13-merklelize proof
 * @param salt - Domain hash
 * @param tagId - DG13 field index (0-based)
 * @param siblings - Merkle path for the field (from cached tree)
 * @param leafData - Packed leaf data { length, data[4], packedHash }
 * @param extra - Additional public inputs (threshold, date_bytes, etc.)
 */
export function buildPredicateInputs(
  commitment: string,
  salt: string,
  tagId: number,
  siblings: readonly string[],
  leafData: { length: string; data: string[]; packedHash: string },
  extra: {
    threshold?: number;
    threshold_min?: number;
    threshold_max?: number;
    date_bytes?: number[];
  },
): PredicateInputs {
  return {
    privateInputs: {
      siblings: [...siblings],
      length: leafData.length,
      data: leafData.data,
      packed_hash: leafData.packedHash,
      ...(extra.date_bytes ? { date_bytes: extra.date_bytes } : {}),
    },
    publicInputs: {
      commitment,
      salt,
      tag_id: tagId.toString(),
      ...(extra.threshold !== undefined ? { threshold: extra.threshold } : {}),
      ...(extra.threshold_min !== undefined ? { threshold_min: extra.threshold_min } : {}),
      ...(extra.threshold_max !== undefined ? { threshold_max: extra.threshold_max } : {}),
    },
  };
}

/**
 * Build inputs for the `dg13-field-reveal` circuit.
 */
export function buildFieldRevealInputs(
  commitment: string,
  salt: string,
  tagId: number,
  siblings: readonly string[],
  leafData: { length: string; data: string[]; packedHash: string },
): FieldRevealInputs {
  return {
    privateInputs: {
      siblings: [...siblings],
      length: leafData.length,
      data: leafData.data,
      packed_hash: leafData.packedHash,
    },
    publicInputs: {
      commitment,
      salt,
      tag_id: tagId.toString(),
    },
  };
}
