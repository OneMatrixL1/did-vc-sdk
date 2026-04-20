/**
 * Circuit witness/input builders.
 *
 * Translates parsed SOD/DG13/DG15 data into the exact input format
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

export interface SodValidateInputs extends CircuitInputs {
  privateInputs: {
    pubkeyX: number[];
    pubkeyY: number[];
    eContent: number[];
    eContentLen: number;
    signedAttrs: number[];
    signedAttrsLen: number;
    digestOffset: number;
    oidOffset: number;
    signatureR: number[];
    signatureS: number[];
  };
  publicInputs: {
    domain: string;
  };
}

export interface DgBridgeInputs extends CircuitInputs {
  privateInputs: {
    eContent: number[];
    eContentLen: number;
    dgOffset: number;
    oidOffset: number;
  };
  publicInputs: {
    domain: string;
    eContentBinding: string;
    dgNumber: number;
  };
}

export interface Dg13MerklelizeInputs extends CircuitInputs {
  privateInputs: {
    rawMsg: number[];
    dgLen: number;
    fieldOffsets: number[];
    fieldLengths: number[];
  };
  publicInputs: {
    domain: string;
  };
}

export interface PredicateInputs extends CircuitInputs {
  privateInputs: {
    siblings: string[];
    length: string;
    data: string[];
    entropy: string;
    dateBytes?: number[];
  };
  publicInputs: {
    commitment: string;
    domain: string;
    tagId: string;
    threshold?: number;
    thresholdMin?: number;
    thresholdMax?: number;
  };
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/**
 * Build inputs for the `sod-validate` circuit.
 *
 * @param sodBase64 - Base64-encoded SOD from credential.proof.sod
 * @param domain - Domain hash (hex field element)
 */
export function buildSodValidateInputs(
  sodBase64: string,
  domain: string,
): { inputs: SodValidateInputs; witness: SODWitnessData } {
  const witness = buildSODWitnessData(sodBase64);

  return {
    witness,
    inputs: {
      privateInputs: {
        pubkeyX: witness.pubkeyX,
        pubkeyY: witness.pubkeyY,
        eContent: witness.econtent,
        eContentLen: witness.econtentLen,
        signedAttrs: witness.signedAttrs,
        signedAttrsLen: witness.signedAttrsLen,
        digestOffset: witness.digestOffset,
        oidOffset: witness.oidOffset,
        signatureR: witness.signatureR,
        signatureS: witness.signatureS,
      },
      publicInputs: {
        domain,
      },
    },
  };
}

/**
 * Build inputs for the `dg-bridge` circuit.
 *
 * @param witness - SOD witness data (reused from sod-validate step)
 * @param domain - Domain hash
 * @param eContentBinding - Output from sod-validate proof
 */
export function buildDgBridgeInputs(
  witness: SODWitnessData,
  domain: string,
  eContentBinding: string,
): DgBridgeInputs {
  return {
    privateInputs: {
      eContent: witness.econtent,
      eContentLen: witness.econtentLen,
      dgOffset: witness.dgOffset,
      oidOffset: witness.oidOffset,
    },
    publicInputs: {
      domain,
      eContentBinding,
      dgNumber: 13,
    },
  };
}

/**
 * Build inputs for the `dg13-merklelize` circuit.
 *
 * @param dg13Base64 - Base64-encoded DG13 from credential.credentialSubject.dg13
 * @param domain - Domain hash
 */
export function buildDg13MerklelizeInputs(
  dg13Base64: string,
  domain: string,
): Dg13MerklelizeInputs {
  const witness = buildDG13WitnessData(dg13Base64);

  return {
    privateInputs: {
      rawMsg: witness.rawMsg,
      dgLen: witness.dgLen,
      fieldOffsets: witness.fieldOffsets,
      fieldLengths: witness.fieldLengths,
    },
    publicInputs: {
      domain,
    },
  };
}

/**
 * Build inputs for a predicate circuit (date-greaterthan, date-lessthan, etc.).
 *
 * @param commitment - DG13 commitment from dg13-merklelize proof
 * @param domain - Domain hash
 * @param tagId - DG13 field index (1-based tagId, 0-based leaf index = tagId - 1)
 * @param siblings - Merkle path for the field (from cached tree, 4 elements)
 * @param leafData - Packed leaf data { length, data[4] }
 * @param entropy - Per-leaf entropy from Merkle tree builder
 * @param extra - Additional public inputs (threshold, dateBytes, etc.)
 */
export function buildPredicateInputs(
  commitment: string,
  domain: string,
  tagId: number,
  siblings: readonly string[],
  leafData: { length: string; data: string[] },
  entropy: string,
  extra: {
    threshold?: number;
    thresholdMin?: number;
    thresholdMax?: number;
    dateBytes?: number[];
  },
): PredicateInputs {
  return {
    privateInputs: {
      siblings: [...siblings],
      length: leafData.length,
      data: leafData.data,
      entropy,
      ...(extra.dateBytes ? { dateBytes: extra.dateBytes } : {}),
    },
    publicInputs: {
      commitment,
      domain,
      tagId: tagId.toString(),
      ...(extra.threshold !== undefined ? { threshold: extra.threshold } : {}),
      ...(extra.thresholdMin !== undefined ? { thresholdMin: extra.thresholdMin } : {}),
      ...(extra.thresholdMax !== undefined ? { thresholdMax: extra.thresholdMax } : {}),
    },
  };
}

