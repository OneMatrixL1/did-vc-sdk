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

export interface DIDDelegateInputs extends CircuitInputs {
  privateInputs: {
    dg15RawBytes: number[];
    dg15Length: number;
    modulusOffset: number;
    chipPubKeyLimbs: string[];
    chipPubKeyRedc: string[];
    signatureLimbs: string[];
  };
  publicInputs: {
    domain: string;
    did: string;
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

// ---------------------------------------------------------------------------
// DG15 / DID delegation witness
// ---------------------------------------------------------------------------

const DG15_MAX_BYTES = 320;
const MODULUS_BYTES = 256;
const RSA_LIMBS = 18;
const LIMB_BITS = 120;

export interface DG15WitnessData {
  dg15RawBytes: number[];
  dg15Length: number;
  modulusOffset: number;
  chipPubKeyLimbs: string[];
  chipPubKeyRedc: string[];
}

/**
 * Parse DG15 base64 and extract RSA-2048 public key components
 * for the did-delegate circuit.
 */
export function buildDG15WitnessData(dg15Base64: string): DG15WitnessData {
  const dg15Bytes = base64ToUint8Array(dg15Base64);
  const dg15Length = dg15Bytes.length;

  if (dg15Length > DG15_MAX_BYTES) {
    throw new Error(`DG15 ${dg15Length} bytes exceeds ${DG15_MAX_BYTES} max`);
  }

  const dg15RawBytes = new Array<number>(DG15_MAX_BYTES).fill(0);
  for (let i = 0; i < dg15Length; i++) dg15RawBytes[i] = dg15Bytes[i]!;

  const modulusOffset = findModulusOffset(dg15Bytes);

  const modulus = extractModulusBigInt(dg15Bytes, modulusOffset);
  const chipPubKeyLimbs = splitTo120BitLimbs(modulus, RSA_LIMBS);
  const chipPubKeyRedc = splitTo120BitLimbs(computeBarrettRedc(modulus), RSA_LIMBS);

  return {
    dg15RawBytes,
    dg15Length,
    modulusOffset,
    chipPubKeyLimbs,
    chipPubKeyRedc,
  };
}

/**
 * Build inputs for the `did-delegate` circuit.
 *
 * @param dg15Base64 - Base64-encoded DG15 from credential
 * @param aaSignatureBase64 - Base64-encoded Active Authentication signature from chip
 * @param domain - Domain hash
 * @param did - Holder DID as hex field element
 */
export function buildDIDDelegateInputs(
  dg15Base64: string,
  aaSignatureBase64: string,
  domain: string,
  did: string,
): DIDDelegateInputs {
  const dg15Witness = buildDG15WitnessData(dg15Base64);
  const sigBytes = base64ToUint8Array(aaSignatureBase64);

  const sigBigInt = bytesToBigInt(sigBytes);
  const signatureLimbs = splitTo120BitLimbs(sigBigInt, RSA_LIMBS);

  return {
    privateInputs: {
      dg15RawBytes: dg15Witness.dg15RawBytes,
      dg15Length: dg15Witness.dg15Length,
      modulusOffset: dg15Witness.modulusOffset,
      chipPubKeyLimbs: dg15Witness.chipPubKeyLimbs,
      chipPubKeyRedc: dg15Witness.chipPubKeyRedc,
      signatureLimbs,
    },
    publicInputs: {
      domain,
      did,
    },
  };
}

// ---------------------------------------------------------------------------
// RSA helpers
// ---------------------------------------------------------------------------

function findModulusOffset(dg15: Uint8Array): number {
  // Walk DG15 TLV to find the RSA modulus INTEGER.
  // DG15 structure: tag(0x6F) → SEQUENCE → SEQUENCE(AlgId) → BIT STRING(key)
  // Inside BIT STRING: SEQUENCE → INTEGER(modulus, with leading 0x00) → INTEGER(exponent)
  // The modulus starts after: INTEGER tag(0x02) + length(0x82 0x01 0x01) + leading-zero(0x00)
  for (let i = 0; i <= dg15.length - (MODULUS_BYTES + 5); i++) {
    if (
      dg15[i] === 0x02 &&
      dg15[i + 1] === 0x82 &&
      dg15[i + 2] === 0x01 &&
      dg15[i + 3] === 0x01 &&
      dg15[i + 4] === 0x00 &&
      (dg15[i + 5]! & 0x80) !== 0
    ) {
      return i + 5;
    }
  }
  throw new Error('RSA-2048 modulus not found in DG15');
}

function extractModulusBigInt(dg15: Uint8Array, offset: number): bigint {
  let result = 0n;
  for (let i = 0; i < MODULUS_BYTES; i++) {
    result = (result << 8n) | BigInt(dg15[offset + i]!);
  }
  return result;
}

function splitTo120BitLimbs(value: bigint, numLimbs: number): string[] {
  const mask = (1n << BigInt(LIMB_BITS)) - 1n;
  const limbs: string[] = [];
  for (let i = 0; i < numLimbs; i++) {
    limbs.push('0x' + ((value >> BigInt(i * LIMB_BITS)) & mask).toString(16));
  }
  return limbs;
}

function computeBarrettRedc(modulus: bigint): bigint {
  const targetBits = 2 * 2048 + 6;
  return (1n << BigInt(targetBits)) / modulus;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]!);
  }
  return result;
}

function base64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
