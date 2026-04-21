/**
 * Circuit witness/input builders.
 *
 * Translates parsed SOD/DG13/DG15 data into the exact input format
 * expected by each ZKP circuit.
 */

import { buildSODWitnessData, type SODWitnessData } from './sod-parser.js';
import { buildDG13WitnessData } from './dg13-parser.js';
import { parseDG15 } from './dg15-parser.js';
import { bytesToLimbs, computeBarrettRedc, LIMB_COUNT } from './bignum.js';

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

// ---------------------------------------------------------------------------
// did-delegate
// ---------------------------------------------------------------------------

const DG15_CIRCUIT_LEN = 320;

export interface DidDelegateInputs extends CircuitInputs {
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

/**
 * Build inputs for the `did-delegate` circuit.
 *
 * @param dg15Base64        - Raw DG15 from credentialSubject.dg15
 * @param aaSignatureBase64 - Chip AA signature (base64, captured at scan time)
 * @param domain            - Domain hash (hex field element)
 * @param did               - Holder DID as a field element (hex, 0x-prefixed address)
 */
export function buildDidDelegateInputs(
  dg15Base64: string,
  aaSignatureBase64: string,
  domain: string,
  did: string,
): DidDelegateInputs {
  const parsed = parseDG15(dg15Base64);
  if (parsed.rawBytes.length > DG15_CIRCUIT_LEN) {
    throw new Error(
      `DG15 (${parsed.rawBytes.length} bytes) exceeds circuit buffer (${DG15_CIRCUIT_LEN})`,
    );
  }

  // Pad DG15 to the circuit's fixed buffer size (u8[320]).
  const padded = new Array<number>(DG15_CIRCUIT_LEN).fill(0);
  for (let i = 0; i < parsed.rawBytes.length; i++) padded[i] = parsed.rawBytes[i]!;

  const chipPubKeyLimbs = bytesToLimbs(parsed.modulusBytes);
  const chipPubKeyRedc = computeBarrettRedc(parsed.modulusBytes);

  const signatureBytes = base64ToBytes(aaSignatureBase64);
  const signatureLimbs = bytesToLimbs(signatureBytes);

  // Sanity — all three bignums must be 18-limb.
  if (chipPubKeyLimbs.length !== LIMB_COUNT || signatureLimbs.length !== LIMB_COUNT) {
    throw new Error('did-delegate: limb count mismatch (expected 18)');
  }

  const pub = { domain, did: normalizeDidField(did) };
  // Diagnostic log — keeps us from flying blind when a constraint fails.
  // Shows enough to verify modulusOffset, limb counts, DID format, and the
  // dg15 byte at the modulus offset (first byte of N, typically 0x8·/0xB·/etc).
  console.log('[did-delegate inputs]', {
    dg15Length: parsed.rawBytes.length,
    modulusOffset: parsed.modulusOffset,
    firstModulusByte: '0x' + (parsed.rawBytes[parsed.modulusOffset] ?? 0).toString(16).padStart(2, '0'),
    modulusBytesLen: parsed.modulusBytes.length,
    chipPubKeyLimbs_0: chipPubKeyLimbs[0],
    chipPubKeyLimbs_17: chipPubKeyLimbs[17],
    signatureLimbs_0: signatureLimbs[0],
    exponent: parsed.exponent,
    public: pub,
  });

  return {
    privateInputs: {
      dg15RawBytes: padded,
      dg15Length: parsed.rawBytes.length,
      modulusOffset: parsed.modulusOffset,
      chipPubKeyLimbs,
      chipPubKeyRedc,
      signatureLimbs,
    },
    publicInputs: pub,
  };
}

/** Convert a `did:...:0x…` or raw hex address into a hex field-element string. */
function normalizeDidField(did: string): string {
  const lastColon = did.lastIndexOf(':');
  const tail = lastColon >= 0 ? did.slice(lastColon + 1) : did;
  const hex = tail.startsWith('0x') ? tail.slice(2) : tail;
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`did-delegate: cannot parse DID "${did}" as field element`);
  }
  return '0x' + hex.toLowerCase();
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
