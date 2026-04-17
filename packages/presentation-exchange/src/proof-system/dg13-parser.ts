/**
 * DG13 (Vietnamese Data Group 13) TLV parser.
 *
 * Extracts field positions from the DG13 ASN.1 structure and builds
 * witness inputs for the dg13-merklelize circuit.
 */

const MAX_DG_BYTES = 700;
const NUM_FIELDS = 16;

// ---------------------------------------------------------------------------
// TLV parsing
// ---------------------------------------------------------------------------

interface TLV {
  tag: number;
  length: number;
  valueOffset: number;
  totalLength: number;
}

function parseTLV(buf: Uint8Array, offset: number): TLV {
  const tag = buf[offset]!;
  let lenOffset = offset + 1;
  let length: number;

  if (buf[lenOffset]! < 0x80) {
    length = buf[lenOffset]!;
    lenOffset += 1;
  } else {
    const n = buf[lenOffset]! & 0x7f;
    length = 0;
    for (let i = 0; i < n; i++) {
      length = (length << 8) | buf[lenOffset + 1 + i]!;
    }
    lenOffset += 1 + n;
  }

  return {
    tag,
    length,
    valueOffset: lenOffset,
    totalLength: lenOffset - offset + length,
  };
}

// ---------------------------------------------------------------------------
// DG13 field extraction
// ---------------------------------------------------------------------------

interface ParsedField {
  index: number;
  tagValue: number;
  offset: number;
  length: number;
}

/**
 * Parse DG13 TLV structure and extract field positions.
 *
 * DG13 structure:
 * ```
 * 0x6D (Application 13) → SEQUENCE → [version, OID, SET of field SEQUENCEs]
 * Each field: SEQUENCE { INTEGER tagId, UTF8String value }
 * ```
 */
function parseDG13Fields(raw: Uint8Array): ParsedField[] {
  const fields: ParsedField[] = [];

  const outer = parseTLV(raw, 0);
  if (outer.tag !== 0x6d) {
    throw new Error(`Expected DG13 tag 0x6D, got 0x${outer.tag.toString(16)}`);
  }

  const innerSeq = parseTLV(raw, outer.valueOffset);
  let pos = innerSeq.valueOffset;

  // Skip version
  pos = parseTLV(raw, pos).valueOffset + parseTLV(raw, pos).length;
  // Skip OID
  const oidTLV = parseTLV(raw, pos);
  pos = oidTLV.valueOffset + oidTLV.length;

  // SET of field SEQUENCEs
  const setTLV = parseTLV(raw, pos);
  if (setTLV.tag !== 0x31) {
    throw new Error(`Expected SET tag 0x31, got 0x${setTLV.tag.toString(16)}`);
  }

  pos = setTLV.valueOffset;
  const setEnd = setTLV.valueOffset + setTLV.length;
  let fieldIndex = 0;

  while (pos < setEnd && fieldIndex < NUM_FIELDS) {
    const fieldSeq = parseTLV(raw, pos);
    let innerPos = fieldSeq.valueOffset;

    // INTEGER tag ID
    const tagInt = parseTLV(raw, innerPos);
    const tagValue = raw[tagInt.valueOffset]!;
    innerPos = tagInt.valueOffset + tagInt.length;

    const fieldSeqEnd = fieldSeq.valueOffset + fieldSeq.length;

    let valueOffset: number;
    let valueLength: number;

    if (innerPos >= fieldSeqEnd) {
      // Empty field
      valueOffset = innerPos + 2;
      valueLength = 0;
    } else {
      const valueTLV = parseTLV(raw, innerPos);
      valueOffset = valueTLV.valueOffset;
      valueLength = fieldSeqEnd - valueTLV.valueOffset;
    }

    fields.push({ index: fieldIndex, tagValue, offset: valueOffset, length: valueLength });
    fieldIndex++;
    pos += fieldSeq.totalLength;
  }

  return fields;
}

// ---------------------------------------------------------------------------
// Witness building
// ---------------------------------------------------------------------------

export interface DG13WitnessData {
  rawMsg: number[];         // padded to 700 bytes
  dgLen: number;            // actual DG13 length
  fieldOffsets: number[];   // 16 offsets
  fieldLengths: number[];   // 16 lengths
}

/**
 * Parse DG13 base64 and build witness inputs for the dg13-merklelize circuit.
 */
export function buildDG13WitnessData(dg13Base64: string): DG13WitnessData {
  const dg13Bytes = base64ToUint8Array(dg13Base64);
  const dgLength = dg13Bytes.length;

  if (dgLength > MAX_DG_BYTES) {
    throw new Error(`DG13 ${dgLength} bytes exceeds ${MAX_DG_BYTES} max`);
  }

  const fields = parseDG13Fields(dg13Bytes);

  const rawMsg = new Array<number>(MAX_DG_BYTES).fill(0);
  for (let i = 0; i < dgLength; i++) rawMsg[i] = dg13Bytes[i]!;

  const fieldOffsets = new Array<number>(NUM_FIELDS).fill(0);
  const fieldLengths = new Array<number>(NUM_FIELDS).fill(0);

  for (const f of fields) {
    fieldOffsets[f.index] = f.offset;
    fieldLengths[f.index] = f.length;
  }

  // Pad missing fields with empty TLV entries after the real data.
  // Layout matches the circuit's unified expectedSeqLen = length + 5 rule:
  //   30 05 02 01 <tagId> 0c 00   (SEQUENCE { INTEGER(1), UTF8String("") })
  let pos = dgLength;
  for (let i = fields.length; i < NUM_FIELDS; i++) {
    const tagId = i + 1;
    rawMsg[pos] = 0x30;       // SEQUENCE
    rawMsg[pos + 1] = 0x05;   // content length = INTEGER(3) + UTF8String(2)
    rawMsg[pos + 2] = 0x02;   // INTEGER tag
    rawMsg[pos + 3] = 0x01;   // INTEGER length 1
    rawMsg[pos + 4] = tagId;  // tagId
    rawMsg[pos + 5] = 0x0c;   // UTF8String tag
    rawMsg[pos + 6] = 0x00;   // UTF8String length 0
    fieldOffsets[i] = pos + 7;
    fieldLengths[i] = 0;
    pos += 7;
  }

  return { rawMsg, dgLen: dgLength, fieldOffsets, fieldLengths };
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function base64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
