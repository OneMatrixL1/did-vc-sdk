/**
 * Profile-aware field resolver
 *
 * Extracts field values from raw DG bytes using the decode strategy defined
 * in the ICAO Document Profile. Supports:
 *  - tlv-positional: DG13-style TLV with INTEGER field IDs (0x02 0x01 [TagNum])
 *  - mrz: DG1 MRZ string parsing (TD1 format)
 *  - biometric: DG2 face image extraction
 */

import type { ICAODocumentProfile, FieldBinding } from './types.js';
import { Buffer } from 'buffer';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Resolve a single field value from raw DG bytes.
 *
 * @param profile  - ICAO Document Profile
 * @param fieldId  - Logical field ID (e.g. 'fullName', 'gender')
 * @param rawDGs   - Map of DG name → base64 string (e.g. { dg1: '...', dg13: '...' })
 * @returns The field value as a string, or undefined if not resolvable
 */
export function resolveField(
  profile: ICAODocumentProfile,
  fieldId: string,
  rawDGs: Record<string, string>,
): string | undefined {
  const binding = profile.fields[fieldId];
  if (!binding) return undefined;

  const sourceDef = profile.sources[binding.source];
  if (!sourceDef) return undefined;

  const b64 = rawDGs[binding.source];
  if (!b64) return undefined;

  const buf = Buffer.from(b64, 'base64');

  switch (sourceDef.decode.method) {
    case 'tlv-positional':
      return resolveTLVPositional(buf, binding);

    case 'mrz':
      return resolveMRZ(buf, binding);

    case 'biometric':
      return resolvePhoto(buf);

    default:
      return undefined;
  }
}

// ---------------------------------------------------------------------------
// TLV-positional decoder (DG13)
// ---------------------------------------------------------------------------

/**
 * Parses DG13 bytes using the 0x02 0x01 [TagNum] INTEGER field ID pattern.
 * The "at" value in the FieldBinding is the INTEGER tag number.
 * An optional subIndex selects from multi-value fields (e.g. familyNames).
 */
function resolveTLVPositional(
  buf: Buffer,
  binding: FieldBinding,
): string | undefined {
  const tagNum = typeof binding.at === 'number' ? binding.at : parseInt(String(binding.at), 10);
  const subIndex = binding.subIndex ?? 0;

  const extractStrings = (b: Buffer): string[] => {
    const strings: string[] = [];
    let pos = 0;
    while (pos < b.length - 1) {
      const tag = b[pos] as number;
      const rawLen = b[pos + 1] as number;
      let len = rawLen;
      let headerSize = 2;

      if (rawLen & 0x80) {
        const lenBytes = rawLen & 0x7F;
        len = 0;
        for (let i = 0; i < lenBytes; i++) {
          len = (len << 8) | ((b[pos + 2 + i] as number));
        }
        headerSize = 2 + lenBytes;
      }

      const dataStart = pos + headerSize;
      if (dataStart + len > b.length) break;

      if ([0x0C, 0x13, 0x16].includes(tag)) {
        strings.push(b.slice(dataStart, dataStart + len).toString('utf-8').trim());
      } else if (tag === 0x30) {
        strings.push(...extractStrings(b.slice(dataStart, dataStart + len)));
      }
      pos = dataStart + len;
    }
    return strings;
  };

  try {
    let offset = 0;
    while (offset < buf.length - 3) {
      if ((buf[offset] as number) === 0x02 && (buf[offset + 1] as number) === 0x01 && (buf[offset + 2] as number) === tagNum) {
        const nextOffset = offset + 3;
        const rawValueLen = buf[nextOffset + 1] as number;
        let valueLen = rawValueLen;
        let valueHeaderSize = 2;

        if (rawValueLen & 0x80) {
          const lenBytes = rawValueLen & 0x7F;
          valueLen = 0;
          for (let i = 0; i < lenBytes; i++) {
            valueLen = (valueLen << 8) | ((buf[nextOffset + 2 + i] as number));
          }
          valueHeaderSize = 2 + lenBytes;
        }

        const valBuf = buf.slice(nextOffset, nextOffset + valueHeaderSize + valueLen);
        const strings = extractStrings(valBuf);
        return strings[subIndex] ?? undefined;
      }
      offset++;
    }
  } catch {
    // parse error
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// MRZ decoder (DG1)
// ---------------------------------------------------------------------------

/** Parses DG1 MRZ bytes in TD1 format and returns the requested field. */
function resolveMRZ(buf: Buffer, binding: FieldBinding): string | undefined {
  const fieldName = String(binding.at);

  // Skip DG1 header: tag 0x61, length, then tag 0x5F 0x1F, length
  let offset = 0;
  if (buf[0] === 0x61) {
    offset += 2;
    if (buf[offset] === 0x5F && buf[offset + 1] === 0x1F) {
      offset += 3;
    }
  }

  const mrz = buf.slice(offset).toString('ascii').replace(/\n/g, '');
  if (mrz.length < 90) return undefined;

  const line1 = mrz.substring(0, 30);
  const line2 = mrz.substring(30, 60);
  const line3 = mrz.substring(60, 90);
  const clean = (s: string) => s.replace(/</g, ' ').trim();

  const parsed: Record<string, string> = {
    documentType: line1.substring(0, 2).replace(/</g, ''),
    issuingCountry: line1.substring(2, 5),
    documentNumber: line1.substring(5, 14).replace(/</g, ''),
    dateOfBirth: line2.substring(0, 6),
    gender: line2.substring(7, 8),
    dateOfExpiry: line2.substring(8, 14),
    nationality: line2.substring(15, 18),
    lastName: clean(line3.split('<<')[0] ?? ''),
    firstName: clean(line3.split('<<')[1] ?? ''),
  };

  return parsed[fieldName];
}

// ---------------------------------------------------------------------------
// Biometric decoder (DG2)
// ---------------------------------------------------------------------------

/** Extracts the JPEG photo from DG2 bytes and returns it as base64. */
function resolvePhoto(buf: Buffer): string | undefined {
  const jpegHeader = Buffer.from([0xFF, 0xD8, 0xFF]);
  const startIdx = buf.indexOf(jpegHeader);
  if (startIdx === -1) return undefined;
  return buf.slice(startIdx).toString('base64');
}
