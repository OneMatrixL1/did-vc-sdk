
import { Buffer } from 'buffer';

/**
 * Parser for Data Groups in Electronic Identity Documents (ICAO 9303)
 */
export class DGParser {
    /**
     * Parse all relevant Data Groups to extract identity data.
     * 
     * @param {Record<string, string>} dataGroups - Map of DG names to base64 strings
     * @returns {object} Extracted identity data
     */
    static parse(dataGroups) {
        let result = {};

        if (dataGroups.dg1) {
            Object.assign(result, this.parseDG1(dataGroups.dg1));
        }

        if (dataGroups.dg2) {
            Object.assign(result, this.parseDG2(dataGroups.dg2));
        }

        if (dataGroups.dg13) {
            Object.assign(result, this.parseDG13(dataGroups.dg13));
        }

        return result;
    }

    /**
     * Parse DG1 (MRZ Data)
     * Supports TD1 (Identity Card - 3 lines of 30 chars each)
     */
    static parseDG1(base64) {
        const buffer = Buffer.from(base64, 'base64');

        // Skip header bytes (usually Tag 61, Length, Tag 5F1F, Length)
        // Common header: 61 [len] 5F 1F [len]
        let offset = 0;
        if (buffer[0] === 0x61) {
            offset += 2; // skip tag 61 and length
            if (buffer[offset] === 0x5F && buffer[offset + 1] === 0x1F) {
                offset += 3; // skip tag 5F1F and its length
            }
        }

        const mrz = buffer.slice(offset).toString('ascii').replace(/\n/g, '');
        if (mrz.length < 90) return {};

        const line1 = mrz.substring(0, 30);
        const line2 = mrz.substring(30, 60);
        const line3 = mrz.substring(60, 90);

        const clean = (str) => str.replace(/</g, ' ').trim();

        return {
            documentType: line1.substring(0, 2).replace(/</g, ''),
            issuingCountry: line1.substring(2, 5),
            documentNumber: line1.substring(5, 14).replace(/</g, ''),
            dateOfBirth: line2.substring(0, 6),
            gender: line2.substring(7, 8),
            dateOfExpiry: line2.substring(8, 14),
            nationality: line2.substring(15, 18),
            lastName: clean(line3.split('<<')[0]),
            firstName: clean(line3.split('<<')[1] || ''),
            passportMRZ: mrz
        };
    }

    /**
     * Parse DG13 (Vietnamese Specific Data)
     * Vietnamese DG13 follows a proprietary TLV structure.
     * Header: 6D [len]
     * Fields: [Tag] [Len] [Value (UTF-8)]
     */
    static parseDG13(base64) {
        const buffer = Buffer.from(base64, 'base64');
        const result = {};

        const tagMap = {
            1: 'documentNumber',
            2: 'fullName',
            3: 'dateOfBirth',
            4: 'gender',
            5: 'nationality',
            6: 'ethnicity',
            7: 'religion',
            8: 'hometown',
            9: 'residentAddress',
            10: 'identificationFeatures',
            11: 'dateOfIssue',
            12: 'dateOfExpiry',
            13: 'familyNames',
            14: 'spouseName',
            16: 'oldIdNumber'
        };

        const extractStrings = (buf) => {
            const strings = [];
            let pos = 0;
            while (pos < buf.length - 1) {
                const tag = buf[pos];
                let len = buf[pos + 1];
                let headerSize = 2;

                if (len & 0x80) {
                    const lenBytes = len & 0x7F;
                    len = 0;
                    for (let i = 0; i < lenBytes; i++) {
                        len = (len << 8) | buf[pos + 2 + i];
                    }
                    headerSize = 2 + lenBytes;
                }

                const dataStart = pos + headerSize;
                if (dataStart + len > buf.length) break;

                if ([0x0C, 0x13, 0x16].includes(tag)) {
                    strings.push(buf.slice(dataStart, dataStart + len).toString('utf-8').trim());
                } else if (tag === 0x30) {
                    strings.push(...extractStrings(buf.slice(dataStart, dataStart + len)));
                }
                pos = dataStart + len;
            }
            return strings;
        };

        try {
            // Scan through the buffer for the tag pattern: 0x02 0x01 [TagNum]
            let offset = 0;
            while (offset < buffer.length - 3) {
                if (buffer[offset] === 0x02 && buffer[offset + 1] === 0x01) {
                    const tagNum = buffer[offset + 2];
                    const fieldName = tagMap[tagNum];

                    if (fieldName) {
                        // The value follows the tag integer. 
                        // It could be a string or a sequence containing strings.
                        const nextOffset = offset + 3;
                        const valueTag = buffer[nextOffset];
                        let valueLen = buffer[nextOffset + 1];
                        let valueHeaderSize = 2;

                        if (valueLen & 0x80) {
                            const lenBytes = valueLen & 0x7F;
                            valueLen = 0;
                            for (let i = 0; i < lenBytes; i++) {
                                valueLen = (valueLen << 8) | buffer[nextOffset + 2 + i];
                            }
                            valueHeaderSize = 2 + lenBytes;
                        }

                        const valBuf = buffer.slice(nextOffset, nextOffset + valueHeaderSize + valueLen);
                        const valueStrings = extractStrings(valBuf);

                        if (fieldName === 'familyNames') {
                            if (valueStrings[0]) result['fatherName'] = valueStrings[0];
                            if (valueStrings[1]) result['motherName'] = valueStrings[1];
                        } else if (valueStrings.length > 0) {
                            result[fieldName] = valueStrings[0];
                        }

                        // Move offset past this tag's value to avoid parsing its internal content twice
                        offset = nextOffset + valueHeaderSize + valueLen - 1;
                    }
                }
                offset++;
            }
        } catch (e) {
            console.error('Error parsing DG13:', e);
        }

        return result;
    }

    /**
     * Parse DG2 (Biometric Data - Face Image)
     * Extracts the raw JPEG image data.
     */
    static parseDG2(base64) {
        const buffer = Buffer.from(base64, 'base64');

        // Face image data is usually a JPEG starting with FF D8 FF
        // Tag 5F 2E marks the start of the image data in the ICAO structure
        const jpegHeader = Buffer.from([0xFF, 0xD8, 0xFF]);
        const startIdx = buffer.indexOf(jpegHeader);

        if (startIdx !== -1) {
            // The image continues until the end of the buffer or another tag
            // In DG2, the JPEG is usually the last part of the 5F2E tag
            const photoData = buffer.slice(startIdx);
            return {
                photo: photoData.toString('base64')
            };
        }

        return {};
    }
}
