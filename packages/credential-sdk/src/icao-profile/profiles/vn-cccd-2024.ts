/**
 * VN-CCCD-2024 ICAO Document Profile
 *
 * Vietnamese Citizen Identity Card (Căn cước công dân) issued from 2024.
 * - DG1: MRZ (TD1 format, 3 lines × 30 chars)
 * - DG2: Biometric face image (JPEG)
 * - DG13: Vietnamese proprietary TLV data
 *
 * DG13 field IDs (INTEGER tag values in the 0x02 0x01 [TagNum] pattern):
 *   1=documentNumber, 2=fullName, 3=dateOfBirth, 4=gender, 5=nationality,
 *   6=ethnicity, 7=religion, 8=hometown, 9=residentAddress,
 *   10=identificationFeatures, 11=dateOfIssue, 12=dateOfExpiry,
 *   13=familyNames (contains fatherName[0] + motherName[1]), 16=oldIdNumber
 */

import type { ICAODocumentProfile } from '../types.js';

export const VN_CCCD_2024: ICAODocumentProfile = {
  profileId: 'VN-CCCD-2024',
  docType: ['CCCDCredential'],
  icaoVersion: '9303-11',

  sources: {
    dg1: {
      dgNumber: 1,
      decode: {
        method: 'mrz',
        format: 'TD1',
        mrzTag: 0x5F1F,
      },
    },
    dg2: {
      dgNumber: 2,
      decode: {
        method: 'biometric',
        imageType: 'jpeg',
      },
    },
    dg13: {
      dgNumber: 13,
      decode: {
        method: 'tlv-positional',
        root: 0x6D,
        container: 0x30,
      },
    },
  },

  fields: {
    // -----------------------------------------------------------------------
    // DG13 fields (tlv-positional, at = INTEGER field ID in DG13 binary)
    // -----------------------------------------------------------------------
    documentNumber: {
      source: 'dg13',
      at: 1,
      type: 'string',
      label: { en: 'Document Number', vi: 'Số CCCD' },
    },
    fullName: {
      source: 'dg13',
      at: 2,
      type: 'string',
      label: { en: 'Full Name', vi: 'Họ và tên' },
    },
    dateOfBirth: {
      source: 'dg13',
      at: 3,
      type: 'date',
      label: { en: 'Date of Birth', vi: 'Ngày sinh' },
    },
    gender: {
      source: 'dg13',
      at: 4,
      type: 'enum',
      label: { en: 'Gender', vi: 'Giới tính' },
    },
    nationality: {
      source: 'dg13',
      at: 5,
      type: 'string',
      label: { en: 'Nationality', vi: 'Quốc tịch' },
    },
    ethnicity: {
      source: 'dg13',
      at: 6,
      type: 'string',
      label: { en: 'Ethnicity', vi: 'Dân tộc' },
    },
    hometown: {
      source: 'dg13',
      at: 8,
      type: 'string',
      label: { en: 'Hometown', vi: 'Quê quán' },
    },
    permanentAddress: {
      source: 'dg13',
      at: 9,
      type: 'string',
      label: { en: 'Permanent Address', vi: 'Địa chỉ thường trú' },
    },
    identifyingMarks: {
      source: 'dg13',
      at: 10,
      type: 'string',
      label: { en: 'Identifying Marks', vi: 'Đặc điểm nhận dạng' },
    },
    issueDate: {
      source: 'dg13',
      at: 11,
      type: 'date',
      label: { en: 'Issue Date', vi: 'Ngày cấp' },
    },
    expiryDate: {
      source: 'dg13',
      at: 12,
      type: 'date',
      label: { en: 'Expiry Date', vi: 'Ngày hết hạn' },
    },
    fatherName: {
      source: 'dg13',
      at: 13,
      subIndex: 0,
      type: 'string',
      label: { en: 'Father\'s Name', vi: 'Họ tên cha' },
    },
    motherName: {
      source: 'dg13',
      at: 13,
      subIndex: 1,
      type: 'string',
      label: { en: 'Mother\'s Name', vi: 'Họ tên mẹ' },
    },

    // -----------------------------------------------------------------------
    // DG1 fields (mrz decode, at = MRZ parsed field name)
    // -----------------------------------------------------------------------
    documentType: {
      source: 'dg1',
      at: 'documentType',
      type: 'string',
      label: { en: 'Document Type', vi: 'Loại tài liệu' },
    },
    mrzDateOfBirth: {
      source: 'dg1',
      at: 'dateOfBirth',
      type: 'date',
      label: { en: 'Date of Birth (MRZ)', vi: 'Ngày sinh (MRZ)' },
    },
    mrzGender: {
      source: 'dg1',
      at: 'gender',
      type: 'enum',
      label: { en: 'Gender (MRZ)', vi: 'Giới tính (MRZ)' },
    },
    dateOfExpiry: {
      source: 'dg1',
      at: 'dateOfExpiry',
      type: 'date',
      label: { en: 'Date of Expiry', vi: 'Ngày hết hạn (MRZ)' },
    },

    // -----------------------------------------------------------------------
    // DG2 fields (biometric decode)
    // -----------------------------------------------------------------------
    photo: {
      source: 'dg2',
      at: 0,
      type: 'biometric',
      label: { en: 'Photo', vi: 'Ảnh chân dung' },
    },
  },
};
