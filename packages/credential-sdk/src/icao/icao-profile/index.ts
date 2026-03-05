export type {
  ICAODocumentProfile,
  SourceDefinition,
  DecodeStrategy,
  TLVPositionalDecode,
  TLVTaggedDecode,
  MRZDecode,
  BiometricDecode,
  FieldBinding,
  LocalizableString,
} from './types.js';

export { getProfile } from './registry.js';
export { resolveField } from './resolver.js';
export { getRequiredDGs } from './utils.js';
export { VN_CCCD_2024 } from './profiles/vn-cccd-2024.js';
