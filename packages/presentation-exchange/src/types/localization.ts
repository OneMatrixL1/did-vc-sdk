/** A single localized string value with language tag */
export interface LocalizedValue {
  '@value': string;
  '@language': string;
}

/** A string that can be plain or localized into multiple languages */
export type LocalizableString = string | LocalizedValue[];
