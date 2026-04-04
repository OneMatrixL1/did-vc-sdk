import type { SchemaResolverMap } from '../types/schema-resolver.js';
import { jsonSchemaResolver } from './json-schema-resolver.js';
import { createICAOSchemaResolver } from './icao-schema-resolver.js';

export { jsonSchemaResolver } from './json-schema-resolver.js';
export { createICAOSchemaResolver } from './icao-schema-resolver.js';
export { createBBSResolver, isBBSProof } from './bbs-resolver.js';
export { createZKPICAOSchemaResolver, isZKPResolver } from './zkp-icao-schema-resolver.js';
export type { ZKPSchemaResolver, ZKPDeriveOptions } from './zkp-icao-schema-resolver.js';
export { fieldIdToLeafIndex, fieldIdToTagId, extractSiblingsForLeaf, isDg13Field } from './zkp-field-mapping.js';

/** Built-in resolvers: JsonSchema + ICAO9303SOD. Works out of the box. */
export const defaultResolvers: SchemaResolverMap = {
  'JsonSchema': jsonSchemaResolver,
  'ICAO9303SOD': createICAOSchemaResolver(),
};
