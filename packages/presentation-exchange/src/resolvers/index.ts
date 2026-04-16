import type { SchemaResolverMap } from '../types/schema-resolver.js';
import { createICAOSchemaResolver } from './icao-schema-resolver.js';

export { createICAOSchemaResolver } from './icao-schema-resolver.js';
export { createBBSResolver, isBBSProof } from './bbs-resolver.js';

/** Built-in resolvers: ICAO9303SOD. */
export const defaultResolvers: SchemaResolverMap = {
  'ICAO9303SOD': createICAOSchemaResolver(),
};
