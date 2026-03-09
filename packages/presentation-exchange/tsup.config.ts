import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  noExternal: [],
  external: [
    '@1matrix/credential-sdk',
    // Keep Node.js CJS deps external so downstream bundlers (Vite) can
    // polyfill `require('crypto')` etc. for browser/iOS targets.
    'jsonld-signatures',
    'rdf-canonize',
  ],
});
