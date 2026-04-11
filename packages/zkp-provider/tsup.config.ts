import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: false,
  clean: true,
  sourcemap: true,
  splitting: false,
  external: [
    '@aztec/bb.js',
    '@noir-lang/noir_js',
  ],
});
