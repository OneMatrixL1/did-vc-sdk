import json from "@rollup/plugin-json";
import multiInput from "rollup-plugin-multi-input";
import commonjs from "@rollup/plugin-commonjs";
import babel from "@rollup/plugin-babel";
import { existsSync } from "fs";
import { resolve as resolvePath, dirname } from "path";
import { fileURLToPath } from "url";

/** Resolve `.js` imports to `.ts` source files when the .ts file exists locally. */
function resolveTs() {
  return {
    name: "resolve-ts",
    resolveId(source, importer) {
      if (!importer || !source.startsWith(".") || !source.endsWith(".js")) return null;
      const importerPath = importer.startsWith("file://") ? fileURLToPath(importer) : importer;
      const tsPath = resolvePath(dirname(importerPath), source.replace(/\.js$/, ".ts"));
      return existsSync(tsPath) ? tsPath : null;
    },
  };
}

export default async function () {
  return [
    {
      plugins: [
        multiInput({ glob: { cwd: process.cwd() } }),
        resolveTs(),
        json(),
        // terser(),
        commonjs(),
        babel({
          babelHelpers: "bundled",
          extensions: [".js", ".ts"],
          presets: [
            ["@babel/preset-env", { targets: { node: "current" } }],
            "@babel/preset-typescript",
          ],
          plugins: [],
        }),
        // Temporarily disabled, not sure if required
        // since rify is a node module doesnt seem to work
        // but would be nice to try embed it
        // wasm({
        //   sync: ['*.wasm'],
        // }),
      ],
      input: ["src/**/*.js", "src/**/*.ts"],
      output: [
        {
          sourcemap: true,
          dir: "dist/esm",
          format: "esm",
          entryFileNames: "[name].js",
        },
        {
          sourcemap: true,
          dir: "dist/cjs",
          format: "cjs",
          entryFileNames: "[name].cjs",
        },
      ],
    },
  ];
}
