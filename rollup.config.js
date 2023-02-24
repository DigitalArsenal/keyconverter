import typescript from "@rollup/plugin-typescript";
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import nodePolyfills from "rollup-plugin-polyfill-node";

export default {
  input: "src/keyconvert.ts",
  output: {
    format: "esm",
    file: "build/keyconvert.mjs",
  },
  plugins: [
    nodePolyfills({
      include: ["buffer", "crypto", "stream", "fs", "path", "os", "util"],
    }),
    typescript({
      module: "esnext",
    }),
    commonjs(),
    json(),
    resolve({ preferBuiltins: false }),
  ],
};
