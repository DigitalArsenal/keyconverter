import typescript from "@rollup/plugin-typescript";
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import { terser } from "rollup-plugin-terser";
export default [{
    input: "src/keyconvert.ts",
    output: {
        dir: "build",
        format: "esm",
    },
    plugins: [typescript({
        "module": "esnext",
    }), commonjs(), json(), resolve({ preferBuiltins: true })],
},
{
    input: "src/keyconvert.ts",
    output: {
        format: "esm",
        file: "build/keyconvert.min.js"
    },
    plugins: [typescript({
        "module": "esnext",
    }), commonjs(), json(), resolve({ preferBuiltins: true }), terser()],
}];