import * as assert from "assert";
import { keymaster } from "../src/index";
import { pbkdf2Sync, scryptSync } from 'crypto';
import * as argon2 from "argon2";

console.log(argon2);

it("creates a keymaster instance", async function () {
    let km = new keymaster('P-256', pbkdf2Sync('Test', 'Test', 1, 32, "sha256"));
});