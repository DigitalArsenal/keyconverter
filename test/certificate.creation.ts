import assert from "assert";
import { keymaster } from "../src/index";
import { pbkdf2Sync, scryptSync } from "crypto";
import * as argon2 from "argon2";
import * as bip32 from "bip32";
import * as bip39 from "bip39";

let curves = {
    secp256k1: 'K-256',
    secp256r1: 'P-256',
};

it("creates a certificate from a buffer", async function () {
    let km = new keymaster(curves.secp256k1);
    let bip39mnemonic = `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel`;
    let privateKeyHex = new Array(64).join("0") + "1";
    let privateKeyWIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
    let publicKeyHex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    await km.import(bip39mnemonic);
    assert.strictEqual(await km.privateKeyHex(), privateKeyHex);
    await km.import(privateKeyWIF, 'wif');
    assert.strictEqual(await km.publicKeyHex(), publicKeyHex);
    assert.strictEqual(await km.export('bip39'), bip39mnemonic);
    assert.strictEqual(await km.export('wif'), privateKeyWIF);
});