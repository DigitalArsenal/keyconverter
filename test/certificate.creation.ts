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
    let privateKeyHex = new Array(64).join("0") + "1";
    let privateKeyHexBuffer = Buffer.from(
        privateKeyHex,
        'hex');
    let bip39mnemonic = `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel`;
    await km.import(bip39mnemonic);
    const seed = await bip39.mnemonicToSeed(bip39mnemonic);
    const node = bip32.fromSeed(seed);
    console.log(node.toBase58());

    assert.strictEqual((await km.hex()), privateKeyHex);
    assert.strictEqual(await km.bip39(), bip39mnemonic);
});