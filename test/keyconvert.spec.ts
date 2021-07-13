import assert from "assert";
import { keyconvert } from "../src/keyconvert";
import { pbkdf2Sync, scryptSync } from "crypto";
import * as bip32 from "bip32";
import * as bip39 from "bip39";

const curves = {
    secp256k1: { name: "ECDSA", namedCurve: "K-256" },
    secp256r1: { name: "ECDSA", namedCurve: "P-256" },
    //x25519: { name: "EdDSA", namedCurve: "X25519" }
};

let km = new keyconvert(curves.secp256k1);

let bip39mnemonic = `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel`;
let privateKeyHex = new Array(64).join("0") + "1"; //"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
let privateKeyWIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
let publicKeyHex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
let jsonWebKey = {
    d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE',
    x: 'eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g',
    y: 'SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg',
    ext: true,
    key_ops: ['sign', 'verify', 'deriveKey', 'deriveBits'],
    crv: 'K-256',
    kty: 'EC'
};

const runAssertions = async () => {

    expect(await km.privateKeyHex()).to.be.equal(privateKeyHex);
    expect(await km.publicKeyHex()).to.be.equal(publicKeyHex);
    expect(await km.export("bip39")).to.be.equal(bip39mnemonic);
    expect(await km.export("wif")).to.be.equal(privateKeyWIF);
    expect(await km.export("jwk")).to.be.eql(jsonWebKey);
}

it("Imports Private Key as Mnemonic", async function () {

    await km.import(bip39mnemonic);
    await runAssertions();

});

it("Imports Private Key as WIF", async function () {

    await km.import(privateKeyWIF, "wif");
    await runAssertions();

});

it("Imports Private Key as hex string", async function () {

    await km.import(privateKeyHex);
    await runAssertions();

});

it("Imports Private Key as JsonWebKey", async function () {
    await km.import(jsonWebKey);
    await runAssertions();
});