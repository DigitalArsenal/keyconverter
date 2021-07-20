import assert from "assert";
import { keyconvert, EncodingOptions } from "../src/keyconvert";
import { pbkdf2Sync, scryptSync } from "crypto";
import * as bip32 from "bip32";
import * as bip39 from "bip39";

const curves = {
    secp256k1: { name: "ECDSA", namedCurve: "K-256" },
    secp256r1: { name: "ECDSA", namedCurve: "P-256" },
    Ed25519: { name: "EdDSA", namedCurve: "Ed25519" }
};

let curve = curves.Ed25519;
let km = new keyconvert(curve);

let bip39mnemonic = `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel`;
let privateKeyHex = new Array(64).join("0") + "1";
let privateKeyWIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

let publicKeyHex: any = {
    "K-256": "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    "P-256": "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
}

let jWKPub: any = {
    "K-256": {
        x: 'eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g',
        y: 'SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg',
    },
    "P-256": {
        "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
    }
}

let jsonWebKey = {
    d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE',
    ...jWKPub[curve.namedCurve],
    ext: true,
    key_ops: ['sign', 'verify', 'deriveKey', 'deriveBits'],
    crv: curve.namedCurve,
    kty: 'EC'
};

const runAssertions = async (type: EncodingOptions) => {

    const k = [
        await km.privateKeyHex(),
        await km.publicKeyHex(),
        await km.export("bip39", "private"),
        await km.export("wif", "private"),
        await km.export("jwk", "private")
    ];


    expect(k[0]).to.be.equal(privateKeyHex);
    expect(k[1]).to.be.equal(publicKeyHex[curve.namedCurve]);
    expect(k[2]).to.be.equal(bip39mnemonic);
    expect(k[3]).to.be.equal(privateKeyWIF);
    expect(k[4]).to.be.eql(jsonWebKey);
    console.log("\n", k.map(n => typeof n === "object" ? JSON.stringify(n, null, 4) : n).join("\n\n"));
    console.log(await km.export("ssh", "private"));
    console.log(await km.export("ssh", "public", `exported-from: ${type}`));

}
if (~curve.name.indexOf('256')) {
    it("Imports Private Key as Mnemonic", async function () {

        await km.import(bip39mnemonic);
        await runAssertions("bip39");

    });

    it("Imports Private Key as WIF", async function () {

        await km.import(privateKeyWIF, "wif");
        await runAssertions("wif");

    });

    it("Imports Private Key as hex string", async function () {

        await km.import(privateKeyHex, "hex");
        await runAssertions("hex");

    });

    it("Imports Private Key as JsonWebKey", async function () {
        await km.import(jsonWebKey, "jwk");
        await runAssertions("jwk");
    });
}
it("Imports Private Key as raw", async function () {
    await km.import(Buffer.from(privateKeyHex, "hex"), "raw");
    console.log(km);
    await runAssertions("raw");

});