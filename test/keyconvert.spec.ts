import { keyconvert, FormatOptions } from "../src/keyconvert";
interface Map {
    [key: string]: any | undefined
}
const curves: Map = {
    "secp256k1": { kty: "EC", name: "ECDSA", namedCurve: "k-256", hash: "SHA-256" },
    "secp256r1": { kty: "EC", name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" },
    "ed25519": { kty: "OKP", name: "EdDSA", namedCurve: "Ed25519", hash: "SHA-256" },
    "x25519": { kty: "OKP", name: "ECDH-ES", namedCurve: "x25519", hash: "SHA-256" }
};

let curve = curves.ed25519;


let PEMS: any = {
    "K-256": {
        privateKeyPEMPKCS1: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABoAoGCCqGSM49
AwEHoUQDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/
m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==
-----END EC PRIVATE KEY-----`,

        privateKeyPEMPKCS8: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAGhRANCAARrF9Hy4SxCR/i85uVjpEDydwN9gS3r
M6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1
-----END PRIVATE KEY-----`
    },
    "Ed25519": {
        privateKeyPEMPKCS8: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB
-----END PRIVATE KEY-----`
    }
}

//https://privatekeys.pw/key/0000000000000000000000000000000000000000000000000000000000000001
let bip39mnemonic = `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel`;
let privateKeyHex = new Array(64).join("0") + "1";
let privateKeyWIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

let publicKeyHex: any = {
    "K-256": "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    "P-256": "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "Ed25519": "4cb5abf6ad79fbf5abbccafcc269d85c"
}

let jWKPub: any = {
    "K-256": {
        x: 'eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g',
        y: 'SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg',
    },
    "P-256": {
        "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
    },
    "Ed25519": {
        x: 'TLWr9q15-_WrvMr8wmnYXA'
    }
}

let jsonWebKeyEC: any = {
    d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE',
    ...jWKPub[curve.namedCurve],
    ext: true,
    key_ops: ['sign', 'verify', 'deriveKey', 'deriveBits'],
    crv: curve.namedCurve,
    kty: 'EC'
};

let jsonWebKeyOKP: any = {
    d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE',
    ...jWKPub[curve.namedCurve],
    ext: true,
    key_ops: ['sign', 'verify', 'deriveKey', 'deriveBits'],
    crv: curve.namedCurve,
    kty: 'OKP'

}

let BTC: string = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
let ETH: string = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"; //checksum address
let km = new keyconvert(curve);

const runAssertions = async (type: FormatOptions) => {
    const x = async (p: keyconvert) => await Promise.all([
        p.privateKeyHex(),
        p.publicKeyHex(),
        p.export("bip39", "private"),
        p.export("wif", "private"),
        p.export("jwk", "private"),
        p.export("pkcs1", "private"),
        p.export("pkcs8", "private"),
        p.bitcoinAddress(),
        p.ethereumAddress()
    ]);

    const k = await x(km);
    expect(k[0]).to.be.equal(privateKeyHex);
    expect(k[1]).to.be.equal(publicKeyHex[curve.namedCurve]);
    expect(k[2]).to.be.equal(bip39mnemonic);
    expect(k[3]).to.be.equal(privateKeyWIF);

    if (curve.kty === "OKP") {
        expect(jsonWebKeyOKP).to.be.eql(k[4]);
    } else if (curve.kty === "EC") {
        expect(jsonWebKeyEC).to.be.eql(k[4]);
    }

    if (PEMS[curve.namedCurve].privateKeyPEMPKCS1) {
        expect(k[5].toString().trim()).to.be.equal(PEMS[curve.namedCurve].privateKeyPEMPKCS1);
    }
    expect(k[6].toString().trim()).to.be.equal(PEMS[curve.namedCurve].privateKeyPEMPKCS8);
    expect(k[7]).to.be.equal(BTC);
    expect(k[8]).to.be.equal(ETH);
    for (let c in curves) {
        console.log(await km.exportX509Certificate({ signingAlgorithm: curves[c] }));
    }

    console.log(await km.export("ssh", "private"));
    console.log(await km.export("ssh", "public", `exported-from: ${type}`));


}
/*
it("Imports Private Key as Mnemonic", async function () {
    await km.import(bip39mnemonic, "bip39");
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
    await km.import(jsonWebKeyOKP, "jwk");
    await runAssertions("jwk");
});

it("Imports Private Key as raw", async function () {
    await km.import(Buffer.from(privateKeyHex, 'hex'), "raw:private");
    await runAssertions("raw:private");
});

it("Imports Private Key as PEM (pkcs1)", async function () {
    await km.import(PEMS["K-256"].privateKeyPEMPKCS1, "pkcs1");
    await runAssertions("pkcs1");
});
*/
it("Imports Private Key as PEM (pkcs8)", async function () {
    let km2 = new keyconvert(curves.secp256k1);
    await km2.import(PEMS["K-256"].privateKeyPEMPKCS8, "pkcs8");
    await runAssertions("pkcs8");
});

//TODO loop through all key curves, difference between JWK OKP and EC