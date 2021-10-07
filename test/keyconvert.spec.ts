import { keyconvert, FormatOptions } from "../src/keyconvert";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { curve } from "elliptic";
var dir = './tmp';

if (!existsSync(dir)) {
    mkdirSync(dir);
};

interface Map {
    [key: string]: any | undefined;
}
const curves: Map = {
    "secp256k1": { kty: "EC", name: "ECDSA", namedCurve: "K-256", hash: "SHA-256" },
    "secp256r1": { kty: "EC", name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" },
    "ed25519": { kty: "OKP", name: "EdDSA", namedCurve: "Ed25519", hash: "SHA-256" },
    "x25519": { kty: "OKP", name: "ECDH-ES", namedCurve: "x25519", hash: "SHA-256" }
};

let PEMS: any = {
    "secp256k1": {
        privateKeyPEMPKCS8: `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAGhRANCAAR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ
8oFbFvgXmEg62ncmo8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4
-----END PRIVATE KEY-----`
    },
    "ed25519": {
        privateKeyPEMPKCS8: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB
-----END PRIVATE KEY-----`
    },
    "x25519": {
        privateKeyPEMPKCS8: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB
-----END PRIVATE KEY-----`
    }
};

//https://privatekeys.pw/key/0000000000000000000000000000000000000000000000000000000000000001
let bip39mnemonic = `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon diesel`;
let privateKeyHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";//new Array(64).join("0") + "1";
let privateKeyWIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

let publicKeyHex: any = {
    "secp256k1": "045b7032d9b3955e59dfdfc1d56860dc971495246ac027eab148699210e66607ac6a8d9d47d313698480e565ee1f18e99683d6ed7a6fbd1e9de68f4dea053898c0",
    "secp256r1": "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "ed25519": "4cb5abf6ad79fbf5abbccafcc269d85c",
    "x25519": "fd3384e132ad02a56c78f45547ee4003"
};

let jWKPub: any = {
    "secp256k1": {
        x: 'eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g',
        y: 'SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg',
    },
    "secp256r1": {
        "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
    },
    "ed25519": {
        x: 'TLWr9q15-_WrvMr8wmnYXA'
    }
};

function jsonWebKeyEC(cindex: string, curve: any): JsonWebKey {
    return {
        d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE',
        ...jWKPub[cindex],
        ext: true,
        key_ops: ['sign', 'verify', 'deriveKey', 'deriveBits'],
        crv: curve.namedCurve,
        kty: 'EC'
    };
}

function jsonWebKeyOKP(cindex: string, curve: any): JsonWebKey {

    return {
        d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE',
        ...jWKPub[cindex],
        ext: true,
        key_ops: ['sign', 'verify', 'deriveKey', 'deriveBits'],
        crv: curve.namedCurve,
        kty: 'OKP'

    };
}

let BTC: string = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
let ETH: string = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"; //checksum address

const runAssertions = async (type: FormatOptions, km: keyconvert, cindex: string, harness: any) => {

    let curve = km.keyCurve as any;
    const x = async (p: keyconvert) => await Promise.all([
        p.privateKeyHex(),
        p.publicKeyHex(),
        p.export("bip39", "private"),
        p.export("wif", "private"),
        p.export("jwk", "private"),
        p.export("pkcs8", "private"),
        p.bitcoinAddress(),
        p.ethereumAddress()
    ]);

    const k = await x(km);

    for (let x = 0; x < harness.length; x++) {
        expect(k[x]).to.be.eql(harness[x]);
    }

   // console.log(await km.export("ssh", "private"));
   // console.log(await km.export("ssh", "public", `exported-from: ${type}`));


};

for (let c in curves) {
    let curve = curves[c];
    let km = new keyconvert(curve);
    let harness = JSON.parse(readFileSync(`./test/check/${c}.json`, 'utf-8'));

    it("Imports Private Key as raw", async function () {
        await km.import(Buffer.from(privateKeyHex, 'hex'), "raw:private");
        await runAssertions("raw:private", km, c, harness);
    });

    it("Imports Private Key as Mnemonic", async function () {
        await km.import(harness[2], "bip39");
        await runAssertions("bip39", km, c, harness);
    });

    it("Imports Private Key as WIF", async function () {
        await km.import(harness[3], "wif");
        await runAssertions("wif", km, c, harness);
    });

    it("Imports Private Key as hex string", async function () {
        await km.import(harness[0], "hex");
        await runAssertions("hex", km, c, harness);

    });

    it("Imports Private Key as JsonWebKey", async function () {
        await km.import(harness[4], "jwk");
        await runAssertions("jwk", km, c, harness);
    });

    it(`Imports Private Key as PEM (pkcs8): ${c}`, async function () {
        if (PEMS[c]) {
            await km.import(harness[5], "pkcs8");
            await runAssertions("pkcs8", km, c, harness);
        }
    });

}


//TODO loop through all key curves, difference between JWK OKP and EC