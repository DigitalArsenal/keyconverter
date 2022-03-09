import { keyconvert, FormatOptions } from "../src/keyconvert";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { exec, execSync } from "child_process";
var dir = "./tmp";

if (!existsSync(dir)) {
  mkdirSync(dir);
}

interface Map {
  [key: string]: any | undefined;
}
const curves: Map = {
  secp256k1: { kty: "EC", name: "ECDSA", namedCurve: "K-256", hash: "SHA-256" },
  secp256r1: { kty: "EC", name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" },
  ed25519: { kty: "OKP", name: "EdDSA", namedCurve: "Ed25519", hash: "SHA-256" }
  // x25519: { kty: "OKP", name: "ECDH-ES", namedCurve: "x25519", hash: "SHA-256" }
};
let privateKeyHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"; //new Array(64).join("0") + "1";

let peerIDString = "bafzaajiiaijccas3oazntm4vlzm57x6b2vugbxexcsksi2wae7vlcsdjsiiomzqhvq";
let ipnsCID: Map = {
  "K-256": "kzwfwjn5ji4puly9aarkabpxg32ajaa427ugoeg4s23op18jjyf2ry01xjoiw8c",
  "P-256": "kzwfwjn5ji4puly9aarkabpxg32ajaa427ugoeg4s23op18jjyf2ry01xjoiw8c"
};

const runAssertions = async (type: FormatOptions, km: keyconvert, cindex: string, harness: any) => {
  let curve = km.keyCurve as any;
  const x = async (p: keyconvert) =>
    await Promise.all([
      p.privateKeyHex(),
      p.publicKeyHex(),
      p.export("bip39", "private"),
      p.export("wif", "private"),
      p.export("jwk", "private"),
      p.export("pkcs8", "private"),
      p.bitcoinAddress(),
      p.ethereumAddress(),
      p.ipfsPeerID(),
      p.ipnsCID()
    ]);

  const k = await x(km);
  let todaysDate = new Date();
  let lastDate = new Date(todaysDate.setFullYear(todaysDate.getFullYear() + 1));


  for (let x = 0; x < harness.length; x++) {
    // expect(k[x]).to.be.eql(harness[x]);
  }
  expect(k[8].toString()).to.be.eql(peerIDString);

  if (ipnsCID[km.keyCurve.namedCurve]) {
    let keyPath = `tmp/${km.keyCurve.namedCurve}_privatekey.pem`;
    let certPath = `tmp/${km.keyCurve.namedCurve}_cert.crt`;
    if (k[9].toString())
      expect(k[9].toString()).to.be.eql(ipnsCID[km.keyCurve.namedCurve]);
    writeFileSync(keyPath, (await km.export("pkcs8", "private")).toString());
    writeFileSync(certPath, (await km.exportX509Certificate(
      {
        serialNumber: `${Date.now()} `,
        subject: `CN = localhost`,
        issuer: `BTC`,
        notBefore: todaysDate,
        notAfter: lastDate,
        signingAlgorithm: null,
        encoding: "pem"
      }
    )).toString());
    execSync(`openssl ec -in ${keyPath} -text -noout > test.txt`);
    execSync(`openssl x509 -in ${certPath} -noout -text`);
  }
  // console.log(await km.export("ssh", "private"));
  // console.log(await km.export("ssh", "public", `exported-from: ${type}`));
};

for (let c in curves) {
  let curve = curves[c];
  let km = new keyconvert(curve);
  let harness = JSON.parse(readFileSync(`./test/check/${c}.json`, "utf-8"));

  it(`Imports Private Key as raw: ${c}`, async function () {
    await km.import(Buffer.from(privateKeyHex, "hex"), "raw:private");
    await runAssertions("raw:private", km, c, harness);
  });

  it(`Imports Private Key as Mnemonic: ${c}`, async function () {
    await km.import(harness[2], "bip39");
    await runAssertions("bip39", km, c, harness);
  });

  it(`Imports Private Key as WIF: ${c}`, async function () {
    await km.import(harness[3], "wif");
    await runAssertions("wif", km, c, harness);
  });

  it(`Imports Private Key as hex string: ${c}`, async function () {
    await km.import(harness[0], "hex");
    await runAssertions("hex", km, c, harness);
  });

  it(`Imports Private Key as JsonWebKey: ${c}`, async function () {
    await km.import(harness[4], "jwk");
    await runAssertions("jwk", km, c, harness);
  });

  it(`Imports Private Key as PEM (pkcs8): ${c}`, async function () {
    await km.import(harness[5], "pkcs8");
    await runAssertions("pkcs8", km, c, harness);
  });
}

//TODO loop through all key curves, difference between JWK OKP and EC
