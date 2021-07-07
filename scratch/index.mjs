import { crypto as linerCrypto } from "webcrypto-liner";
import bitcoinjs from "bitcoinjs-lib";
import wif from "wif";
import { pbkdf2Sync } from "crypto";
import * as x509 from "@peculiar/x509";
import { writeFileSync } from "fs";
import inquirer from "inquirer";
import { of } from "rxjs";
import bip39 from "bip39";
import sshpk from "sshpk";
import base64URL from "base64-url";

globalThis.btoa =
  globalThis.btoa ||
  function (str) {
    var buffer;

    if (str instanceof Buffer) {
      buffer = str;
    } else {
      buffer = Buffer.from(str.toString(), "binary");
    }

    return buffer.toString("base64");
  };

x509.cryptoProvider.set(linerCrypto);

let { subtle } = linerCrypto;

let keyLength = 32;

async function main() {
  let username = "Test",
    password = "Test",
    pin = 1;
  pin = parseInt(pin);
  if (isNaN(pin)) {
    throw Error("Pin Invalid");
    return;
  }

  const jwkConversion = (prvHex, pubHex, namedCurve) => ({
    kty: "EC",
    crv: namedCurve,
    d: base64URL.encode(prvHex, "hex"),
    x: null,
    y: null,
  });
  let pK = pbkdf2Sync(username, password, 1, 32, "sha256", 0);
  const privateKeyHex = pK.toString("hex");
  console.log(privateKeyHex);
  const mem = bip39.entropyToMnemonic(Buffer.from(new Array(33).join("0"), "hex"));
  console.log(mem);
  const bjsKeyPair = bitcoinjs.ECPair.fromWIF(wif.encode(128, pK, true));

  const { address } = bitcoinjs.payments.p2pkh({
    pubkey: bjsKeyPair.publicKey,
  });

  const namedCurve = "K-256";
  const keys = await subtle.importKey("jwk", jwkConversion(privateKeyHex, null, namedCurve), { name: "ECDSA", namedCurve }, true, ["sign", "verify"]);

  const keyExt = await subtle.exportKey("jwk", keys);

  let algorithm = {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
    length: 256,
  };

  let { d, ...pubKeyExt } = keyExt;

  const caKeys = {
    privateKey: await subtle.importKey("jwk", keyExt, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]),
    publicKey: await subtle.importKey("jwk", pubKeyExt, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]),
  };
  const publicKey = await subtle.exportKey("jwk", caKeys.publicKey);
  const bufferPrivateKey = await subtle.exportKey("jwk", keys);
  console.log(keys);
  const publicKeyHex = caKeys.publicKey;
  const privateKeyHex1 = Buffer.from(await subtle.exportKey("raw", keys), "hex").toString("hex");

  const hexToUintArray = (hex) => {
    const a = [];
    for (let i = 0, len = hex.length; i < len; i += 2) {
      a.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(a);
  };

  const hexToArrayBuf = (hex) => {
    return hexToUintArray(hex).buffer;
  };

  const jwkConv = (prvHex, pubHex) => ({
    kty: "EC",
    crv: "P-256",
    d: base64URL.encode(hexToArrayBuf(prvHex)),
    x: null, //base64URL.encode(hexToArrayBuf(pubHex).slice(1, 33)),
    y: null, //base64URL.encode(hexToArrayBuf(pubHex).slice(33, 66))
  });

  const importedPrivateKey = await subtle.importKey(
    "jwk",
    jwkConversion(privateKeyHex, null, namedCurve),
    {
      name: "ECDH",
      namedCurve,
    },
    true,
    ["sign"]
  );

  let exportedPK = (await subtle.exportKey("jwk", keys)).d;
  console.log(keys, exportedPK);
  console.log(base64URL.decode(exportedPK, "hex") === privateKeyHex);


  let pkBody = btoa(String.fromCharCode(...new Uint8Array(publicKey)))
    .match(/.{1,64}/g)
    .join("\n");
  pkBody = `-----BEGIN PUBLIC KEY-----\n${pkBody}\n-----END PUBLIC KEY-----`;
  console.log("public key: ", pkBody);
  /* Read in a PEM public key */
  let sshkey = sshpk.parseKey(pkBody, "pem");

  /* Convert to PEM PKCS#8 public key format */
  var pemBuf = sshkey.toBuffer("pkcs8");

  /* Convert to SSH public key format (and return as a string) */
  var sshKey = sshkey.toString("ssh");

  console.log(sshKey, pemBuf);
  let { digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment } = x509.KeyUsageFlags;

  const caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=AAA.x509.localhostCA",
    notBefore: new Date("2020/01/01"),
    notAfter: new Date("2022/01/02"),
    signingAlgorithm: algorithm,
    keys: caKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 2, true),
      await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(caKeys.publicKey),
      new x509.KeyUsagesExtension(digitalSignature | nonRepudiation | keyEncipherment | dataEncipherment, true),
    ],
  });
  await x509.X509Certificate.digitalSignature;
  let exportedCAKey = await subtle.exportKey("pkcs8", caKeys.privateKey);

  console.log(x509.PemConverter.encode(exportedCAKey, "private key"));

  console.log(caCert.toString("pem"));

  let SAN = new x509.SubjectAlternativeNameExtension({
    dns: ["localhost"],
  });

  const serverKey = await subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"]
  );

  let exportedServerKey = await subtle.exportKey("pkcs8", serverKey.privateKey);

  console.log(x509.PemConverter.encode(exportedServerKey, "private key"));

  const serverCert = await x509.X509CertificateGenerator.create({
    serialNumber: `${Date.now()}`,
    subject: `CN=localhost`,
    issuer: caCert.issuer,
    notBefore: new Date("2020/01/01"),
    notAfter: new Date("2022/01/02"),
    signingAlgorithm: algorithm,
    publicKey: serverKey.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [
      new x509.KeyUsagesExtension(digitalSignature | nonRepudiation | keyEncipherment | dataEncipherment, true),
      await x509.AuthorityKeyIdentifierExtension.create(caKeys.publicKey),
      SAN,
    ],
  });
  console.log(serverCert.toString("pem"));
}

main();

export default "";
