
import { crypto as linerCrypto } from "webcrypto-liner";
import bitcoinjs from 'bitcoinjs-lib';
import wif from "wif";
import { pbkdf2Sync } from 'crypto';
import * as x509 from '@peculiar/x509';
import base64URL from "base64url";
import { writeFileSync } from 'fs';

export const clean = new RegExp(/[:\n\s\r]{1,}/g);

const jwkConversion = (prvHex, pubHex, namedCurve) => ({
    kty: "EC",
    crv: namedCurve,
    d: base64URL.encode(prvHex, "hex"),
    x: null,
    y: null,
});

x509.cryptoProvider.set(linerCrypto);

let { subtle } = linerCrypto;


let password = "password", salt = "salt", pin = 1, keyLength = 32;

async function main() {

    let pK = pbkdf2Sync(password, salt, 1, 32, "sha256", 0);
    const privateKeyHex = pK.toString("hex");

    const bjsKeyPair = bitcoinjs.ECPair.fromWIF(wif.encode(128, pK, true));

    const { address } = bitcoinjs.payments.p2pkh({
        pubkey: bjsKeyPair.publicKey,
    });
    console.log(address);

    const namedCurve = "P-256";
    const keys = await subtle.importKey("jwk", jwkConversion(privateKeyHex, null, namedCurve), { name: "ECDSA", namedCurve }, true, ["sign", "verify"]);

    const keyExt = await subtle.exportKey("jwk", keys);

    let algorithm = {
        name: "ECDSA",
        hash: "SHA-256",
        namedCurve: "P-256",
        length: 256
    };

    let { d, ...pubKeyExt } = keyExt;

    const caKeys = {
        privateKey: await subtle.importKey("jwk", keyExt, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]),
        publicKey: await subtle.importKey("jwk", pubKeyExt, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]),
    };

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

        ]
    });

    let exportedCAKey = await subtle.exportKey("pkcs8", caKeys.privateKey);


    console.log(x509.PemConverter.encode(
        exportedCAKey,
        "private key"
    ));
    
    console.log(caCert.toString("pem"));

    let SAN = new x509.SubjectAlternativeNameExtension({
        dns: ["localhost"]
    });


    const serverKey = await subtle.generateKey({
        name: "ECDSA", namedCurve: "P-256"
    }, true, ["sign", "verify"]);

    let exportedServerKey = await subtle.exportKey("pkcs8", serverKey.privateKey);

    console.log(x509.PemConverter.encode(
        exportedServerKey,
        "private key"
    ));

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
            SAN
        ]
    });
    console.log(serverCert.toString('pem'));
}

main();