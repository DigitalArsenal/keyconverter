
import { crypto as linerCrypto } from "webcrypto-liner";
import bitcoinjs from 'bitcoinjs-lib';
import wif from "wif";
import { pbkdf2Sync } from 'crypto';
import * as x509 from '@peculiar/x509';
import base64URL from "base64url";
import { writeFileSync } from 'fs';
import inquirer from 'inquirer';
import { of } from "rxjs";
import bip39 from 'bip39';
import sshpk from 'sshpk';

globalThis.btoa = globalThis.btoa || function (str) {
    var buffer;

    if (str instanceof Buffer) {
        buffer = str;
    } else {
        buffer = Buffer.from(str.toString(), 'binary');
    }

    return buffer.toString('base64');
};

x509.cryptoProvider.set(linerCrypto);

let { subtle } = linerCrypto;


let keyLength = 32;

async function main() {
    let answers = await inquirer
        .prompt([
            {
                type: 'input',
                name: 'username',
                message: "Username?",
            },
            {
                type: 'password',
                name: 'password',
                message: "Password?",
            },
            {
                type: 'input',
                name: 'pin',
                message: "Pin?"
            }
        ]).catch((error) => {
            console.log(error);
            if (error.isTtyError) {
                // Prompt couldn't be rendered in the current environment
            } else {
                // Something else went wrong
            }
        });


    let { username, password, pin } = answers;
    pin = parseInt(pin);
    if (isNaN(pin)) {
        throw Error('Pin Invalid');
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

    const mem = bip39.entropyToMnemonic(pK);
    console.log(mem);
    console.log(pK);
    console.log(Buffer.from(bip39.mnemonicToEntropy(mem), 'hex'));
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
    const publicKey = await subtle.exportKey('spki', caKeys.publicKey);

    let pkBody = btoa(String.fromCharCode(...new Uint8Array(publicKey))).match(/.{1,64}/g).join('\n');
    pkBody = `-----BEGIN PUBLIC KEY-----\n${pkBody}\n-----END PUBLIC KEY-----`;
    console.log('public key: ', pkBody);
    /* Read in a PEM public key */
    let sshkey = sshpk.parseKey(pkBody, 'pem');

    /* Convert to PEM PKCS#8 public key format */
    var pemBuf = sshkey.toBuffer('pkcs8');

    /* Convert to SSH public key format (and return as a string) */
    var sshKey = sshkey.toString('ssh');

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

        ]
    });
    await x509.X509Certificate.digitalSignature
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