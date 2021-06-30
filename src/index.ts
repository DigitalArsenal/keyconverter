import base64URL from "base64url";
import { crypto as linerCrypto } from "webcrypto-liner/build/index.js";
import * as bitcoinjs from 'bitcoinjs-lib';
import wif from "wif";
import { pbkdf2Sync } from 'crypto';
import * as x509 from '@peculiar/x509';
import { writeFileSync } from 'fs';
import inquirer from 'inquirer';
import { of } from "rxjs";
import sshpk from 'sshpk';

let { subtle } = linerCrypto;

export class keymaster {

    privateKey: CryptoKey;
    publicKey: CryptoKey;
    curve: NamedCurve;


    /*
    encrypt: The key may be used to encrypt messages.
    decrypt: The key may be used to decrypt messages.
    sign: The key may be used to sign messages.
    verify: The key may be used to verify signatures.
    deriveKey: The key may be used in deriving a new key.
    deriveBits: The key may be used in deriving bits.
    wrapKey: The key may be used to wrap a key.
    unwrapKey: The key may be used to unwrap a key.
    */

    keyUsages: Array<string> = ["sign", "verify"];

    private static jwkConversion(prvHex: string, namedCurve: NamedCurve, format: string = "hex"): JsonWebKey {
        return {
            kty: "EC",
            crv: namedCurve,
            d: base64URL.encode(prvHex, format),
            x: null,
            y: null,
        }
    };

    get bip39(): string {
        return ""
    }

    init(privateKey: Buffer);
    init(bip39: string);
    init(privateKey: string, format: string);

    public async init(privateKey: any, format?: string): Promise<void> {
        if (privateKey instanceof Buffer) {
            format = "hex";
            privateKey = privateKey.toString("hex");
        }
        this.privateKey = await subtle.importKey(
            "jwk",
            keymaster.jwkConversion(privateKey, this.curve, format),
            { name: "ECDSA", namedCurve: this.curve },
            true,
            this.keyUsages);
    }

    constructor(namedCurve: NamedCurve) {
        this.curve = namedCurve;
    }
}

