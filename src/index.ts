import base64URL from "base64-url/index.js";
import { crypto as linerCrypto } from "webcrypto-liner/build/index.js";
import wif from "wif";
import * as x509 from "@peculiar/x509";
import sshpk from "sshpk";
import * as bip39 from "bip39";

x509.cryptoProvider.set(linerCrypto);

let { subtle } = linerCrypto;

/**
 * @type
 * 
 * @description
 * 
 * 
 */

type EncodingOptions = BufferEncoding | "wif" | "bip39" | "jwk" | "x509";

/**
 * @type
 * 
 * @description
 * 
 * encrypt: The key may be used to encrypt messages.
 * 
 * decrypt: The key may be used to decrypt messages.
 * 
 * sign: The key may be used to sign messages.
 * 
 * verify: The key may be used to verify signatures.
 * 
 * deriveKey: The key may be used in deriving a new key.
 * 
 * deriveBits: The key may be used in deriving bits.
 * 
 * wrapKey: The key may be used to wrap a key.
 * 
 * unwrapKey: The key may be used to unwrap a key.
 */

type KeyUsageOptions = "encrypt" | "decrypt" | "sign" | "verify" | "deriveKey" | "deriveBits" | "wrapKey" | "unwrapKey";

type NamedCurve = {
    name: string;
    namedCurve: string
}

export class keyconvert {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    curve: NamedCurve;


    keyUsages: Array<KeyUsageOptions>;

    /**
     * Converts hex format to an RFC7517 JSONWebKey
     * @link https://datatracker.ietf.org/doc/html/rfc7517
     * @param
     * @returns {JsonWebKey}
     */
    private static jwkConversion(
        prvHex: string,
        curve: NamedCurve,
        format: string = "hex"
    ): JsonWebKey {
        return {
            kty: "EC",
            crv: curve.namedCurve,
            d: base64URL.encode(prvHex, format),
            x: null,
            y: null
        };
    }

    private static toHex(buffer: any): string {
        return Buffer.from(buffer, "hex").toString("hex");
    }

    async export(encoding: EncodingOptions): Promise<string> {
        const _hex = await this.privateKeyHex();
        if (encoding === "hex") {
            return _hex;
        } else if (encoding === "bip39") {
            return bip39.entropyToMnemonic(Buffer.from(_hex, "hex"));
        } else if (encoding === "wif") {
            return wif.encode(128, Buffer.from(_hex, "hex"), true);
        } else if (encoding === "jwk") {
            return await subtle.exportKey("jwk", this.privateKey);
        }
    }

    async privateKeyHex(): Promise<string> {
        let jwkPrivateKey = await subtle.exportKey("jwk", this.privateKey);
        return base64URL.decode(jwkPrivateKey.d, "hex");
    }

    async publicKeyHex(): Promise<string> {
        let keyExt = await subtle.exportKey("jwk", this.privateKey);
        let { d, ...pubKeyExt } = keyExt;
        this.publicKey = await subtle.importKey("jwk", pubKeyExt, { name: "ECDSA", namedCurve: this.curve }, true, ["verify"])
        let publicKey = await subtle.exportKey("raw", this.publicKey);
        return keyconvert.toHex(publicKey);
    }

    public async import(privateKey: Buffer);
    public async import(privateKey: JsonWebKey);
    public async import(privateKey: string, encoding?: EncodingOptions);

    public async import(privateKey: any, encoding?: EncodingOptions): Promise<void> {

        let convert: Boolean = true;
        let importJWK: JsonWebKey;

        if (typeof privateKey === "string") {
            if (privateKey.match(/[0-9a-fA-F]+/) && !encoding) {
                encoding = "hex";
            }
            if (privateKey.indexOf(" ") > -1 || encoding === "bip39") {
                privateKey = bip39.mnemonicToEntropy(privateKey);
            } else if (encoding === "wif") {
                const decodedWif = wif.decode(privateKey);
                privateKey = keyconvert.toHex(decodedWif.privateKey);
                encoding = "hex";
            } else if (!encoding) {
                throw Error(`Unknown Private Key Encoding: ${encoding}`);
            }
        } else if ((privateKey as JsonWebKey).d) {
            importJWK = privateKey;
            convert = false;
        } else if (!(privateKey instanceof Buffer)) {
            throw Error(`Unknown Input: ${privateKey}`);
        }

        if (convert) {
            encoding = "hex";
            privateKey = privateKey.toString("hex");
            importJWK = keyconvert.jwkConversion(privateKey, this.curve, encoding);
        }

        this.privateKey = await subtle.importKey(
            "jwk",
            importJWK,
            this.curve,
            true,
            this.keyUsages
        );
    }

    constructor(namedCurve: NamedCurve, keyUsages?: Array<KeyUsageOptions>) {
        this.curve = namedCurve;
        this.keyUsages = keyUsages || ["sign", "verify", "deriveKey", "deriveBits"];
    }
}
