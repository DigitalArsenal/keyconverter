
import base64URL from "base64-url/index.js";
import * as liner from "../lib/webcrypto.liner.index.es";
import wif from "wif";
import * as x509 from "../lib/x509.es";
import sshpk from "sshpk";
import * as bip39 from "bip39";
import { EcAlgorithm } from "../lib/x509.es";
import { Buffer } from 'buffer';

const { crypto: linerCrypto } = liner;

let { subtle } = linerCrypto;

x509.cryptoProvider.set(liner);

/**

 * @type
 * 
 * @description
 * 
 * 
 */

export type EncodingOptions = KeyFormat | BufferEncoding | "wif" | "bip39" | "ssh" | "x509" | "raw:private";

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

export class keyconvert {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    keyCurve: EcKeyGenParams;
    extractable: boolean;
    algorithm: AlgorithmIdentifier;
    keyUsages: Array<KeyUsageOptions>;

    /**
     * Converts hex format to an RFC7517 JSONWebKey
     * @link https://datatracker.ietf.org/doc/html/rfc7517
     * @param
     * @returns {JsonWebKey}
     */
    private static jwkConversion(
        prvHex: string,
        curve: EcKeyGenParams,
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

    private static exportFormatError(encoding: string, type: KeyType): void {
        throw Error(`${encoding} format is not available for KeyType ${type}`);
    }

    async export(encoding: EncodingOptions, type: KeyType = "public", comment?: string): Promise<JsonWebKey | ArrayBuffer | string> {

        const _hex = type === "private" ? await this.privateKeyHex() : await this.publicKeyHex();
        if (encoding === "hex") {
            return _hex;
        } else if (encoding === "bip39") {
            if (type === "public") {
                keyconvert.exportFormatError(encoding, type);
            } else {
                return bip39.entropyToMnemonic(Buffer.from(_hex, "hex"));
            }
        } else if (encoding === "wif") {
            if (type === "public") {
                keyconvert.exportFormatError(encoding, type);
            } else {
                return wif.encode(128, Buffer.from(_hex, "hex"), true);
            }
        } else if (encoding === "ssh") {
            let openSSHPEM = `-----BEGIN PRIVATE KEY-----
${btoa(String.fromCharCode(...new Uint8Array(await subtle.exportKey('pkcs8', this.privateKey))))
                    .match(/.{1,64}/g)
                    .join("\n")}
-----END PRIVATE KEY-----`;
            let sshkey = sshpk.parsePrivateKey(openSSHPEM, "pem");
            if (type === "private") {
                return sshkey.toString();
            } else {

                sshkey.comment = comment;
                return sshkey.toPublic().toString("ssh");
            }
            return
        } else if (encoding) {
            return await subtle.exportKey(encoding, type === "private" ? this.privateKey : this.publicKey);
        }

    }

    async privateKeyHex(): Promise<string> {
        let jwkPrivateKey = await subtle.exportKey("jwk", this.privateKey);
        return base64URL.decode(jwkPrivateKey.d, "hex");
    }

    async publicKeyHex(): Promise<string> {
        let keyExt = await subtle.exportKey("jwk", this.privateKey);
        let { d, ...pubKeyExt } = keyExt;
        this.publicKey = await subtle.importKey("jwk", pubKeyExt, this.keyCurve, true, ["verify"])
        let publicKey = await subtle.exportKey("raw", this.publicKey);
        return keyconvert.toHex(publicKey);
    }

    public async import(privateKey: Buffer, encoding?: EncodingOptions): Promise<void>;
    public async import(privateKey: JsonWebKey): Promise<void>;
    public async import(privateKey: string, encoding?: EncodingOptions): Promise<void>;
    public async import(privateKey: any, encoding?: EncodingOptions): Promise<void> {

        let convert: Boolean = true;
        let importJWK: JsonWebKey;

        if (~["jwk", "pkcs8", "raw", "spki"].indexOf(encoding)) {
            this.privateKey = await subtle.importKey(encoding, privateKey, this.keyCurve, this.extractable, this.keyUsages);
            return;
        }

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
            importJWK = keyconvert.jwkConversion(privateKey, this.keyCurve, encoding);
        }

        this.privateKey = await subtle.importKey(
            "jwk",
            importJWK,
            this.keyCurve,
            this.extractable,
            this.keyUsages
        );
        return;
    }

    constructor(namedCurve: EcKeyGenParams, algorithm: AlgorithmIdentifier = EcAlgorithm, extractable: boolean = true, keyUsages?: Array<KeyUsageOptions>) {
        this.keyCurve = namedCurve;
        this.extractable = extractable;
        this.algorithm = algorithm;
        this.keyUsages = keyUsages || ["sign", "verify", "deriveKey", "deriveBits"];
    }
}