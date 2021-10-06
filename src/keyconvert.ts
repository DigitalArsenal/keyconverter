
import base64URL from "base64url";
import * as liner from "../lib/webcrypto.liner.index.es";
import wif from "wif";
import * as x509 from "../lib/x509.es";
import sshpk from "sshpk";
import * as bip39 from "bip39";
import { Buffer } from 'buffer';
import * as bitcoinjs from "bitcoinjs-lib";
import elliptic, { eddsa } from "elliptic";
import createKeccakHash from 'keccak';
import { toChecksumAddress } from 'ethereum-checksum-address';

const { EcAlgorithm } = x509;
const { CryptoKey } = liner;

const { crypto: linerCrypto } = liner;

let { subtle } = linerCrypto;

/**

 * @type
 * 
 * @description
 * 
 * 
 */

export type FormatOptions = KeyFormat | BufferEncoding | "wif" | "bip39" | "ssh" | "raw:private";

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

type ExtendedCryptoKey = {
    data: any;
}

export class keyconvert {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    keyCurve: EcKeyGenParams;
    extractable: boolean;
    algorithm: AlgorithmIdentifier;
    keyUsages: Array<KeyUsageOptions>;

    public get secretKey(): CryptoKey {
        return this.privateKey;
    }
    public set secretKey(key: CryptoKey) {
        this.privateKey = key;
    }
    /**
     * Converts hex format to an RFC7517 JSONWebKey
     * @link https://datatracker.ietf.org/doc/html/rfc7517
     * @param
     * @returns {JsonWebKey}
     */
    private static jwkConversion(
        prvHex: string,
        curve: EcKeyGenParams,
        format: string = "hex",
        x?: string,
        y?: string,
    ): JsonWebKey {
        if (curve.namedCurve.toLowerCase() === "ed25519") {
            let ec = new elliptic.eddsa("ed25519");
            let key = ec.keyFromSecret(prvHex);
            let pubPoint: any = key.getPublic("hex");
            console.log(pubPoint)
            x = pubPoint.slice(0, 32);
            y = pubPoint.slice(32, 64);
            console.log(x,y)
        }
        return {
            kty: ~curve.namedCurve.indexOf("secp") ? "EC" : "OKP",
            crv: curve.namedCurve,
            d: base64URL(prvHex, format),
            x: base64URL(x, format),
            y: base64URL(y, format)
        };
    }

    private static toHex(buffer: any): string {
        return Buffer.from(buffer, "hex").toString("hex");
    }

    private static exportFormatError(encoding: string, type: KeyType): void {
        throw Error(`${encoding} format is not available for KeyType ${type}`);
    }

    async export(encoding: FormatOptions, type: KeyType = "public", comment?: string): Promise<JsonWebKey | ArrayBuffer | string> {
        if (this.privateKey === undefined) {
            throw Error("No Private Key");
        } else {
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
            } else if (~["ssh", "pkcs8"].indexOf(encoding)) {
                let _type = type === "public" ? "public" : "private";
                let tt = `${_type} key`;
                let xx = await subtle.exportKey("pkcs8", _type === "public" ? this.publicKey : this.privateKey,
                    tt
                );
                let pkcs8 = x509.PemConverter.encode(xx, tt);
                if (encoding === "pkcs8" && type !== "public") {
                    return pkcs8;
                } else if (this.keyCurve.namedCurve.toLowerCase() === "secp256k1") {
                    throw Error(`Cannot export ${this.keyCurve.namedCurve} as SSH Public Key.`)
                } else {
                    let sshkey = sshpk.parsePrivateKey(pkcs8, "pkcs8");
                    sshkey.comment = comment;
                    return sshkey.toPublic().toString("ssh");
                }
            } else if (encoding === "jwk") {
                let publicKey = await subtle.exportKey(encoding, this.publicKey);
                let privateKey = await subtle.exportKey(encoding, this.privateKey);
                return Object.assign(privateKey, publicKey);

            } else if (encoding) {
                return await subtle.exportKey(encoding, type === "private" ? this.privateKey : this.publicKey);
            }
        }
    }

    async privateKeyHex(): Promise<string> {
        if (this.privateKey === undefined) {
            throw Error("No Private Key");
        } else {
            let jwkPrivateKey = await subtle.exportKey("jwk", this.privateKey);
            return base64URL.decode(jwkPrivateKey.d, "hex");
        }
    }

    async publicKeyHex(): Promise<string> {
        if (this.privateKey === undefined) {
            throw Error("No Private Key");
        } else {
            return (this.publicKey as unknown as ExtendedCryptoKey).data.getPublic("hex");

        }
    }

    async bitcoinAddress(): Promise<string> {

        const bjsKeyPair = bitcoinjs.ECPair.fromWIF((await this.export("wif", "private")).toString());
        const { address } = bitcoinjs.payments.p2pkh({
            pubkey: bjsKeyPair.publicKey,
        });
        return address;
    }
    async ethereumAddress(): Promise<string> {
        let ec = new elliptic.ec("secp256k1");
        let key = ec.keyFromPrivate(await this.privateKeyHex());
        let pubPoint: any = key.getPublic("hex");
        let keccakHex = createKeccakHash('keccak256').update(Buffer.from(pubPoint.slice(2), "hex")).digest('hex');
        return toChecksumAddress(`${keccakHex.substring(keccakHex.length - 40, keccakHex.length).toUpperCase()}`);
    }
    public async exportX509Certificate({
        serialNumber = `${Date.now()} `,
        subject = `CN = localhost`,
        issuer = `BTC`,
        notBefore = new Date("2020/01/01"),
        notAfter = new Date("2022/01/02"),
        signingAlgorithm = null,
        publicKey = this.publicKey,
        signingKey = this.privateKey,
        extensions = null,
        encoding = "pem"
    }: {
        serialNumber?: string,
        subject?: string,
        issuer?: string,
        notBefore?: Date,
        notAfter?: Date,
        signingAlgorithm?: Object,
        publicKey?: CryptoKey,
        signingKey?: CryptoKey,
        extensions?: any[],
        encoding?: string
    } = {}): Promise<string> {

        x509.cryptoProvider.set(liner.crypto);

        let { digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment } = x509.KeyUsageFlags;

        if (!extensions) {
            extensions =
                [
                    new x509.BasicConstraintsExtension(true, 2, true),
                    await x509.SubjectKeyIdentifierExtension.create(this.publicKey),
                    await x509.AuthorityKeyIdentifierExtension.create(this.publicKey),
                    new x509.KeyUsagesExtension(digitalSignature | nonRepudiation | keyEncipherment | dataEncipherment, true)
                ];
        };

        const cert = x509.X509CertificateGenerator.create({
            serialNumber,
            subject,
            issuer,
            notBefore,
            notAfter,
            signingAlgorithm,
            publicKey,
            signingKey,
            extensions,
        });

        return (await cert).toString(encoding);
    }

    public async import(privateKey: Buffer, encoding?: FormatOptions): Promise<void>;
    public async import(privateKey: JsonWebKey): Promise<void>;
    public async import(privateKey: string, encoding?: FormatOptions): Promise<void>;
    public async import(privateKey: CryptoKey): Promise<void>;
    public async import(privateKey: any, encoding?: FormatOptions): Promise<void> {

        let convert: Boolean = true;
        let importJWK: JsonWebKey;

        this.privateKey = undefined;

        if (privateKey instanceof CryptoKey) {
            this.privateKey = privateKey;
        } else {
            if (~["raw", "raw:private", undefined].indexOf(encoding)) {
                convert = true;
            } else {
                if (typeof privateKey === "string") {
                    if (privateKey.match(/\-{5}BEGIN.*PRIVATE KEY/g)) {
                        let pp = x509.PemConverter.decode(privateKey);
                        this.privateKey = await subtle.importKey("pkcs8", pp[0], this.keyCurve, this.extractable, this.keyUsages);
                    } else if (encoding === "bip39") {
                        privateKey = bip39.mnemonicToEntropy(privateKey);
                    } else if (encoding === "wif") {
                        const decodedWif = wif.decode(privateKey);
                        privateKey = keyconvert.toHex(decodedWif.privateKey);
                        encoding = "hex";
                    } else if (!encoding) {
                        throw Error(`Unknown Private Key Encoding: ${encoding} `);
                    }
                } else if ((privateKey as JsonWebKey).d) {
                    this.privateKey = await subtle.importKey(
                        "jwk",
                        Object.assign({}, privateKey),
                        this.keyCurve,
                        this.extractable,
                        this.keyUsages
                    );
                } else if (!(privateKey instanceof Buffer)) {
                    throw Error(`Unknown Input: ${privateKey} `);
                }
            }

            if (!this.privateKey) {
                let jwk = keyconvert.jwkConversion(privateKey, this.keyCurve, "hex");
                this.privateKey = subtle.importKey("jwk",
                    jwk,
                    this.keyCurve,
                    this.extractable,
                    this.keyUsages)
            }
            let importJWK = await subtle.exportKey("jwk", this.privateKey);
            if (!importJWK.x) {
                let jwk = keyconvert.jwkConversion(importJWK.d, this.keyCurve, "hex");
                delete jwk.d;
                importJWK = jwk;
            }
            console.log(this.keyCurve.namedCurve, importJWK);
            this.publicKey = await subtle.importKey("jwk",
                importJWK,
                this.keyCurve,
                this.extractable,
                this.keyUsages);
        }

        return;
    }

    constructor(namedCurve: EcKeyGenParams, algorithm: AlgorithmIdentifier = EcAlgorithm, extractable: boolean = true, keyUsages?: Array<KeyUsageOptions>) {
        this.keyCurve = namedCurve;
        this.extractable = extractable;
        this.algorithm = algorithm;
        this.keyUsages = keyUsages || ["sign", "verify", "deriveKey", "deriveBits"];
    }
}