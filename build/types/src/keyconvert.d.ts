/// <reference types="node" />
import "./shims";
import { Buffer } from "buffer";
import PeerId from "peer-id";
/**

 * @type
 *
 * @description
 *
 *
 */
export declare type FormatOptions = KeyFormat | BufferEncoding | "wif" | "bip39" | "ssh" | "raw:private" | "ipfs:protobuf";
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
declare type KeyUsageOptions = "encrypt" | "decrypt" | "sign" | "verify" | "deriveKey" | "deriveBits" | "wrapKey" | "unwrapKey";
declare class keyconvert {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    keyCurve: EcKeyGenParams;
    extractable: boolean;
    algorithm: AlgorithmIdentifier;
    keyUsages: Array<KeyUsageOptions>;
    get secretKey(): CryptoKey;
    set secretKey(key: CryptoKey);
    /**
     * Converts hex format to an RFC7517 JSONWebKey
     * @link https://datatracker.ietf.org/doc/html/rfc7517
     * @param
     * @returns {JsonWebKey}
     */
    private static jwkConversion;
    private static toHex;
    private static exportFormatError;
    export(encoding: FormatOptions, type?: KeyType, comment?: string): Promise<JsonWebKey | ArrayBuffer | string>;
    privateKeyHex(): Promise<string>;
    publicKeyHex(): Promise<string>;
    ipfsPeerID(): Promise<PeerId>;
    ipnsCID(): Promise<String>;
    exportX509Certificate({ serialNumber, subject, issuer, notBefore, notAfter, signingAlgorithm, publicKey, signingKey, extensions, encoding }?: {
        serialNumber?: string;
        subject?: string;
        issuer?: string;
        notBefore?: Date;
        notAfter?: Date;
        signingAlgorithm?: Object;
        publicKey?: CryptoKey;
        signingKey?: CryptoKey;
        extensions?: any[];
        encoding?: string;
    }): Promise<string>;
    import(privateKey: Buffer | JsonWebKey | string | CryptoKey, encoding?: FormatOptions): Promise<void>;
    constructor(namedCurve: EcKeyGenParams, algorithm?: AlgorithmIdentifier, extractable?: boolean, keyUsages?: Array<KeyUsageOptions>);
}
declare const pubKeyToEthAddress: (pubPoint: string) => Promise<string>;
export { keyconvert, pubKeyToEthAddress };
