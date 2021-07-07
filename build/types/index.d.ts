/// <reference types="node" />
/**
 * @type
 *
 * @description
 *
 *
 */
declare type EncodingOptions = BufferEncoding | "wif" | "bip39" | "jwk" | "x509";
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
declare type NamedCurve = {
    name: string;
    namedCurve: string;
};
export declare class keyconvert {
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
    private static jwkConversion;
    private static toHex;
    export(encoding: EncodingOptions): Promise<string>;
    privateKeyHex(): Promise<string>;
    publicKeyHex(): Promise<string>;
    import(privateKey: Buffer): any;
    import(privateKey: JsonWebKey): any;
    import(privateKey: string, encoding?: EncodingOptions): any;
    constructor(namedCurve: NamedCurve, keyUsages?: Array<KeyUsageOptions>);
}
export {};
