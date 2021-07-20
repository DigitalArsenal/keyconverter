/// <reference types="node" />
/**

 * @type
 *
 * @description
 *
 *
 */
export declare type EncodingOptions = KeyFormat | BufferEncoding | "wif" | "bip39" | "ssh" | "x509";
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
export declare class keyconvert {
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
    private static jwkConversion;
    private static toHex;
    private static exportFormatError;
    export(encoding: EncodingOptions, type?: KeyType, comment?: string): Promise<JsonWebKey | ArrayBuffer | string>;
    privateKeyHex(): Promise<string>;
    publicKeyHex(): Promise<string>;
    import(privateKey: Buffer, encoding?: KeyFormat): Promise<void>;
    import(privateKey: JsonWebKey): Promise<void>;
    import(privateKey: string, encoding?: EncodingOptions): Promise<void>;
    constructor(namedCurve: EcKeyGenParams, algorithm?: AlgorithmIdentifier, extractable?: boolean, keyUsages?: Array<KeyUsageOptions>);
}
export {};
