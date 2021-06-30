/// <reference types="node" />
export declare class keymaster {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    curve: NamedCurve;
    keyUsages: Array<string>;
    private static jwkConversion;
    get bip39(): string;
    init(privateKey: Buffer): any;
    init(bip39: string): any;
    init(privateKey: string, format: string): any;
    constructor(namedCurve: NamedCurve);
}
