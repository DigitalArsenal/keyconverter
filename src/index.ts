import base64URL from "base64url";

export class keymaster {

    privateKey: CryptoKey;
    publicKey: CryptoKey;
    curve: NamedCurve;
    jwk: JsonWebKey;

    private static jwkConversion(prvHex, namedCurve): JsonWebKey {
        return {
            kty: "EC",
            crv: namedCurve,
            d: base64URL.encode(prvHex, "hex"),
            x: null,
            y: null,
        }
    };

    get bip39(): string {
        return ""
    }
    constructor(curve: string, privateKey: Buffer);
    constructor(curve: string, privateKey: string, format: string);
    constructor(curve: string, bip39: string);
    constructor(curve: string, ...args: any[]) {
        if (args[0] instanceof Buffer) {
            let _jwk: JsonWebKey = keymaster.jwkConversion(args[0].toString('hex'), curve);
            console.log(_jwk);
        }
    }
}

