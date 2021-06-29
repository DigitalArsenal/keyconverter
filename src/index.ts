export class keymaster {

    privateKey: CryptoKey;
    publicKey: CryptoKey;
    curve: NamedCurve;

    get bip39(): string {
        return ""
    }
    constructor(privateKey: Buffer);
    constructor(bip39: string);
    constructor(bip39: string);
    constructor(privateKey?: any, y?: any) {
        this.privateKey = privateKey;
    }
}

