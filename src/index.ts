export class keymaster {

    privateKey: CryptoKey;
    publicKey: CryptoKey;
    curve: NamedCurve;

    get bip39(): string {
        return ""
    }
    constructor(privateKey: Buffer);
    constructor(privateKey: string, format: string);
    constructor(bip39: string);
    constructor(login: string, pass: string, pin: Number);
    constructor(privateKey?: any, y?: any) {
        this.privateKey = privateKey;
    }
}

