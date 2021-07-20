export class Crypto extends Crypto$1 {
    constructor(...args: any[]);
    get nativeCrypto(): any;
}
export class CryptoKey extends CryptoKey$1 {
    constructor(algorithm: any, extractable: any, type: any, usages: any);
}
export const crypto: Crypto;
export let nativeCrypto: any;
export let nativeSubtle: any;
export function setCrypto(crypto: any): void;
import { Crypto as Crypto$1 } from "webcrypto-core/build/types/crypto";
import { CryptoKey as CryptoKey$1 } from "webcrypto-core/build/types/key";
