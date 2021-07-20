/**
 * Copyright (c) 2021, Peculiar Ventures, LLC.
 */

import { CryptoKey as CryptoKey$1, AlgorithmError, BufferSourceConverter, OperationError, isJWK, AesCbcProvider as AesCbcProvider$1, AesEcbProvider as AesEcbProvider$1, AesGcmProvider as AesGcmProvider$1, AesCtrProvider as AesCtrProvider$1, AesKwProvider as AesKwProvider$1, asn1, RsaOaepProvider as RsaOaepProvider$1, RsaPssProvider as RsaPssProvider$1, RsaSsaProvider as RsaSsaProvider$1, ProviderCrypto, CryptoError, EcdhProvider as EcdhProvider$1, EcdsaProvider as EcdsaProvider$1, EdDsaProvider as EdDsaProvider$1, Pbkdf2Provider as Pbkdf2Provider$1, DesProvider, HmacProvider as HmacProvider$1, SubtleCrypto as SubtleCrypto$1, Crypto as Crypto$1 } from 'webcrypto-core';
import { __awaiter, __decorate, __classPrivateFieldSet, __classPrivateFieldGet } from 'tslib';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import { JsonParser, JsonSerializer, JsonProp, JsonPropTypes } from '@peculiar/json-schema';
import { Convert, BufferSourceConverter as BufferSourceConverter$1 } from 'pvtsutils';
import { AES_CBC, AES_GCM, AES_ECB, AES_CTR, Sha512, Sha256, Sha1, RSA_OAEP, RSA_PSS, RSA_PKCS1_v1_5, RSA, BigNumber, Pbkdf2HmacSha512, Pbkdf2HmacSha256, Pbkdf2HmacSha1, HmacSha512, HmacSha256, HmacSha1 } from 'asmcrypto.js';
import * as elliptic from 'elliptic';
import { ec, eddsa } from 'elliptic';
import * as des from 'des.js';
import { CBC, EDE, DES } from 'des.js';

let NodeJSWebCrypto = null;
if (typeof process !== 'undefined' && process.version) {
    const { webcrypto } = require('crypto');
    NodeJSWebCrypto = webcrypto;
}
let window = {};
if (typeof self !== "undefined") {
    window = self;
}
let nativeCrypto = window["msCrypto"]
    || window.crypto
    || NodeJSWebCrypto
    || {};
let nativeSubtle = null;
try {
    nativeSubtle = (nativeCrypto === null || nativeCrypto === void 0 ? void 0 : nativeCrypto.subtle) || (nativeCrypto === null || nativeCrypto === void 0 ? void 0 : nativeCrypto["webkitSubtle"]) || null;
}
catch (err) {
    console.warn("Cannot get subtle from crypto", err);
}
function setCrypto(crypto) {
    nativeCrypto = crypto;
    nativeSubtle = crypto.subtle;
}

class Debug {
    static get enabled() {
        return typeof self !== "undefined" && self.PV_WEBCRYPTO_LINER_LOG;
    }
    static log(...args) {
        if (this.enabled) {
            console.log.apply(console, args);
        }
    }
    static error(...args) {
        if (this.enabled) {
            console.error.apply(console, args);
        }
    }
    static info(...args) {
        if (this.enabled) {
            console.info.apply(console, args);
        }
    }
    static warn(...args) {
        if (this.enabled) {
            console.warn.apply(console, args);
        }
    }
    static trace(...args) {
        if (this.enabled) {
            console.trace.apply(console, args);
        }
    }
}

var Browser;
(function (Browser) {
    Browser["Unknown"] = "Unknown";
    Browser["IE"] = "Internet Explorer";
    Browser["Safari"] = "Safari";
    Browser["Edge"] = "Edge";
    Browser["Chrome"] = "Chrome";
    Browser["Firefox"] = "Firefox Mozilla";
    Browser["Mobile"] = "Mobile";
})(Browser || (Browser = {}));
function BrowserInfo() {
    const res = {
        name: Browser.Unknown,
        version: "0",
    };
    if (typeof self === "undefined") {
        return res;
    }
    const userAgent = self.navigator.userAgent;
    let reg;
    if (reg = /edge\/([\d\.]+)/i.exec(userAgent)) {
        res.name = Browser.Edge;
        res.version = reg[1];
    }
    else if (/msie/i.test(userAgent)) {
        res.name = Browser.IE;
        res.version = /msie ([\d\.]+)/i.exec(userAgent)[1];
    }
    else if (/Trident/i.test(userAgent)) {
        res.name = Browser.IE;
        res.version = /rv:([\d\.]+)/i.exec(userAgent)[1];
    }
    else if (/chrome/i.test(userAgent)) {
        res.name = Browser.Chrome;
        res.version = /chrome\/([\d\.]+)/i.exec(userAgent)[1];
    }
    else if (/firefox/i.test(userAgent)) {
        res.name = Browser.Firefox;
        res.version = /firefox\/([\d\.]+)/i.exec(userAgent)[1];
    }
    else if (/mobile/i.test(userAgent)) {
        res.name = Browser.Mobile;
        res.version = /mobile\/([\w]+)/i.exec(userAgent)[1];
    }
    else if (/safari/i.test(userAgent)) {
        res.name = Browser.Safari;
        res.version = /version\/([\d\.]+)/i.exec(userAgent)[1];
    }
    return res;
}
function concat(...buf) {
    const res = new Uint8Array(buf.map((item) => item.length).reduce((prev, cur) => prev + cur));
    let offset = 0;
    buf.forEach((item, index) => {
        for (let i = 0; i < item.length; i++) {
            res[offset + i] = item[i];
        }
        offset += item.length;
    });
    return res;
}

class CryptoKey extends CryptoKey$1 {
    constructor(algorithm, extractable, type, usages) {
        super();
        this.extractable = extractable;
        this.type = type;
        this.usages = usages;
        this.algorithm = Object.assign({}, algorithm);
    }
}

function isAlgorithm(algorithm, name) {
    return algorithm.name.toUpperCase() === name.toUpperCase();
}

class AesCryptoKey extends CryptoKey {
    constructor(algorithm, extractable, usages, raw) {
        super(algorithm, extractable, "secret", usages);
        this.raw = raw;
    }
    toJSON() {
        const jwk = {
            kty: "oct",
            alg: this.getJwkAlgorithm(),
            k: Convert.ToBase64Url(this.raw),
            ext: this.extractable,
            key_ops: this.usages,
        };
        return jwk;
    }
    getJwkAlgorithm() {
        switch (this.algorithm.name.toUpperCase()) {
            case "AES-CBC":
                return `A${this.algorithm.length}CBC`;
            case "AES-CTR":
                return `A${this.algorithm.length}CTR`;
            case "AES-GCM":
                return `A${this.algorithm.length}GCM`;
            case "AES-ECB":
                return `A${this.algorithm.length}ECB`;
            default:
                throw new AlgorithmError("Unsupported algorithm name");
        }
    }
}

class AesCrypto {
    static checkCryptoKey(key) {
        if (!(key instanceof AesCryptoKey)) {
            throw new TypeError("key: Is not AesCryptoKey");
        }
    }
    static generateKey(algorithm, extractable, usages) {
        return __awaiter(this, void 0, void 0, function* () {
            const raw = nativeCrypto.getRandomValues(new Uint8Array(algorithm.length / 8));
            return new AesCryptoKey(algorithm, extractable, usages, raw);
        });
    }
    static encrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.cipher(algorithm, key, BufferSourceConverter.toUint8Array(data), true);
        });
    }
    static decrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.cipher(algorithm, key, BufferSourceConverter.toUint8Array(data), false);
        });
    }
    static exportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            switch (format) {
                case "jwk":
                    return key.toJSON();
                case "raw":
                    return key.raw.buffer;
                default:
                    throw new OperationError("format: Must be 'jwk' or 'raw'");
            }
        });
    }
    static importKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            let raw;
            if (isJWK(keyData)) {
                raw = Convert.FromBase64Url(keyData.k);
            }
            else {
                raw = BufferSourceConverter.toArrayBuffer(keyData);
            }
            switch (raw.byteLength << 3) {
                case 128:
                case 192:
                case 256:
                    break;
                default:
                    throw new OperationError("keyData: Is wrong key length");
            }
            const key = new AesCryptoKey({ name: algorithm.name, length: raw.byteLength << 3 }, extractable, keyUsages, new Uint8Array(raw));
            return key;
        });
    }
    static cipher(algorithm, key, data, encrypt) {
        return __awaiter(this, void 0, void 0, function* () {
            const action = encrypt ? "encrypt" : "decrypt";
            let result;
            if (isAlgorithm(algorithm, AesCrypto.AesCBC)) {
                const iv = BufferSourceConverter.toUint8Array(algorithm.iv);
                result = AES_CBC[action](data, key.raw, undefined, iv);
            }
            else if (isAlgorithm(algorithm, AesCrypto.AesGCM)) {
                const iv = BufferSourceConverter.toUint8Array(algorithm.iv);
                let additionalData;
                if (algorithm.additionalData) {
                    additionalData = BufferSourceConverter.toArrayBuffer(algorithm.additionalData);
                }
                const tagLength = (algorithm.tagLength || 128) / 8;
                result = AES_GCM[action](data, key.raw, iv, additionalData, tagLength);
            }
            else if (isAlgorithm(algorithm, AesCrypto.AesECB)) {
                result = AES_ECB[action](data, key.raw, true);
            }
            else {
                throw new OperationError(`algorithm: Is not recognized`);
            }
            return BufferSourceConverter.toArrayBuffer(result);
        });
    }
}
AesCrypto.AesCBC = "AES-CBC";
AesCrypto.AesECB = "AES-ECB";
AesCrypto.AesGCM = "AES-GCM";

class AesCbcProvider extends AesCbcProvider$1 {
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onEncrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.encrypt(algorithm, key, data);
        });
    }
    onDecrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.decrypt(algorithm, key, data);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        AesCrypto.checkCryptoKey(key);
    }
}

class AesEcbProvider extends AesEcbProvider$1 {
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onEncrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.encrypt(algorithm, key, data);
        });
    }
    onDecrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.decrypt(algorithm, key, data);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        AesCrypto.checkCryptoKey(key);
    }
}

class AesGcmProvider extends AesGcmProvider$1 {
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onEncrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.encrypt(algorithm, key, data);
        });
    }
    onDecrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.decrypt(algorithm, key, data);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        AesCrypto.checkCryptoKey(key);
    }
}

class AesCtrProvider extends AesCtrProvider$1 {
    onEncrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = new AES_CTR(key.raw, BufferSourceConverter.toUint8Array(algorithm.counter))
                .encrypt(BufferSourceConverter.toUint8Array(data));
            return BufferSourceConverter.toArrayBuffer(result);
        });
    }
    onDecrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = new AES_CTR(key.raw, BufferSourceConverter.toUint8Array(algorithm.counter))
                .decrypt(BufferSourceConverter.toUint8Array(data));
            return BufferSourceConverter.toArrayBuffer(result);
        });
    }
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return AesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        AesCrypto.checkCryptoKey(key);
    }
}

class AesKwProvider extends AesKwProvider$1 {
    onEncrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error("Method not implemented.");
        });
    }
    onDecrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error("Method not implemented.");
        });
    }
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error("Method not implemented.");
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error("Method not implemented.");
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error("Method not implemented.");
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        AesCrypto.checkCryptoKey(key);
    }
}

class RsaCryptoKey extends CryptoKey {
    constructor(algorithm, extractable, type, usages, data) {
        super(algorithm, extractable, type, usages);
        this.data = data;
    }
}

class RsaCrypto {
    static checkCryptoKey(key) {
        if (!(key instanceof RsaCryptoKey)) {
            throw new TypeError("key: Is not RsaCryptoKey");
        }
    }
    static generateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            const alg = {
                name: "RSA-PSS",
                hash: "SHA-256",
                publicExponent: algorithm.publicExponent,
                modulusLength: algorithm.modulusLength,
            };
            const keys = (yield nativeSubtle.generateKey(alg, true, ["sign", "verify"]));
            const crypto = new Crypto();
            const pkcs8 = yield crypto.subtle.exportKey("pkcs8", keys.privateKey);
            const privateKey = yield crypto.subtle.importKey("pkcs8", pkcs8, algorithm, extractable, keyUsages.filter((o) => this.privateUsages.includes(o)));
            const spki = yield crypto.subtle.exportKey("spki", keys.publicKey);
            const publicKey = yield crypto.subtle.importKey("spki", spki, algorithm, true, keyUsages.filter((o) => this.publicUsages.includes(o)));
            return { privateKey, publicKey };
        });
    }
    static exportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            switch (format) {
                case "pkcs8":
                    return this.exportPkcs8Key(key);
                case "spki":
                    return this.exportSpkiKey(key);
                case "jwk":
                    return this.exportJwkKey(key);
                default:
                    throw new OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
            }
        });
    }
    static importKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            let asmKey;
            switch (format) {
                case "pkcs8":
                    asmKey = this.importPkcs8Key(keyData);
                    break;
                case "spki":
                    asmKey = this.importSpkiKey(keyData);
                    break;
                case "jwk":
                    asmKey = this.importJwkKey(keyData);
                    break;
                default:
                    throw new OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
            }
            const key = new RsaCryptoKey(Object.assign({
                publicExponent: asmKey[1][1] === 1
                    ? asmKey[1].slice(1)
                    : asmKey[1].slice(3), modulusLength: asmKey[0].byteLength << 3
            }, algorithm), extractable, asmKey.length === 2 ? "public" : "private", keyUsages, asmKey);
            return key;
        });
    }
    static randomNonZeroValues(data) {
        data = nativeCrypto.getRandomValues(data);
        return data.map((n) => {
            while (!n) {
                n = nativeCrypto.getRandomValues(new Uint8Array(1))[0];
            }
            return n;
        });
    }
    static exportPkcs8Key(key) {
        const keyInfo = new asn1.PrivateKeyInfo();
        keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
        keyInfo.privateKeyAlgorithm.parameters = null;
        keyInfo.privateKey = AsnConvert.serialize(this.exportAsmKey(key.data));
        return AsnConvert.serialize(keyInfo);
    }
    static importPkcs8Key(data) {
        const keyInfo = AsnConvert.parse(data, asn1.PrivateKeyInfo);
        const privateKey = AsnConvert.parse(keyInfo.privateKey, asn1.RsaPrivateKey);
        return this.importAsmKey(privateKey);
    }
    static importSpkiKey(data) {
        const keyInfo = AsnConvert.parse(data, asn1.PublicKeyInfo);
        const publicKey = AsnConvert.parse(keyInfo.publicKey, asn1.RsaPublicKey);
        return this.importAsmKey(publicKey);
    }
    static exportSpkiKey(key) {
        const publicKey = new asn1.RsaPublicKey();
        publicKey.modulus = key.data[0].buffer;
        publicKey.publicExponent = key.data[1][1] === 1
            ? key.data[1].buffer.slice(1)
            : key.data[1].buffer.slice(3);
        const keyInfo = new asn1.PublicKeyInfo();
        keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
        keyInfo.publicKeyAlgorithm.parameters = null;
        keyInfo.publicKey = AsnConvert.serialize(publicKey);
        return AsnConvert.serialize(keyInfo);
    }
    static importJwkKey(data) {
        let key;
        if (data.d) {
            key = JsonParser.fromJSON(data, { targetSchema: asn1.RsaPrivateKey });
        }
        else {
            key = JsonParser.fromJSON(data, { targetSchema: asn1.RsaPublicKey });
        }
        return this.importAsmKey(key);
    }
    static exportJwkKey(key) {
        const asnKey = this.exportAsmKey(key.data);
        const jwk = JsonSerializer.toJSON(asnKey);
        jwk.ext = true;
        jwk.key_ops = key.usages;
        jwk.kty = "RSA";
        jwk.alg = this.getJwkAlgorithm(key.algorithm);
        return jwk;
    }
    static getJwkAlgorithm(algorithm) {
        switch (algorithm.name.toUpperCase()) {
            case "RSA-OAEP":
                const mdSize = /(\d+)$/.exec(algorithm.hash.name)[1];
                return `RSA-OAEP${mdSize !== "1" ? `-${mdSize}` : ""}`;
            case "RSASSA-PKCS1-V1_5":
                return `RS${/(\d+)$/.exec(algorithm.hash.name)[1]}`;
            case "RSA-PSS":
                return `PS${/(\d+)$/.exec(algorithm.hash.name)[1]}`;
            case "RSAES-PKCS1-V1_5":
                return `PS1`;
            default:
                throw new OperationError("algorithm: Is not recognized");
        }
    }
    static exportAsmKey(asmKey) {
        let key;
        if (asmKey.length > 2) {
            const privateKey = new asn1.RsaPrivateKey();
            privateKey.privateExponent = asmKey[2].buffer;
            privateKey.prime1 = asmKey[3].buffer;
            privateKey.prime2 = asmKey[4].buffer;
            privateKey.exponent1 = asmKey[5].buffer;
            privateKey.exponent2 = asmKey[6].buffer;
            privateKey.coefficient = asmKey[7].buffer;
            key = privateKey;
        }
        else {
            key = new asn1.RsaPublicKey();
        }
        key.modulus = asmKey[0].buffer;
        key.publicExponent = asmKey[1][1] === 1
            ? asmKey[1].buffer.slice(1)
            : asmKey[1].buffer.slice(3);
        return key;
    }
    static importAsmKey(key) {
        const expPadding = new Uint8Array(4 - key.publicExponent.byteLength);
        const asmKey = [
            new Uint8Array(key.modulus),
            concat(expPadding, new Uint8Array(key.publicExponent)),
        ];
        if (key instanceof asn1.RsaPrivateKey) {
            asmKey.push(new Uint8Array(key.privateExponent));
            asmKey.push(new Uint8Array(key.prime1));
            asmKey.push(new Uint8Array(key.prime2));
            asmKey.push(new Uint8Array(key.exponent1));
            asmKey.push(new Uint8Array(key.exponent2));
            asmKey.push(new Uint8Array(key.coefficient));
        }
        return asmKey;
    }
}
RsaCrypto.RsaSsa = "RSASSA-PKCS1-v1_5";
RsaCrypto.RsaPss = "RSA-PSS";
RsaCrypto.RsaOaep = "RSA-OAEP";
RsaCrypto.privateUsages = ["sign", "decrypt", "unwrapKey"];
RsaCrypto.publicUsages = ["verify", "encrypt", "wrapKey"];

class ShaCrypto {
    static getDigest(name) {
        switch (name) {
            case "SHA-1":
                return new Sha1();
            case "SHA-256":
                return new Sha256();
            case "SHA-512":
                return new Sha512();
            default:
                throw new AlgorithmError("keyAlgorithm.hash: Is not recognized");
        }
    }
    static digest(algorithm, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const mech = this.getDigest(algorithm.name);
            const result = mech
                .process(BufferSourceConverter.toUint8Array(data))
                .finish().result;
            return BufferSourceConverter.toArrayBuffer(result);
        });
    }
}

class RsaOaepProvider extends RsaOaepProvider$1 {
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    onEncrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.cipher(algorithm, key, data);
        });
    }
    onDecrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.cipher(algorithm, key, data);
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        RsaCrypto.checkCryptoKey(key);
    }
    cipher(algorithm, key, data) {
        const digest = ShaCrypto.getDigest(key.algorithm.hash.name);
        let label;
        if (algorithm.label) {
            label = BufferSourceConverter.toUint8Array(algorithm.label);
        }
        const cipher = new RSA_OAEP(key.data, digest, label);
        let res;
        const u8Data = BufferSourceConverter.toUint8Array(data);
        if (key.type === "public") {
            res = cipher.encrypt(u8Data);
        }
        else {
            res = cipher.decrypt(u8Data);
        }
        return BufferSourceConverter.toArrayBuffer(res);
    }
}

class RsaPssProvider extends RsaPssProvider$1 {
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    onSign(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const rsa = new RSA_PSS(key.data, ShaCrypto.getDigest(key.algorithm.hash.name), algorithm.saltLength);
            const result = rsa.sign(BufferSourceConverter.toUint8Array(data));
            return BufferSourceConverter.toArrayBuffer(result);
        });
    }
    onVerify(algorithm, key, signature, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const rsa = new RSA_PSS(key.data, ShaCrypto.getDigest(key.algorithm.hash.name), algorithm.saltLength);
            try {
                rsa.verify(BufferSourceConverter.toUint8Array(signature), BufferSourceConverter.toUint8Array(data));
            }
            catch (_a) {
                return false;
            }
            return true;
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        RsaCrypto.checkCryptoKey(key);
    }
}

class RsaSsaProvider extends RsaSsaProvider$1 {
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    onSign(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const rsa = new RSA_PKCS1_v1_5(key.data, ShaCrypto.getDigest(key.algorithm.hash.name));
            const result = rsa.sign(BufferSourceConverter.toUint8Array(data));
            return BufferSourceConverter.toArrayBuffer(result);
        });
    }
    onVerify(algorithm, key, signature, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const rsa = new RSA_PKCS1_v1_5(key.data, ShaCrypto.getDigest(key.algorithm.hash.name));
            try {
                rsa.verify(BufferSourceConverter.toUint8Array(signature), BufferSourceConverter.toUint8Array(data));
            }
            catch (_a) {
                return false;
            }
            return true;
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        RsaCrypto.checkCryptoKey(key);
    }
}

class RsaEsProvider extends ProviderCrypto {
    constructor() {
        super(...arguments);
        this.name = "RSAES-PKCS1-v1_5";
        this.usages = {
            publicKey: ["encrypt", "wrapKey"],
            privateKey: ["decrypt", "unwrapKey"],
        };
        this.hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
    }
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    checkGenerateKeyParams(algorithm) {
        this.checkRequiredProperty(algorithm, "publicExponent");
        if (!(algorithm.publicExponent && algorithm.publicExponent instanceof Uint8Array)) {
            throw new TypeError("publicExponent: Missing or not a Uint8Array");
        }
        const publicExponent = Convert.ToBase64(algorithm.publicExponent);
        if (!(publicExponent === "Aw==" || publicExponent === "AQAB")) {
            throw new TypeError("publicExponent: Must be [3] or [1,0,1]");
        }
        this.checkRequiredProperty(algorithm, "modulusLength");
        switch (algorithm.modulusLength) {
            case 1024:
            case 2048:
            case 4096:
                break;
            default:
                throw new TypeError("modulusLength: Must be 1024, 2048, or 4096");
        }
    }
    onDecrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const EM = new RSA(key.data).decrypt(new BigNumber(BufferSourceConverter.toUint8Array(data))).result;
            const k = key.algorithm.modulusLength >> 3;
            if (data.byteLength !== k) {
                throw new CryptoError("Decryption error. Encrypted message size doesn't match to key length");
            }
            let offset = 0;
            if (EM[offset++] || EM[offset++] !== 2) {
                throw new CryptoError("Decryption error");
            }
            do {
                if (EM[offset++] === 0) {
                    break;
                }
            } while (offset < EM.length);
            if (offset < 11) {
                throw new CryptoError("Decryption error. PS is less than 8 octets.");
            }
            if (offset === EM.length) {
                throw new CryptoError("Decryption error. There is no octet with hexadecimal value 0x00 to separate PS from M");
            }
            return EM.buffer.slice(offset);
        });
    }
    onEncrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const k = key.algorithm.modulusLength >> 3;
            if (data.byteLength > k - 11) {
                throw new CryptoError("Message too long");
            }
            const psLen = k - data.byteLength - 3;
            const PS = RsaCrypto.randomNonZeroValues(new Uint8Array(psLen));
            const EM = new Uint8Array(k);
            EM[0] = 0;
            EM[1] = 2;
            EM.set(PS, 2);
            EM[2 + psLen] = 0;
            EM.set(new Uint8Array(data), 3 + psLen);
            const result = new RSA(key.data).encrypt(new BigNumber(EM)).result;
            return BufferSourceConverter.toArrayBuffer(result);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return RsaCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield RsaCrypto.importKey(format, keyData, Object.assign(Object.assign({}, algorithm), { name: this.name }), extractable, keyUsages);
            return key;
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        RsaCrypto.checkCryptoKey(key);
    }
    prepareSignData(algorithm, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const crypto = new Crypto();
            return crypto.subtle.digest(algorithm.hash, data);
        });
    }
}

const namedOIDs = {
    "1.2.840.10045.3.1.7": "P-256",
    "P-256": "1.2.840.10045.3.1.7",
    "1.3.132.0.34": "P-384",
    "P-384": "1.3.132.0.34",
    "1.3.132.0.35": "P-521",
    "P-521": "1.3.132.0.35",
    "1.3.132.0.10": "K-256",
    "K-256": "1.3.132.0.10",
};
function getOidByNamedCurve(namedCurve) {
    const oid = namedOIDs[namedCurve];
    if (!oid) {
        throw new OperationError(`Cannot convert WebCrypto named curve '${namedCurve}' to OID`);
    }
    return oid;
}

class EcCryptoKey extends CryptoKey {
    constructor(algorithm, extractable, type, usages, data) {
        super(algorithm, extractable, type, usages);
        this.data = data;
    }
}

class EcCrypto {
    static checkLib() {
        if (typeof (elliptic) === "undefined") {
            throw new OperationError("Cannot implement EC mechanism. Add 'https://peculiarventures.github.io/pv-webcrypto-tests/src/elliptic.js' script to your project");
        }
    }
    static generateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            const key = this.initEcKey(algorithm.namedCurve);
            const ecKey = key.genKeyPair();
            ecKey.getPublic();
            const prvKey = new EcCryptoKey(Object.assign({}, algorithm), extractable, "private", keyUsages.filter((usage) => ~this.privateUsages.indexOf(usage)), ecKey);
            const pubKey = new EcCryptoKey(Object.assign({}, algorithm), true, "public", keyUsages.filter((usage) => ~this.publicUsages.indexOf(usage)), ecKey);
            return {
                privateKey: prvKey,
                publicKey: pubKey,
            };
        });
    }
    static checkCryptoKey(key) {
        if (!(key instanceof EcCryptoKey)) {
            throw new TypeError("key: Is not EcCryptoKey");
        }
    }
    static concat(...buf) {
        const res = new Uint8Array(buf.map((item) => item.length).reduce((prev, cur) => prev + cur));
        let offset = 0;
        buf.forEach((item, index) => {
            for (let i = 0; i < item.length; i++) {
                res[offset + i] = item[i];
            }
            offset += item.length;
        });
        return res;
    }
    static exportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            switch (format) {
                case "pkcs8":
                    return this.exportPkcs8Key(key);
                case "spki":
                    return this.exportSpkiKey(key);
                case "jwk":
                    return this.exportJwkKey(key);
                case "raw":
                    return new Uint8Array(key.data.getPublic("der")).buffer;
                default:
                    throw new OperationError("format: Must be 'jwk', 'raw, 'pkcs8' or 'spki'");
            }
        });
    }
    static importKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            let ecKey;
            switch (format) {
                case "pkcs8":
                    ecKey = this.importPkcs8Key(keyData, algorithm.namedCurve);
                    break;
                case "spki":
                    ecKey = this.importSpkiKey(keyData, algorithm.namedCurve);
                    break;
                case "raw":
                    let pK = new asn1.EcPrivateKey(keyData);
                    pK.privateKey = keyData;
                    ecKey = this.importEcKey(pK, algorithm.namedCurve);
                    break;
                case "jwk":
                    ecKey = this.importJwkKey(keyData);
                    break;
                default:
                    throw new OperationError("format: Must be 'jwk', 'raw', 'pkcs8' or 'spki'");
            }
            const key = new EcCryptoKey(Object.assign({}, algorithm), extractable, ecKey.priv ? "private" : "public", keyUsages, ecKey);
            return key;
        });
    }
    static getNamedCurve(wcNamedCurve) {
        const crv = wcNamedCurve.toUpperCase();
        let res = "";
        if (["P-256", "P-384", "P-521"].indexOf(crv) > -1) {
            res = crv.replace("-", "").toLowerCase();
        }
        else if (crv === "K-256") {
            res = "secp256k1";
        }
        else {
            throw new OperationError(`Unsupported named curve '${wcNamedCurve}'`);
        }
        return res;
    }
    static initEcKey(namedCurve) {
        return ec(this.getNamedCurve(namedCurve));
    }
    static exportPkcs8Key(key) {
        const keyInfo = new asn1.PrivateKeyInfo();
        keyInfo.privateKeyAlgorithm.algorithm = this.ASN_ALGORITHM;
        keyInfo.privateKeyAlgorithm.parameters = AsnConvert.serialize(new asn1.ObjectIdentifier(getOidByNamedCurve(key.algorithm.namedCurve)));
        keyInfo.privateKey = AsnConvert.serialize(this.exportEcKey(key));
        return AsnConvert.serialize(keyInfo);
    }
    static importPkcs8Key(data, namedCurve) {
        const keyInfo = AsnConvert.parse(data, asn1.PrivateKeyInfo);
        const privateKey = AsnConvert.parse(keyInfo.privateKey, asn1.EcPrivateKey);
        return this.importEcKey(privateKey, namedCurve);
    }
    static importSpkiKey(data, namedCurve) {
        const keyInfo = AsnConvert.parse(data, asn1.PublicKeyInfo);
        const publicKey = new asn1.EcPublicKey(keyInfo.publicKey);
        return this.importEcKey(publicKey, namedCurve);
    }
    static exportSpkiKey(key) {
        const publicKey = new asn1.EcPublicKey(new Uint8Array(key.data.getPublic("der")).buffer);
        const keyInfo = new asn1.PublicKeyInfo();
        keyInfo.publicKeyAlgorithm.algorithm = this.ASN_ALGORITHM;
        keyInfo.publicKeyAlgorithm.parameters = AsnConvert.serialize(new asn1.ObjectIdentifier(getOidByNamedCurve(key.algorithm.namedCurve)));
        keyInfo.publicKey = publicKey.value;
        return AsnConvert.serialize(keyInfo);
    }
    static importJwkKey(data) {
        let key;
        if (data.d) {
            key = JsonParser.fromJSON(data, { targetSchema: asn1.EcPrivateKey });
        }
        else {
            key = JsonParser.fromJSON(data, { targetSchema: asn1.EcPublicKey });
        }
        return this.importEcKey(key, data.crv);
    }
    static exportJwkKey(key) {
        const asnKey = this.exportEcKey(key);
        const jwk = JsonSerializer.toJSON(asnKey);
        jwk.ext = true;
        jwk.key_ops = key.usages;
        jwk.crv = key.algorithm.namedCurve;
        jwk.kty = "EC";
        return jwk;
    }
    static exportEcKey(ecKey) {
        if (ecKey.type === "private") {
            const privateKey = new asn1.EcPrivateKey();
            const point = new Uint8Array(ecKey.data.getPrivate("der").toArray());
            const pointPad = new Uint8Array(this.getPointSize(ecKey.algorithm.namedCurve) - point.length);
            privateKey.privateKey = concat(pointPad, point);
            privateKey.publicKey = new Uint8Array(ecKey.data.getPublic("der"));
            return privateKey;
        }
        else if (ecKey.data.pub) {
            return new asn1.EcPublicKey(new Uint8Array(ecKey.data.getPublic("der")).buffer);
        }
        else {
            throw new Error("Cannot get private or public key");
        }
    }
    static importEcKey(key, namedCurve) {
        const ecKey = this.initEcKey(namedCurve);
        if (key instanceof asn1.EcPublicKey) {
            return ecKey.keyFromPublic(new Uint8Array(key.value));
        }
        return ecKey.keyFromPrivate(new Uint8Array(key.privateKey));
    }
    static getPointSize(namedCurve) {
        switch (namedCurve) {
            case "P-256":
            case "K-256":
                return 32;
            case "P-384":
                return 48;
            case "P-521":
                return 66;
        }
        throw new Error("namedCurve: Is not recognized");
    }
}
EcCrypto.privateUsages = ["sign", "deriveKey", "deriveBits"];
EcCrypto.publicUsages = ["verify"];
EcCrypto.ASN_ALGORITHM = "1.2.840.10045.2.1";

class EcdhProvider extends EcdhProvider$1 {
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return EcCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return EcCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return EcCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    onDeriveBits(algorithm, baseKey, length) {
        return __awaiter(this, void 0, void 0, function* () {
            EcCrypto.checkLib();
            const shared = baseKey.data.derive(algorithm.public.data.getPublic());
            let array = new Uint8Array(shared.toArray());
            let len = array.length;
            len = (len > 32 ? (len > 48 ? 66 : 48) : 32);
            if (array.length < len) {
                array = EcCrypto.concat(new Uint8Array(len - array.length), array);
            }
            const buf = array.slice(0, length / 8).buffer;
            return buf;
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        EcCrypto.checkCryptoKey(key);
    }
}

function b2a(buffer) {
    const buf = new Uint8Array(buffer);
    const res = [];
    for (let i = 0; i < buf.length; i++) {
        res.push(buf[i]);
    }
    return res;
}
function hex2buffer(hexString, padded) {
    if (hexString.length % 2) {
        hexString = "0" + hexString;
    }
    let res = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i++) {
        const c = hexString.slice(i, ++i + 1);
        res[(i - 1) / 2] = parseInt(c, 16);
    }
    if (padded) {
        let len = res.length;
        len = len > 32 ? len > 48 ? 66 : 48 : 32;
        if (res.length < len) {
            res = EcCrypto.concat(new Uint8Array(len - res.length), res);
        }
    }
    return res;
}
function buffer2hex(buffer, padded) {
    let res = "";
    for (let i = 0; i < buffer.length; i++) {
        const char = buffer[i].toString(16);
        res += char.length % 2 ? "0" + char : char;
    }
    if (padded) {
        let len = buffer.length;
        len = len > 32 ? len > 48 ? 66 : 48 : 32;
        if ((res.length / 2) < len) {
            res = new Array(len * 2 - res.length + 1).join("0") + res;
        }
    }
    return res;
}
class EcdsaProvider extends EcdsaProvider$1 {
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return EcCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return EcCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return EcCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    onSign(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            EcCrypto.checkLib();
            const crypto = new Crypto();
            let array;
            const hash = yield crypto.subtle.digest(algorithm.hash, data);
            array = b2a(hash);
            const signature = yield key.data.sign(array);
            const hexSignature = buffer2hex(signature.r.toArray(), true) + buffer2hex(signature.s.toArray(), true);
            return hex2buffer(hexSignature).buffer;
        });
    }
    onVerify(algorithm, key, signature, data) {
        return __awaiter(this, void 0, void 0, function* () {
            EcCrypto.checkLib();
            const crypto = new Crypto();
            const sig = {
                r: new Uint8Array(signature.slice(0, signature.byteLength / 2)),
                s: new Uint8Array(signature.slice(signature.byteLength / 2)),
            };
            const hashedData = yield crypto.subtle.digest(algorithm.hash, data);
            const array = b2a(hashedData);
            return key.data.verify(array, sig);
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        EcCrypto.checkCryptoKey(key);
    }
}

const edOIDs = {
    [asn1.idEd448]: "Ed448",
    "ed448": asn1.idEd448,
    [asn1.idX448]: "X448",
    "x448": asn1.idX448,
    [asn1.idEd25519]: "Ed25519",
    "ed25519": asn1.idEd25519,
    [asn1.idX25519]: "X25519",
    "x25519": asn1.idX25519,
};
function getOidByNamedCurve$1(namedCurve) {
    const oid = edOIDs[namedCurve.toLowerCase()];
    if (!oid) {
        throw new OperationError(`Cannot convert WebCrypto named curve '${namedCurve}' to OID`);
    }
    return oid;
}

class EdPrivateKey extends CryptoKey {
    constructor(algorithm, extractable, usages, data) {
        super(algorithm, extractable, "private", usages);
        this.data = data;
    }
    toJSON() {
        const json = {
            kty: "OKP",
            crv: this.algorithm.namedCurve,
            key_ops: this.usages,
            ext: this.extractable,
        };
        return Object.assign(json, {
            d: Convert.ToBase64Url(Convert.FromHex(/^ed/i.test(json.crv) ? this.data.getSecret("hex") : this.data.getPrivate("hex"))),
        });
    }
    fromJSON(json) {
        if (!json.d) {
            throw new OperationError(`Cannot get private data from JWK. Property 'd' is required`);
        }
        if (!json.crv) {
            throw new OperationError(`Cannot get named curve from JWK. Property 'crv' is required`);
        }
        const hexPrivateKey = Convert.ToHex(Convert.FromBase64Url(json.d));
        if (/^ed/i.test(json.crv)) {
            const eddsa$1 = new eddsa(json.crv.toLowerCase());
            this.data = eddsa$1.keyFromSecret(hexPrivateKey);
        }
        else {
            const ecdhEs = ec(json.crv.replace(/^x/i, "curve"));
            this.data = ecdhEs.keyFromPrivate(hexPrivateKey, "hex");
        }
        return this;
    }
}

class EdPublicKey extends CryptoKey {
    constructor(algorithm, extractable, usages, data) {
        super(algorithm, extractable, "public", usages);
        this.data = data;
    }
    toJSON() {
        const json = {
            kty: "OKP",
            crv: this.algorithm.namedCurve,
            key_ops: this.usages,
            ext: this.extractable,
        };
        return Object.assign(json, {
            x: Convert.ToBase64Url(Convert.FromHex(this.data.getPublic("hex"))),
        });
    }
    fromJSON(json) {
        if (!json.crv) {
            throw new OperationError(`Cannot get named curve from JWK. Property 'crv' is required`);
        }
        if (!json.x) {
            throw new OperationError(`Cannot get property from JWK. Property 'x' is required`);
        }
        const hexPublicKey = Convert.ToHex(Convert.FromBase64Url(json.x));
        if (/^ed/i.test(json.crv)) {
            const eddsa$1 = new eddsa(json.crv.toLowerCase());
            this.data = eddsa$1.keyFromPublic(hexPublicKey, "hex");
        }
        else {
            const ecdhEs = ec(json.crv.replace(/^x/i, "curve"));
            this.data = ecdhEs.keyFromPublic(hexPublicKey, "hex");
        }
        return this;
    }
}

class EdCrypto {
    static checkLib() {
        if (typeof (elliptic) === "undefined") {
            throw new OperationError("Cannot implement EC mechanism. Add 'https://peculiarventures.github.io/pv-webcrypto-tests/src/elliptic.js' script to your project");
        }
    }
    static concat(...buf) {
        const res = new Uint8Array(buf.map((item) => item.length).reduce((prev, cur) => prev + cur));
        let offset = 0;
        buf.forEach((item, index) => {
            for (let i = 0; i < item.length; i++) {
                res[offset + i] = item[i];
            }
            offset += item.length;
        });
        return res;
    }
    static generateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            const curve = algorithm.namedCurve.toLowerCase() === "x25519" ? "curve25519" : "ed25519";
            let edKey;
            if (curve === "ed25519") {
                const raw = nativeCrypto.getRandomValues(new Uint8Array(32));
                const eddsa$1 = new eddsa(curve);
                edKey = eddsa$1.keyFromSecret(raw);
            }
            else {
                edKey = ec(curve).genKeyPair();
                edKey.getPublic();
            }
            const prvKey = new EdPrivateKey(algorithm, extractable, keyUsages.filter((usage) => this.privateKeyUsages.indexOf(usage) !== -1), edKey);
            const pubKey = new EdPublicKey(algorithm, true, keyUsages.filter((usage) => this.publicKeyUsages.indexOf(usage) !== -1), edKey);
            return {
                privateKey: prvKey,
                publicKey: pubKey,
            };
        });
    }
    static sign(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            const array = b2a(data);
            const signature = key.data.sign(array).toHex();
            return Convert.FromHex(signature);
        });
    }
    static verify(algorithm, key, signature, data) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            const array = b2a(data);
            const ok = key.data.verify(array, Convert.ToHex(signature));
            return ok;
        });
    }
    static deriveBits(algorithm, baseKey, length) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            const shared = baseKey.data.derive(algorithm.public.data.getPublic());
            let array = new Uint8Array(shared.toArray());
            let len = array.length;
            len = (len > 32 ? (len > 48 ? 66 : 48) : 32);
            if (array.length < len) {
                array = EdCrypto.concat(new Uint8Array(len - array.length), array);
            }
            const buf = array.slice(0, length / 8).buffer;
            return buf;
        });
    }
    static exportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            switch (format.toLowerCase()) {
                case "jwk":
                    return JsonSerializer.toJSON(key);
                case "pkcs8": {
                    const raw = Convert.FromHex(/^x/i.test(key.algorithm.namedCurve)
                        ? key.data.getPrivate("hex")
                        : key.data.getSecret("hex"));
                    const keyInfo = new asn1.PrivateKeyInfo();
                    keyInfo.privateKeyAlgorithm.algorithm = getOidByNamedCurve$1(key.algorithm.namedCurve);
                    keyInfo.privateKey = AsnConvert.serialize(new OctetString(raw));
                    return AsnConvert.serialize(keyInfo);
                }
                case "spki": {
                    const raw = Convert.FromHex(key.data.getPublic("hex"));
                    const keyInfo = new asn1.PublicKeyInfo();
                    keyInfo.publicKeyAlgorithm.algorithm = getOidByNamedCurve$1(key.algorithm.namedCurve);
                    keyInfo.publicKey = raw;
                    return AsnConvert.serialize(keyInfo);
                }
                case "raw": {
                    return Convert.FromHex(key.data.getPublic("hex"));
                }
                default:
                    throw new OperationError("format: Must be 'jwk', 'raw', pkcs8' or 'spki'");
            }
        });
    }
    static importKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            switch (format.toLowerCase()) {
                case "jwk": {
                    const jwk = keyData;
                    if (jwk.d) {
                        const asnKey = JsonParser.fromJSON(keyData, { targetSchema: asn1.CurvePrivateKey });
                        return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
                    }
                    else {
                        if (!jwk.x) {
                            throw new TypeError("keyData: Cannot get required 'x' filed");
                        }
                        return this.importPublicKey(Convert.FromBase64Url(jwk.x), algorithm, extractable, keyUsages);
                    }
                }
                case "raw": {
                    return this.importPublicKey(keyData, algorithm, extractable, keyUsages);
                }
                case "spki": {
                    const keyInfo = AsnConvert.parse(new Uint8Array(keyData), asn1.PublicKeyInfo);
                    return this.importPublicKey(keyInfo.publicKey, algorithm, extractable, keyUsages);
                }
                case "pkcs8": {
                    const keyInfo = AsnConvert.parse(new Uint8Array(keyData), asn1.PrivateKeyInfo);
                    const asnKey = AsnConvert.parse(keyInfo.privateKey, asn1.CurvePrivateKey);
                    return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
                }
                default:
                    throw new OperationError("format: Must be 'jwk', 'raw', 'pkcs8' or 'spki'");
            }
        });
    }
    static importPrivateKey(asnKey, algorithm, extractable, keyUsages) {
        const key = new EdPrivateKey(Object.assign({}, algorithm), extractable, keyUsages, null);
        key.fromJSON({
            crv: algorithm.namedCurve,
            d: Convert.ToBase64Url(asnKey.d),
        });
        return key;
    }
    static importPublicKey(asnKey, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = new EdPublicKey(Object.assign({}, algorithm), extractable, keyUsages, null);
            key.fromJSON({
                crv: algorithm.namedCurve,
                x: Convert.ToBase64Url(asnKey),
            });
            return key;
        });
    }
}
EdCrypto.publicKeyUsages = ["verify"];
EdCrypto.privateKeyUsages = ["sign", "deriveKey", "deriveBits"];

class EdDsaProvider extends EdDsaProvider$1 {
    constructor() {
        super(...arguments);
        this.namedCurves = ["Ed25519"];
    }
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            const keys = yield EdCrypto.generateKey({
                name: this.name,
                namedCurve: algorithm.namedCurve.replace(/^ed/i, "Ed"),
            }, extractable, keyUsages);
            return keys;
        });
    }
    onSign(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return EdCrypto.sign(algorithm, key, new Uint8Array(data));
        });
    }
    onVerify(algorithm, key, signature, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return EdCrypto.verify(algorithm, key, new Uint8Array(signature), new Uint8Array(data));
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return EdCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield EdCrypto.importKey(format, keyData, Object.assign(Object.assign({}, algorithm), { name: this.name }), extractable, keyUsages);
            return key;
        });
    }
}

class Sha1Provider extends ProviderCrypto {
    constructor() {
        super(...arguments);
        this.name = "SHA-1";
        this.usages = [];
    }
    onDigest(algorithm, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return ShaCrypto.digest(algorithm, data);
        });
    }
}

class Sha256Provider extends Sha1Provider {
    constructor() {
        super(...arguments);
        this.name = "SHA-256";
    }
}

class Sha512Provider extends Sha1Provider {
    constructor() {
        super(...arguments);
        this.name = "SHA-512";
    }
}

class PbkdfCryptoKey extends CryptoKey {
    constructor(algorithm, extractable, usages, raw) {
        super(algorithm, extractable, "secret", usages);
        this.raw = raw;
    }
}

class Pbkdf2Provider extends Pbkdf2Provider$1 {
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return new PbkdfCryptoKey(algorithm, extractable, keyUsages, BufferSourceConverter.toUint8Array(keyData));
        });
    }
    onDeriveBits(algorithm, baseKey, length) {
        return __awaiter(this, void 0, void 0, function* () {
            let result;
            const salt = BufferSourceConverter.toUint8Array(algorithm.salt);
            const password = baseKey.raw;
            switch (algorithm.hash.name.toUpperCase()) {
                case "SHA-1":
                    result = Pbkdf2HmacSha1(password, salt, algorithm.iterations, length >> 3);
                    break;
                case "SHA-256":
                    result = Pbkdf2HmacSha256(password, salt, algorithm.iterations, length >> 3);
                    break;
                case "SHA-512":
                    result = Pbkdf2HmacSha512(password, salt, algorithm.iterations, length >> 3);
                    break;
                default:
                    throw new OperationError(`algorithm.hash: '${algorithm.hash.name}' hash algorithm is not supported`);
            }
            return BufferSourceConverter.toArrayBuffer(result);
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        if (!(key instanceof PbkdfCryptoKey)) {
            throw new TypeError("key: Is not PbkdfCryptoKey");
        }
    }
}

class DesCryptoKey extends CryptoKey {
    constructor(algorithm, extractable, usages, raw) {
        super(algorithm, extractable, "secret", usages);
        this.raw = raw;
    }
    toJSON() {
        const jwk = {
            kty: "oct",
            alg: this.getJwkAlgorithm(),
            k: Convert.ToBase64Url(this.raw),
            ext: this.extractable,
            key_ops: this.usages,
        };
        return jwk;
    }
    getJwkAlgorithm() {
        switch (this.algorithm.name.toUpperCase()) {
            case "DES-CBC":
                return `DES-CBC`;
            case "DES-EDE3-CBC":
                return `3DES-CBC`;
            default:
                throw new AlgorithmError("Unsupported algorithm name");
        }
    }
}

class DesCrypto {
    static checkLib() {
        if (typeof (des) === "undefined") {
            throw new OperationError("Cannot implement DES mechanism. Add 'https://peculiarventures.github.io/pv-webcrypto-tests/src/des.js' script to your project");
        }
    }
    static checkCryptoKey(key) {
        if (!(key instanceof DesCryptoKey)) {
            throw new TypeError("key: Is not DesCryptoKey");
        }
    }
    static generateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            const raw = nativeCrypto.getRandomValues(new Uint8Array(algorithm.length / 8));
            return new DesCryptoKey(algorithm, extractable, keyUsages, raw);
        });
    }
    static exportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            switch (format) {
                case "jwk":
                    return key.toJSON();
                case "raw":
                    return key.raw.buffer;
                default:
                    throw new OperationError("format: Must be 'jwk' or 'raw'");
            }
        });
    }
    static importKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            let raw;
            if (isJWK(keyData)) {
                raw = Convert.FromBase64Url(keyData.k);
            }
            else {
                raw = BufferSourceConverter.toArrayBuffer(keyData);
            }
            if ((algorithm.name === "DES-CBC" && raw.byteLength !== 8)
                || (algorithm.name === "DES-EDE3-CBC" && raw.byteLength !== 24)) {
                throw new OperationError("keyData: Is wrong key length");
            }
            const key = new DesCryptoKey({ name: algorithm.name, length: raw.byteLength << 3 }, extractable, keyUsages, new Uint8Array(raw));
            return key;
        });
    }
    static encrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.cipher(algorithm, key, data, true);
        });
    }
    static decrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.cipher(algorithm, key, data, false);
        });
    }
    static cipher(algorithm, key, data, encrypt) {
        return __awaiter(this, void 0, void 0, function* () {
            this.checkLib();
            const type = encrypt ? "encrypt" : "decrypt";
            let DesCipher;
            const iv = BufferSourceConverter.toUint8Array(algorithm.iv);
            switch (algorithm.name.toUpperCase()) {
                case "DES-CBC":
                    DesCipher = CBC.instantiate(DES).create({
                        key: key.raw,
                        type,
                        iv,
                    });
                    break;
                case "DES-EDE3-CBC":
                    DesCipher = CBC.instantiate(EDE).create({
                        key: key.raw,
                        type,
                        iv,
                    });
                    break;
                default:
                    throw new OperationError("algorithm: Is not recognized");
            }
            const enc = DesCipher.update(new Uint8Array(data)).concat(DesCipher.final());
            return new Uint8Array(enc).buffer;
        });
    }
}

class DesCbcProvider extends DesProvider {
    constructor() {
        super(...arguments);
        this.keySizeBits = 64;
        this.ivSize = 8;
        this.name = "DES-CBC";
    }
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return DesCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return DesCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return DesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    onEncrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return DesCrypto.encrypt(algorithm, key, data);
        });
    }
    onDecrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return DesCrypto.decrypt(algorithm, key, data);
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        DesCrypto.checkCryptoKey(key);
    }
}

class DesEde3CbcProvider extends DesProvider {
    constructor() {
        super(...arguments);
        this.keySizeBits = 192;
        this.ivSize = 8;
        this.name = "DES-EDE3-CBC";
    }
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return DesCrypto.generateKey(algorithm, extractable, keyUsages);
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return DesCrypto.exportKey(format, key);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            return DesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
        });
    }
    onEncrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return DesCrypto.encrypt(algorithm, key, data);
        });
    }
    onDecrypt(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return DesCrypto.decrypt(algorithm, key, data);
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        DesCrypto.checkCryptoKey(key);
    }
}

const JsonBase64UrlConverter = {
    fromJSON: (value) => Buffer.from(Convert.FromBase64Url(value)),
    toJSON: (value) => Convert.ToBase64Url(value),
};
class HmacCryptoKey extends CryptoKey {
    constructor(algorithm = { name: "HMAC" }, extractable = false, usages = [], data = new Uint8Array(0)) {
        super(algorithm, extractable, "secret", usages);
        this.kty = "oct";
        this.data = data;
    }
    get alg() {
        const hash = this.algorithm.hash.name.toUpperCase();
        return `HS${hash.replace("SHA-", "")}`;
    }
    set alg(value) {
    }
}
__decorate([
    JsonProp({ name: "ext", type: JsonPropTypes.Boolean, optional: true })
], HmacCryptoKey.prototype, "extractable", void 0);
__decorate([
    JsonProp({ name: "key_ops", type: JsonPropTypes.String, repeated: true, optional: true })
], HmacCryptoKey.prototype, "usages", void 0);
__decorate([
    JsonProp({ name: "k", converter: JsonBase64UrlConverter })
], HmacCryptoKey.prototype, "data", void 0);
__decorate([
    JsonProp({ type: JsonPropTypes.String })
], HmacCryptoKey.prototype, "kty", void 0);
__decorate([
    JsonProp({ type: JsonPropTypes.String })
], HmacCryptoKey.prototype, "alg", null);

class HmacProvider extends HmacProvider$1 {
    onGenerateKey(algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            const length = algorithm.length || this.getDefaultLength(algorithm.hash.name);
            const raw = nativeCrypto.getRandomValues(new Uint8Array(length >> 3));
            const key = new HmacCryptoKey(algorithm, extractable, keyUsages, raw);
            return key;
        });
    }
    onSign(algorithm, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            let fn;
            switch (key.algorithm.hash.name.toUpperCase()) {
                case "SHA-1":
                    fn = HmacSha1;
                    break;
                case "SHA-256":
                    fn = HmacSha256;
                    break;
                case "SHA-512":
                    fn = HmacSha512;
                    break;
                default:
                    throw new OperationError("key.algorithm.hash: Is not recognized");
            }
            const result = new fn(key.data)
                .process(BufferSourceConverter.toUint8Array(data))
                .finish().result;
            return BufferSourceConverter.toArrayBuffer(result);
        });
    }
    onVerify(algorithm, key, signature, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const signature2 = yield this.onSign(algorithm, key, data);
            return Convert.ToHex(signature2) === Convert.ToHex(signature);
        });
    }
    onImportKey(format, keyData, algorithm, extractable, keyUsages) {
        return __awaiter(this, void 0, void 0, function* () {
            let key;
            switch (format.toLowerCase()) {
                case "jwk":
                    key = JsonParser.fromJSON(keyData, { targetSchema: HmacCryptoKey });
                    break;
                case "raw":
                    if (!BufferSourceConverter.isBufferSource(keyData)) {
                        throw new TypeError("keyData: Is not ArrayBuffer or ArrayBufferView");
                    }
                    key = new HmacCryptoKey(algorithm, extractable, keyUsages, BufferSourceConverter.toUint8Array(keyData));
                    break;
                default:
                    throw new OperationError("format: Must be 'jwk' or 'raw'");
            }
            key.algorithm = {
                hash: { name: algorithm.hash.name },
                name: this.name,
                length: key.data.length << 3,
            };
            key.extractable = extractable;
            key.usages = keyUsages;
            return key;
        });
    }
    onExportKey(format, key) {
        return __awaiter(this, void 0, void 0, function* () {
            switch (format.toLowerCase()) {
                case "jwk":
                    const jwk = JsonSerializer.toJSON(key);
                    return jwk;
                case "raw":
                    return new Uint8Array(key.data).buffer;
                default:
                    throw new OperationError("format: Must be 'jwk' or 'raw'");
            }
        });
    }
    checkCryptoKey(key, keyUsage) {
        super.checkCryptoKey(key, keyUsage);
        if (!(key instanceof HmacCryptoKey)) {
            throw new TypeError("key: Is not HMAC CryptoKey");
        }
    }
}

var _nativeKey;
class WrappedNativeCryptoKey extends CryptoKey {
    constructor(algorithm, extractable, type, usages, nativeKey) {
        super(algorithm, extractable, type, usages);
        _nativeKey.set(this, void 0);
        __classPrivateFieldSet(this, _nativeKey, nativeKey);
    }
    getNative() {
        return __classPrivateFieldGet(this, _nativeKey);
    }
}
_nativeKey = new WeakMap();

class SubtleCrypto extends SubtleCrypto$1 {
    constructor() {
        super();
        this.browserInfo = BrowserInfo();
        this.providers.set(new AesCbcProvider());
        this.providers.set(new AesCtrProvider());
        this.providers.set(new AesEcbProvider());
        this.providers.set(new AesGcmProvider());
        this.providers.set(new AesKwProvider());
        this.providers.set(new DesCbcProvider());
        this.providers.set(new DesEde3CbcProvider());
        this.providers.set(new RsaSsaProvider());
        this.providers.set(new RsaPssProvider());
        this.providers.set(new RsaOaepProvider());
        this.providers.set(new RsaEsProvider());
        this.providers.set(new EcdsaProvider());
        this.providers.set(new EcdhProvider());
        this.providers.set(new Sha1Provider());
        this.providers.set(new Sha256Provider());
        this.providers.set(new Sha512Provider());
        this.providers.set(new Pbkdf2Provider());
        this.providers.set(new HmacProvider());
        this.providers.set(new EdDsaProvider());
    }
    static isAnotherKey(key) {
        if (typeof key === "object"
            && typeof key.type === "string"
            && typeof key.extractable === "boolean"
            && typeof key.algorithm === "object") {
            return !(key instanceof CryptoKey);
        }
        return false;
    }
    digest(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.wrapNative("digest", ...args);
        });
    }
    importKey(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            this.fixFirefoxEcImportPkcs8(args);
            return this.wrapNative("importKey", ...args);
        });
    }
    exportKey(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return (yield this.fixFirefoxEcExportPkcs8(args)) ||
                (yield this.wrapNative("exportKey", ...args));
        });
    }
    generateKey(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.wrapNative("generateKey", ...args);
        });
    }
    sign(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.wrapNative("sign", ...args);
        });
    }
    verify(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.wrapNative("verify", ...args);
        });
    }
    encrypt(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.wrapNative("encrypt", ...args);
        });
    }
    decrypt(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.wrapNative("decrypt", ...args);
        });
    }
    wrapKey(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.wrapNative("wrapKey", ...args);
        });
    }
    unwrapKey(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.wrapNative("unwrapKey", ...args);
        });
    }
    deriveBits(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.wrapNative("deriveBits", ...args);
        });
    }
    deriveKey(...args) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.wrapNative("deriveKey", ...args);
        });
    }
    wrapNative(method, ...args) {
        const _superIndex = name => super[name];
        return __awaiter(this, void 0, void 0, function* () {
            if (~["generateKey", "unwrapKey", "deriveKey", "importKey"].indexOf(method)) {
                this.fixAlgorithmName(args);
            }
            try {
                if (method !== "digest" || !args.some((a) => a instanceof CryptoKey)) {
                    const nativeArgs = this.fixNativeArguments(method, args);
                    Debug.info(`Call native '${method}' method`, nativeArgs);
                    const res = yield nativeSubtle[method].apply(nativeSubtle, nativeArgs);
                    return this.fixNativeResult(method, args, res);
                }
            }
            catch (e) {
                Debug.warn(`Error on native '${method}' calling. ${e.message}`, e);
            }
            if (method === "wrapKey") {
                try {
                    Debug.info(`Trying to wrap key by using native functions`, args);
                    const data = yield this.exportKey(args[0], args[1]);
                    const keyData = (args[0] === "jwk") ? Convert.FromUtf8String(JSON.stringify(data)) : data;
                    const res = yield this.encrypt(args[3], args[2], keyData);
                    return res;
                }
                catch (e) {
                    Debug.warn(`Cannot wrap key by native functions. ${e.message}`, e);
                }
            }
            if (method === "unwrapKey") {
                try {
                    Debug.info(`Trying to unwrap key by using native functions`, args);
                    const data = yield this.decrypt(args[3], args[2], args[1]);
                    const keyData = (args[0] === "jwk") ? JSON.parse(Convert.ToUtf8String(data)) : data;
                    const res = yield this.importKey(args[0], keyData, args[4], args[5], args[6]);
                    return res;
                }
                catch (e) {
                    Debug.warn(`Cannot unwrap key by native functions. ${e.message}`, e);
                }
            }
            if (method === "deriveKey") {
                try {
                    Debug.info(`Trying to derive key by using native functions`, args);
                    const data = yield this.deriveBits(args[0], args[1], args[2].length);
                    const res = yield this.importKey("raw", data, args[2], args[3], args[4]);
                    return res;
                }
                catch (e) {
                    Debug.warn(`Cannot derive key by native functions. ${e.message}`, e);
                }
            }
            if (method === "deriveBits" || method === "deriveKey") {
                for (const arg of args) {
                    if (typeof arg === "object" && arg.public && SubtleCrypto.isAnotherKey(arg.public)) {
                        arg.public = yield this.castKey(arg.public);
                    }
                }
            }
            for (let i = 0; i < args.length; i++) {
                const arg = args[i];
                if (SubtleCrypto.isAnotherKey(arg)) {
                    args[i] = yield this.castKey(arg);
                }
            }
            return _superIndex(method).apply(this, args);
        });
    }
    fixNativeArguments(method, args) {
        var _a, _b, _c, _d, _e, _f, _g, _h;
        const res = [...args];
        if (method === "importKey") {
            if (this.browserInfo.name === Browser.IE && ((_b = (_a = res[0]) === null || _a === void 0 ? void 0 : _a.toLowerCase) === null || _b === void 0 ? void 0 : _b.call(_a)) === "jwk" && !BufferSourceConverter$1.isBufferSource(res[1])) {
                res[1] = Convert.FromUtf8String(JSON.stringify(res[1]));
            }
        }
        if (this.browserInfo.name === Browser.IE && args[1] instanceof WrappedNativeCryptoKey) {
            switch (method) {
                case "sign":
                case "verify":
                case "encrypt":
                case "decrypt":
                    res[0] = Object.assign(Object.assign({}, this.prepareAlgorithm(res[0])), { hash: (_e = (_d = (_c = res[1]) === null || _c === void 0 ? void 0 : _c.algorithm) === null || _d === void 0 ? void 0 : _d.hash) === null || _e === void 0 ? void 0 : _e.name });
                    break;
                case "wrapKey":
                case "unwrapKey":
                    res[4] = Object.assign(Object.assign({}, this.prepareAlgorithm(res[4])), { hash: (_h = (_g = (_f = res[3]) === null || _f === void 0 ? void 0 : _f.algorithm) === null || _g === void 0 ? void 0 : _g.hash) === null || _h === void 0 ? void 0 : _h.name });
                    break;
            }
        }
        for (let i = 0; i < res.length; i++) {
            const arg = res[i];
            if (arg instanceof WrappedNativeCryptoKey) {
                res[i] = arg.getNative();
            }
        }
        return res;
    }
    fixNativeResult(method, args, res) {
        var _a, _b;
        if (this.browserInfo.name === Browser.IE) {
            if (method === "exportKey") {
                if (((_b = (_a = args[0]) === null || _a === void 0 ? void 0 : _a.toLowerCase) === null || _b === void 0 ? void 0 : _b.call(_a)) === "jwk" && res instanceof ArrayBuffer) {
                    return JSON.parse(Convert.ToUtf8String(res));
                }
            }
            if ("privateKey" in res) {
                const privateKeyUsages = ["sign", "decrypt", "unwrapKey", "deriveKey", "deriveBits"];
                const publicKeyUsages = ["verify", "encrypt", "wrapKey"];
                return {
                    privateKey: this.wrapNativeKey(res.privateKey, args[0], args[1], args[2].filter((o) => privateKeyUsages.includes(o))),
                    publicKey: this.wrapNativeKey(res.publicKey, args[0], args[1], args[2].filter((o) => publicKeyUsages.includes(o))),
                };
            }
            else if ("extractable" in res) {
                let algorithm;
                let usages;
                switch (method) {
                    case "importKey":
                        algorithm = args[2];
                        usages = args[4];
                        break;
                    case "unwrapKey":
                        algorithm = args[4];
                        usages = args[6];
                        break;
                    case "generateKey":
                        algorithm = args[0];
                        usages = args[2];
                        break;
                    default:
                        throw new OperationError("Cannot wrap native key. Unsupported method in use");
                }
                return this.wrapNativeKey(res, algorithm, res.extractable, usages);
            }
        }
        return res;
    }
    wrapNativeKey(key, algorithm, extractable, keyUsages) {
        if (this.browserInfo.name === Browser.IE) {
            const algs = [
                "RSASSA-PKCS1-v1_5", "RSA-PSS", "RSA-OAEP",
                "AES-CBC", "AES-CTR", "AES-KW", "HMAC",
            ];
            const index = algs.map((o) => o.toLowerCase()).indexOf(key.algorithm.name.toLowerCase());
            if (index !== -1) {
                const alg = this.prepareAlgorithm(algorithm);
                const newAlg = Object.assign(Object.assign({}, key.algorithm), { name: algs[index] });
                if (SubtleCrypto$1.isHashedAlgorithm(alg)) {
                    newAlg.hash = {
                        name: alg.hash.name.toUpperCase(),
                    };
                }
                Debug.info(`Wrapping ${algs[index]} crypto key to WrappedNativeCryptoKey`);
                return new WrappedNativeCryptoKey(newAlg, extractable, key.type, keyUsages, key);
            }
        }
        return key;
    }
    castKey(key) {
        return __awaiter(this, void 0, void 0, function* () {
            Debug.info("Cast native CryptoKey to linter key.", key);
            if (!key.extractable) {
                throw new Error("Cannot cast unextractable crypto key");
            }
            const provider = this.getProvider(key.algorithm.name);
            const jwk = yield this.exportKey("jwk", key);
            return provider.importKey("jwk", jwk, key.algorithm, true, key.usages);
        });
    }
    fixAlgorithmName(args) {
        if (this.browserInfo.name === Browser.Edge) {
            for (let i = 0; i < args.length; i++) {
                const arg = args[0];
                if (typeof arg === "string") {
                    for (const algorithm of this.providers.algorithms) {
                        if (algorithm.toLowerCase() === arg.toLowerCase()) {
                            args[i] = algorithm;
                            break;
                        }
                    }
                }
                else if (typeof arg === "object" && typeof arg.name === "string") {
                    for (const algorithm of this.providers.algorithms) {
                        if (algorithm.toLowerCase() === arg.name.toLowerCase()) {
                            arg.name = algorithm;
                        }
                        if ((typeof arg.hash === "string" && algorithm.toLowerCase() === arg.hash.toLowerCase())
                            || (typeof arg.hash === "object" && typeof arg.hash.name === "string" && algorithm.toLowerCase() === arg.hash.name.toLowerCase())) {
                            arg.hash = { name: algorithm };
                        }
                    }
                }
            }
        }
    }
    fixFirefoxEcImportPkcs8(args) {
        const preparedAlgorithm = this.prepareAlgorithm(args[2]);
        const algName = preparedAlgorithm.name.toUpperCase();
        if (this.browserInfo.name === Browser.Firefox
            && args[0] === "pkcs8"
            && ~["ECDSA", "ECDH"].indexOf(algName)
            && ~["P-256", "P-384", "P-521"].indexOf(preparedAlgorithm.namedCurve)) {
            if (!BufferSourceConverter.isBufferSource(args[1])) {
                throw new TypeError("data: Is not ArrayBuffer or ArrayBufferView");
            }
            const preparedData = BufferSourceConverter.toArrayBuffer(args[1]);
            const keyInfo = AsnConvert.parse(preparedData, asn1.PrivateKeyInfo);
            const privateKey = AsnConvert.parse(keyInfo.privateKey, asn1.EcPrivateKey);
            const jwk = JsonSerializer.toJSON(privateKey);
            jwk.ext = true;
            jwk.key_ops = args[4];
            jwk.crv = preparedAlgorithm.namedCurve;
            jwk.kty = "EC";
            args[0] = "jwk";
            args[1] = jwk;
        }
    }
    fixFirefoxEcExportPkcs8(args) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (this.browserInfo.name === Browser.Firefox
                    && args[0] === "pkcs8"
                    && ~["ECDSA", "ECDH"].indexOf(args[1].algorithm.name)
                    && ~["P-256", "P-384", "P-521"].indexOf(args[1].algorithm.namedCurve)) {
                    const jwk = yield this.exportKey("jwk", args[1]);
                    const ecKey = JsonParser.fromJSON(jwk, { targetSchema: asn1.EcPrivateKey });
                    const keyInfo = new asn1.PrivateKeyInfo();
                    keyInfo.privateKeyAlgorithm.algorithm = EcCrypto.ASN_ALGORITHM;
                    keyInfo.privateKeyAlgorithm.parameters = AsnConvert.serialize(new asn1.ObjectIdentifier(getOidByNamedCurve(args[1].algorithm.namedCurve)));
                    keyInfo.privateKey = AsnConvert.serialize(ecKey);
                    return AsnConvert.serialize(keyInfo);
                }
            }
            catch (err) {
                Debug.error(err);
                return null;
            }
        });
    }
}
SubtleCrypto.methods = ["digest", "importKey", "exportKey", "sign", "verify", "generateKey", "encrypt", "decrypt", "deriveBits", "deriveKey", "wrapKey", "unwrapKey"];

class Crypto extends Crypto$1 {
    constructor() {
        super(...arguments);
        this.subtle = new SubtleCrypto();
    }
    get nativeCrypto() {
        return nativeCrypto;
    }
    getRandomValues(array) {
        return nativeCrypto.getRandomValues(array);
    }
}

function WrapFunction(subtle, name) {
    const fn = subtle[name];
    subtle[name] = function () {
        const args = arguments;
        return new Promise((resolve, reject) => {
            const op = fn.apply(subtle, args);
            op.oncomplete = (e) => {
                resolve(e.target.result);
            };
            op.onerror = (e) => {
                reject(`Error on running '${name}' function`);
            };
        });
    };
}
if (typeof self !== "undefined" && self["msCrypto"]) {
    WrapFunction(nativeSubtle, "generateKey");
    WrapFunction(nativeSubtle, "digest");
    WrapFunction(nativeSubtle, "sign");
    WrapFunction(nativeSubtle, "verify");
    WrapFunction(nativeSubtle, "encrypt");
    WrapFunction(nativeSubtle, "decrypt");
    WrapFunction(nativeSubtle, "importKey");
    WrapFunction(nativeSubtle, "exportKey");
    WrapFunction(nativeSubtle, "wrapKey");
    WrapFunction(nativeSubtle, "unwrapKey");
    WrapFunction(nativeSubtle, "deriveKey");
    WrapFunction(nativeSubtle, "deriveBits");
}
if (!Math.imul) {
    Math.imul = function imul(a, b) {
        const ah = (a >>> 16) & 0xffff;
        const al = a & 0xffff;
        const bh = (b >>> 16) & 0xffff;
        const bl = b & 0xffff;
        return ((al * bl) + (((ah * bl + al * bh) << 16) >>> 0) | 0);
    };
}

if (nativeCrypto) {
    Object.freeze(nativeCrypto.getRandomValues);
}
const crypto = new Crypto();

export { Crypto, CryptoKey, crypto, nativeCrypto, nativeSubtle, setCrypto };
