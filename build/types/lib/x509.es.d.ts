export class AlgorithmProvider {
    getAlgorithms(): any[];
    toAsnAlgorithm(alg: any): any;
    toWebAlgorithm(alg: any): any;
}
export class AsnData {
    constructor(...args: any[]);
    rawData: ArrayBuffer;
    equal(data: any): boolean;
}
export class AsnDefaultSignatureFormatter {
    toAsnSignature(algorithm: any, signature: any): ArrayBuffer;
    toWebSignature(algorithm: any, signature: any): ArrayBuffer;
}
export class AsnEcSignatureFormatter {
    addPadding(pointSize: any, data: any): Uint8Array;
    removePadding(data: any, positive?: boolean): ArrayBufferLike;
    toAsnSignature(algorithm: any, signature: any): ArrayBuffer;
    toWebSignature(algorithm: any, signature: any): ArrayBufferLike;
}
export namespace AsnEcSignatureFormatter {
    const namedCurveSize: Map<any, any>;
    const defaultNamedCurveSize: number;
}
export class Attribute extends AsnData {
    onInit(asn: any): void;
    type: any;
    values: any;
}
export class AttributeFactory {
    static register(id: any, type: any): void;
    static create(data: any): any;
}
export namespace AttributeFactory {
    const items: Map<any, any>;
}
export class AuthorityKeyIdentifierExtension extends Extension {
    static create(param: any, critical?: boolean, crypto?: any): Promise<AuthorityKeyIdentifierExtension>;
    keyId: string;
    certId: {
        name: asn1X509.GeneralName[];
        serialNumber: string;
    };
}
export class BasicConstraintsExtension extends Extension {
    ca: any;
    pathLength: any;
}
export class ChallengePasswordAttribute extends Attribute {
    password: string;
}
export class CryptoProvider extends Map<any, any> {
    static isCryptoKeyPair(data: any): any;
    static isCryptoKey(data: any): boolean;
    constructor();
}
export namespace CryptoProvider {
    const DEFAULT: string;
}
export let EcAlgorithm: {
    new (): {
        toAsnAlgorithm(alg: any): asn1X509.AlgorithmIdentifier;
        toWebAlgorithm(alg: any): {
            name: string;
            hash: {
                name: string;
            };
            namedCurve?: undefined;
        } | {
            name: string;
            namedCurve: string;
            hash?: undefined;
        };
    };
};
export let EdAlgorithm: {
    new (): {
        toAsnAlgorithm(alg: any): asn1X509.AlgorithmIdentifier;
        toWebAlgorithm(alg: any): {
            name: string;
            namedCurve: string;
        };
    };
};
export class ExtendedKeyUsageExtension extends Extension {
    usages: any;
}
export class Extension extends AsnData {
    onInit(asn: any): void;
    type: any;
    critical: any;
    value: any;
}
export class ExtensionFactory {
    static register(id: any, type: any): void;
    static create(data: any): any;
}
export namespace ExtensionFactory {
    const items_1: Map<any, any>;
    export { items_1 as items };
}
export class ExtensionsAttribute extends Attribute {
    items: any[];
}
export var KeyUsageFlags: any;
export class KeyUsagesExtension extends Extension {
    usages: any;
}
export class Name {
    constructor(data: any, extraNames?: {});
    extraNames: NameIdentifier;
    asn: asn1X509.Name;
    getName(idOrName: any): any;
    toString(): string;
    toJSON(): {}[];
    fromString(data: any): asn1X509.Name;
    fromJSON(data: any): asn1X509.Name;
    toArrayBuffer(): ArrayBuffer;
}
export class NameIdentifier {
    items: {};
    get(idOrName: any): any;
    register(id: any, name: any): void;
}
export class OtherName extends AsnData {
    onInit(asn: any): void;
    type: any;
    value: any;
    toJSON(): {
        type: any;
        value: string;
    };
}
export class PemConverter {
    static isPem(data: any): boolean;
    static decode(pem: any): ArrayBuffer[];
    static encode(rawData: any, tag: any): string;
    static encodeBuffer(rawData: any, tag: any): string;
    CertificateTag: string;
    CertificateRequestTag: string;
    PublicKeyTag: string;
    PrivateKeyTag: string;
}
export class Pkcs10CertificateRequest extends PemData {
    constructor(param: any);
    tag: string;
    onInit(asn: any): void;
    tbs: ArrayBuffer;
    publicKey: PublicKey;
    signatureAlgorithm: any;
    signature: any;
    attributes: any;
    extensions: any[];
    subject: string;
    getAttribute(type: any): any;
    getAttributes(type: any): any;
    getExtension(type: any): any;
    getExtensions(type: any): any[];
    verify(crypto?: any): Promise<any>;
}
export class Pkcs10CertificateRequestGenerator {
    static create(params: any, crypto?: any): Promise<Pkcs10CertificateRequest>;
}
export class PublicKey extends PemData {
    constructor(param: any);
    tag: string;
    export(...args: any[]): Promise<any>;
    onInit(asn: any): void;
    algorithm: any;
    getThumbprint(...args: any[]): Promise<any>;
}
export let RsaAlgorithm: {
    new (): {
        toAsnAlgorithm(alg: any): asn1X509.AlgorithmIdentifier;
        toWebAlgorithm(alg: any): {
            name: string;
            hash?: undefined;
        } | {
            name: string;
            hash: {
                name: string;
            };
        };
    };
};
export class SubjectAlternativeNameExtension extends Extension {
    dns: string[];
    email: string[];
    ip: string[];
    url: string[];
    upn: string[];
    guid: string[];
    registeredId: string[];
    otherNames: OtherName[];
    toJSON(): {
        dns: string[];
        email: string[];
        ip: string[];
        guid: string[];
        upn: string[];
        url: string[];
        registeredId: string[];
        otherName: {
            type: any;
            value: string;
        }[];
    };
}
export namespace SubjectAlternativeNameExtension {
    const GUID: string;
    const UPN: string;
}
export class SubjectKeyIdentifierExtension extends Extension {
    static create(publicKey: any, critical?: boolean, crypto?: any): Promise<SubjectKeyIdentifierExtension>;
    keyId: string;
}
export class X509Certificate extends PemData {
    constructor(param: any);
    tag: string;
    onInit(asn: any): void;
    tbs: ArrayBuffer;
    serialNumber: string;
    subject: string;
    issuer: string;
    signatureAlgorithm: any;
    signature: any;
    notBefore: any;
    notAfter: any;
    extensions: any;
    publicKey: PublicKey;
    getExtension(type: any): any;
    getExtensions(type: any): any;
    verify(params?: {}, crypto?: any): Promise<any>;
    getThumbprint(...args: any[]): Promise<any>;
    isSelfSigned(): Promise<any>;
}
export class X509CertificateGenerator {
    static createSelfSigned(params: any, crypto?: any): Promise<X509Certificate>;
    static create(params: any, crypto?: any): Promise<X509Certificate>;
}
export class X509Certificates extends Array<any> {
    constructor(param: any);
    export(format: any): any;
    import(data: any): void;
    clear(): void;
}
export class X509ChainBuilder {
    constructor(params?: {});
    certificates: any;
    build(cert: any): Promise<X509Certificates>;
    findIssuer(cert: any): Promise<any>;
}
export const cryptoProvider: CryptoProvider;
export const diAlgorithm: "crypto.algorithm";
export const diAlgorithmProvider: "crypto.algorithmProvider";
export const diAsnSignatureFormatter: "crypto.signatureFormatter";
export const idEd25519: "1.3.101.112";
export const idEd448: "1.3.101.113";
export const idX25519: "1.3.101.110";
export const idX448: "1.3.101.111";
import * as asn1X509 from "@peculiar/asn1-x509";
declare class PemData extends AsnData {
    static isAsnEncoded(data: any): boolean;
    static toArrayBuffer(raw: any): any;
    toString(format?: string): string;
}
export {};
