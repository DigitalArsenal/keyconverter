//@ts-nocheck
import "./shims";
import base64URL from "base64url";
import * as liner from "webcrypto-liner";
import wif from "wif";
import * as x509 from "@peculiar/x509";
import sshpk from "sshpk";
import * as bip39 from "bip39";
import { Buffer } from "buffer";
import elliptic from "elliptic";
import { generateKeyPair } from "curve25519-js";
import { Convert } from "pvtsutils";
import PeerId from "peer-id";
import protobufjs from "protobufjs";
import crypto, { PrivateKey } from "libp2p-crypto";
let { secp256k1 } = crypto.keys.supportedKeys;
import CID from 'cids';
import { base58btc } from 'multiformats/bases/base58';
import multihash from "multihashes";
import { atob } from "buffer";

const { FromHex } = Convert;
const { EcAlgorithm } = x509;
const { CryptoKey } = liner;

const { crypto: linerCrypto } = liner;

let { subtle } = linerCrypto;

/**

 * @type
 * 
 * @description
 * 
 * 
 */

export type FormatOptions = KeyFormat | BufferEncoding | "wif" | "bip39" | "ssh" | "raw:private" | "ipfs:protobuf";

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

type KeyUsageOptions = "encrypt" | "decrypt" | "sign" | "verify" | "deriveKey" | "deriveBits" | "wrapKey" | "unwrapKey";

type ExtendedCryptoKey = {
  data: any;
};

class keyconvert {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  keyCurve: EcKeyGenParams;
  extractable: boolean;
  algorithm: AlgorithmIdentifier;
  keyUsages: Array<KeyUsageOptions>;

  public get secretKey(): CryptoKey {
    return this.privateKey;
  }
  public set secretKey(key: CryptoKey) {
    this.privateKey = key;
  }
  /**
   * Converts hex format to an RFC7517 JSONWebKey
   * @link https://datatracker.ietf.org/doc/html/rfc7517
   * @param
   * @returns {JsonWebKey}
   */
  private static jwkConversion(prvHex: string, curve: EcKeyGenParams, format: string = "hex", x?: string, y?: string): JsonWebKey {
    let namedCurve = curve.namedCurve.toLowerCase();
    if (namedCurve === "ed25519") {
      let ec = new elliptic.eddsa("ed25519");
      let key = ec.keyFromSecret(prvHex);
      let pubPoint: any = key.getPublic("hex");
      x = pubPoint.slice(0, 32);
      y = pubPoint.slice(32, 64);
    } else if (namedCurve === "x25519") {
      let keys = generateKeyPair(Buffer.from(prvHex, "hex"));
      let pubPoint: any = this.toHex(keys.public);
      x = pubPoint.slice(0, 32);
      y = pubPoint.slice(32, 64);
    }

    return {
      kty: ~namedCurve.indexOf("secp") ? "EC" : "OKP",
      crv: namedCurve,
      d: base64URL(prvHex, format),
      x: x ? base64URL(x, format) : null,
      y: y ? base64URL(y, format) : null
    };
  }

  private static toHex(buffer: any): string {
    return Buffer.from(buffer, "hex").toString("hex");
  }

  private static exportFormatError(encoding: string, type: KeyType): void {
    throw Error(`${encoding} format is not available for KeyType ${type}`);
  }

  async export(encoding: FormatOptions, type: KeyType = "public", comment?: string): Promise<JsonWebKey | ArrayBuffer | string> {
    let namedCurve = this.keyCurve.namedCurve.toLowerCase();
    if (this.privateKey === undefined) {
      throw Error("No Private Key");
    } else {
      const _hex = type === "private" ? await this.privateKeyHex() : await this.publicKeyHex();
      if (encoding === "ipfs:protobuf") {
        if (this.keyCurve.namedCurve != "K-256") return Buffer.from("");
        let pP = [Buffer.from(await this.publicKeyHex(), "hex"), Buffer.from(await this.privateKeyHex(), "hex")];
        let key = type === "public" ? pP[0] : pP[1];
        let keyToExport = new crypto.keys.supportedKeys.secp256k1[type === "public" ? "Secp256k1PublicKey" : "Secp256k1PrivateKey"](key, pP[0]);
        return crypto.keys[`marshal${type === "public" ? "Public" : "Private"}Key`](keyToExport as any, "secp256k1");
      } else if (encoding === "hex") {
        return _hex;
      } else if (encoding === "bip39") {
        if (type === "public") {
          keyconvert.exportFormatError(encoding, type);
        } else {
          return bip39.entropyToMnemonic(Buffer.from(_hex, "hex"));
        }
      } else if (encoding === "wif") {
        if (type === "public") {
          keyconvert.exportFormatError(encoding, type);
        } else {
          return wif.encode(128, Buffer.from(_hex, "hex"), true);
        }
      } else if (~["ssh", "pkcs8"].indexOf(encoding)) {
        let _type = type === "public" ? "public" : "private";
        let _keyType = `${_type} key`;
        let exportedKey = await subtle.exportKey("pkcs8", _type === "public" ? this.publicKey : this.privateKey, _keyType);
        let pkcs8 = x509.PemConverter.encode(exportedKey, _keyType);
        if (encoding === "pkcs8" && type !== "public") {
          return pkcs8;
        } else if (~["secp256r1", "ed25519"].indexOf(namedCurve)) {
          let sshkey = sshpk.parsePrivateKey(pkcs8, "pkcs8");
          sshkey.comment = comment;
          return sshkey.toPublic().toString("ssh");
        } else {
          throw Error(`Cannot export ${namedCurve} as SSH Public Key.`);
        }
      } else if (encoding === "jwk") {
        let publicKey = await subtle.exportKey(encoding, this.publicKey);
        let privateKey = await subtle.exportKey(encoding, this.privateKey);
        return Object.assign(privateKey, publicKey);
      } else if (encoding) {
        return await subtle.exportKey(encoding, type === "private" ? this.privateKey : this.publicKey);
      }
    }
  }

  async privateKeyHex(): Promise<string> {
    if (this.privateKey === undefined) {
      throw Error("No Private Key");
    } else {
      let jwkPrivateKey = await subtle.exportKey("jwk", this.privateKey);
      return base64URL.decode(jwkPrivateKey.d, "hex");
    }
  }

  async publicKeyHex(): Promise<string> {
    if (this.privateKey === undefined) {
      throw Error("No Private Key");
    } else {
      return (this.publicKey as unknown as ExtendedCryptoKey).data.getPublic("hex");
    }
  }

  async ipfsPeerID(): Promise<PeerId> {
    const crypto = require("libp2p-crypto");
    const PeerId = require("peer-id");
    //This is hard-coded to secp256k1 for BTC and ETH, even though Ed25519 keys are available
    let convertedKey = new crypto.keys.supportedKeys.secp256k1.Secp256k1PrivateKey(Buffer.from(await this.privateKeyHex(), "hex"));
    let pID: PeerId = await PeerId.createFromPrivKey(crypto.keys.marshalPrivateKey(convertedKey), "secp256k1");
    return pID;
  }

  async ipnsCID(): Promise<String> {
    if (this.keyCurve.namedCurve !== "K-256") return "";
    //This is hard-coded to secp256k1 for BTC and ETH, even though Ed25519 keys are available
    let key = new crypto.keys.supportedKeys.secp256k1.Secp256k1PublicKey(Buffer.from(await this.publicKeyHex(), "hex"));
    let cID: string = new CID(1, "libp2p-key", multihash.encode(key.bytes, "identity")).toString('base36');
    return cID;
  }

  public async exportX509Certificate({
    serialNumber = `${Date.now()} `,
    subject = `CN = localhost`,
    issuer = `BTC`,
    notBefore = new Date("2020/01/01"),
    notAfter = new Date("2022/01/02"),
    signingAlgorithm = null,
    publicKey = this.publicKey,
    signingKey = this.privateKey,
    extensions = null,
    encoding = "pem"
  }: {
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
  } = {}): Promise<string> {

    if (!~["K-256", "P-256"].indexOf(this.keyCurve.namedCurve)) return "";
    x509.cryptoProvider.set(liner.crypto);

    let { digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment } = x509.KeyUsageFlags;

    if (!extensions) {
      extensions = [
        new x509.BasicConstraintsExtension(true, 2, true),
        await x509.SubjectKeyIdentifierExtension.create(this.publicKey),
        await x509.AuthorityKeyIdentifierExtension.create(this.publicKey),
        new x509.KeyUsagesExtension(digitalSignature | nonRepudiation | keyEncipherment | dataEncipherment, true)
      ];
    }

    const cert = x509.X509CertificateGenerator.create({
      serialNumber,
      subject,
      issuer,
      notBefore,
      notAfter,
      signingAlgorithm,
      publicKey,
      signingKey,
      extensions
    });

    return (await cert).toString(encoding);
  }

  public async import(privateKey: Buffer, encoding?: FormatOptions): Promise<void>;
  public async import(privateKey: JsonWebKey): Promise<void>;
  public async import(privateKey: string, encoding?: FormatOptions): Promise<void>;
  public async import(privateKey: CryptoKey): Promise<void>;
  public async import(privateKey: any, encoding?: FormatOptions): Promise<void> {

    this.privateKey = undefined;
    let tt = encoding;
    if (encoding === "ipfs:protobuf") {
      try {
        const ipfsKey = await protobufjs.parse(`
        syntax = "proto2";

        enum KeyType {
          RSA = 0;
          Ed25519 = 1;
          Secp256k1 = 2;
          ECDSA = 3;
        }

        message PublicKey {
          required KeyType Type = 1;
          required bytes Data = 2;
        }

        message PrivateKey {
          required KeyType Type = 1;
          required bytes Data = 2;
        }`).root;
        privateKey = (ipfsKey.lookupType("PrivateKey").decode(privateKey) as any).Data;
        encoding = "raw:private";
      } catch (e) {
        console.log(e)
      }
    }

    if (privateKey instanceof CryptoKey) {
      this.privateKey = privateKey;
    } else {
      if (~["raw", "raw:private", undefined].indexOf(encoding)) {
        privateKey = keyconvert.toHex(privateKey);
      } else {
        if (typeof privateKey === "string") {
          if (encoding.match(/pkcs/) || privateKey.match(/\-{5}BEGIN.*PRIVATE KEY/g)) {
            let pp = x509.PemConverter.decode(privateKey);
            this.privateKey = await subtle.importKey("pkcs8", pp[0], this.keyCurve, this.extractable, this.keyUsages);
            const exportedPrivateKey: JsonWebKey = await subtle.exportKey("jwk", this.privateKey);
            privateKey = base64URL.decode(exportedPrivateKey.d, "hex");
          } else if (encoding === "bip39") {
            privateKey = bip39.mnemonicToEntropy(privateKey);
          } else if (encoding === "wif") {
            const decodedWif = wif.decode(privateKey);
            privateKey = keyconvert.toHex(decodedWif.privateKey);
            encoding = "hex";
          } else if (!encoding) {
            throw Error(`Unknown Private Key Encoding: ${encoding} `);
          }
        } else if ((privateKey as JsonWebKey).d) {
          this.privateKey = await subtle.importKey("jwk", Object.assign({}, privateKey), this.keyCurve, this.extractable, this.keyUsages);
        } else if (!(privateKey instanceof Buffer)) {
          throw Error(`Unknown Input: ${privateKey} `);
        }
      }

      if (!this.privateKey) {
        let jwk = keyconvert.jwkConversion(privateKey, this.keyCurve, "hex");
        this.privateKey = await subtle.importKey("jwk", jwk, this.keyCurve, this.extractable, this.keyUsages);
      }

      let importJWK = await subtle.exportKey("jwk", this.privateKey);
      if (!importJWK.x) {
        const exportedPrivateKey: JsonWebKey = await subtle.exportKey("jwk", this.privateKey);
        privateKey = base64URL.toBuffer(exportedPrivateKey.d);
        let jwk = keyconvert.jwkConversion(privateKey.toString("hex"), this.keyCurve, "hex");
        delete jwk.d;
        importJWK = jwk;
      }

      this.publicKey = await subtle.importKey("jwk", importJWK, this.keyCurve, this.extractable, this.keyUsages);
    }

    return;
  }

  constructor(namedCurve: EcKeyGenParams, algorithm: AlgorithmIdentifier = EcAlgorithm, extractable: boolean = true, keyUsages?: Array<KeyUsageOptions>) {
    this.keyCurve = namedCurve;
    this.extractable = extractable;
    this.algorithm = algorithm;
    this.keyUsages = keyUsages || ["sign", "verify", "deriveKey", "deriveBits"];
  }
}

export { keyconvert };