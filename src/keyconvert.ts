import base64URL from "base64url";
import * as liner from "../lib/webcrypto.liner.index.es";
import wif from "wif";
import * as x509 from "../lib/x509.es";
import sshpk from "sshpk";
import * as bip39 from "bip39";
import { Buffer } from "buffer";
import { ECPair, payments } from "bitcoinjs-lib";
import elliptic, { eddsa } from "elliptic";
import createKeccakHash from "keccak";
import { toChecksumAddress } from "ethereum-checksum-address";
import { generateKeyPair } from "curve25519-js";
import { Convert } from "pvtsutils";
import PeerId from "peer-id";
import protobufjs from "protobufjs";
import { existsSync } from "fs";
import { readFile, writeFile } from "fs/promises";
import crypto from "libp2p-crypto";
import CID from 'cids';
import { base58btc } from 'multiformats/bases/base58';
import multihash from "multihashes";

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

export type FormatOptions = KeyFormat | BufferEncoding | "wif" | "bip39" | "ssh" | "raw:private";

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

export class keyconvert {
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
      //fd3384e132ad02a56c78f45547ee40038dc79002b90d29ed90e08eee762ae715
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
      if (encoding === "hex") {
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
  async bitcoinAddress(): Promise<string> {
    const bjsKeyPair = ECPair.fromWIF((await this.export("wif", "private")).toString());
    const { address } = payments.p2pkh({
      pubkey: bjsKeyPair.publicKey
    });
    return address;
  }
  async ethereumAddress(): Promise<string> {
    let ec = new elliptic.ec("secp256k1");
    let key = ec.keyFromPrivate(await this.privateKeyHex());
    let pubPoint: any = key.getPublic("hex");
    let keccakHex = createKeccakHash("keccak256")
      .update(Buffer.from(pubPoint.slice(2), "hex"))
      .digest("hex");
    return toChecksumAddress(`${keccakHex.substring(keccakHex.length - 40, keccakHex.length).toUpperCase()}`);
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
    let convert: Boolean = true;
    let importJWK: JsonWebKey;

    this.privateKey = undefined;

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
