//Copyright 2023 DigitalArsenal.io, Inc.
// MIT-Licensed.

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
import PeerId from "peer-id";
import lp2pcrypto from "libp2p-crypto";
import CID from 'cids';
import multihash from "multihashes";
import createKeccakHash from "keccak";
import { toChecksumAddress } from "ethereum-checksum-address";

const { EcAlgorithm } = x509;

//@ts-ignore
const { CryptoKey } = liner;

//@ts-ignore
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

class keyconverter {
  privateKey: CryptoKey;
  privateKeyLength: number;
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
      x: x ? base64URL(x, format) : "",
      y: y ? base64URL(y, format) : ""
    };
  }

  private static toHex(buffer: any): string {
    return Buffer.from(buffer, "hex").toString("hex");
  }

  private static trimHex(h: string, len: number): string {
    return h.slice(-(len / 4));
  }

  private static exportFormatError(encoding: string, type: KeyType): void {
    throw Error(`${encoding} format is not available for KeyType ${type}`);
  }

  async export(encoding: FormatOptions, type: KeyType = "public", comment?: string): Promise<JsonWebKey | ArrayBuffer | string | undefined> {
    let namedCurve = this?.keyCurve?.namedCurve.toLowerCase();
    if (this.privateKey === undefined) {
      throw Error("No Private Key");
    } else {
      const _hex = type === "private" ? keyconverter.trimHex((await this.privateKeyHex()), this.privateKeyLength) : await this.publicKeyHex();
      if (encoding === "ipfs:protobuf") {
        if (this?.keyCurve?.namedCurve != "K-256") return Buffer.from("");
        let pP = [Buffer.from(await this.publicKeyHex(), "hex"), Buffer.from(await this.privateKeyHex(), "hex")];
        let key = type === "public" ? pP[0] : pP[1];
        let keyToExport = new lp2pcrypto.keys.supportedKeys.secp256k1[type === "public" ? "Secp256k1PublicKey" : "Secp256k1PrivateKey"](key, pP[0]);
        let exportedKey = lp2pcrypto.keys[`marshal${type === "public" ? "Public" : "Private"}Key`](keyToExport as any, "secp256k1");
        return exportedKey;
      } else if (encoding === "hex") {
        return _hex;
      } else if (encoding === "bip39") {
        if (type === "public") {
          keyconverter.exportFormatError(encoding, type);
        } else {
          return bip39.entropyToMnemonic(_hex);
        }
      } else if (encoding === "wif") {
        if (type === "public") {
          keyconverter.exportFormatError(encoding, type);
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
        } else if (namedCurve && ~["secp256r1", "ed25519"].indexOf(namedCurve)) {
          let sshkey = sshpk.parsePrivateKey(pkcs8, "pkcs8");
          sshkey.comment = comment;
          return sshkey.toPublic().toString("ssh");
        } else {
          throw Error(`Cannot export ${namedCurve} as SSH Public Key.`);
        }
      } else if (encoding === "jwk") {
        let publicKey = await subtle.exportKey(encoding, this.publicKey);
        let privateKey = await subtle.exportKey(encoding, this.privateKey);

        if (type === "public") {
          return publicKey;
        } else {
          return Object.assign(privateKey, publicKey);
        }

      } else if (encoding) {
        return await subtle.exportKey(encoding, type === "private" ? this.privateKey : this.publicKey);
      }
    }
    return undefined;
  }

  async privateKeyHex(): Promise<string> {
    if (!this.privateKey.algorithm?.name) {
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
    //@ts-ignore
    let convertedKey = new lp2pcrypto.keys.supportedKeys.secp256k1.Secp256k1PrivateKey(Buffer.from(await this.privateKeyHex(), "hex"));
    let pID: PeerId = await PeerId.createFromPrivKey(lp2pcrypto.keys.marshalPrivateKey(convertedKey), "secp256k1");
    return pID;
  }

  async ipnsCID(): Promise<String> {
    if (this?.keyCurve?.namedCurve !== "K-256") return "";
    //This is hard-coded to secp256k1 for BTC and ETH, even though Ed25519 keys are available
    let key = new lp2pcrypto.keys.supportedKeys.secp256k1.Secp256k1PublicKey(Buffer.from(await this.publicKeyHex(), "hex"));
    let cID: string = new CID(1, "libp2p-key", multihash.encode(key.bytes, "identity")).toString('base36');
    return cID;
  }

  public async exportX509Certificate({
    serialNumber = `${Date.now()} `,
    subject = `CN = localhost`,
    issuer = `BTC`,
    notBefore = new Date("2020/01/01"),
    notAfter = new Date("2022/01/02"),
    signingAlgorithm = {
      name: "No Value"
    },
    publicKey = this.publicKey,
    signingKey = this.privateKey,
    extensions = undefined,
    encoding = "pem"
  }: {
    serialNumber?: string;
    subject?: string;
    issuer?: string;
    notBefore?: Date;
    notAfter?: Date;
    signingAlgorithm?: Algorithm | EcdsaParams;
    publicKey?: CryptoKey;
    signingKey?: CryptoKey;
    extensions?: any[] | undefined;
    encoding?: "base64" | "base64url" | "hex" | "pem";
  } = {}): Promise<string> {

    if (this?.keyCurve?.namedCurve && !~["K-256", "P-256"].indexOf(this.keyCurve.namedCurve)) return "";
    //@ts-ignore
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

  public async import(privateKey: Buffer | JsonWebKey | string | CryptoKey, encoding?: FormatOptions): Promise<CryptoKey> {

    this.privateKey = new CryptoKey;

    if ((privateKey as JsonWebKey)?.crv === "secp256k1") {
      (privateKey as JsonWebKey).crv = "K-256";
    }

    if (encoding === "ipfs:protobuf") {
      try {
        privateKey = ((await lp2pcrypto.keys.unmarshalPrivateKey(privateKey as Buffer)) as any)._key;
        encoding = "raw:private";
      } catch (e) {
        console.log(e)
      }
    }

    if (privateKey instanceof CryptoKey) {
      this.privateKey = privateKey as CryptoKey;
    } else {
      if (~["raw", "raw:private", undefined].indexOf(encoding)) {
        privateKey = keyconverter.toHex(privateKey);
        encoding = "hex";
      } else {
        if (typeof privateKey === "string") {
          if (encoding?.match(/pkcs/) || privateKey?.match(/\-{5}BEGIN.*PRIVATE KEY/g) && this.privateKey.algorithm?.name) {
            let pp = x509.PemConverter.decode(privateKey);
            this.privateKey = await subtle.importKey("pkcs8", pp[0], this.keyCurve, this.extractable, this.keyUsages);
            const exportedPrivateKey: JsonWebKey = await subtle.exportKey("jwk", this.privateKey);
            privateKey = base64URL.decode(exportedPrivateKey.d as string, "hex");
            encoding = "hex";
          } else if (encoding === "bip39") {
            privateKey = bip39.mnemonicToEntropy(privateKey);
            encoding = "hex";
          } else if (encoding === "wif") {
            const decodedWif = wif.decode(privateKey);
            privateKey = keyconverter.toHex(decodedWif.privateKey);
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
      if (encoding === "hex") {
        privateKey = keyconverter.trimHex((privateKey as string), this.privateKeyLength);
      } else {
        throw Error(`Unknown Private Key Format, ${encoding}, ${privateKey}`);
      }

      if (!this.privateKey.algorithm?.name) {
        let jwk = keyconverter.jwkConversion(privateKey as string, this.keyCurve as EcKeyGenParams, "hex");
        this.privateKey = await subtle.importKey("jwk", jwk, this.keyCurve, this.extractable, this.keyUsages);
      }

      let importJWK;
      if (this.privateKey.algorithm?.name) {
        importJWK = await subtle.exportKey("jwk", this.privateKey);
      } else {
        throw Error("No Private Key Loaded");
      }
      if (!importJWK.x && this.privateKey.algorithm?.name) {
        const exportedPrivateKey: JsonWebKey = await subtle.exportKey("jwk", this.privateKey);
        privateKey = base64URL.toBuffer(exportedPrivateKey.d as string);
        let jwk = keyconverter.jwkConversion(privateKey.toString("hex"), this.keyCurve as EcKeyGenParams, "hex");
        delete jwk.d;
        importJWK = jwk;
      }
      delete importJWK.d;
      delete importJWK.key_ops;
      delete importJWK.ext;

      this.publicKey = await subtle.importKey("jwk", importJWK, this.keyCurve, this.extractable, this.keyUsages);
    }

    return this.publicKey;
  }

  constructor(namedCurve: EcKeyGenParams, privateKeyLength: number = 128, algorithm: AlgorithmIdentifier = EcAlgorithm, extractable: boolean = true, keyUsages?: Array<KeyUsageOptions>) {
    this.privateKey = new CryptoKey();
    this.privateKeyLength = privateKeyLength;
    this.publicKey = new CryptoKey();
    this.keyCurve = namedCurve;
    this.extractable = extractable;
    this.algorithm = algorithm;
    this.keyUsages = keyUsages || ["sign", "verify", "deriveKey", "deriveBits"];
  }
}

const pubKeyToEthAddress = async (pubPoint: string): Promise<string> => {
  if (pubPoint.slice(0, 2) !== "04" || pubPoint.length < 130) return "";
  let keccakHex = createKeccakHash("keccak256")
    .update(Buffer.from(pubPoint.slice(2), "hex"))
    .digest("hex");
  return toChecksumAddress(`${keccakHex.substring(keccakHex.length - 40, keccakHex.length).toUpperCase()}`);
}

export { keyconverter, pubKeyToEthAddress };