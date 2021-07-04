import base64URL from 'base64-url/index.js';
import { crypto as linerCrypto } from 'webcrypto-liner/build/index.js';
import * as bitcoinjs from 'bitcoinjs-lib';
import wif from 'wif';
import { pbkdf2Sync } from 'crypto';
import * as x509 from '@peculiar/x509';
import { of } from 'rxjs';
import sshpk from 'sshpk';
import * as bip39 from 'bip39';

x509.cryptoProvider.set(linerCrypto);

let { subtle } = linerCrypto;

type EncodingOptions = BufferEncoding | 'wif';

export class keymaster {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  curve: NamedCurve;

  /*
    encrypt: The key may be used to encrypt messages.
    decrypt: The key may be used to decrypt messages.
    sign: The key may be used to sign messages.
    verify: The key may be used to verify signatures.
    deriveKey: The key may be used in deriving a new key.
    deriveBits: The key may be used in deriving bits.
    wrapKey: The key may be used to wrap a key.
    unwrapKey: The key may be used to unwrap a key.
    */

  keyUsages: Array<string>;

  /**
   * Converts hex format to an RFC7517 JSONWebKey
   * @link https://datatracker.ietf.org/doc/html/rfc7517
   * @param
   * @returns {JsonWebKey}
   */
  private static jwkConversion(
    prvHex: string,
    namedCurve: NamedCurve,
    format: string = 'hex'
  ): JsonWebKey {
    return {
      kty: 'EC',
      crv: namedCurve,
      d: base64URL.encode(prvHex, format),
      x: null,
      y: null
    };
  }

  async bip39(): Promise<string> {
    return bip39.entropyToMnemonic(Buffer.from(await this.hex(), "hex"));
  }

  async hex(): Promise<string> {
    let jwkPrivateKey = await subtle.exportKey("jwk", this.privateKey);
    return base64URL.decode(jwkPrivateKey.d, 'hex');
  }

  import(privateKey: Buffer);
  import(privateKey: string, format?: EncodingOptions);

  public async import(privateKey: any, format?: EncodingOptions): Promise<void> {

    let convert: Boolean = false;

    if (typeof privateKey === 'string' && privateKey.indexOf(' ') > -1) {
      privateKey = bip39.mnemonicToEntropy(privateKey);
      convert = true;
    } else if (privateKey instanceof Buffer) {
      convert = true;
    }

    if (convert) {
      format = 'hex';
      privateKey = privateKey.toString('hex');
    }

    this.privateKey = await subtle.importKey(
      'jwk',
      keymaster.jwkConversion(privateKey, this.curve, format),
      { name: 'ECDSA', namedCurve: this.curve },
      true,
      this.keyUsages
    );
  }

  constructor(namedCurve: NamedCurve, keyUsages?: Array<string>) {
    this.curve = namedCurve;
    this.keyUsages = keyUsages || ['sign', 'verify'];
  }
}
