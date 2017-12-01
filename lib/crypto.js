/*!
 * Tozny e3db
 *
 * LICENSE
 *
 * Tozny dual licenses this product. For commercial use, please contact
 * info@tozny.com. For non-commercial use, the contents of this file are
 * subject to the TOZNY NON-COMMERCIAL LICENSE (the "License") which
 * permits use of the software only by government agencies, schools,
 * universities, non-profit organizations or individuals on projects that
 * do not receive external funding other than government research grants
 * and contracts.  Any other use requires a commercial license. You may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at https://tozny.com/legal/non-commercial-license.
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations under
 * the License. Portions of the software are Copyright (c) TOZNY LLC, 2017.
 * All rights reserved.
 *
 * @copyright Copyright (c) 2017 Tozny, LLC (https://tozny.com)
 */

'use strict'

import 'es6-promise/auto'
import base64url from 'base64url'
import crypto from 'crypto'
import sodium from 'libsodium-wrappers'

import { default as Meta } from './types/meta'
import { default as Record } from './types/record'

export default class Crypto {
  /**
   * Decrypt the access key provided for a specific reader so it can be used
   * to further decrypt a protected record.
   *
   * @param {string} readerKey   Base64url-encoded private key for the reader (current client)
   * @param {object} encryptedAk Encrypted access key
   *
   * @return {Promise<string>} Raw binary string of the access key
   */
  static decryptEak(readerKey, encryptedAk) {
    let encodedEak = encryptedAk.eak
    let publicKey = this.b64decode(encryptedAk.authorizer_public_key.curve25519)
    let privateKey = this.b64decode(readerKey)

    let [eak, nonce] = encodedEak.split('.').map(x => this.b64decode(x))
    let ak = sodium.crypto_box_open_easy(eak, nonce, publicKey, privateKey)

    return Promise.resolve(ak)
  }

  /**
   * Encrypt an access key for a given reader.
   *
   * @param {string} writerKey Base64url-encoded private key of the writer
   * @param {string} ak        Raw binary string of the access key
   * @param {string} readerKey Base64url-encoded public key of the reader
   *
   * @return {Promise<string>} Encrypted and encoded access key.
   */
  static encryptAk(writerKey, ak, readerKey) {
    let publicKey = this.b64decode(readerKey)
    let privateKey = this.b64decode(writerKey)

    let nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    let eak = sodium.crypto_box_easy(ak, nonce, publicKey, privateKey)

    let encodedEak = this.b64encode(eak) + '.' + this.b64encode(nonce)

    return Promise.resolve(encodedEak)
  }

  /**
   * Create a clone of a given record, but decrypting each field in turn based on
   * the provided access key.
   *
   * @param {Record} encrypted Record to be unwrapped
   * @param {string} accessKey Access key to use for decrypting each data key.
   *
   * @return {Promise<Record>}
   */
  static decryptRecord(encrypted, accessKey) {
    // Clone the record meta
    let meta = new Meta(
      encrypted.meta.writerId,
      encrypted.meta.userId,
      encrypted.meta.type,
      encrypted.meta.plain
    )
    meta.recordId = encrypted.meta.recordId
    meta.created = encrypted.meta.created
    meta.lastModified = encrypted.meta.lastModified
    meta.version = encrypted.meta.version
    let decrypted = new Record(meta, {}, encrypted.signature)

    // Decrypt the record data
    for (let key in encrypted.data) {
      if (encrypted.data.hasOwnProperty(key)) {
        let [edk, edkN, ef, efN] = encrypted.data[key]
          .split('.')
          .map(x => this.b64decode(x))

        let dk = sodium.crypto_secretbox_open_easy(edk, edkN, accessKey)
        let field = sodium.crypto_secretbox_open_easy(ef, efN, dk)

        decrypted.data[key] = String.fromCharCode.apply(null, field)
      }
    }

    return Promise.resolve(decrypted)
  }

  /**
   * Create a clone of a plaintext record, encrypting each field in turn with a random
   * data key and protecting the data key with a set access key.
   *
   * @param {Record} record    Record to be encrypted.
   * @param {string} accessKey Access key to use for decrypting each data key.
   *
   * @return {Promise<Record>}
   */
  static encryptRecord(record, accessKey) {
    // Clone the record meta
    let meta = new Meta(
      record.meta.writerId,
      record.meta.userId,
      record.meta.type,
      record.meta.plain
    )
    let encrypted = new Record(meta, {}, record.signature)

    // Encrypt the record data
    for (let key in record.data) {
      if (record.data.hasOwnProperty(key)) {
        let field = record.data[key]

        let dk = sodium.crypto_secretbox_keygen()
        let efN = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
        let ef = sodium.crypto_secretbox_easy(field, efN, dk)
        let edkN = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
        let edk = sodium.crypto_secretbox_easy(dk, edkN, accessKey)

        encrypted.data[key] = [edk, edkN, ef, efN].map(this.b64encode).join('.')
      }
    }

    return Promise.resolve(encrypted)
  }

  /**
   * Verify the signature on a given JSON document, given a specific public signing key.
   *
   * @param {Serializable} document     Document to be verified
   * @param {string}       signature    Base64URL-encoded signature
   * @param {string}       verifyingKey Base64URL-encoded signing key
   *
   * @returns {Promise<bool>}
   */
  static verifyDocumentSignature(document, signature, verifyingKey) {
    let message = document.stringify()
    let rawSignature = Crypto.b64decode(signature)
    let rawKey = Crypto.b64decode(verifyingKey)

    let result = sodium.crypto_sign_verify_detached(rawSignature, message, rawKey)

    return Promise.resolve(result)
  }

  /**
  * Sign a document and return the signature
  *
  * @param {Serializable} document   Serializable object to be signed
  * @param {string}       signingKey Key to use to sign the document
  *
  * @returns {Promise<string>}
  */
  static signDocument(document, signingKey) {
    let message = document.stringify()
    let rawKey = Crypto.b64decode(signingKey)

    let signature = sodium.crypto_sign_detached(message, rawKey)

    return Promise.resolve(Crypto.b64encode(signature))
  }

  /**
   * Base64 encode a string in a URL safe manner with no padding
   *
   * @param {string} raw Raw data to be encoded
   *
   * @returns {string}
   */
  static b64encode(raw) {
    return base64url.fromBase64(sodium.to_base64(new Buffer(raw)))
  }

  /**
   * Decode a Base64URL-encoded string
   *
   * @param {string} encoded Base64URL-encoded string
   *
   * @returns {string}
   */
  static b64decode(encoded) {
    return sodium.from_base64(base64url.toBase64(encoded))
  }

  /**
   * Generate a random key for use with Libsodium's secretbox interface
   *
   * @returns {string}
   */
  static randomKey() {
    return sodium.crypto_secretbox_keygen()
  }

  /**
   * Use PBKDF2 to derive a key of a given length using a specified password
   * and salt.
   *
   * @param {string} password User-specified password
   * @param {string} salt     User-specified salt (should be random)
   * @param {number} length   Length of the key to generate
   *
   * @returns {string}
   */
  static deriveKey(password, salt, length) {
    return crypto.pbkdf2Sync(password, salt, 1000, length, 'sha512')
  }

  /**
   * Derive an Ed25519 keypair from a password and a random salt
   *
   * @param {string} password User-specified password
   * @param {string} salt     User-specified salt (should be random)
   *
   * @returns {object} Object containing publicKey and privateKey fields
   */
  static deriveSigningKey(password, salt) {
    let seed = Crypto.deriveKey(password, salt, sodium.crypto_sign_SEEDBYTES)

    return sodium.crypto_sign_seed_keypair(new Uint8Array(seed))
  }

  /**
   * Derive a Curve25519 keypair from a password and a random salt
   *
   * @param {string} password User-specified password
   * @param {string} salt     User-specified salt (should be random)
   *
   * @returns {object} Object containing publicKey and privateKey fields
   */
  static deriveCryptoKey(password, salt) {
    let seed = Crypto.deriveKey(password, salt, sodium.crypto_sign_SEEDBYTES)

    return sodium.crypto_box_seed_keypair(new Uint8Array(seed))
  }

  /**
   * Derive a symmetric encryption key from a password and a random salt
   *
   * @param {string} password User-specified password
   * @param {string} salt     User-specified salt (should be random)
   *
   * @returns {string}
   */
  static deriveSymmetricKey(password, salt) {
    return Crypto.deriveKey(password, salt, sodium.crypto_secretbox_KEYBYTES)
  }
}
