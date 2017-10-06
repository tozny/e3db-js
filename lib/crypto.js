/*!
 * Tozny e3db
 *
 * LICENSE
 */

'use strict'

import 'es6-promise/auto'
import sodium from 'libsodium-wrappers'
import { default as helpers } from './helpers'

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
    let publicKey = helpers.b64decode(encryptedAk.authorizer_public_key.curve25519)
    let privateKey = helpers.b64decode(readerKey)

    let eak = helpers.b64decode(encodedEak.split('.')[0])
    let nonce = helpers.b64decode(encodedEak.split('.')[1])
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
    let publicKey = helpers.b64decode(readerKey)
    let privateKey = helpers.b64decode(writerKey)

    let nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    let eak = sodium.crypto_box_easy(ak, nonce, publicKey, privateKey)

    let encodedEak = helpers.b64encode(eak) + '.' + helpers.b64encode(nonce)

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
    let decrypted = new Record(meta, {})

    // Decrypt the record data
    for (let key in encrypted.data) {
      if (encrypted.data.hasOwnProperty(key)) {
        let cipher = encrypted.data[key].split('.')

        let edk = helpers.b64decode(cipher[0])
        let edkN = helpers.b64decode(cipher[1])
        let ef = helpers.b64decode(cipher[2])
        let efN = helpers.b64decode(cipher[3])

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
    let encrypted = new Record(meta, {})

    // Encrypt the record data
    for (let key in record.data) {
      if (record.data.hasOwnProperty(key)) {
        let field = record.data[key]

        let dk = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
        let efN = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
        let ef = sodium.crypto_secretbox_easy(field, efN, dk)
        let edkN = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
        let edk = sodium.crypto_secretbox_easy(dk, edkN, accessKey)

        encrypted.data[key] = [edk, edkN, ef, efN].map(helpers.b64encode).join('.')
      }
    }

    return Promise.resolve(encrypted)
  }
}