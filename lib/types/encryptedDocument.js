/*!
 * Tozny e3db
 *
 * LICENSE
 *
 * Tozny dual licenses this product. For commercial use, please contact
 * info@tozny.com. For non-commercial use, this license permits use of the
 * software only by government agencies, schools, universities, non-profit
 * organizations or individuals on projects that do not receive external
 * funding other than government research grants and contracts. Any other use
 * requires a commercial license. For the full license, please see LICENSE.md,
 * in this source repository.
 *
 * @copyright Copyright (c) 2017 Tozny, LLC (https://tozny.com)
 */

'use strict'

import { default as Signable } from './signable'

/**
 * Represents a signed, encrypted documents
 *
 * @property {ClientMeta} clientMeta
 * @property {CipherData} encryptedData
 * @property {string}     signature
 */
export default class EncryptedDocuement extends Signable {
  constructor(clientMeta, encryptedData, signature) {
    super()

    this.clientMeta = clientMeta
    this.encryptedData = encryptedData
    this.signature = signature
  }

  /* eslint-disable camelcase */

  /**
   * Generate a JSON.stringify-friendly version of the object
   * automatically omitting any `null` fields.
   *
   * @returns {object}
   */
  serializable() {
    let toSerialize = {
      data: this.encryptedData,
      meta: this.clientMeta,
      rec_sig: this.signature
    }

    return toSerialize
  }

  /* eslint-enabled */

  /**
   * Specify how an already unserialized JSON array should be marshaled into
   * an object representation.
   *
   * <code>
   * encryptedDocument = EncryptedDocuement.decode({
   *   'data': {},
   *   'meta': {},
   *   'rec_sig': ''
   * })
   * </code>
   *
   * @param {object} json
   *
   * @return {Promise<EncryptedDocuement>}
   */
  static decode(json) {
    let encryptedDocument = new EncryptedDocuement(json.meta, json.data, json.rec_sig)

    return Promise.resolve(encryptedDocument)
  }
}
