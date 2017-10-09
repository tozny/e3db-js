/*!
 * Tozny e3db
 *
 * LICENSE
 */

'use strict'

import { default as Meta } from './meta'

/**
 * A E3DB record containing data and metadata. Records are
 * a key/value mapping containing data serialized
 * into strings. All records are encrypted prior to sending them
 * to the server for storage, and decrypted in the client after
 * they are read.
 *
 * @property {Meta} meta Meta information about the record.
 */
export default class Record {
  constructor(meta, data) {
    this.meta = meta
    this.data = data
  }

  /**
   * Generate a JSON.stringify-friendly version of the object
   * automatically omitting any `null` fields.
   *
   * @returns {object}
   */
  serializable() {
    return {
      meta: this.meta.serializable(),
      data: this.data
    }
  }

  /**
   * Serialize the object to JSON
   *
   * @returns {string}
   */
  stringify() {
    return JSON.stringify(this.serializable())
  }

  /**
   * Specify how an already unserialized JSON array should be marshaled into
   * an object representation.
   *
   * Records consist of two elements, meta and data. The array we deserialize into a Record instance
   * must match this format. The meta element is itself an array representing the Meta class. The
   * data element is a simpler array mapping string keys to either encrypted or plaintext string values.
   *
   * <code>
   * record = Record::decode({
   *   meta: {
   *     record_id:     '',
   *     writer_id:     '',
   *     user_id:       '',
   *     type:          '',
   *     plain:         {},
   *     created:       '',
   *     last_modified: '',
   *     version:       ''
   *   },
   *   data: {
   *     key1: 'value',
   *     key2: 'value'
   *   }
   * })
   * </code>
   *
   * @param {array} parsed
   *
   * @return {Promise<Record>}
   */
  static async decode(json) {
    let meta = await Meta.decode(json.meta)

    return Promise.resolve(new Record(meta, json.data))
  }
}
