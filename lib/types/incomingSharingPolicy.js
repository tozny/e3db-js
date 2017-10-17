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

/**
 * Information about a specific E3DB client, including the client's
 * public key to be used for cryptographic operations.
 *
 * @property {string} writerId      Unique ID of the writer that shared with this client
 * @property {string} recordType    Type of record shared with this client
 * @property {string} [writerName]  Display name of the writer, if available
 */
export default class IncomingSharingPolicy {
  constructor(writerId, recordType, writerName = null) {
    this.writerId = writerId
    this.recordType = recordType
    this.writerName = writerName
  }

  /**
   * Specify how an already unserialized JSON array should be marshaled into
   * an object representation.
   *
   * Client information contains the ID of the client, a Curve25519 public key
   * component, and a flag describing whether or not the client has been validated.
   *
   * <code>
   * isp = IncomingSharingPolicy::decode({
   *   writer_id: '',
   *   record_type: '',
   *   writer_name: ''
   * })
   * <code>
   *
   * @param {object} json
   *
   * @return {Promise<IncomingSharingPolicy>}
   */
  static async decode(json) {
    return Promise.resolve(
      new IncomingSharingPolicy(json.writer_id, json.record_type, json.writer_name)
    )
  }
}
