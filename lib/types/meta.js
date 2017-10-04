/*!
 * Tozny e3db
 *
 * LICENSE
 */

'use strict'

/**
 * Describe the meta information attributed to a specific encrypted record.
 *
 * @property {string} recordId     Unique ID of the record, or `null` if not yet written
 * @property {string} writerId     Unique ID of the writer of the record
 * @property {string} userId       Unique ID of the subject/user the record is about
 * @property {string} type         Free-form description of thr record content type
 * @property {object} plain        Map of String->String values describing the record's plaintext meta
 * @property {Date}   created      When this record was created, or `null` if unavailable.
 * @property {Date}   lastModified When this record last changed, or `null` if unavailable.
 * @property {string} version      Opaque version identifier created by the server on changes.
 */
export default class Meta {
  constructor(writerId, userId, type, plain) {
    this.recordId = null
    this.writerId = writerId
    this.userId = userId
    this.type = type
    this.plain = plain
    this.created = null
    this.lastModified = null
    this.version = null
  }

  /**
   * Specify how an already unserialized JSON array should be marshaled into
   * an object representation.
   *
   * Meta objects consist of both mutable and immutable information describing
   * the record to which they're attached. Ownership, type, and datetime information
   * is fixed and only updated by the server, but the plaintext fields attributed
   * to a record can be controlled by the user. This mutable field is a map of
   * strings to strings (a JSON object) and is stored in plaintext on the
   * server. The array expected for deserializing back into an object requires:
   *
   * <code>
   * $meta = Meta::decode({
   *   'record_id'     => '',
   *   'writer_id'     => '',
   *   'user_id'       => '',
   *   'type'          => '',
   *   'plain'         => {},
   *   'created'       => ''
   *   'last_modified' => ''
   *   'version'       => ''
   * });
   * </code>
   *
   * @param {object} json
   *
   * @return {Promise<Meta>}
   */
  static decode(json) {
    let meta = new Meta(json.writer_id, json.user_id, json.type, json.plain)

    meta.recordId = json.record_id
    meta.created = new Date(json.created)
    meta.lastModified = new Date(json.last_modified)
    meta.version = json.version

    return Promise.resolve(meta)
  }
}
