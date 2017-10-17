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
 * Describe a Curve25519 public key for use in Sodium-powered cryptographic
 * operations.
 *
 * @property {string} curve25519 Public component of the Curve25519 key.
 */
export default class PublicKey {
  constructor(curve25519) {
    this.curve25519 = curve25519
  }

  /**
   * Specify how an already unserialized JSON array should be marshaled into
   * an object representation.
   *
   * The public key component of a Curve25519 key alone is serialized for transmission between
   * various parties.
   *
   * <code>
   * key = PublicKey::decode({
   *   curve25519: ''
   * })
   * </code>
   *
   * @param {object} json
   *
   * @return {Promise<PublicKey>}
   */
  static decode(json) {
    let key = new PublicKey(json.curve25519)

    return Promise.resolve(key)
  }
}
