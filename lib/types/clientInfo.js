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

import { default as PublicKey } from './publicKey'

/**
 * Information about a specific E3DB client, including the client's
 * public key to be used for cryptographic operations.
 *
 * @property {string}    clientId   UUID representing the client.
 * @property {PublicKey} publicKey  Curve 25519 public key for the client.
 * @property {bool}      validated  Flag whether or not the client has been validated.
 */
export default class ClientInfo {
  constructor(clientId, publicKey, validated) {
    this.clientId = clientId
    this.publicKey = publicKey
    this.valdiated = validated
  }

  /**
   * Specify how an already unserialized JSON array should be marshaled into
   * an object representation.
   *
   * Client information contains the ID of the client, a Curve25519 public key
   * component, and a flag describing whether or not the client has been validated.
   *
   * <code>
   * info = ClientInfo::decode({
   *   client_id: '',
   *   public_key: {
   *     curve25519: ''
   *   },
   *   validated: true
   * })
   * <code>
   *
   * @param {object} json
   *
   * @return {Promise<ClientInfo>}
   */
  static async decode(json) {
    let publicKey = await PublicKey.decode(json.public_key)

    return Promise.resolve(new ClientInfo(json.client_id, publicKey, json.validated))
  }
}
