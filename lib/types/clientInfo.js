/*!
 * Tozny e3db
 *
 * LICENSE
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
   * @return {ClientInfo}
   */
  static decode(json) {
    return PublicKey.decode(json.public_key).then(publicKey =>
      Promise.resolve(new ClientInfo(json.client_id, publicKey, json.validated))
    )
  }
}
