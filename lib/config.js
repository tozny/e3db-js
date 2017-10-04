/*!
 * Tozny e3db
 *
 * LICENSE
 */

'use strict'

const DEFAULT_API_URL = 'https://api.e3db.com'

/**
 * Configuration and credentials for E3DB.
 *
 * @property {number} version    The version number of the configuration format (currently 1)
 * @property {string} clientId   The client's unique client identifier
 * @property {string} apiKeyId   The client's non-secret API key component
 * @property {string} apiSecret  The client's confidential API key component
 * @property {string} publicKey  The client's Base64URL encoded Curve25519 public key
 * @property {string} privateKey The client's Base64URL encoded Curve25519 private key
 * @property {string} [apiUrl]   Optional base URL for the E3DB API service
 */
export default class Config {
  constructor(
    clientId,
    apiKeyId,
    apiSecret,
    publicKey,
    privateKey,
    apiUrl = DEFAULT_API_URL
  ) {
    this.version = 1
    this.clientId = clientId
    this.apiKeyId = apiKeyId
    this.apiSecret = apiSecret
    this.publicKey = publicKey
    this.privateKey = privateKey
    this.apiUrl = apiUrl
  }
}
