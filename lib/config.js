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
