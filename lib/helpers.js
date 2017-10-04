/*!
 * Tozny e3db
 *
 * LICENSE
 */

'use strict'

import base64url from 'base64url'
import sodium from 'libsodium-wrappers'

export default class {
  static b64encode(raw) {
    return base64url.fromBase64(sodium.to_base64(new Buffer(raw)))
  }

  static b64decode(encoded) {
    return sodium.from_base64(base64url.toBase64(encoded))
  }
}
