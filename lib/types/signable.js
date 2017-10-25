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

import { default as Serializable } from './serializable'

/**
 * Recursively sort an object by its keys so we have a deterministic
 * output of the data when serialized.
 *
 * @param {object} obj Object to sort
 *
 * @returns {object}
 */
function sortObject(obj) {
  let keys = Object.keys(obj)
  keys.sort()

  let returner = {}
  for (let key of keys) {
    if (typeof obj[key] === 'object') {
      returner[key] = sortObject(obj[key])
    } else {
      returner[key] = obj[key]
    }
  }

  return returner
}

/**
 * Interface for serializable (offline-signable) documents to implement
 */
export default class Signable extends Serializable {
  /**
   * Generate a JSON.stringify-friendly version of the object
   * automatically omitting any `null` fields.
   *
   * @returns {object}
   */
  serializable() {
    return this
  }

  /**
   * Serialize the object to JSON
   *
   * @returns {string}
   */
  stringify() {
    return JSON.stringify(sortObject(this.serializable()))
  }
}
