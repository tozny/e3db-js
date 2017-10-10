/*!
 * Tozny e3db
 *
 * LICENSE
 */

'use strict'

import { default as Crypto } from '../crypto'

import { default as Meta } from './meta'
import { default as Record } from './record'

/**
 * Describe a query result returned from E3DB API.
 */
export default class QueryResult {
  constructor(client, query) {
    this.afterIndex = 0
    this.client = client
    this.query = query
  }

  /**
   * Get the next page of results from the current query
   *
   * @returns {Promise<array>}
   */
  async next() {
    let query = this.query
    query.afterIndex = this.afterIndex

    let response = await this.client._query(query)
    let records = await Promise.all(
      response.results.map(async result => {
        let meta = await Meta.decode(result.meta)
        let record = new Record(meta, result.record_data)

        if (query.data) {
          return Crypto.decryptEak(this.config.privateKey, result.access_key).then(ak =>
            Crypto.decryptRecord(record, ak)
          )
        }

        return Promise.resolve(record)
      })
    )

    this.afterIndex = response.last_index

    return Promise.resolve(records)
  }
}
