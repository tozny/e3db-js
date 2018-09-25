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

/* global fetch */

'use strict'

import 'es6-promise/auto'
import 'isomorphic-fetch'
import sodium from 'libsodium-wrappers'
import { default as Crypto } from './crypto'

import { default as Config } from './config'
import { default as ClientDetails } from './types/clientDetails'
import { default as ClientInfo } from './types/clientInfo'
import { default as EAKInfo } from './types/eakInfo'
import { default as IncomingSharingPolicy } from './types/incomingSharingPolicy'
import { default as KeyPair } from './types/keyPair'
import { default as Meta } from './types/meta'
import { default as OutgoingSharingPolicy } from './types/outgoingSharingPolicy'
import { default as PublicKey } from './types/publicKey'
import { default as Query } from './types/query'
import { default as QueryResult } from './types/queryResult'
import { default as Record } from './types/record'
import { default as RecordData } from './types/recordData'
import { default as RecordInfo } from './types/recordInfo'
import { default as SignedDocument } from './types/signedDocument'
import { default as SigningKey } from './types/signingKey'

const DEFAULT_QUERY_COUNT = 100
const DEFAULT_API_URL = 'https://api.e3db.com'
const EMAIL = /(.+)@(.+){2,}\.(.+){2,}/

/* eslint-disable no-buffer-constructor */

/**
 * Fallback polyfill to allow for HTTP Basic authentication from either Node
 * or browser-based JavaScript.
 *
 * @param {string} str String to encode as Base64
 */
let btoa = function(str) {
  return new Buffer(str).toString('base64')
}

/* eslint-enable */

/**
 * Potentially refresh the authorization token used during requests to the E3DB server.
 *
 * The token will be cached for 10 minutes before being automatically refreshed.
 *
 * @param {Config} config E3DB client configuration
 *
 * @returns {Promise<string>}
 */
async function getToken(client) {
  if (client._authToken === null || Date.now() > client._authTokenTimeout) {
    let response = await fetch(client.config.apiUrl + '/v1/auth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'x-www-form-urlencoded',
        Authorization:
          'Basic ' + btoa(client.config.apiKeyId + ':' + client.config.apiSecret)
      },
      body: 'grant_type=client_credentials'
    })
    let json = await response.json()

    client._authToken = json.access_token
    client._authTokenTimeout = Date.parse(json.expires_at)

    return client._authToken
  }

  return Promise.resolve(client._authToken)
}

/**
 * Transparent fetch() wrapper to set up OAuth2 authentication headers
 *
 * @param {Client} client  E3DB client instance
 * @param {string} url     Absolute URL to fetch from the server
 * @param {object} options Object representing additional settings for the fetch
 *
 * @returns {Promise}
 */
async function oauthFetch(client, url, options) {
  let token = await getToken(client)

  options.headers = options.headers || {}
  options.headers.Authorization = 'Bearer ' + token

  return fetch(url, options)
}

/**
 * Check the return status of a fetch request and throw an error if one occurred
 *
 * @param {Response} response
 *
 * @returns {Promise}
 */
async function checkStatus(response) {
  if (response.status >= 200 && response.status < 300) {
    return Promise.resolve(response)
  }

  let error = new Error(response.statusText)
  error.response = response
  throw error
}

/**
 * Retrieve an access key from the server.
 *
 * @param {Client} client E3DB client instance
 * @param {string} writerId Writer/Authorizer for the access key
 * @param {string} userId   Record subject
 * @param {string} readerId Authorized reader
 * @param {string} type     Record type for which the key will be used
 *
 * @returns {Promise<EAKInfo|null>} Encrypted access key on success, NULL if no key exists.
 */
async function getEncryptedAccessKey(client, writerId, userId, readerId, type) {
  let response = await oauthFetch(
    client,
    client.config.apiUrl +
      '/v1/storage/access_keys/' +
      writerId +
      '/' +
      userId +
      '/' +
      readerId +
      '/' +
      type,
    {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    }
  )

  if (response.status && response.status === 404) {
    return Promise.resolve(null)
  }

  return checkStatus(response)
    .then(response => response.json())
    .then(eak => EAKInfo.decode(eak))
}

/**
 * Retrieve an access key from the server.
 *
 * @param {Client} client E3DB client instance
 * @param {string} writerId Writer/Authorizer for the access key
 * @param {string} userId   Record subject
 * @param {string} readerId Authorized reader
 * @param {string} type     Record type for which the key will be used
 *
 * @returns {Promise<string|null>} Decrypted access key on success, NULL if no key exists.
 */
async function getAccessKey(client, writerId, userId, readerId, type) {
  let cacheKey = `${writerId}.${userId}.${type}`
  if (client._akCache[cacheKey] !== undefined) {
    return Promise.resolve(client._akCache[cacheKey])
  }

  return getEncryptedAccessKey(client, writerId, userId, readerId, type)
    .then(eak => {
      if (eak === null) {
        return Promise.resolve(null)
      }

      return Crypto.decryptEak(client.config.privateKey, eak)
    })
    .then(key => {
      if (key !== null) {
        client._akCache[cacheKey] = key
      }

      return Promise.resolve(key)
    })
}

/**
 * Create an access key on the server.
 *
 * @param {Client} client   E3DB client instance
 * @param {string} writerId Writer/Authorizer for the access key
 * @param {string} userId   Record subject
 * @param {string} readerId Authorized reader
 * @param {string} type     Record type for which the key will be used
 * @param {string} ak       Unencrypted access key

 @returns {Promise<string>} Decrypted access key
 */
async function putAccessKey(client, writerId, userId, readerId, type, ak) {
  let clientInfo = await client.getClient(readerId)
  let readerKey = clientInfo.publicKey.curve25519
  let eak = await Crypto.encryptAk(client.config.privateKey, ak, readerKey)

  return oauthFetch(
    client,
    client.config.apiUrl +
      '/v1/storage/access_keys/' +
      writerId +
      '/' +
      userId +
      '/' +
      readerId +
      '/' +
      type,
    {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ eak: eak })
    }
  )
    .then(checkStatus)
    .then(() => {
      let cacheKey = `${writerId}.${userId}.${type}`
      client._akCache[cacheKey] = ak

      return Promise.resolve(ak)
    })
}

/**
 * Delete an access key on the server.
 *
 * @param {Client} client   E3DB client instance
 * @param {string} writerId Writer/Authorizer for the access key
 * @param {string} userId   Record subject
 * @param {string} readerId Authorized reader
 * @param {string} type     Record type for which the key will be used
 *
 * @returns {Promise<bool>}
 */
async function deleteAccessKey(client, writerId, userId, readerId, type) {
  let request = await oauthFetch(
    client,
    client.config.apiUrl +
      '/v1/storage/access_keys/' +
      writerId +
      '/' +
      userId +
      '/' +
      readerId +
      '/' +
      type,
    {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      }
    }
  )

  await checkStatus(request)

  let cacheKey = `${writerId}.${userId}.${type}`
  delete client._akCache[cacheKey]

  return true
}

/**
 * Fetch the access key for a record type and use it to decrypt a given record.
 *
 * @param {Client} client E3DB client instance
 * @param {Record} encrypted Record to be decrypted
 *
 * @return {Promise<Record>}
 */
async function decryptRecord(client, encrypted) {
  let ak = await getAccessKey(
    client,
    encrypted.meta.writerId,
    encrypted.meta.userId,
    client.config.clientId,
    encrypted.meta.type
  )

  if (ak === null) {
    throw new Error('No access key available.')
  }

  return Crypto.decryptRecord(encrypted, ak)
}

/**
 * Fetch the access key for a record type and use it to encrypt a given record.
 *
 * @param {Client} client E3DB client instance
 * @param {Record} record Record to be decrypted
 *
 * @return {Promise<Record>}
 */
async function encryptRecord(client, record) {
  let ak = await getAccessKey(
    client,
    record.meta.writerId,
    record.meta.userId,
    client.config.clientId,
    record.meta.type
  )

  if (ak === null) {
    ak = await Crypto.randomKey()
    await putAccessKey(
      client,
      record.meta.writerId,
      record.meta.userId,
      client.config.clientId,
      record.meta.type,
      ak
    )
  }

  return Crypto.encryptRecord(record, ak)
}

/**
 * Core client module used to interact with the E3DB API.
 *
 * @property {Config} config E3DB client configuration.
 */
export default class Client {
  constructor(config) {
    this.config = config
    this._authToken = null
    this._authTokenTimeout = 0 // Minimum UNIX timestamp
    this._akCache = {}
  }

  /**
   * Get an access key from the cache if it exists, otherwise decrypt
   * the provided EAK and populate the cache.
   *
   * @param {string}  writerId
   * @param {string}  userId
   * @param {string}  readerId
   * @param {string}  type
   * @param {EAKInfo} eak
   *
   * @returns {Promise<string>}
   */
  async _getCachedAk(writerId, userId, readerId, type, eak) {
    let cacheKey = `${writerId}.${userId}.${type}`
    let ak = this._akCache[cacheKey]

    if (ak === undefined) {
      ak = await Crypto.decryptEak(this.config.privateKey, eak)
      this._akCache[cacheKey] = ak
    }

    return Promise.resolve(ak)
  }

  /**
   * Get a client's information based on their ID.
   *
   * @param {string} clientId UUID of the client to fetch
   *
   * @returns {Promise<ClientInfo>}
   */
  async getClient(clientId) {
    let request = await oauthFetch(
      this,
      this.config.apiUrl + '/v1/storage/clients/' + clientId,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      }
    )

    let response = await checkStatus(request)

    let json = await response.json()

    return ClientInfo.decode(json)
  }

  /**
   * Create a key for the current client as a writer if one does not exist
   * in the cache already. If no access key does exist, create a random one
   * and store it with the server.
   *
   * @param {string} type Record type for this key
   *
   * @returns {Promise<EAKInfo>}
   */
  async createWriterKey(type) {
    let ak = await getAccessKey(
      this,
      this.config.clientId,
      this.config.clientId,
      this.config.clientId,
      type
    )

    if (ak === null) {
      ak = await Crypto.randomKey()
      await putAccessKey(
        this,
        this.config.clientId,
        this.config.clientId,
        this.config.clientId,
        type,
        ak
      )
    }

    let eak = await Crypto.encryptAk(this.config.privateKey, ak, this.config.publicKey)

    return new EAKInfo(
      eak,
      this.config.clientId,
      this.config.publicKey,
      this.config.clientId,
      this.config.publicSignKey
    )
  }

  /**
   * Get a key for the current client as the reader of a specific record written by someone else.
   *
   * @param {string} writerId Writer of the record in the database
   * @param {string} userID   Subject of the record in the database
   * @param {string} type     Type of record
   *
   * @returns {Promise<EAKInfo>}
   */
  async getReaderKey(writerId, userId, type) {
    return getEncryptedAccessKey(this, writerId, userId, this.config.clientId, type)
  }

  /**
   * Retrieve information about a client, primarily its UUID and public key,
   * based either on an already-known client ID or a discoverable client
   * email address.
   *
   * @param {string} clientId
   *
   * @returns {Promise<ClientInfo>}
   */
  async clientInfo(clientId) {
    if (EMAIL.test(clientId)) {
      // ID is an email address
      throw new Error('Client discovery by email address is not supported')
    }

    return this.getClient(clientId)
  }

  /**
   * Retrieve the Curve 25519 public key associated with a known client.
   *
   * @param {string} clientId
   *
   * @returns {Promise<PublicKey>}
   */
  async clientKey(clientId) {
    if (clientId === this.clientId) {
      return Promise.resolve(null)
    }

    let info = await this.clientInfo(clientId)
    return Promise.resolve(info.publicKey)
  }

  /**
   * Reads a record from the E3DB system and decrypts it automatically.
   *
   * @param {string} recordId
   * @param {array}  [fields] Optional fields to select on the record
   *
   * @returns {Promise<Record>}
   */
  async read(recordId, fields = null) {
    let path = this.config.apiUrl + '/v1/storage/records/' + recordId

    if (fields !== null) {
      let mapped = []
      for (let field of fields) {
        mapped.push('field=' + field)
      }

      path += '?' + mapped.join('&')
    }

    let request = await oauthFetch(this, path, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    let response = await checkStatus(request)
    let json = await response.json()
    let record = await Record.decode(json)
    return decryptRecord(this, record)
  }

  /**
   * Create a new record entry with E3DB.
   *
   * @param {string} type  The content type with which to associate the record.
   * @param {object} data  A hashmap of the data to encrypt and store
   * @param {object} plain Optional hashmap of data to store with the record's meta in plaintext
   *
   * @return {Promise<Record>}
   */
  async write(type, data, plain = {}) {
    // Build the record
    if (data instanceof Object) {
      data = new RecordData(data)
    }

    let meta = new Meta(this.config.clientId, this.config.clientId, type, plain)
    let info = new RecordInfo(meta, data)

    let signature = this.config.version > 1 ? await this.sign(info) : null
    let record = new Record(meta, data, signature)

    let encrypted = await encryptRecord(this, record)

    return this.writeRaw(encrypted)
  }

  /**
   * Write a previously stored encrypted/signed record directly to E3DB.
   *
   * @param {Record} record The fully-constructed record object, as returned by `encrypt()`
   *
   * @return {Promise<Record>}
   */
  async writeRaw(record) {
    if (!(record instanceof Record)) {
      throw new Error('Can only write encrypted/signed records directly to the server!')
    }

    let request = await oauthFetch(this, this.config.apiUrl + '/v1/storage/records', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: record.stringify()
    })

    let response = await checkStatus(request)
    let json = await response.json()
    let written = await Record.decode(json)
    return decryptRecord(this, written)
  }

  /**
   * Encrypt a plaintext record using the AK wrapped and encrypted for the current
   * client. The key will be cached for future use.
   *
   * @param {string}            type  The content type with which to associate the record.
   * @param {RecordData|object} data  A hashmap of the data to encrypt and store
   * @param {object}            eak   Encrypted access key instance
   * @param {object}            plain Optional hashmap of data to store with the record's meta in plaintext
   *
   * @returns {Promise<Record>}
   */
  async encrypt(type, data, eak, plain = {}) {
    let ak = await this._getCachedAk(
      this.config.clientId,
      this.config.clientId,
      this.config.clientId,
      type,
      eak
    )

    if (data instanceof Object) {
      data = new RecordData(data)
    }

    // Build the record
    let meta = new Meta(this.config.clientId, this.config.clientId, type, plain)
    let recordInfo = new RecordInfo(meta, data)
    let signature = this.config.version > 1 ? await this.sign(recordInfo) : null
    let record = new Record(meta, data, signature)

    return Crypto.encryptRecord(record, ak)
  }

  /**
   * Sign a document and return the signature
   *
   * @param {Signable} document Serializable object to be signed.
   *
   * @returns {Promise<string>}
   */
  async sign(document) {
    if (this.config.version === 1) {
      throw new Error('Cannot sign documents without a signing key!')
    }

    return Crypto.signDocument(document, this.config.privateSignKey)
  }

  /**
   * Decrypt an encrypted record using the AK wrapped and encrypted for the current
   * client. The key will be cached for future use.
   *
   * @param {Record}  record Record instance with encrypted data for decryption
   * @param {EAKInfo} eak    Encrypted access key instance
   *
   * @returns {Promise<Record>}
   */
  async decrypt(record, eak) {
    if (eak.signerSigningKey === null) {
      throw new Error('EAKInfo has no signing key!')
    }

    let ak = await this._getCachedAk(
      record.meta.writerId,
      record.meta.userId,
      this.config.clientId,
      record.meta.type,
      eak
    )

    let decrypted = await Crypto.decryptRecord(record, ak)
    let info = new RecordInfo(decrypted.meta, decrypted.data)
    let signed = new SignedDocument(info, decrypted.signature)

    let verify = await this.verify(signed, eak.signerSigningKey.ed25519)
    if (!verify) {
      throw new Error('Document failed verification')
    }

    return decrypted
  }

  /**
   * Verify the signature attached to a specific document.
   *
   * @param {SignedDocument} signed        Document with an attached signature
   * @param {string}         publicSignKey Key to use during signature verification
   *
   * @returns {Promise<bool>}
   */
  async verify(signed, publicSignKey) {
    let verified = await Crypto.verifyDocumentSignature(
      signed.document,
      signed.signature,
      publicSignKey
    )

    return Promise.resolve(verified)
  }

  /**
   * Update a record, with optimistic concurrent locking, that already exists in the E3DB system.
   *
   * @param {Record} record Record to be updated.
   *
   * @returns {Promise<Record>} Updated record
   */
  async update(record) {
    let recordId = record.meta.recordId
    let version = record.meta.version

    // Update record signature
    let recordInfo = new RecordInfo(record.meta, record.data)
    record.signature = this.config.version > 1 ? await this.sign(recordInfo) : null

    let encrypted = await encryptRecord(this, record)

    return oauthFetch(
      this,
      this.config.apiUrl + '/v1/storage/records/safe/' + recordId + '/' + version,
      {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: encrypted.stringify()
      }
    )
      .then(checkStatus)
      .then(response => response.json())
      .then(Record.decode)
      .then(record => decryptRecord(this, record))
  }

  /**
   * Deletes a record from the E3DB system
   *
   * @param {string} recordId  ID of the record to remove
   * @param {string} [version] Optional version ID to remove safely
   *
   * @returns {Promise<bool>}
   */
  async delete(recordId, version = null) {
    let url = this.config.apiUrl + '/v1/storage/records/' + recordId
    if (version !== null) {
      url = this.config.apiUrl + '/v1/storage/records/safe/' + recordId + '/' + version
    }

    let response = await oauthFetch(this, url, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      }
    })

    switch (response.status) {
      case 204:
      case 403:
        return Promise.resolve(true)
      case 409:
        throw new Error('Conflict')
      default:
        throw new Error('Error while deleting record data!')
    }
  }

  /**
   * Back up the client's configuration to E3DB in a serialized format that can be read
   * by the Admin Console. The stored configuration will be shared with the specified client,
   * and the account service notified that the sharing has taken place.
   *
   * @param {string} clientId          Unique ID of the client to which we're backing up
   * @param {string} registrationToken Original registration token used to create the client
   *
   * @returns {Promise<bool>}
   */
  async backup(clientId, registrationToken) {
    /* eslint-disable camelcase */
    let credentials = {
      version: '"' + this.config.version.toString() + '"',
      client_id: '"' + this.config.clientId + '"',
      api_key_id: '"' + this.config.apiKeyId + '"',
      api_secret: '"' + this.config.apiSecret + '"',
      client_email: '""',
      public_key: '"' + this.config.publicKey + '"',
      private_key: '"' + this.config.privateKey + '"'
    }

    if (this.config.version === 2) {
      credentials.public_sign_key = '"' + this.config.publicSignKey + '"'
      credentials.private_sign_key = '"' + this.config.privateSignKey + '"'
    }

    credentials.api_url = '"' + this.config.apiUrl + '"'
    /* eslint-enable */

    await this.write('tozny.key_backup', credentials, {
      client: this.config.clientId
    })

    await this.share('tozny.key_backup', clientId)

    await fetch(
      this.config.apiUrl +
        '/v1/account/backup/' +
        registrationToken +
        '/' +
        this.config.clientId,
      {
        method: 'POST'
      }
    )

    return Promise.resolve(true)
  }

  /**
   * Query E3DB records according to a set of selection criteria.
   *
   * The default behavior is to return all records written by the
   * current authenticated client.
   *
   * To restrict the results to a particular type, pass a type or
   * list of types as the `type` argument.
   *
   * To restrict the results to a set of clients, pass a single or
   * list of client IDs as the `writer` argument. To list records
   * written by any client that has shared with the current client,
   * pass the special string 'all' as the `writer` argument.
   *
   * @param {bool}         data     Flag to include data in records
   * @param {string|array} writer   Select records written by a single writer, a list of writers, or 'all'
   * @param {string|array} record   Select a single record or list of records
   * @param {string|array} type     Select records of a single type or a list of types
   * @param {array}        plain    Associative array of plaintext meta to use as a filter
   * @param {number}       pageSize Number of records to fetch per request
   *
   * @returns {QueryResult}
   */
  query(
    data = true,
    writer = null,
    record = null,
    type = null,
    plain = null,
    pageSize = DEFAULT_QUERY_COUNT
  ) {
    let allWriters = false
    if (writer === 'all') {
      allWriters = true
      writer = []
    }

    let query = new Query(
      0,
      data,
      writer,
      record,
      type,
      plain,
      null,
      pageSize,
      allWriters
    )

    return new QueryResult(this, query)
  }

  /**
   * Internal-only method to execute a query against the server and parse the response.
   *
   * @param {Query} query Query request to execute against the server
   *
   * @returns {QueryResult}
   */
  async _query(query) {
    let response = await oauthFetch(this, this.config.apiUrl + '/v1/storage/search', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: query.stringify()
    })
    await checkStatus(response)
    return response.json()
  }

  /**
   * Grant another E3DB client access to records of a particular type.
   *
   * @param {string} type     Type of records to share
   * @param {string} readerId Client ID or email address of reader to grant access to
   *
   * @returns {Promise<bool>}
   */
  async share(type, readerId) {
    if (readerId === this.config.clientId) {
      return Promise.resolve(true)
    }
    if (EMAIL.test(readerId)) {
      let clientInfo = await this.clientInfo(readerId)
      return this.share(type, clientInfo.clientId)
    }

    let clientId = this.config.clientId
    let ak = await getAccessKey(this, clientId, clientId, clientId, type)

    if (ak === null) {
      ak = await Crypto.randomKey()
      await putAccessKey(
        this,
        this.config.clientId,
        this.config.clientId,
        this.config.clientId,
        type,
        ak
      )
    }

    await putAccessKey(this, clientId, clientId, readerId, type, ak)
    let policy = { allow: [{ read: {} }] }

    let request = await oauthFetch(
      this,
      this.config.apiUrl +
        '/v1/storage/policy/' +
        clientId +
        '/' +
        clientId +
        '/' +
        readerId +
        '/' +
        type,
      {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(policy)
      }
    )
    await checkStatus(request)

    return Promise.resolve(true)
  }

  /**
   * Revoke another E3DB client's access to records of a particular type.
   *
   * @param {string} type     Type of records to share
   * @param {string} readerId Client ID or email address of reader to grant access from
   *
   * @returns {Promise<bool>}
   */
  async revoke(type, readerId) {
    if (readerId === this.config.clientId) {
      return Promise.resolve(true)
    }
    if (EMAIL.test(readerId)) {
      let clientInfo = await this.clientInfo(readerId)
      return this.revoke(type, clientInfo.clientId)
    }

    let clientId = this.config.clientId
    let policy = { deny: [{ read: {} }] }
    let request = await oauthFetch(
      this,
      this.config.apiUrl +
        '/v1/storage/policy/' +
        clientId +
        '/' +
        clientId +
        '/' +
        readerId +
        '/' +
        type,
      {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(policy)
      }
    )
    await checkStatus(request)

    // Delete any existing access keys
    await deleteAccessKey(this, clientId, clientId, readerId, type)

    return Promise.resolve(true)
  }

  /**
   * Get a list of all outgoing sharing policy relationships
   *
   * @returns {Promise<array>}
   */
  async outgoingSharing() {
    let request = await oauthFetch(
      this,
      this.config.apiUrl + '/v1/storage/policy/outgoing',
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      }
    )
    let response = await checkStatus(request)
    let json = await response.json()

    return Promise.all(json.map(OutgoingSharingPolicy.decode))
  }

  /**
   * Get a list of all incoming sharing policy relationships
   *
   * @returns {Promise<array>}
   */
  async incomingSharing() {
    let request = await oauthFetch(
      this,
      this.config.apiUrl + '/v1/storage/policy/incoming',
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      }
    )
    let response = await checkStatus(request)
    let json = await response.json()

    return Promise.all(json.map(IncomingSharingPolicy.decode))
  }

  /**
   * Register a new client with a specific account.
   *
   * @param {string}  registrationToken Registration token as presented by the admin console
   * @param {string}  clientName        Distinguishable name to be used for the token in the console
   * @param {KeyPair} cryptoKeys        Curve25519 keypair used for encryption
   * @param {KeyPair} signingKeys       Ed25519 keypair used for signing
   * @param {bool}    [backup]          Optional flag to automatically back up the newly-created credentials to the account service
   * @param {string}  [apiUrl]          Base URI for the e3DB API
   *
   * @returns {ClientDetails}
   */
  static async register(
    registrationToken,
    clientName,
    cryptoKeys,
    signingKeys,
    backup = false,
    apiUrl = DEFAULT_API_URL
  ) {
    /* eslint-disable camelcase */
    let payload = {
      token: registrationToken,
      client: {
        name: clientName,
        public_key: new PublicKey(cryptoKeys.publicKey),
        signing_key: new SigningKey(signingKeys.publicKey)
      }
    }
    /* eslint-enable */

    let backupClientId = false

    let request = await fetch(apiUrl + '/v1/account/e3db/clients/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    })
    let response = await checkStatus(request)
    if (response.headers.has('X-Backup-Client')) {
      backupClientId = response.headers.get('X-Backup-Client')
    }

    let json = await response.json()
    let details = await ClientDetails.decode(json)

    if (backup && backupClientId) {
      if (cryptoKeys.privateKey === null) {
        throw new Error('Cannot back up credentials without a private key!')
      }

      let config = new Config(
        details.clientId,
        details.apiKeyId,
        details.apiSecret,
        cryptoKeys.publicKey,
        cryptoKeys.privateKey,
        apiUrl,
        signingKeys.publicKey,
        signingKeys.privateKey
      )
      let client = new Client(config)
      await client.backup(backupClientId, registrationToken)
    }

    return Promise.resolve(details)
  }

  /**
   * Dynamically generate a Curve25519 keypair for use with registration and cryptographic operations
   *
   * @returns {KeyPair} Base64URL-encoded representation of the new keypair
   */
  static async generateKeypair() {
    await sodium.ready
    let keypair = sodium.crypto_box_keypair()

    return new KeyPair(
      await Crypto.b64encode(keypair.publicKey),
      await Crypto.b64encode(keypair.privateKey)
    )
  }

  /**
   * Dynamically generate an Ed25519 keypair for use with registration and signing operations
   *
   * @returns {KeyPair} Base64URL-encoded representation of the new keypair
   */
  static async generateSigningKeypair() {
    await sodium.ready
    let keypair = sodium.crypto_sign_keypair()

    return new KeyPair(
      await Crypto.b64encode(keypair.publicKey),
      await Crypto.b64encode(keypair.privateKey)
    )
  }
}
