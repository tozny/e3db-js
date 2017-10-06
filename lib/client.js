/*!
 * Tozny e3db
 *
 * LICENSE
 */

/* global fetch */

'use strict'

import 'es6-promise/auto'
import 'isomorphic-fetch'
import sodium from 'libsodium-wrappers'
import { default as helpers } from './helpers'

import { default as Config } from './config'
import { default as ClientDetails } from './types/clientDetails'
import { default as ClientInfo } from './types/clientInfo'
import { default as Meta } from './types/meta'
import { default as Query } from './types/query'
import { default as Record } from './types/record'

const DEFAULT_QUERY_COUNT = 100
const DEFAULT_API_URL = 'https://api.e3db.com'

let authToken = null
let authTokenTimeout = null
let akCache = {}

/**
 * Fallback polyfill to allow for HTTP Basic authentication from either Node
 * or browser-based JavaScript.
 *
 * @param {string} str String to encode as Base64
 */
let btoa = function(str) {
  return new Buffer(str).toString('base64')
}

/**
 * Potentially refresh the authorization token used during requests to the E3DB server.
 *
 * The token will be cached for 10 minutes before being automatically refreshed.
 *
 * @param {Config} config E3DB client configuration
 *
 * @returns {Promise<string>}
 */
function refreshToken(config) {
  if (authToken === null) {
    return fetch(config.apiUrl + '/v1/auth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'x-www-form-urlencoded',
        Authorization: 'Basic ' + btoa(config.apiKeyId + ':' + config.apiSecret)
      },
      body: 'grant_type=client_credentials'
    })
      .then(resp => resp.json())
      .then(json => Promise.resolve(json.access_token))
      .then(token => {
        authToken = token

        authTokenTimeout = setTimeout(() => {
          authToken = null
        }, 10 * 60 * 1000)

        return Promise.resolve(authToken)
      })
  }

  return Promise.resolve(authToken)
}

/**
 * Transparent fetch() wrapper to set up OAuth2 authentication headers
 *
 * @param {Client} client E3DB client instance
 * @param {array}  params Array of parameters to be passed to the fetch request
 *
 * @returns {Promise}
 */
function oauthFetch(client, ...params) {
  return refreshToken(client.config).then(token => {
    let url = params[0]
    let options = params[1]

    options.headers = options.headers || {}
    options.headers.Authorization = 'Bearer ' + token

    return fetch(url, options)
  })
}

/**
 * Check the return status of a fetch request and throw an error if one occurred
 *
 * @param {Response} response
 *
 * @returns {Promise}
 */
function checkStatus(response) {
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
 * @returns {Promise<string|null>} Decrypted access key on success, NULL if no key exists.
 */
function getAccessKey(client, writerId, userId, readerId, type) {
  let cacheKey = `${writerId}.${userId}.${type}`
  if (akCache[cacheKey] !== undefined) {
    return Promise.resolve(akCache[cacheKey])
  }

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
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    }
  ).then(response => {
    if (response.status && response.status === 404) {
      return Promise.resolve(null)
    }

    return checkStatus(response)
      .then(response => response.json())
      .then(eak => decryptEak(client, eak))
      .then(key => {
        akCache[cacheKey] = key
        return Promise.resolve(key)
      })
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
function putAccessKey(client, writerId, userId, readerId, type, ak) {
  return client
    .getClient(readerId)
    .then(clientInfo => {
      let readerKey = clientInfo.publicKey.curve25519
      return encryptAk(client, ak, readerKey)
    })
    .then(eak => {
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
          akCache[cacheKey] = ak

          return Promise.resolve(ak)
        })
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
function deleteAccessKey(client, writerId, userId, readerId, type) {
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
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      }
    }
  )
    .then(checkStatus)
    .then(() => {
      let cacheKey = `${writerId}.${userId}.${type}`
      delete akCache[cacheKey]

      return Promise.resolve(true)
    })
}

/**
 * Decrypt the access key provided for a specific reader so it can be used
 * to further decrypt a protected record.
 *
 * @param {Client} client E3DB client instance
 * @param {object} encryptedAk
 *
 * @return {Promise<string>} Raw binary string of the access key
 */
function decryptEak(client, encryptedAk) {
  let encodedEak = encryptedAk.eak
  let publicKey = helpers.b64decode(encryptedAk.authorizer_public_key.curve25519)
  let privateKey = helpers.b64decode(client.config.privateKey)

  let eak = helpers.b64decode(encodedEak.split('.')[0])
  let nonce = helpers.b64decode(encodedEak.split('.')[1])
  let ak = sodium.crypto_box_open_easy(eak, nonce, publicKey, privateKey)

  return Promise.resolve(ak)
}

/**
 * Encrypt an access key for a given reader.
 *
 * @param {Client} client    E3DB client instance
 * @param {string} ak        Raw binary string of the access key
 * @param {string} readerKey Base64url-encoded public key of the reader
 *
 * @return {Promise<string>} Encrypted and encoded access key.
 */
function encryptAk(client, ak, readerKey) {
  let publicKey = helpers.b64decode(readerKey)
  let privateKey = helpers.b64decode(client.config.privateKey)

  let nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
  let eak = sodium.crypto_box_easy(ak, nonce, publicKey, privateKey)

  let encodedEak = helpers.b64encode(eak) + '.' + helpers.b64encode(nonce)

  return Promise.resolve(encodedEak)
}

/**
 * Fetch the access key for a record type and use it to decrypt a given record.
 *
 * @param {Client} client E3DB client instance
 * @param {Record} record Record to be decrypted
 *
 * @return {Promise<Record>}
 */
function decryptRecord(client, encrypted) {
  return getAccessKey(
    client,
    encrypted.meta.writerId,
    encrypted.meta.userId,
    client.config.clientId,
    encrypted.meta.type
  ).then(ak => {
    if (ak === null) {
      throw new Error('No access key available.')
    }

    return decryptRecordWithKey(encrypted, ak)
  })
}

/**
 * Create a clone of a given record, but decrypting each field in turn based on
 * the provided access key.
 *
 * @param {Record} encrypted Record to be unwrapped
 * @param {string} accessKey Access key to use for decrypting each data key.
 *
 * @return {Promise<Record>}
 */
function decryptRecordWithKey(encrypted, accessKey) {
  // Clone the record meta
  let meta = new Meta(
    encrypted.meta.writerId,
    encrypted.meta.userId,
    encrypted.meta.type,
    encrypted.meta.plain
  )
  meta.recordId = encrypted.meta.recordId
  meta.created = encrypted.meta.created
  meta.lastModified = encrypted.meta.lastModified
  meta.version = encrypted.meta.version
  let decrypted = new Record(meta, {})

  // Decrypt the record data
  for (let key in encrypted.data) {
    if (encrypted.data.hasOwnProperty(key)) {
      let cipher = encrypted.data[key].split('.')

      let edk = helpers.b64decode(cipher[0])
      let edkN = helpers.b64decode(cipher[1])
      let ef = helpers.b64decode(cipher[2])
      let efN = helpers.b64decode(cipher[3])

      let dk = sodium.crypto_secretbox_open_easy(edk, edkN, accessKey)
      let field = sodium.crypto_secretbox_open_easy(ef, efN, dk)

      decrypted.data[key] = String.fromCharCode.apply(null, field)
    }
  }

  return Promise.resolve(decrypted)
}

/**
 * Create a clone of a plaintext record, encrypting each field in turn with a random
 * data key and protecting the data key with a set access key.
 *
 * @param {Client} client E3DB client instance
 * @param {Record} record Record to be encrypted.
 *
 * @return {Promise<Record>}
 */
function encryptRecord(client, record) {
  return getAccessKey(
    client,
    record.meta.writerId,
    record.meta.userId,
    client.config.clientId,
    record.meta.type
  )
    .then(ak => {
      if (ak === null) {
        ak = helpers.randomKey()
        return putAccessKey(
          client,
          record.meta.writerId,
          record.meta.userId,
          client.config.clientId,
          record.meta.type,
          ak
        )
      }

      return Promise.resolve(ak)
    })
    .then(ak => {
      // Clone the record meta
      let meta = new Meta(
        record.meta.writerId,
        record.meta.userId,
        record.meta.type,
        record.meta.plain
      )
      let encrypted = new Record(meta, {})

      // Encrypt the record data
      for (let key in record.data) {
        if (record.data.hasOwnProperty(key)) {
          let field = record.data[key]

          let dk = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
          let efN = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
          let ef = sodium.crypto_secretbox_easy(field, efN, dk)
          let edkN = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
          let edk = sodium.crypto_secretbox_easy(dk, edkN, ak)

          encrypted.data[key] = [edk, edkN, ef, efN].map(helpers.b64encode).join('.')
        }
      }

      return Promise.resolve(encrypted)
    })
}

/**
 * Core client module used to interact with the E3DB API.
 *
 * @property {Config} config E3DB client configuration.
 */
export default class Client {
  constructor(config) {
    this.config = config
  }

  /**
   * Close the client's open connections and clear any timeouts.
   *
   * Typically, objects will be purged from memory automatically by JavaScript. However,
   * integration tests and deeper bindings will need a way to purge any pending timeouts
   * to properly clean up the client.
   */
  close() {
    clearTimeout(authTokenTimeout)
  }

  /**
   * Attempt to find a client based on their email address.
   *
   * @param {string} email Email address of the client to fetch
   *
   * @returns {ClientInfo}
   */
  findClient(email) {
    let query = {
      query: {
        email: email
      }
    }

    return oauthFetch(this, this.config.apiUrl + '/v1/storage/clients/find', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(query)
    })
      .then(checkStatus)
      .then(response => response.json())
      .then(ClientInfo.decode)
  }

  /**
   * Get a client's information based on their ID.
   *
   * @param {string} clientId UUID of the client to fetch
   *
   * @returns {Promise<ClientInfo>}
   */
  getClient(clientId) {
    return oauthFetch(this, this.config.apiUrl + '/v1/storage/clients/' + clientId, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    })
      .then(checkStatus)
      .then(response => response.json())
      .then(ClientInfo.decode)
  }

  /**
   * Retrieve information about a client, primarily its UUID and public key,
   * based either on an already-known client ID or a discoverable client
   * email address.
   *
   * @param {string} client_id
   *
   * @returns {Promise<ClientInfo>}
   */
  clientInfo(clientId) {
    if (/(.+)@(.+){2,}\.(.+){2,}/.test(clientId)) {
      // ID is an email address
      return this.findClient(clientId)
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
  clientKey(clientId) {
    if (clientId === this.clientId) {
      return null
    }

    return this.clientInfo(clientId).then(info => Promise.resolve(info.publicKey))
  }

  /**
   * Read a raw record from the E3DB system and return it, still encrypted, to the
   * original requester.
   *
   * @param {string} recordId
   *
   * @returns {Promise<Record>}
   */
  readRaw(recordId) {
    return oauthFetch(this, this.config.apiUrl + '/v1/storage/records/' + recordId, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    })
      .then(checkStatus)
      .then(response => response.json())
      .then(Record.decode)
  }

  /**
   * Reads a record from the E3DB system and decrypts it automatically.
   *
   * @param {string} recordId
   *
   * @returns {Promise<Record>}
   */
  read(recordId) {
    return this.readRaw(recordId).then(record => decryptRecord(this, record))
  }

  /**
   * Create a new record entry with E3DB.
   *
   * @param {string} type  The content type with which to associate the record.
   * @param {object} data  A hashmap of the data to encrypt and store
   * @param {object} plain Optional hashmap of data to store with the record's meta in plaintext.
   *
   * @return {Promise<Record>}
   */
  write(type, data, plain = {}) {
    // Build the record
    let meta = new Meta(this.config.clientId, this.config.clientId, type, plain)
    let record = new Record(meta, data)

    return encryptRecord(this, record).then(encrypted => {
      return oauthFetch(this, this.config.apiUrl + '/v1/storage/records', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: encrypted.stringify()
      })
        .then(checkStatus)
        .then(response => response.json())
        .then(Record.decode)
        .then(record => decryptRecord(this, record))
    })
  }

  /**
   * Update a record, with optimistic concurrent locking, that already exists in the E3DB system.
   *
   * @param {Record} record Record to be updated.
   *
   * @returns {Promise<Record>} Updated record
   */
  update(record) {
    let recordId = record.meta.recordId
    let version = record.meta.version

    return encryptRecord(this, record).then(encrypted => {
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
    })
  }

  /**
   * Deletes a record from the E3DB system
   *
   * @param {string} recordId
   *
   * @returns {Promise<bool>}
   */
  delete(recordId) {
    return oauthFetch(this, this.config.apiUrl + '/v1/storage/records/' + recordId, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      }
    }).then(response => {
      switch (response.status) {
        case 204:
        case 403:
        case 404:
        case 410:
          return Promise.resolve(true)
        default:
          throw new Error('Error while deleting record data!')
      }
    })
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
  backup(clientId, registrationToken) {
    /* eslint-disable camelcase */
    let credentials = {
      version: '1',
      client_id: '"' + this.config.clientId + '"',
      api_key_id: '"' + this.config.apiKeyId + '"',
      api_secret: '"' + this.config.apiSecret + '"',
      client_email: '""',
      public_key: '"' + this.config.publicKey + '"',
      private_key: '"' + this.config.privateKey + '"',
      api_url: '"' + this.config.apiUrl + '"'
    }
    /* eslint-enable */

    return this.write('tozny.key_backup', credentials, {
      client: this.config.clientId
    }).then(() => {
      return this.share('tozny.key_backup', clientId).then(() => {
        return fetch(
          this.config.apiUrl +
            '/v1/account/backup/' +
            registrationToken +
            '/' +
            this.config.clientId,
          {
            method: 'POST'
          }
        ).then(() => Promise.resolve(true))
      })
    })
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
   * @param {bool}         raw      Flag to skip decryption of data
   * @param {string|array} writer   Select records written by a single writer, a list of writers, or 'all'
   * @param {string|array} record   Select a single record or list of records
   * @param {string|array} type     Select records of a single type or a list of types
   * @param {array}        plain    Associative array of plaintext meta to use as a filter
   * @param {number}       pageSize Number of records to fetch per request
   *
   * @returns {Promise<array>}
   */
  query(
    data = true,
    raw = false,
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

    return oauthFetch(this, this.config.apiUrl + '/v1/storage/search', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: query.stringify()
    })
      .then(checkStatus)
      .then(response => response.json())
      .then(items => {
        return Promise.all(
          items.results.map(result => {
            return Meta.decode(result.meta)
              .then(meta => Promise.resolve(new Record(meta, result.record_data)))
              .then(record => {
                if (data && !raw) {
                  return decryptEak(this, result.access_key).then(ak =>
                    decryptRecordWithKey(record, ak)
                  )
                }

                return Promise.resolve(record)
              })
          })
        )
      })
  }

  /**
   * Grant another E3DB client access to records of a particular type.
   *
   * @param {string} type     Type of records to share
   * @param {string} readerId Client ID or email address of reader to grant access to
   *
   * @returns {Promise<bool>}
   */
  share(type, readerId) {
    if (readerId === this.config.clientId) {
      return Promise.resolve(true)
    } else if (/(.+)@(.+){2,}\.(.+){2,}/.test(readerId)) {
      return this.clientInfo(readerId).then(clientInfo => {
        return this.share(type, clientInfo.clientId)
      })
    }

    let clientId = this.config.clientId
    return getAccessKey(this, clientId, clientId, clientId, type).then(ak => {
      return putAccessKey(this, clientId, clientId, readerId, type, ak).then(() => {
        let policy = { allow: [{ read: {} }] }
        return oauthFetch(
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
          .then(checkStatus)
          .then(() => Promise.resolve(true))
      })
    })
  }

  /**
   * Revoke another E3DB client's access to records of a particular type.
   *
   * @param {string} type     Type of records to share
   * @param {string} readerId Client ID or email address of reader to grant access from
   *
   * @returns {Promise<bool>}
   */
  revoke(type, readerId) {
    if (readerId === this.config.clientId) {
      return Promise.resolve(true)
    } else if (/(.+)@(.+){2,}\.(.+){2,}/.test(readerId)) {
      return this.clientInfo(readerId).then(clientInfo => {
        return this.revoke(type, clientInfo.clientId)
      })
    }

    let clientId = this.config.clientId
    let policy = { deny: [{ read: {} }] }
    return oauthFetch(
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
      .then(checkStatus)
      .then(() => {
        // Delete any existing access keys
        return deleteAccessKey(this, clientId, clientId, readerId, type).then(() =>
          Promise.resolve(true)
        )
      })
  }

  /**
   * Register a new client with a specific account.
   *
   * @param {string}    registrationToken Registration token as presented by the admin console
   * @param {string}    clientName        Distinguishable name to be used for the token in the console
   * @param {PublicKey} publicKey         Curve25519 public key component used for encryption
   * @param {string}    [privateKey]      Optional Curve25519 private key component used to sign the backup key
   * @param {bool}      [backup]          Optional flag to automatically back up the newly-created credentials to the account service
   * @param {string}    [apiUrl]          Base URI for the e3DB API
   *
   * @returns {ClientDetails}
   */
  static register(
    registrationToken,
    clientName,
    publicKey,
    privateKey = null,
    backup = false,
    apiUrl = DEFAULT_API_URL
  ) {
    /* eslint-disable camelcase */
    let payload = {
      token: registrationToken,
      client: {
        name: clientName,
        public_key: publicKey
      }
    }
    /* eslint-enable */

    let backupClientId = false

    return fetch(apiUrl + '/v1/account/e3db/clients/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    })
      .then(checkStatus)
      .then(response => {
        if (response.headers.has('X-Backup-Client')) {
          backupClientId = response.headers.get('X-Backup-Client')
        }

        return response.json()
      })
      .then(ClientDetails.decode)
      .then(details => {
        if (backup && backupClientId) {
          if (privateKey === null) {
            throw new Error('Cannot back up credentials without a private key!')
          }

          let config = new Config(
            details.clientId,
            details.apiKeyId,
            details.apiSecret,
            publicKey.curve25519,
            privateKey,
            apiUrl
          )
          let client = new Client(config)
          return client.backup(backupClientId, registrationToken).then(() => {
            client.close()

            return Promise.resolve(details)
          })
        }

        return Promise.resolve(details)
      })
  }

  /**
   * Dynamically generate a Curve25519 keypair for use with registration and cryptographic operations
   *
   * @return {array} Tuple of [public_key, private_key], both Base64URL-encoded.
   */
  static generateKeypair() {
    let keypair = sodium.crypto_box_keypair()

    return [helpers.b64encode(keypair.publicKey), helpers.b64encode(keypair.privateKey)]
  }
}
