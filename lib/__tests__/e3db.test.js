const assert = require('assert');
const e3db = require('../index.js');

require('es6-promise').polyfill();
require('isomorphic-fetch');

let token = process.env.REGISTRATION_TOKEN
let apiUrl = process.env.API_URL
var client1, client2

beforeAll(() => {
  let client1CryptoKeys = e3db.Client.generateKeypair()
  let client1SigningKeys = e3db.Client.generateSigningKeypair()
  let client2CryptoKeys = e3db.Client.generateKeypair()
  let client2SigningKeys = e3db.Client.generateSigningKeypair()
  let client1Name = 'js_client_' + Math.random().toString(36).substr(2)
  let client2Name = 'js_client_' + Math.random().toString(36).substr(2)

  let first = e3db.Client.register(token, client1Name, client1CryptoKeys, client1SigningKeys, false, apiUrl)
    .then(client => {
      let config = new e3db.Config(
        client.clientId,
        client.apiKeyId,
        client.apiSecret,
        client1CryptoKeys.publicKey,
        client1CryptoKeys.privateKey,
        apiUrl,
        client1SigningKeys.publicKey,
        client1SigningKeys.privateKey
      )
      client1 = new e3db.Client(config)
    })
  let second = e3db.Client.register(token, client2Name, client2CryptoKeys, client2SigningKeys, false, apiUrl)
    .then(client => {
      let config = new e3db.Config(
        client.clientId,
        client.apiKeyId,
        client.apiSecret,
        client2CryptoKeys.publicKey,
        client2CryptoKeys.privateKey,
        apiUrl,
        client2SigningKeys.publicKey,
        client2SigningKeys.privateKey
      )
      client2 = new e3db.Client(config)
    })

  return Promise.all([first, second])
})

describe('e3db', () => {
  it('defines specific building blocks', () => {
    expect(e3db.Client).toBeDefined()
    expect(e3db.Config).toBeDefined()
    expect(e3db.Crypto).toBeDefined()

    expect(e3db.Meta).toBeDefined()
    expect(e3db.Record).toBeDefined()
    expect(e3db.RecordData).toBeDefined()
    expect(e3db.SignedDocument).toBeDefined()
    expect(e3db.SignedString).toBeDefined()
  })

  it('can register clients', () => {
    let cryptoKeys = e3db.Client.generateKeypair()
    let signingKeys = e3db.Client.generateSigningKeypair()
    let name = 'js_client_test_' + Math.random().toString(36).substr(2)

    return e3db.Client.register(token, name, cryptoKeys, signingKeys, false, apiUrl)
      .then(client => {
        expect(client.name).toBe(name)
        expect(client.publicKey.curve25519).toBe(cryptoKeys.publicKey)

        expect(client.clientId).toBeTruthy()
        expect(client.apiKeyId).toBeTruthy()
        expect(client.apiSecret).toBeTruthy()
      })
  })

  it('can obtain its own client info', () => {
    return client1.clientInfo(client1.config.clientId).then(info => {
      expect(info.clientId).toBe(client1.config.clientId)
    })
  })

  it('can write then read a record', () => {
    let timestamp = (new Date()).toISOString()

    return client1.write('test_record', {
      now: timestamp
    }).then(record => {
      return client1.read(record.meta.recordId)
        .then(second => {
          expect(second.meta.recordId).toBe(record.meta.recordId)
          expect(second.meta.version).toBe(record.meta.version)

          expect(record.data.now).toBe(timestamp)
          expect(second.data.now).toBe(timestamp)
        })
    })
  })

  it('can write, update, then read a record', () => {
    return client1.write('inc_test', {
      counter: '0'
    }).then(record => {
      let oldVersion = record.meta.version
      record.data.counter = '1'
      return client1.update(record).then(updated => {
        expect(updated.data.counter).toBe('1')
        expect(updated.meta.version).not.toBe(oldVersion)
      })
    })
  })

  it('can select fields on a single record', () => {
    return client1.write('field-test', {
      visible: 'this can be read',
      alsovisible: 'so can this',
      hidden: 'this is filtered out'
    }).then(record => {
      return client1.read(record.meta.recordId, ['visible', 'alsovisible'])
        .then(retrieved => {
          expect(retrieved.meta.recordId).toBe(record.meta.recordId)
          expect(retrieved.data.visible).toBeDefined()
          expect(retrieved.data.alsovisible).toBeDefined()
          expect(retrieved.data.hidden).not.toBeDefined()
        })
    })
  })

  it('fails on conflicted updates', () => {
    expect.assertions(1)
    return client1.write('confict_test', {
      data: 'nonsense'
    }).then(record => {
      record.data.data = 'sense'
      return client1.update(record).then(() => {
        record.data.data = 'nope, still nonsense'
        return client1.update(record).catch(e => {
          expect(e.message).toMatch('Conflict')
        })
      })
    })
  })

  it('can query records by type', () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    return client1.write(type, {field: 'this is some data'})
      .then(record => {
        return client1.query(true, null, null, type).next()
          .then(results => {
            expect(results.length).toBeGreaterThanOrEqual(1)
            expect(results[0].meta.recordId).toBe(record.meta.recordId)
          })
      })
  })

  it('can query records by record id and delete', () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    return client1.write(type, {field: 'this is some data'})
      .then(record1 => {
        return client1.write(type, {field: 'this is some other data'})
          .then(record2 => {
            return client1.query(true, null, null, type).next()
              .then(results => {
                expect(results.length).toBeGreaterThanOrEqual(2)
                expect(results[0].meta.type).toBe(type)
                expect(results[1].meta.type).toBe(type)

                return Promise.all([
                  client1.delete(results[0].meta.recordId),
                  client1.delete(results[1].meta.recordId)
                ]).then(() => {
                  return client1.query(true, null, null, type).next()
                    .then(followup => {
                      expect(followup.length).toBe(0)
                    })
                })
              })
          })
      })
  })

  it('can query records by writer id', () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    return client1.write(type, {field: 'this is some data'})
      .then(() => {
        return client1.query(false, client1.config.clientId).next()
          .then(results => {
            expect(results.length).toBeGreaterThanOrEqual(1)
            expect(results[0].meta.writerId).toBe(client1.config.clientId)
          })
      })
  })

  it('can query records by plaintext meta', () => {
    let plainId = 'id-' + Math.random().toString(36).substr(2)
    let query = {eq: {name: 'id', value: plainId}}

    return client1.write('test-plain', {this: 'does not matter'}, {id: plainId})
      .then(record => {
        return client1.query(true, null, null, null, query).next()
          .then(results => {
            expect(results.length).toBeGreaterThanOrEqual(1)
            expect(results[0].meta.recordId).toBe(record.meta.recordId)
          })
      })
  })

  it('can paginate query results', () => {
    let type = 'test-paginate-' + Math.random().toString(36).substr(2)

    return client1.write(type, {field: 'junk data'})
      .then(() => {
        return client1.write(type, {field: 'second junk data'})
          .then(() => {
            let data = true
            let writer = null
            let record = null
            let plain = null
            let pageSize = 1

            let result = client1.query(data, writer, record, type, plain, pageSize)

            return result.next()
              .then(results => {
                expect(results.length).toBe(1)
                let first = results[0]

                return result.next()
                  .then(nextResults => {
                    expect(nextResults.length).toBe(1)
                    expect(nextResults[0].data.field).not.toBe(first.data.field)

                    return result.next()
                      .then(() => {
                        expect(result.done).toBe(true)
                      })
                  })
              })
          })
      })
  })

  it('can share with another client', () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    return client1.write(type, { misc: 'this is a sharing test' })
      .then(record => {
        return client1.share(type, client2.config.clientId)
          .then(() => {
            client2.read(record.meta.recordId)
              .then(actual => {
                expect(actual.meta.recordId).toBe(record.meta.recordId)
                expect(actual.data.misc).toBe(record.data.misc)
              })
          })
      })
  })

  it('can list outgoing sharing', () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    return client1.write(type, {field: 'this is some data'})
      .then(() => {
        return client1.share(type, client2.config.clientId)
          .then(() => {
            let found = false
            return client1.outgoingSharing().then(osp => {
              for (let policy of osp) {
                if (policy.readerId === client2.config.clientId && policy.recordType === type) {
                  found = true
                }
              }

              expect(found).toBe(true)
            })
          })
      })
  })

  it('can list incoming sharing', () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    return client1.write(type, {field: 'this is some data'})
      .then(record => {
        return client1.share(type, client2.config.clientId)
          .then(() => {
            let found = false
            return client2.incomingSharing().then(isp => {
              for (let policy of isp) {
                if (policy.writerId === client1.config.clientId && policy.recordType === type) {
                  found = true
                }
              }

              expect(found).toBe(true)
            })
          })
      })
  })

  it('fails on delete with version conflicts', () => {
    expect.assertions(1)
    return client1.write('delete_confict_test', {
      data: 'nonsense'
    }).then(record => {
      record.data.data = 'nope, still nonsense'
      return client1.update(record).then(() => {
        record.data.data = 'nope, still nonsense'
        return client1.delete(record.meta.recordId, record.meta.version).catch(e => {
          expect(e.message).toMatch('Conflict')
        })
      })
    })
  })
})
