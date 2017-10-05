const assert = require('assert');
const e3db = require('../index.js');

require('es6-promise').polyfill();
require('isomorphic-fetch');

let token = process.env.REGISTRATION_TOKEN
let apiUrl = process.env.API_URL
var client1, client2

beforeAll(() => {
  let [client1PublicKey, client1PrivateKey] = e3db.Client.generateKeypair()
  let [client2PublicKey, client2PrivateKey] = e3db.Client.generateKeypair()
  client1PublicKey = new e3db.PublicKey(client1PublicKey)
  client2PublicKey = new e3db.PublicKey(client2PublicKey)
  let client1Name = 'js_client_' + Math.random().toString(36).substr(2)
  let client2Name = 'js_client_' + Math.random().toString(36).substr(2)

  let first = e3db.Client.register(token, client1Name, client1PublicKey, null, false, apiUrl)
    .then(client => {
      let config = new e3db.Config(
        client.clientId,
        client.apiKeyId,
        client.apiSecret,
        client.publicKey.curve25519,
        client1PrivateKey,
        apiUrl
      )
      client1 = new e3db.Client(config)
    })
  let second = e3db.Client.register(token, client2Name, client2PublicKey, null, false, apiUrl)
    .then(client => {
      let config = new e3db.Config(
        client.clientId,
        client.apiKeyId,
        client.apiSecret,
        client.publicKey.curve25519,
        client2PrivateKey,
        apiUrl
      )
      client2 = new e3db.Client(config)
    })

  return Promise.all([first, second])
})

afterAll(() => {
  client1.close()
  client2.close()
})

describe('e3db', () => {
  it('defines specific building blocks', () => {
    expect(e3db.Client).toBeDefined()
    expect(e3db.Config).toBeDefined()
    expect(e3db.PublicKey).toBeDefined()
  })

  it('can register clients', () => {
    let [publicKey] = e3db.Client.generateKeypair()
    publicKey = new e3db.PublicKey(publicKey)
    let name = 'js_client_test_' + Math.random().toString(36).substr(2)

    return e3db.Client.register(token, name, publicKey, null, false, apiUrl)
      .then(client => {
        expect(client.name).toBe(name)
        expect(client.publicKey.curve25519).toBe(publicKey.curve25519)

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

  xit('can query records by type', () => {
    assert(false)
  })

  xit('can query records from any writer', () => {
    assert(false)
  })

  xit('can query records by record id and delete', () => {
    assert(false)
  })

  xit('can query records by writer id', () => {
    assert(false)
  })

  xit('can query records by plaintext meta', () => {
    assert(false)
  })

  xit('can share with another client', () => {
    assert(false)
  })
})
