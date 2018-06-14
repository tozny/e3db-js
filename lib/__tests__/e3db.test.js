const e3db = require('../index.js');

require('es6-promise').polyfill();
require('isomorphic-fetch');

let token = process.env.REGISTRATION_TOKEN
let apiUrl = process.env.API_URL
let client1, client2

beforeAll(async (done) => {
  let client1CryptoKeys = await e3db.Client.generateKeypair()
  let client1SigningKeys = await e3db.Client.generateSigningKeypair()
  let client2CryptoKeys = await e3db.Client.generateKeypair()
  let client2SigningKeys = await e3db.Client.generateSigningKeypair()
  let client1Name = 'js_client_' + Math.random().toString(36).substr(2)
  let client2Name = 'js_client_' + Math.random().toString(36).substr(2)

  let client1Info = await e3db.Client.register(token, client1Name, client1CryptoKeys, client1SigningKeys, false, apiUrl)

  let client1Config = new e3db.Config(
    client1Info.clientId,
    client1Info.apiKeyId,
    client1Info.apiSecret,
    client1CryptoKeys.publicKey,
    client1CryptoKeys.privateKey,
    apiUrl,
    client1SigningKeys.publicKey,
    client1SigningKeys.privateKey
  )
  client1 = new e3db.Client(client1Config)

  let client2Info = await e3db.Client.register(token, client2Name, client2CryptoKeys, client2SigningKeys, false, apiUrl)

  let client2Config = new e3db.Config(
    client2Info.clientId,
    client2Info.apiKeyId,
    client2Info.apiSecret,
    client2CryptoKeys.publicKey,
    client2CryptoKeys.privateKey,
    apiUrl,
    client2SigningKeys.publicKey,
    client2SigningKeys.privateKey
  )
  client2 = new e3db.Client(client2Config)

  done()
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

  it('can register clients', async () => {
    let cryptoKeys = await e3db.Client.generateKeypair()
    let signingKeys = await e3db.Client.generateSigningKeypair()
    let name = 'js_client_test_' + Math.random().toString(36).substr(2)

    let client = await e3db.Client.register(token, name, cryptoKeys, signingKeys, false, apiUrl)

    expect(client.name).toBe(name)
    expect(client.publicKey.curve25519).toBe(cryptoKeys.publicKey)

    expect(client.clientId).toBeTruthy()
    expect(client.apiKeyId).toBeTruthy()
    expect(client.apiSecret).toBeTruthy()
  })

  it('can obtain its own client info', async () => {
    let info = await client1.clientInfo(client1.config.clientId)

    expect(info.clientId).toBe(client1.config.clientId)
  })

  it('can write then read a record', async () => {
    let timestamp = (new Date()).toISOString()

    let record = await client1.write('test_record', {
      now: timestamp
    })

    let second = await client1.read(record.meta.recordId)
    expect(second.meta.recordId).toBe(record.meta.recordId)
    expect(second.meta.version).toBe(record.meta.version)

    expect(record.data.now).toBe(timestamp)
    expect(second.data.now).toBe(timestamp)
  })

  it('can write, update, then read a record', async () => {
    let record = await client1.write('inc_test', {
      counter: '0'
    })

    let oldVersion = record.meta.version
    record.data.counter = '1'

    let updated = await client1.update(record)
    expect(updated.data.counter).toBe('1')
    expect(updated.meta.version).not.toBe(oldVersion)
  })

  it('can select fields on a single record', async () => {
    let record = await client1.write('field-test', {
      visible: 'this can be read',
      alsovisible: 'so can this',
      hidden: 'this is filtered out'
    })

    let retrieved = await client1.read(record.meta.recordId, ['visible', 'alsovisible'])
    expect(retrieved.meta.recordId).toBe(record.meta.recordId)
    expect(retrieved.data.visible).toBeDefined()
    expect(retrieved.data.alsovisible).toBeDefined()
    expect(retrieved.data.hidden).not.toBeDefined()
  })

  it('fails on conflicted updates', async () => {
    expect.assertions(1)

    let record = await client1.write('confict_test', {
      data: 'nonsense'
    })
    record.data.data = 'sense'

    await client1.update(record)

    record.data.data = 'nope, still nonsense'

    try {
      await client1.update(record)
    } catch (e) {
      expect(e.message).toMatch('Conflict')
    }
  })

  it('can query records by type', async () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    let record = await client1.write(type, {field: 'this is some data'})

    let results = await client1.query(true, null, null, type).next()
    expect(results.length).toBeGreaterThanOrEqual(1)
    expect(results[0].meta.recordId).toBe(record.meta.recordId)
  })

  it('can query records by record id and delete', async () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    await client1.write(type, {field: 'this is some data'})
    await client1.write(type, {field: 'this is some other data'})

    let results = await client1.query(true, null, null, type).next()
    expect(results.length).toBeGreaterThanOrEqual(2)
    expect(results[0].meta.type).toBe(type)
    expect(results[1].meta.type).toBe(type)

    await client1.delete(results[0].meta.recordId)
    await client1.delete(results[1].meta.recordId)

    let followup = await client1.query(true, null, null, type).next()
    expect(followup.length).toBe(0)
  })

  it('can query records by writer id', async () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    await client1.write(type, {field: 'this is some data'})
    let results = await client1.query(false, client1.config.clientId).next()
    expect(results.length).toBeGreaterThanOrEqual(1)
    expect(results[0].meta.writerId).toBe(client1.config.clientId)
  })

  it('can query records by plaintext meta', async () => {
    let plainId = 'id-' + Math.random().toString(36).substr(2)
    let query = {eq: {name: 'id', value: plainId}}

    let record = await client1.write('test-plain', {this: 'does not matter'}, {id: plainId})
    let results = await client1.query(true, null, null, null, query).next()
    expect(results.length).toBeGreaterThanOrEqual(1)
    expect(results[0].meta.recordId).toBe(record.meta.recordId)
  })

  it('can paginate query results', async () => {
    let type = 'test-paginate-' + Math.random().toString(36).substr(2)

    await client1.write(type, {field: 'junk data'})
    await client1.write(type, {field: 'second junk data'})
    let data = true
    let writer = null
    let record = null
    let plain = null
    let pageSize = 1

    let result = client1.query(data, writer, record, type, plain, pageSize)

    let results = await result.next()
    expect(results.length).toBe(1)
    let first = results[0]

    let nextResults = await result.next()
    expect(nextResults.length).toBe(1)
    expect(nextResults[0].data.field).not.toBe(first.data.field)

    await result.next()
    expect(result.done).toBe(true)
  })

  it('can share with another client', async () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    let record = await client1.write(type, {misc: 'this is a sharing test'})

    await client1.share(type, client2.config.clientId)

    let actual = await client2.read(record.meta.recordId)
    expect(actual.meta.recordId).toBe(record.meta.recordId)
    expect(actual.data.misc).toBe(record.data.misc)
  })

  it('can revoke sharing with another client', async () => {
    jest.setTimeout(30000)

    let type = 'test-revoke-' + Math.random().toString(36).substr(2)
    let record = await client1.write(type, {misc: 'this is a sharing test'})

    await client1.share(type, client2.config.clientId)

    let actual = await client2.read(record.meta.recordId)
    expect(actual.meta.recordId).toBe(record.meta.recordId)
    expect(actual.data.misc).toBe(record.data.misc)

    await client1.revoke(type, client2.config.clientId)

    let followup = await client2.query(true, null, null, type).next()
    expect(followup.length).toBe(0)
  })

  it('can list outgoing sharing', async () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    await client1.write(type, {field: 'this is some data'})

    await client1.share(type, client2.config.clientId)
    let found = false
    let osp = await client1.outgoingSharing()
    for (let policy of osp) {
      if (policy.readerId === client2.config.clientId && policy.recordType === type) {
        found = true
      }
    }

    expect(found).toBe(true)
  })

  it('can list incoming sharing', async () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    await client1.write(type, {field: 'this is some data'})

    await client1.share(type, client2.config.clientId)
    let found = false
    let isp = await client2.incomingSharing()
    for (let policy of isp) {
      if (policy.writerId === client1.config.clientId && policy.recordType === type) {
        found = true
      }
    }

    expect(found).toBe(true)
  })

  it('allows sharing records before writing those records', async () => {
    let type = 'test-share-' + Math.random().toString(36).substr(2)
    await client1.share(type, client2.config.clientId)

    let found = false
    let osp = await client1.outgoingSharing()
    for (let policy of osp) {
      if (policy.readerId === client2.config.clientId && policy.recordType === type) {
        found = true
      }
    }

    expect(found).toBe(true)

    found = false
    let isp = await client2.incomingSharing()
    for (let policy of isp) {
      if (policy.writerId === client1.config.clientId && policy.recordType === type) {
        found = true
      }
    }

    expect(found).toBe(true)
  })

  it('fails on delete with version conflicts', async () => {
    expect.assertions(1)
    let record = await client1.write('delete_confict_test', {
      data: 'nonsense'
    })

    record.data.data = 'nope, still nonsense'
    await client1.update(record)

    record.data.data = 'nope, still nonsense'
    try {
      await client1.delete(record.meta.recordId, record.meta.version)
    } catch (e) {
      expect(e.message).toMatch('Conflict')
    }
  })

  it('allows legacy clients to write records without a signature', async () => {
    let legacyConfig = new e3db.Config(
      client1.config.clientId,
      client1.config.apiKeyId,
      client1.config.apiSecret,
      client1.config.publicKey,
      client1.config.privateKey,
      client1.config.apiUrl
    )
    let legacyClient = new e3db.Client(legacyConfig)

    let timestamp = (new Date()).toISOString()
    let record = await legacyClient.write('test_record', {
      now: timestamp
    })

    let second = await legacyClient.read(record.meta.recordId)

    expect(second.meta.recordId).toBe(record.meta.recordId)
    expect(second.meta.version).toBe(record.meta.version)

    expect(record.data.now).toBe(timestamp)
    expect(second.data.now).toBe(timestamp)
    expect(second.signature).toBe(null)
  })

  it('can perform local encryption and decryption', async () => {
    let type = 'test-type'
    let eak = await client1.createWriterKey(type)
    let timestamp = (new Date()).toISOString()
    let encrypted = await client1.encrypt(type, {now: timestamp}, eak)
    let decrypted = await client1.decrypt(encrypted, eak)

    expect(decrypted.data.now).toBe(timestamp)
  })

  it('can perform local encryption and decryption between different clients', async () => {
    let type = 'test-type'
    let eak1 = await client1.createWriterKey(type)
    await client1.share(type, client2.config.clientId)

    let timestamp = (new Date()).toISOString()
    let encrypted = await client1.encrypt(type, {now: timestamp}, eak)

    let eak2 = await client2.getReaderKey(client1.config.clientId, client1.config.clientId, type)
    let decrypted = await client2.decrypt(encrypted, eak2)

    expect(decrypted.data.now).toBe(timestamp)
  })
})
