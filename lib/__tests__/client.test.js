import assert from 'assert'
import { default as Client } from '../client'
import { default as Config } from '../config'
import { default as Crypto } from '../crypto'

import { default as Meta } from '../types/meta'
import { default as Record } from '../types/record'

let clientId = '00000000-0000-0000-0000-000000000000'
let [publicKey, privateKey] = Client.generateKeypair()
let config = new Config(
  clientId,
  'thisisabogusapikeyid',
  'thisisabogusapisecret',
  publicKey,
  privateKey,
  'https://localhost'
)

beforeAll(() => {

})

describe('Client', () => {
  it.only('can encrypt and decrypt a record', async () => {
    let ak = Crypto.randomKey()
    let encryptedAk = await Crypto.encryptAk(privateKey, ak, publicKey)
    let eak = {eak: encryptedAk, authorizer_public_key: {curve25519: publicKey}}

    let meta = new Meta(clientId, clientId, 'test', {})
    let original = new Record(meta, {field1: 'this is a test', field2: 'another'})

    let client = new Client(config)
    let encrypted = await client.encrypt(original, eak)

    let decrypted = await client.decrypt(encrypted, eak)

    expect(decrypted.meta.writerId).toBe(clientId)
    expect(decrypted.meta.userId).toBe(clientId)
    expect(decrypted.data.field1).toBe(original.data.field1)
    expect(decrypted.data.field2).toBe(original.data.field2)
  })
})
