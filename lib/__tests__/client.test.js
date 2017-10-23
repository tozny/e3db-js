import assert from 'assert'
import { default as Client } from '../client'
import { default as Config } from '../config'
import { default as Crypto } from '../crypto'

import { default as EncryptedDocuement } from '../types/encryptedDocument'
import { default as Meta } from '../types/meta'
import { default as Record } from '../types/record'
import { default as SignedDocument } from '../types/signedDocument'

let clientId = '00000000-0000-0000-0000-000000000000'
let cryptoKeys = Client.generateKeypair()
let signingKeys = Client.generateSigningKeypair()
let config = new Config(
  clientId,
  'thisisabogusapikeyid',
  'thisisabogusapisecret',
  cryptoKeys.publicKey,
  cryptoKeys.privateKey,
  signingKeys.publicKey,
  signingKeys.privateKey,
  'https://localhost'
)

describe('Client', () => {
  it('can encrypt and decrypt a record', async () => {
    let ak = Crypto.randomKey()
    let encryptedAk = await Crypto.encryptAk(cryptoKeys.privateKey, ak, cryptoKeys.publicKey)
    let eak = {eak: encryptedAk, authorizer_public_key: {curve25519: cryptoKeys.publicKey}}

    let client = new Client(config)
    let encrypted = await client.encrypt('type', {field1: 'this is a test', field2: 'another'}, {}, eak)

    let decrypted = await client.decrypt(encrypted, eak)

    expect(decrypted.meta.writerId).toBe(clientId)
    expect(decrypted.meta.userId).toBe(clientId)
    expect(decrypted.data.field1).toBe('this is a test')
    expect(decrypted.data.field2).toBe('another')
  })

  it('can verify a signature', async () => {
    let document = `{
  "doc": {
    "data": {
      "test_field": "c9biefj_xNB2TFrRZZwCLGknyPvn5yTveMYKj3kxVyzSgdZ5fRenRX9Be6dt2kMJ.OcqrcbMFkX2H-mIrokZoZ2HBLPR1AlG6.i3azn3obe0qh0igrkz_PsuF7UXMdcYdqZFA.SA4nVOiIcfh2tuKKemHZG9h6K5UeuuXU"
    },
    "meta": {
      "plain": {
        "client_pub_sig_key": "uf-C25itTZUUQ9e58vonHNDIkF7OPRaLbRueCKcRt3M",
        "server_sig_of_client_sig_key": "xc90mv9vxh-AJq-9TuTz5-nNF3M-0MJYCnvy7W08n3wSrQnm2pf5gz0BlqKywFNGu6w7CLp3nJnVpH6MbHsUBw"
      },
      "type": "ticket",
      "user_id": "3d719041-7d63-4782-a87c-d64793d85488",
      "writer_id": "3d719041-7d63-4782-a87c-d64793d85488"
    },
    "rec_sig": "D8nfYtxX3Lu3MA-VsUvPvxItdWcy-xvQHwe4RoN0gA4bAHMQElVfNUs9NVRBqM8YgSmGb0Fyg5CqLt-iUKapCw"
  },
  "sig": "BNRROUpP-7SbrkmvHKcvN-swVz_TIzGwq_T0I683-WCEXmlaaFKg3lSBdvhcc2R0S5ehrV5pA7bvLl4WIEibCg"
}`

    let client = new Client(config)
    let parsed = JSON.parse(document)
    let encrypted = await EncryptedDocuement.decode(parsed.doc)
    let doc = new SignedDocument(encrypted, parsed.sig)

    let publicKey = encrypted.clientMeta.plain.client_pub_sig_key
    let verify = await client.verify(doc, publicKey)

    expect(verify).toBe(true)
  })
})
