import assert from 'assert'
import { default as Client } from '../client'
import { default as Config } from '../config'
import { default as Crypto } from '../crypto'

import { default as EncryptedDocuement } from '../types/encryptedDocument'
import { default as Meta } from '../types/meta'
import { default as Record } from '../types/record'
import { default as RecordInfo } from '../types/recordInfo'
import { default as SignedDocument } from '../types/signedDocument'
import { default as SignedString } from '../types/signedString'

let clientId = '00000000-0000-0000-0000-000000000000'
let cryptoKeys = Client.generateKeypair()
let signingKeys = Client.generateSigningKeypair()
let config = new Config(
  clientId,
  'thisisabogusapikeyid',
  'thisisabogusapisecret',
  cryptoKeys.publicKey,
  cryptoKeys.privateKey,
  'https://localhost',
  signingKeys.publicKey,
  signingKeys.privateKey
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
      "test_field": "sGiYGo1g-jgnlx3hn4-9jhONDx2mOqxtxdxNu7-4-ApeWevWHqEroeVscWwBIfEW.Ls1dffWfa8EZZZvwg39ctIoGVJZjhhUA.9KkzIavtjaeNlXTrs2zGEmh-_0wMERyXgkk.OIkSnOWiUB1R3WFYAXLLQZQVcjyQnRxg"
    },
    "meta": {
      "plain": {
        "client_pub_sig_key": "QaC_UtENuIgG3XSyUMKKuB_mzSffRC-GK4FHDG0lxIc",
        "server_sig_of_client_sig_key": "quXsoHIIRjRdNglbhOqA_vFH9seApqyjp4vysgrnesb7g8oo1qgFFFaoHCrC621Jjewy3NhQ2DgzlcLzrbTRAQ"
      },
      "type": "ticket",
      "user_id": "8ce6ae92-68b9-472f-9af6-75059c21b643",
      "writer_id": "8ce6ae92-68b9-472f-9af6-75059c21b643"
    },
    "rec_sig": "Mu3R1kczZlOqw6ceIEDTiQSf6LmsuZOCe5kL6tqpH3mJX2WYpwRGQnZdaVt4nLzE6LPdxz0SexRhmkXU8FHnBw"
  },
  "sig": "eIrkAZMFxQFBW_TRh26KW8Ty9w6i4c7LFAL7P9J1p5PAfibtrWOU6BFgx_G2V4_6TQzCCgkb8w6ANnNAvG1IDg"
}`
    let serverPublicKey = 'VRCz0mVaB3P6tgfaQVWOsR642De6ZFrwdWFdeXALq5I'

    let client = new Client(config)
    let parsed = JSON.parse(document)
    let encrypted = await EncryptedDocuement.decode(parsed.doc)
    let doc = new SignedDocument(encrypted, parsed.sig)
    let publicKey = encrypted.clientMeta.plain.client_pub_sig_key

    // Validate the server signature on the public key
    let signedKey = new SignedDocument(new SignedString(publicKey), encrypted.clientMeta.plain.server_sig_of_client_sig_key)

    let keyVerify = await client.verify(signedKey, serverPublicKey)
    expect(keyVerify).toBe(true)

    let verify = await client.verify(doc, publicKey)
    expect(verify).toBe(true)
  })
})
