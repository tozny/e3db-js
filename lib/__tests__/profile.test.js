import sodium from 'libsodium-wrappers'
import { default as Client } from '../client'
import { default as Config } from '../config'
import { default as Crypto } from '../crypto'

import { default as EAKInfo } from '../types/eakInfo'
import { default as Meta } from '../types/meta'
import { default as Record } from '../types/record'
import { default as RecordData } from '../types/recordData'
import { default as RecordInfo } from '../types/recordInfo'
import { default as SignedDocument } from '../types/signedDocument'
import { default as SignedString } from '../types/signedString'

let clientId = '00000000-0000-0000-0000-000000000000'
let cryptoKeys, signingKeys, config, recordType
let data1B, data500B, data250KB, data500KB, data1MB, data2MB
let rec1B, rec500B, rec250KB, rec500KB, rec1MB, rec2MB
let signed1B, signed500B, signed250KB, signed500KB, signed1MB, signed2MB

/**
 * Create a record composed of random data for encryption and signing
 *
 * @param {int} bytes Number of bytes to stream
 *
 * @returns {RecordData}
 */
function randomRecordData(bytes) {
  let data = ''

  return new RecordData({'': data})
}

/**
 * Print out the sizes of all data elements we've created for comparison
 *
 * @returns {void}
 */
function printSizes() {
  
}

beforeAll(async (done) => {
  await sodium.ready
  recordType = await Crypto.b64encode(sodium.randombytes_buf(8))

  cryptoKeys = await Client.generateKeypair()
  signingKeys = await Client.generateSigningKeypair()
  config = new Config(
    clientId,
    'thisisabogusapikeyid',
    'thisisabogusapisecret',
    cryptoKeys.publicKey,
    cryptoKeys.privateKey,
    'https://localhost',
    signingKeys.publicKey,
    signingKeys.privateKey
  )

  let client = new Client(config)

  // Create an EAK for crypto
  let ak = await Crypto.randomKey()
  let encryptedAk = await Crypto.encryptAk(cryptoKeys.privateKey, ak, cryptoKeys.publicKey)
  let eak = new EAKInfo(encryptedAk, clientId, cryptoKeys.publicKey, clientId, signingKeys.publicKey)

  data1B = randomRecordData(1)
  data500B = randomRecordData(500)
  data250KB = randomRecordData(250000)
  data500KB = randomRecordData(500000)
  data1MB = randomRecordData(1000000)
  data2MB = randomRecordData(2000000)

  rec1B = await client.encrypt(recordType, data1B, eak)
  rec500B = await client.encrypt(recordType, data500B, eak)
  rec250KB = await client.encrypt(recordType, data250KB, eak)
  rec500KB = await client.encrypt(recordType, data500KB, eak)
  rec1MB = await client.encrypt(recordType, data1MB, eak)
  rec2MB = await client.encrypt(recordType, data2MB, eak)

  signed1B = await client.sign(data1B)
  signed500B = await client.sign(data500B)
  signed250KB = await client.sign(data250KB)
  signed500KB = await client.sign(data500KB)
  signed1MB = await client.sign(data1MB)
  signed2MB = await client.sign(data2MB)

  printSizes()

  done()
})

describe('Profile', () => {
  it('works', () => {

    expect(true).toBe(true)
  })
})

describe('Encrypt 1B', () => {
  it('works', () => {
    expect(true).toBe(true)
  })
})
