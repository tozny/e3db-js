import sodium from 'libsodium-wrappers'
import util from 'util'

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
let client, eak
let cryptoKeys, signingKeys, config, recordType
let data1B, data500B, data250KB, data500KB, data1MB, data2MB, data4MB
let rec1B, rec500B, rec250KB, rec500KB, rec1MB, rec2MB, rec4MB
let signed1B, signed500B, signed250KB, signed500KB, signed1MB, signed2MB, signed4MB

/**
 * Create a record composed of random data for encryption and signing
 *
 * @param {int} bytes Number of bytes to stream
 *
 * @returns {RecordData}
 */
async function randomRecordData(bytes) {
  await sodium.ready
  let buffer = sodium.randombytes_buf(bytes).map(v => v & 127)
  let data = Buffer.from(buffer).toString('utf8')

  return new RecordData({'': data})
}

function zip(left, right) {
  return left.map((n, index) => [n, right[index]])
}

/**
 * Print out the sizes of all data elements we've created for comparison
 *
 * @returns {void}
 */
function printSizes() {
  let dats = [data1B, data500B, data250KB, data500KB, data1MB, data2MB, data4MB]
  let recs = [rec1B, rec500B, rec250KB, rec500KB, rec1MB, rec2MB, rec4MB]
  let sigs = [signed1B, signed500B, signed250KB, signed500KB, signed1MB, signed2MB, signed4MB]

  for (let row of zip(dats, zip(recs, sigs))) {
    let data = row[0]
    let encrypted = row[1][0]
    let signed = row[1][1]

    console.log(
      util.format(
        'Data %d; Encrypted %d;',
        Buffer.from(data[''], 'utf8').byteLength,
        Buffer.from(encrypted.data[''], 'utf8').byteLength
      )
    )
  }
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

  client = new Client(config)

  // Create an EAK for crypto
  let ak = await Crypto.randomKey()
  let encryptedAk = await Crypto.encryptAk(cryptoKeys.privateKey, ak, cryptoKeys.publicKey)
  eak = new EAKInfo(encryptedAk, clientId, cryptoKeys.publicKey, clientId, signingKeys.publicKey)

  data1B = await randomRecordData(1)
  data500B = await randomRecordData(500)
  data250KB = await randomRecordData(250000)
  data500KB = await randomRecordData(500000)
  data1MB = await randomRecordData(1000000)
  data2MB = await randomRecordData(2000000)
  data4MB = await randomRecordData(4000000)

  done()
})

describe('Profile', () => {
  it('tests record sizes', async (done) => {
    rec1B = await client.encrypt(recordType, data1B, eak)
    rec500B = await client.encrypt(recordType, data500B, eak)
    rec250KB = await client.encrypt(recordType, data250KB, eak)
    rec500KB = await client.encrypt(recordType, data500KB, eak)
    rec1MB = await client.encrypt(recordType, data1MB, eak)
    rec2MB = await client.encrypt(recordType, data2MB, eak)
    rec4MB = await client.encrypt(recordType, data4MB, eak)

    signed1B = await client.sign(data1B)
    signed500B = await client.sign(data500B)
    signed250KB = await client.sign(data250KB)
    signed500KB = await client.sign(data500KB)
    signed1MB = await client.sign(data1MB)
    signed2MB = await client.sign(data2MB)
    signed4MB = await client.sign(data4MB)

    printSizes()

    done()
  })

  it('tests 1B', async (done) => {
    let enc, dec, sign, verify

    do {
      let start = Date.now()
      let encrypted = await client.encrypt(recordType, data1B, eak)
      let pause = Date.now()
      await client.decrypt(encrypted, eak)
      dec = Date.now() - pause
      enc = pause - start
    } while (false)

    do {
      let start = Date.now()
      let signature = await client.sign(data1B)
      let pause = Date.now()
      await client.verify(new SignedDocument(data1B, signature), signingKeys.publicKey)
      verify = Date.now() - pause
      sign = pause - start
    } while (false)

    console.log(
      util.format(
        'Size 1B; Encrypt %dms; Decrypt %dms; Sign %dms; Verify %dms;',
        enc, dec, sign, verify
      )
    )

    done()
  })

  it('tests 500B', async (done) => {
    let enc, dec, sign, verify

    do {
      let start = Date.now()
      let encrypted = await client.encrypt(recordType, data500B, eak)
      let pause = Date.now()
      await client.decrypt(encrypted, eak)
      dec = Date.now() - pause
      enc = pause - start
    } while (false)

    do {
      let start = Date.now()
      let signature = await client.sign(data500B)
      let pause = Date.now()
      await client.verify(new SignedDocument(data500B, signature), signingKeys.publicKey)
      verify = Date.now() - pause
      sign = pause - start
    } while (false)

    console.log(
      util.format(
        'Size 500B; Encrypt %dms; Decrypt %dms; Sign %dms; Verify %dms;',
        enc, dec, sign, verify
      )
    )

    done()
  })

  it('tests 250KB', async () => {
    let enc, dec, sign, verify

    do {
      let start = Date.now()
      let encrypted = await client.encrypt(recordType, data250KB, eak)
      let pause = Date.now()
      await client.decrypt(encrypted, eak)
      dec = Date.now() - pause
      enc = pause - start
    } while (false)

    do {
      let start = Date.now()
      let signature = await client.sign(data250KB)
      let pause = Date.now()
      await client.verify(new SignedDocument(data250KB, signature), signingKeys.publicKey)
      verify = Date.now() - pause
      sign = pause - start
    } while (false)

    console.log(
      util.format(
        'Size 250KB; Encrypt %dms; Decrypt %dms; Sign %dms; Verify %dms;',
        enc, dec, sign, verify
      )
    )

    expect(true).toBe(true)
  })

  it('tests 500KB', async () => {
    let enc, dec, sign, verify

    do {
      let start = Date.now()
      let encrypted = await client.encrypt(recordType, data500KB, eak)
      let pause = Date.now()
      await client.decrypt(encrypted, eak)
      dec = Date.now() - pause
      enc = pause - start
    } while (false)

    do {
      let start = Date.now()
      let signature = await client.sign(data500KB)
      let pause = Date.now()
      await client.verify(new SignedDocument(data500KB, signature), signingKeys.publicKey)
      verify = Date.now() - pause
      sign = pause - start
    } while (false)

    console.log(
      util.format(
        'Size 500KB; Encrypt %dms; Decrypt %dms; Sign %dms; Verify %dms;',
        enc, dec, sign, verify
      )
    )

    expect(true).toBe(true)
  })

  it('tests 1MB', async () => {
    let enc, dec, sign, verify

    do {
      let start = Date.now()
      let encrypted = await client.encrypt(recordType, data1MB, eak)
      let pause = Date.now()
      await client.decrypt(encrypted, eak)
      dec = Date.now() - pause
      enc = pause - start
    } while (false)

    do {
      let start = Date.now()
      let signature = await client.sign(data1MB)
      let pause = Date.now()
      await client.verify(new SignedDocument(data1MB, signature), signingKeys.publicKey)
      verify = Date.now() - pause
      sign = pause - start
    } while (false)

    console.log(
      util.format(
        'Size 1MB; Encrypt %dms; Decrypt %dms; Sign %dms; Verify %dms;',
        enc, dec, sign, verify
      )
    )

    expect(true).toBe(true)
  })

  it('tests 2MB', async () => {
    let enc, dec, sign, verify

    do {
      let start = Date.now()
      let encrypted = await client.encrypt(recordType, data2MB, eak)
      let pause = Date.now()
      await client.decrypt(encrypted, eak)
      dec = Date.now() - pause
      enc = pause - start
    } while (false)

    do {
      let start = Date.now()
      let signature = await client.sign(data2MB)
      let pause = Date.now()
      await client.verify(new SignedDocument(data2MB, signature), signingKeys.publicKey)
      verify = Date.now() - pause
      sign = pause - start
    } while (false)

    console.log(
      util.format(
        'Size 2MB; Encrypt %dms; Decrypt %dms; Sign %dms; Verify %dms;',
        enc, dec, sign, verify
      )
    )

    expect(true).toBe(true)
  })

  it('tests 4MB', async () => {
    let enc, dec, sign, verify

    do {
      let start = Date.now()
      let encrypted = await client.encrypt(recordType, data4MB, eak)
      let pause = Date.now()
      await client.decrypt(encrypted, eak)
      dec = Date.now() - pause
      enc = pause - start
    } while (false)

    do {
      let start = Date.now()
      let signature = await client.sign(data4MB)
      let pause = Date.now()
      await client.verify(new SignedDocument(data4MB, signature), signingKeys.publicKey)
      verify = Date.now() - pause
      sign = pause - start
    } while (false)

    console.log(
      util.format(
        'Size 4MB; Encrypt %dms; Decrypt %dms; Sign %dms; Verify %dms;',
        enc, dec, sign, verify
      )
    )

    expect(true).toBe(true)
  })
})
