import sodium from 'libsodium-wrappers'
import { default as Crypto } from '../crypto'

import { default as SignedString } from '../types/signedString'

describe('Crypto', () => {
  it('properly base64 encodes', async () => {
    let expected = 'VGhpcyBpcyBhIHRlc3Qh'
    let raw = 'This is a test!'

    let encoded = await Crypto.b64encode(raw)

    expect(encoded).toBe(expected)
  })

  it('properly base64 decodes', async () => {
    let expected = 'This is not a drill'
    let raw = 'VGhpcyBpcyBub3QgYSBkcmlsbA'

    let decoded = await Crypto.b64decode(raw)

    let encoded = String.fromCharCode.apply(null, decoded)

    expect(encoded).toBe(expected)
  })

  it('generates disctinct random keys', () => {
    expect(Crypto.randomKey()).not.toBe(Crypto.randomKey())
  })

  it('deterministically generates signing keys', async () => {
    await sodium.ready
    let salt = sodium.randombytes_buf(16)

    let keypair = Crypto.deriveSigningKey('thisisapassword', salt)
    let second = Crypto.deriveSigningKey('thisisapassword', salt)

    expect(keypair.publicKey).toEqual(second.publicKey)
    expect(keypair.privateKey).toEqual(second.privateKey)
  })

  it('deterministically generates encryption keys', async () => {
    await sodium.ready
    let salt = sodium.randombytes_buf(16)

    let keypair = Crypto.deriveCryptoKey('thisisapassword', salt)
    let second = Crypto.deriveCryptoKey('thisisapassword', salt)

    expect(keypair.publicKey).toEqual(second.publicKey)
    expect(keypair.privateKey).toEqual(second.privateKey)
  })

  it('deterministically generates symmetric keys', async () => {
    await sodium.ready
    let salt = sodium.randombytes_buf(16)

    let keypair = await Crypto.deriveSymmetricKey('thisisapassword', salt)
    let second = await Crypto.deriveSymmetricKey('thisisapassword', salt)

    expect(keypair).toEqual(second)
  })

  it('signs and verifies with a given key', async () => {
    await sodium.ready
    let salt = sodium.randombytes_buf(16)
    let keyPair = await Crypto.deriveSigningKey('thisisapassword', salt)

    let document = new SignedString('this is a test')

    let signature = await Crypto.signDocument(document, keyPair.privateKey)
    let verified = await Crypto.verifyDocumentSignature(document, signature, keyPair.publicKey)

    expect(verified).toBe(true)
  })
})
