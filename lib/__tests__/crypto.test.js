import assert from 'assert'
import sodium from 'libsodium-wrappers'
import { default as Crypto } from '../crypto'

import { default as SignedString } from '../types/signedString'

describe('Crypto', () => {
  it('properly base64 encodes', () => {
    let expected = 'VGhpcyBpcyBhIHRlc3Qh'
    let raw = 'This is a test!'

    expect(Crypto.b64encode(raw)).toBe(expected)
  })

  it('properly base64 decodes', () => {
    let expected = 'This is not a drill'
    let raw = 'VGhpcyBpcyBub3QgYSBkcmlsbA'

    let encoded = String.fromCharCode.apply(null, Crypto.b64decode(raw))

    expect(encoded).toBe(expected)
  })

  it('generates disctinct random keys', () => {
    expect(Crypto.randomKey()).not.toBe(Crypto.randomKey())
  })

  it('deterministically generates signing keys', () => {
    let salt = sodium.randombytes_buf(16)

    let keypair = Crypto.deriveSigningKey('thisisapassword', salt)
    let second = Crypto.deriveSigningKey('thisisapassword', salt)

    expect(keypair.publicKey).toEqual(second.publicKey)
    expect(keypair.privateKey).toEqual(second.privateKey)
  })

  it('deterministically generates encryption keys', () => {
    let salt = sodium.randombytes_buf(16)

    let keypair = Crypto.deriveCryptoKey('thisisapassword', salt)
    let second = Crypto.deriveCryptoKey('thisisapassword', salt)

    expect(keypair.publicKey).toEqual(second.publicKey)
    expect(keypair.privateKey).toEqual(second.privateKey)
  })

  it('deterministically generates symmetric keys', () => {
    let salt = sodium.randombytes_buf(16)

    let keypair = Crypto.deriveSymmetricKey('thisisapassword', salt)
    let second = Crypto.deriveSymmetricKey('thisisapassword', salt)

    expect(keypair).toEqual(second)
  })

  it('signs and verifies with a given key', async () => {
    let salt = sodium.randombytes_buf(16)
    let keyPair = Crypto.deriveSigningKey('thisisapassword', salt)

    let publicKey = Crypto.b64encode(keyPair.publicKey)
    let privateKey = Crypto.b64encode(keyPair.privateKey)

    let document = new SignedString('this is a test')

    let signature = await Crypto.signDocument(document, privateKey)
    let verified = await Crypto.verifyDocumentSignature(document, signature, publicKey)

    expect(verified).toBe(true)
  })
})
