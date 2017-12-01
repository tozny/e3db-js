/**
 * This program provides a simple example illustrating how to programmatically
 * register a client with InnoVault and e3db. In some situations, it's preferable
 * to register a client from the server or system that will be using its
 * credentials (to ensure that all data is truly encrypted from end-to-end
 * with no possibilities of a credential leak). For more detailed information,
 * please see the documentation home page: https://tozny.com/documentation/e3db
 *
 * @author    Eric Mann <eric@tozny.com>
 * @copyright Copyright (c) 2017 Tozny, LLC
 * @license   Public Domain
*/

const e3db = require('../dist/index.js')

async function main() {
  /**
   * ---------------------------------------------------------
   * Initialization
   * ---------------------------------------------------------
   */

  // A registration token is required to set up a client. In this situation,
  // we assume an environment variable called REGISTRATION_TOKEN is set
  let token = process.env.REGISTRATION_TOKEN

  // Clients can either create new cryptographic keypairs, or load in a pre-defined
  // pair of Curve25519 keys. In this situation, we will generate a new keypair.
  let cryptoKeys = e3db.Client.generateKeypair();
  let signingKeys = e3db.Client.generateSigningKeypair();

  console.log('Public Key:          ' + cryptoKeys.publicKey)
  console.log('Private Key:         ' + cryptoKeys.privateKey)
  console.log('Public Signing Key:  ' + signingKeys.publicKey)
  console.log('Private Signing Key: ' + signingKeys.privateKey)

  // Clients must be registered with a name unique to your account to help
  // differentiate between different sets of credentials in the Admin Console.
  // In this example, the name is set at random
  let clientName = 'example_client_' + Math.random().toString(36).substr(2)

  console.log('Client Name: ' + clientName)

  // Passing all of the data above into the registration routine will create
  // a new client with the system. Remember to keep your private key private!
  let clientInfo = await e3db.Client.register(token, clientName, cryptoKeys, signingKeys)

  // Optionally, you can automatically back up the credentials of the newly-created
  // client to your InnoVault account (accessible via https://console.tozny.com) by
  // passing your private key and a backup flag when registering. The private key is
  // not sent anywhere, but is used by the newly-created client to sign an encrypted
  // copy of its credentials that is itself stored in e3db for later use.
  //
  // Client credentials are not backed up by default.

  // let clientInfo = await e3db.Client.register(token, clientName, cryptoKeys, signingKeys, true)

  console.log('Client ID:   ' + clientInfo.clientId)
  console.log('API Key ID:  ' + clientInfo.apiKeyId)
  console.log('API Secret:  ' + clientInfo.apiSecret)

  /**
   * ---------------------------------------------------------
   * Usage
   * ---------------------------------------------------------
   */

  // Once the client is registered, you can use it immediately to create the
  // configuration used to instantiate a Client that can communicate with
  // e3db directly.

  let config = new e3db.Config(
      clientInfo.clientId,
      clientInfo.apiKeyId,
      clientInfo.apiSecret,
      publicKey,
      privateKey
  )

  // Now create a client using that configuration.
  let client = new e3db.Client(config)

  // From this point on, the new client can be used as any other client to read
  // write, delete, and query for records. See the `simple.js` documentation
  // for more complete examples ...
}

main()
