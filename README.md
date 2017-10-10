[![Build Status][travis-image]][travis-url] [![Coverage Status][coveralls-image]][coveralls-url] [![NPM version][npm-image]][npm-url] [![Dependency Status][daviddm-image]][daviddm-url]

# Introduction

The Tozny End-to-End Encrypted Database (E3DB) is a storage platform with powerful sharing and consent management features.
[Read more on our blog.](https://tozny.com/blog/announcing-project-e3db-the-end-to-end-encrypted-database/)

E3DB provides a familiar JSON-based NoSQL-style API for reading, writing, and querying data stored securely in the cloud.

# Installation

## NPM

To install with NPM add the following to your `package.json` file:

```
"dependencies": {
    "e3db": "1.0.0"
}
```

Then run `npm install`

Alternatively, run:

```
$ npm install --save e3db
```

NPM will automatically amend your `package.json` file for you with the latest package version.

## Registering a client

Register an account with [InnoVault](https://inoovault.io) to get started. From the Admin Console you can create clients directly (and grab their credentials from the console) or create registration tokens to dynamically create clients with `e3db.Client.register()`. Clients registered from within the console will automatically back their credentials up to your account. Clients created dynamically via the SDK can _optionally_ back their credentials up to your account.

For a more complete walkthrough, see [`/examples/registration.js`](https://github.com/tozny/e3db-js/blob/master/examples/registration.js).

### Without Credential Backup

```js
const e3db = require('e3db')

let token = '...'
let clientName = '...'

let [publicKey] = e3db.Client.generateKeypair()
e3db.Client.register(token, clientName, publicKey)
  .then(clientInfo => {
    // ... Run operations with the client's details here
  })
```

The object returned from the server contains the client's UUID, API key, and API secret (as well as echos back the public key passed during registration). It's your responsibility to store this information locally as it _will not be recoverable_ without credential backup.

### With Credential Backup

```js
const e3db = require('e3db')

let token = '...'
let clientName = '...'

let [publicKey, privateKey] = e3db.Client.generateKeypair()
e3db.Client.register(token, clientName, publicKey, privateKey, true)
  .then(clientInfo => {
    // ... Run operations with the client's details here
  })
```

The private key must be passed to the registration handler when backing up credentials as it is used to cryptographically sign the encrypted backup file stored on the server. The private key never leaves the system, and the stored credentials will only be accessible to the newly-registered client itself or the account with which it is registered.

## Loading configuration and creating a client

Configuration is managed at runtime by instantiating an `e3db.Config` object with your client's credentials.

```js
const e3db = require('e3db')

/**
 * Assuming your credentials are stored as defined constants in the
 * application, pass them each into the configuration constructor as
 * follows:
 */
let config = new e3db.Config(
  process.env.CLIENT_ID,
  process.env.API_KEY_ID,
  process.env.API_SECRET,
  process.env.PUBLIC_KEY,
  process.env.PRIVATE_KEY,
  process.env.API_URL
)

/**
 * Pass the configuration when building a new client instance.
 */
let client = new e3db.Client(config)
```

# Usage

## Writing a record

To write new records to the database, call the `e3db.Client::write` method with a string describing the type of data to be written, along with an associative array containing the fields of the record. `e3db.Client::write` returns the newly created record.

```js
const e3db = require('e3db')

let client = new e3db.Client(/* config */)

client.write('contact', {
  'first_name': 'Jon',
  'last_name': 'Snow',
  'phone': '555-555-1212',
}).then(record => {
  console.log('Wrote record ' + record.meta.recordId)
})
```

## Querying records

E3DB supports many options for querying records based on the fields stored in record metadata. Refer to the API documentation for the complete set of options that can be passed to `e3db.Client::query`.

For example, to list all records of type `contact` and print a simple report containing names and phone numbers:

```js
const e3db = require('e3db')

let client = new e3db.Client(/* config */)

let data = true
let writer = null
let record = null
let type = 'contact'

client.query(data, writer, record, type).next()
  .then(records => {
    let fullName = record.data.first_name + ' ' + record.data.last_name
    console.log(fullName + ' --- ' + record.data.phone)
  })
```

In this example, the `e3db.Client::query` method returns an array that contains each record that matches the query.

## More examples

See [the simple example code](https://github.com/tozny/e3db-js/blob/master/examples/simple.js) for runnable detailed examples.

## Documentation

General E3DB documentation is [on our web site](https://tozny.com/documentation/e3db/).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/tozny/e3db-js.

## License

This library is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

[npm-image]: https://badge.fury.io/js/e3db.svg
[npm-url]: https://npmjs.org/package/e3db
[travis-image]: https://travis-ci.org/tozny/e3db-js.svg?branch=master
[travis-url]: https://travis-ci.org/tozny/e3db-js
[coveralls-image]: https://coveralls.io/repos/github/tozny/e3db-js/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/github/tozny/e3db-js
[daviddm-image]: https://david-dm.org/tozny/e3db-js.svg?theme=shields.io
[daviddm-url]: https://david-dm.org/tozny/e3db-js
