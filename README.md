# `authenticated-request`

> Authenticate HTTP requests using modern crypto

## Usage

Authentication means several things in cryptography, but common for them all is
to verify the integrity and validity of something. Authentication in regards to
messages and requests is that only someone with access to the original secret
can verify the message. It is like a signature, but requires a symmetric key,
meaning both the party authenticating a message and the party verifying need to
share the same key, which must be kept secret.

### Authenticate

```js
var authenticatedRequest = require('authenticated-request')
var sodium = require('sodium-native')

// Create secure buffer key in-memory (you probably get this from a file somehow)
var key = sodium.sodium_malloc(authenticatedRequest.KEYBYTES)
sodium.randombytes_random(key)

var authReq = authenticatedRequest(['Host', 'Accept', 'Content-Length', 'Content-Type', 'Date', 'Origin', 'Referer', 'If-Match'])


var req = {
  method: 'POST',
  url: 'https://example.com/gateway/upload',
  headers: {
    host: 'example.com',
    accept: 'application/json',
    'content-length': '5',
    'content-type': 'text/plain',
    'date': new Date().toUTCString()
  },
  payload: Buffer.from('My CV')
}

// Calculate a Message Authentication Code
var mac = authReq.authenticate(req.method, req.url, req.headers, req.payload, key)

// This header will be ignored because it is not in the whitelist
sigReq.headers['authorization'] = mac.toString('base64') // maybe you want to prefix this with module name and version
```

### Verify

```js
var authenticatedRequest = require('authenticated-request')
var sodium = require('sodium-native')

// Create secure buffer key in-memory (you probably get this from a file somehow)
var key = sodium.sodium_malloc(authenticatedRequest.KEYBYTES)
sodium.randombytes_random(key)

var authReq = authenticatedRequest(['Host', 'Accept', 'Content-Length', 'Content-Type', 'Date', 'Origin', 'Referer', 'If-Match'])


var req = {
  method: 'POST',
  url: 'https://example.com/gateway/upload',
  headers: {
    host: 'example.com',
    accept: 'application/json',
    'content-length': '5',
    'content-type': 'text/plain',
    'date': new Date().toUTCString(),
    'authorization': 'some long base64 value'
  },
  payload: Buffer.from('My CV')
}

var mac = Buffer.from(req.headers.authorization, 'base64')

if(!authReq.verify(mac, req.method, req.url, req.headers, req.payload, key)) {
  throw new Error('MAC did not verify')
}
```

### Canonicalisation

Canonicalisation means to convert something to a representation where there is
no ambiguity whether two statements represent the same value. This module
canonicalises HTTP headers by lower casing them and HTTP verbs by upper casing.
URLs are up to you to canonicalise. Some things to consider is whether you want
to treat URLs as case sensitive, if the order of query parameters matter and
whether you want to remove duplicate query parameters or consecutive slashes.

Consider the following urls:

```
http://example.com/REST//image-server?width=1280&height=720&width=720
http://example.com/rest/image-server?height=720&width=1280
```

Do they represent the same resource or are they different?

## API

### Constants

* `authenticatedRequest.KEYBYTES` - Length in bytes of a valid key
* `authenticatedRequest.BYTES` - Length in bytes of a valid MAC

### `var policy = authenticatedRequest(headerWhitelist)`

Create an instance with a whitelist of headers, which must be an array of
strings, that will be included in the authenticated if passed to `authenticate`
and `verify`. Note that the headers in the whitelist are optional in the sense
that no methods will fail if the exact headers are not present, but headers not
in the whitelist will be ignored. The headers are lower cased to give them a
canonical representation.

### `var mac = policy.authenticate(method, url, headers, payload, key)`

Authenticate a request given the following arguments:

* `method` must be a string, and should be a HTTP method
* `url` must be a string. Consider whether you deem protocol and hostname part
  of the url.
* `headers` should be a object of `key: value` pairs. `key`s are lower cased and
  matched against the whitelist. Headers with a `null` value are ignored
* `payload` is optional, but must be a Buffer. The default value is the empty
  Buffer.
* `key` must be a cryptographically pseudorandom key of length
  `authenticatedRequest.KEYBYTES` passed as a Buffer. It is recommended to use
  `sodium-native` Secure Buffers if possible.

Returns a message authentication code (prefix mac) as a Buffer of length
`authenticatedRequest.BYTES`

### `var valid = policy.verify(mac, method, url, headers, payload, key)`

Verify the MAC of a request given the following arguments:

* `mac` must be a Buffer of length `authenticatedRequest.BYTES`
* `method` must be a string, and should be a HTTP method
* `url` must be a string. Consider whether you deem protocol and hostname part
  of the url.
* `headers` should be a object of `key: value` pairs. `key`s are lower cased and
  matched against the whitelist. Headers with a `null` value are ignored
* `payload` is optional, but must be a Buffer. The default value is the empty
  Buffer.
* `key` must be a cryptographically pseudorandom key of length
  `authenticatedRequest.KEYBYTES` passed as a Buffer. It is recommended to use
  `sodium-native` Secure Buffers if possible.

Returns boolean on whether the MAC was valid or not.

## License

[ISC](LICENSE)
