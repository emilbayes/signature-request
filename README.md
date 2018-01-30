# `signature-request`

> Sign HTTP requests using modern crypto

## Usage

### Sign

```js
var signatureRequest = require('signature-request')
var sodium = require('sodium-native')

// Create secure buffer key in-memory (you probably get this from a file somehow)
var key = sodium.sodium_malloc(signatureRequest.KEYBYTES)
sodium.randombytes_random(key)

var sigReq = signatureRequest(['Host', 'Accept', 'Content-Length', 'Content-Type', 'Date', 'Origin', 'Referer', 'If-Match'])


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


var signature = sigReq.sign(req.method, req.url, req.headers, req.payload, key)

// This header will be ignored because it is not in the whitelist
sigReq.headers['authorization'] = signature.toString('base64') // maybe you want to prefix this with module name and version
```

### Verify

```js
var signatureRequest = require('signature-request')
var sodium = require('sodium-native')

// Create secure buffer key in-memory (you probably get this from a file somehow)
var key = sodium.sodium_malloc(signatureRequest.KEYBYTES)
sodium.randombytes_random(key)

var sigReq = signatureRequest(['Host', 'Accept', 'Content-Length', 'Content-Type', 'Date', 'Origin', 'Referer', 'If-Match'])


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

var signature = Buffer.from(req.headers.authorization, 'base64')

if(!sigReq.verify(signature, req.method, req.url, req.headers, req.payload, key)) {
  throw new Error('Signature did not verify')
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

* `signatureRequest.KEYBYTES` - Length in bytes of a valid key
* `signatureRequest.BYTES` - Length in bytes of a valid signature

### `var policy = signatureRequest(whitelistedHeaders)`

Create an instance with a whitelist of headers, which must be an array of
strings, that will be included in the signature if passed to `sign` and
`verify`. Note that the headers in the whitelist are optional in the sense that
no methods will fail if the exact headers are not present, but headers not in
the whitelist will be ignored. The headers are lower cased to give them a
canonical representation.

### `var signature = policy.sign(method, url, headers, payload, key)`

Sign a request given the following arguments:

* `method` must be a string, and should be a HTTP method
* `url` must be a string. Consider whether you deem protocol and hostname part
  of the url.
* `headers` should be a object of `key: value` pairs. `key`s are lower cased and
  matched against the whitelist. Headers with a `null` value are ignored
* `payload` is optional, but must be a Buffer. The default value is the empty
  Buffer.
* `key` must be a cryptographically pseudorandom key of length
  `signatureRequest.KEYBYTES` passed as a Buffer. It is recommended to use
  `sodium-native` Secure Buffers if possible.

Returns a signature (prefix mac) as a Buffer of length `signatureRequest.BYTES`

### `var valid = policy.verify(signature, method, url, headers, payload, key)`

Verify a signature of a request given the following arguments:

* `signature` must be a Buffer of length `signatureRequest.BYTES`
* `method` must be a string, and should be a HTTP method
* `url` must be a string. Consider whether you deem protocol and hostname part
  of the url.
* `headers` should be a object of `key: value` pairs. `key`s are lower cased and
  matched against the whitelist. Headers with a `null` value are ignored
* `payload` is optional, but must be a Buffer. The default value is the empty
  Buffer.
* `key` must be a cryptographically pseudorandom key of length
  `signatureRequest.KEYBYTES` passed as a Buffer. It is recommended to use
  `sodium-native` Secure Buffers if possible.

Returns boolean on whether the signature was valid or not.

## License

[ISC](LICENSE)
