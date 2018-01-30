var sodium = require('sodium-native')
var assert = require('nanoassert')

SignatureRequest.KEYBYTES = sodium.crypto_generichash_KEYBYTES
SignatureRequest.BYTES = sodium.crypto_generichash_BYTES

var NL_BUF = Buffer.from('\n')

function SignatureRequest (signedHeaders) {
  if (!(this instanceof SignatureRequest)) return new SignatureRequest(signedHeaders)
  assert(Array.isArray(signedHeaders), 'signedHeaders must be an array')
  assert(signedHeaders.every(s => typeof s === 'string'), 'signedHeaders must be an array of strings')

  this._signedHeaders = signedHeaders.map(s => s.toLowerCase()).sort()
}

SignatureRequest.prototype.sign = function (method, url, headers, payload, key) {
  if (payload == null) payload = new Buffer(0)
  assert(typeof method == 'string', 'method must be string')
  assert(typeof url == 'string', 'method must be string')
  assert(Buffer.isBuffer(payload), 'payload must be Buffer')
  assert(Buffer.isBuffer(key), 'key must be Buffer (recommended sodium-native Secure Buffer)')
  assert(key.length >= SignatureRequest.KEYBYTES, 'key must be SignatureRequest.KEYBYTES long')

  // Utilise that Blake2 can function as a prefix MAC
  var hash = sodium.crypto_generichash_instance(key, SignatureRequest.BYTES)

  hash.update(Buffer.from(method.toUpperCase()))
  hash.update(NL_BUF)
  hash.update(Buffer.from(url))
  hash.update(NL_BUF)
  this._hashHeaders(hash, headers)

  // Include a separator before the payload
  hash.update(NL_BUF)
  hash.update(payload)

  var signature = Buffer.allocUnsafe(SignatureRequest.BYTES)
  hash.final(signature)

  return signature
}

SignatureRequest.prototype.verify = function (signature, method, url, headers, payload, key) {
  assert(Buffer.isBuffer(signature), 'signature must be Buffer')
  assert(signature.length >= SignatureRequest.BYTES, 'signature must be SignatureRequest.BYTES long')

  var computedSignature = this.sign(method, headers, payload, key)
  return sodium.sodium_memcmp(signature, computedSignature, SignatureRequest.BYTES)
}

SignatureRequest.prototype._hashHeaders = function(instance, headers) {
  var normalizedHeaders = Object.keys(headers).reduce(function (norm, key) {
    norm[key.toLowerCase()] = headers[key]
    return norm
  }, {})

  this._signedHeaders.forEach(function (header) {
    if (normalizedHeaders[header] == null) return
    // Important to include the header name and a separator, otherwise two
    // different, consecutive, but mutually exclusive headers may produce the
    // same MAC. Also include a trailing separator so the current value may not
    // cause the next header to be conflated
    hash.update(Buffer.from(`${header}:${normalizedHeaders[header]}`))
    hash.update(NL_BUF)
  })
}
