var sodium = require('sodium-native')
var assert = require('nanoassert')

AuthenticatedRequest.BYTES = 64 // Use blake2b-512
AuthenticatedRequest.KEYBYTES = 64 // Key bytes is the same since we use the header mac as the key for the payload hash

var NL_BUF = Buffer.from('\n')

module.exports = AuthenticatedRequest
function AuthenticatedRequest (headerWhitelist) {
  if (!(this instanceof AuthenticatedRequest)) return new AuthenticatedRequest(headerWhitelist)
  assert(Array.isArray(headerWhitelist), 'headerWhitelist must be an array')
  assert(headerWhitelist.every(s => typeof s === 'string'), 'headerWhitelist must be an array of strings')

  this._headerWhitelist = headerWhitelist.map(s => s.toLowerCase()).sort()
}

AuthenticatedRequest.prototype.authenticate = function (key, {method, url, headers, payload}) {
  assert(Buffer.isBuffer(key), 'key must be Buffer (recommended sodium-native Secure Buffer)')
  assert(key.length >= AuthenticatedRequest.KEYBYTES, 'key must be AuthenticatedRequest.KEYBYTES long')
  if (payload == null) payload = new Buffer(0)
  assert(typeof method == 'string', 'method must be string')
  assert(typeof url == 'string', 'method must be string')
  assert(Buffer.isBuffer(payload), 'payload must be Buffer')

  var headerMac = this._hashHeaders(key, method, url, headers)

  var hash = sodium.crypto_generichash_instance(headerMac, AuthenticatedRequest.BYTES)

  hash.update(payload)

  var mac = Buffer.allocUnsafe(AuthenticatedRequest.BYTES)
  hash.final(mac)

  return mac
}

AuthenticatedRequest.prototype.verify = function (mac, key, req) {
  assert(Buffer.isBuffer(mac), 'mac must be Buffer')
  assert(mac.length >= AuthenticatedRequest.BYTES, 'mac must be AuthenticatedRequest.BYTES long')
  // other asserts are defered to authenticate

  var computedMac = this.authenticate(key, req)
  return sodium.sodium_memcmp(mac, computedMac, AuthenticatedRequest.BYTES)
}

AuthenticatedRequest.prototype._hashHeaders = function(key, method, url, headers) {
  // Utilise that Blake2 can function as a prefix MAC
  var hash = sodium.crypto_generichash_instance(key, AuthenticatedRequest.BYTES)

  hash.update(Buffer.from(method.toUpperCase()))
  hash.update(NL_BUF)
  hash.update(Buffer.from(url))
  hash.update(NL_BUF)

  var normalizedHeaders = Object.keys(headers).reduce(function (norm, key) {
    norm[key.toLowerCase()] = headers[key]
    return norm
  }, {})

  this._headerWhitelist.forEach(function (header) {
    if (normalizedHeaders[header] == null) return
    // Important to include the header name and a separator, otherwise two
    // different, consecutive, but mutually exclusive headers may produce the
    // same MAC. Also include a trailing separator so the current value may not
    // cause the next header to be conflated
    hash.update(Buffer.from(`${header}:${normalizedHeaders[header]}`))
    hash.update(NL_BUF)
  })

  var mac = Buffer.allocUnsafe(AuthenticatedRequest.BYTES)
  hash.final(mac)

  return mac
}
