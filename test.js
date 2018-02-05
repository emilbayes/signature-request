var test = require('tape')
var authReq = require('.')

test('Simple test', function (assert) {
  var ar = authReq(['accept-encoding', 'content-length', 'content-type'])

  var key = authReq.keygen()

  var req1 = {
    method: 'GET',
    url: 'www.example.com',
    headers: {
      'Host': 'example.com',
      'X-Forwarded-For': 'localhost',
      'Content-Length': 20
    }
  }

  var req2 = {
    method: 'GET',
    url: 'www.example.com',
    headers: {
      'Host': 'fake.com',
      'X-Forwarded-For': 'localhost',
      'Content-Length': 20
    }
  }

  var mac = ar.authenticate(key, req1)

  assert.ok(ar.verify(mac, key, req2))
  assert.end()
})

test('different keys should fail', function (assert) {
  assert.ok()
  assert.end()
})

test('difference between whitelist and given headers', function (assert) {
  assert.ok()
  assert.end()
})

test('same headers different method', function (assert) {
  assert.ok()
  assert.end()
})

test('same headers different url', function (assert) {
  assert.ok()
  assert.end()
})

test('ignored headers', function (assert) {
  assert.ok()
  assert.end()
})

test('no headers', function (assert) {
  assert.ok()
  assert.end()
})
