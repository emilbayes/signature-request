var test = require('tape')
var authReq = require('.')

test('', function (assert) {
  var ar = authReq(['accept-encoding', 'content-length', 'content-type'])

  {
    'X-Forwarded-For': 'http://localhost.com',
    'Accept-Encoding': 'Jesus',
    'Content-Length': 'Master',
    'Cookie': 'hello World'
  }

  assert.ok()
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
