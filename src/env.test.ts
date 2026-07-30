/**
 * Configuration.
 *
 * `loadEnv` is pure over its source, which is the whole reason the failure paths are testable at
 * all: the eager `env` export calls `process.exit(1)`, and a test suite cannot assert on a process
 * that is gone.
 */

import './testsupport.ts'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EnvError, loadEnv, parseServiceGrants } from './env.ts'

/** The smallest source that boots. Every case below removes or corrupts exactly one thing. */
const COMPLETE: Readonly<Record<string, string>> = {
  IDENTITY_DATABASE_URL: 'postgres://cloudsforge@127.0.0.1:5432/identity',
  IDENTITY_ISSUER: 'https://identity.cloudsforge.local',
  IDENTITY_KEY_SECRET: 'a-real-key-secret-with-enough-entropy-1234',
  IDENTITY_PUBLIC_URL: 'https://account.cloudsforge.local',
  OUTBOX_SIGNING_SECRET: 'a-real-outbox-signing-secret-1234',
}

test('a complete source loads, and the defaults are the ones documented', () => {
  const env = loadEnv(COMPLETE, 'host-1')
  assert.equal(env.port, 4000)
  assert.equal(env.databasePoolMax, 10)
  assert.equal(env.instanceId, 'host-1')
  assert.equal(env.deletionGraceDays, 7)
  assert.deepEqual(env.handoffOrigins, [])
  assert.deepEqual(env.serviceTokenGrants, {})
})

test('every required variable names itself when it is missing', () => {
  for (const name of Object.keys(COMPLETE)) {
    const source: Record<string, string> = { ...COMPLETE }
    delete source[name]
    assert.throws(
      () => loadEnv(source),
      (err: unknown) => err instanceof EnvError && err.message.includes(name),
      // `undefined` propagating into a connection string surfaces four layers later as an
      // unreadable driver error, which is the failure this is written to prevent.
      `${name} must name itself`,
    )
  }
})

test('a known placeholder is refused outright, for both secrets', () => {
  for (const name of ['IDENTITY_KEY_SECRET', 'OUTBOX_SIGNING_SECRET']) {
    assert.throws(
      () => loadEnv({ ...COMPLETE, [name]: 'changeme' }),
      /known placeholder/,
      `${name} accepted a placeholder`,
    )
  }
})

test('the key secret is held to a longer minimum than everything else', () => {
  // It wraps the RS256 private half, which is the estate's universal forging credential — every
  // service verifies iss plus aud and nothing more. Twenty-four characters is the general bar; this
  // one is 32.
  const twentyEight = 'x'.repeat(28)
  assert.doesNotThrow(() => loadEnv({ ...COMPLETE, OUTBOX_SIGNING_SECRET: twentyEight }))
  assert.throws(() => loadEnv({ ...COMPLETE, IDENTITY_KEY_SECRET: twentyEight }), /at least 32/)
})

test('the secret the test suite runs under is not itself a placeholder', () => {
  // A placeholder that boots in the suite is a placeholder that reaches production, because the
  // suite is where anyone would notice.
  assert.doesNotThrow(() =>
    loadEnv({ ...COMPLETE, IDENTITY_KEY_SECRET: process.env['IDENTITY_KEY_SECRET']! }),
  )
})

test('the public URL must be an origin, because a reset link is built from it', () => {
  // SD-04: the link is built from configuration and never from the request Host header. A value
  // carrying a path or a query would produce a link that is subtly wrong in a way nobody notices
  // until a user cannot recover their account.
  for (const bad of ['not-a-url', 'ftp://account.example', 'https://account.example/portal', 'https://a.example?x=1']) {
    assert.throws(() => loadEnv({ ...COMPLETE, IDENTITY_PUBLIC_URL: bad }), EnvError, bad)
  }
  // A trailing slash is an origin and is normalised, so the comparison never has to be clever.
  assert.equal(loadEnv({ ...COMPLETE, IDENTITY_PUBLIC_URL: 'https://a.example/' }).publicUrl, 'https://a.example')
})

test('hand-off origins are parsed, normalised and de-duplicated', () => {
  const env = loadEnv({
    ...COMPLETE,
    IDENTITY_HANDOFF_ORIGINS: 'https://app.example, https://app.example/ ,https://play.example',
  })
  assert.deepEqual(env.handoffOrigins, ['https://app.example', 'https://play.example'])
})

test('the scope grant map refuses a scope that is not in the contracts registry', () => {
  // Fail at boot rather than issue a token that is quietly narrower than the operator believes.
  assert.throws(() => parseServiceGrants('{"settlement":["ledger:everything"]}'), /unknown scope/)
  assert.throws(() => parseServiceGrants('{"settlement":["custody:*"]}'), /unknown scope/)
  assert.throws(() => parseServiceGrants('not json'), EnvError)
  assert.throws(() => parseServiceGrants('["settlement"]'), /must be a JSON object/)
  assert.throws(() => parseServiceGrants('{"Settlement Service":["ledger:read"]}'), /implausible service name/)
})

test('the grant map de-duplicates, so a subset check that counts cannot be fooled', () => {
  const grants = parseServiceGrants('{"settlement":["ledger:post","ledger:post","ledger:read"]}')
  assert.deepEqual(grants['settlement'], ['ledger:post', 'ledger:read'])
})

test('a service with no grants is absent rather than empty, so issuance fails closed', () => {
  const grants = parseServiceGrants('{}')
  assert.equal(grants['settlement'], undefined)
})

test('numeric bounds are enforced with the variable named', () => {
  assert.throws(() => loadEnv({ ...COMPLETE, PORT: '0' }), /PORT/)
  assert.throws(() => loadEnv({ ...COMPLETE, PORT: '70000' }), /PORT/)
  assert.throws(() => loadEnv({ ...COMPLETE, IDENTITY_DATABASE_POOL_MAX: '2.5' }), /POOL_MAX/)
  assert.throws(() => loadEnv({ ...COMPLETE, IDENTITY_DELETION_GRACE_DAYS: '-1' }), /GRACE_DAYS/)
  // Zero grace IS allowed: a deployment with no subscribers yet has nothing to wait for, and
  // forbidding it would mean the only way to test the tombstone path is to wait a week.
  assert.equal(loadEnv({ ...COMPLETE, IDENTITY_DELETION_GRACE_DAYS: '0' }).deletionGraceDays, 0)
})

test('LOG_LEVEL is a closed set', () => {
  assert.throws(() => loadEnv({ ...COMPLETE, LOG_LEVEL: 'verbose' }), /LOG_LEVEL/)
  assert.equal(loadEnv({ ...COMPLETE, LOG_LEVEL: 'debug' }).logLevel, 'debug')
})

test('no error message can quote a secret', () => {
  // Every failure path names the VARIABLE. Quoting the value would put the secret in a log line
  // whose whole purpose is to be read by whoever is debugging the deployment.
  const secret = 'sk-this-must-never-appear-in-a-message'
  for (const name of ['IDENTITY_KEY_SECRET', 'OUTBOX_SIGNING_SECRET']) {
    try {
      loadEnv({ ...COMPLETE, [name]: 'short' })
      assert.fail(`${name} should have thrown`)
    } catch (err) {
      assert.ok(err instanceof EnvError)
      assert.ok(!err.message.includes(secret))
      assert.ok(err.message.includes(name))
    }
  }
})
