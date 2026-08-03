/**
 * The HTTP surface, end to end, against a real server on a real database.
 *
 * These are the tests that prove the routes agree with the modules underneath them — the two have
 * drifted apart before in this estate, which is how Nimbus ended up answering 202 to a
 * forgot-password request that had silently done nothing.
 */

import {
  GOOD_PASSWORD,
  OTHER_PASSWORD,
  enabled,
  freshEmail,
  freshHandle,
  grantAdmin,
  migrateTestDb,
  openDb,
  resetIdentity,
  skip,
} from './testsupport.ts'
import { before, after, beforeEach, test } from 'node:test'
import assert from 'node:assert/strict'
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { randomUUID } from 'node:crypto'
import { decodeJwt } from 'jose'
import { Lifecycle } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics, registerJobMetrics } from '@cloudsforge/telemetry'
import { SCOPE_NAMES } from '@cloudsforge/contracts-auth'
import type postgres from 'postgres'
import { createServer, registerServiceMetrics } from './server.ts'
import { WEBAUTHN_NOT_IMPLEMENTED } from './mfa.ts'
import { DEFAULT_PARAMS, base32Decode, totp } from './totp.ts'
import { ROTATION_GRACE_MS } from './tokens.ts'
import type { Db } from './outbox.ts'

let sql: postgres.Sql
let db: Db
let server: Server
let origin: string

before(async () => {
  if (!enabled) return
  sql = openDb(16)
  await migrateTestDb(sql)
  db = sql as unknown as Db

  const lifecycle = new Lifecycle({ drainDelayMs: 0, drainTimeoutMs: 1_000 })
  lifecycle.markReady()
  server = createServer({
    lifecycle,
    // Silent: these tests deliberately drive failure paths, and the log lines they produce are the
    // correct behaviour rather than noise worth reading.
    logger: new Logger({ service: 'identity-test', level: 'error', sink: () => {} }),
    metrics: registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics()))),
    sql: db,
    deletionGraceDays: 0,
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
})

after(async () => {
  if (!enabled) return
  await new Promise<void>((resolve) => server.close(() => resolve()))
  await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (enabled) await resetIdentity(sql)
})

interface Response {
  readonly status: number
  readonly headers: Headers
  readonly body: Record<string, unknown>
}

/**
 * A distinct client address per call, unless one is given.
 *
 * The per-address limiter is a real control with real ceilings — five registrations a minute — and a
 * suite that shares one address trips it and fails tests that are about something else entirely.
 * Giving each call its own address is also what a suite of independent clients would look like. The
 * limiter itself is exercised deliberately, from a fixed address, in its own test below.
 */
let client = 0
function nextClientAddress(): string {
  client += 1
  return `10.${(client >> 16) & 0xff}.${(client >> 8) & 0xff}.${client & 0xff}`
}

async function call(
  method: string,
  path: string,
  options: { body?: unknown; token?: string; headers?: Record<string, string> } = {},
): Promise<Response> {
  const response = await fetch(`${origin}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      // A stable, plausible browser, so device grouping behaves the way it would in life.
      'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/120',
      'x-forwarded-for': nextClientAddress(),
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      ...options.headers,
    },
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  })
  const text = await response.text()
  return {
    status: response.status,
    headers: response.headers,
    body: text ? (JSON.parse(text) as Record<string, unknown>) : {},
  }
}

interface Registered {
  readonly email: string
  readonly handle: string
  readonly userId: string
  readonly accessToken: string
  readonly refreshToken: string
}

async function register(): Promise<Registered> {
  const email = freshEmail()
  const handle = freshHandle()
  const response = await call('POST', '/auth/register', {
    body: { email, handle, password: GOOD_PASSWORD },
  })
  assert.equal(response.status, 201, JSON.stringify(response.body))
  return {
    email,
    handle,
    userId: (response.body['user'] as { id: string }).id,
    accessToken: response.body['accessToken'] as string,
    refreshToken: response.body['refreshToken'] as string,
  }
}

/* ------------------------------------------------------------------ health and JWKS */

test('the four handlers every service must have are present', { skip }, async () => {
  assert.equal((await call('GET', '/livez')).status, 200)
  assert.equal((await call('GET', '/readyz')).status, 200)
  const metrics = await fetch(`${origin}/metrics`)
  assert.equal(metrics.status, 200)
  assert.match(metrics.headers.get('content-type') ?? '', /text\/plain/)
  assert.match(await metrics.text(), /http_requests_total/)
})

test('JWKS is public, cacheable, and carries no private material', { skip }, async () => {
  const response = await call('GET', '/.well-known/jwks.json')
  assert.equal(response.status, 200)
  const keys = response.body['keys'] as Record<string, unknown>[]
  assert.equal(keys.length, 1)
  assert.equal(keys[0]!['alg'], 'RS256')
  assert.equal(keys[0]!['use'], 'sig')
  for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
    assert.equal(keys[0]![secret], undefined, `${secret} would publish the estate's forging credential`)
  }
  // The one endpoint on this service that may be cached. A verifier re-fetching per request would
  // make identity a synchronous dependency of every request in twenty-two services — SD-01 rejects
  // that on availability grounds.
  assert.match(response.headers.get('cache-control') ?? '', /max-age=300/)
})

test('every other response forbids caching', { skip }, async () => {
  const { accessToken } = await register()
  const me = await call('GET', '/auth/me', { token: accessToken })
  assert.equal(me.headers.get('cache-control'), 'no-store')
  // And varies on the header that decides the answer, so a shared cache cannot serve one user's
  // identity to the next.
  assert.match(me.headers.get('vary') ?? '', /authorization/)
})

/* ------------------------------------------------------------------ the core journey */

test('register, then /auth/me answers with the user and their personal organisation', { skip }, async () => {
  const registered = await register()
  const me = await call('GET', '/auth/me', { token: registered.accessToken })
  assert.equal(me.status, 200)

  const user = me.body['user'] as Record<string, unknown>
  assert.equal(user['id'], registered.userId)
  assert.equal(user['email'], registered.email.toLowerCase())
  assert.equal(user['status'], 'active')
  // "Public" means free of secrets. A password hash or a work factor reaching this shape is the
  // failure the type exists to prevent.
  assert.equal(user['passwordHash'], undefined)
  assert.equal(user['hashAlgo'], undefined)

  const organisations = me.body['organisations'] as Record<string, unknown>[]
  assert.equal(organisations.length, 1, 'there is never a code path that handles "no organisation"')
  assert.equal(organisations[0]!['kind'], 'personal')
  assert.equal(organisations[0]!['role'], 'owner')
})

test('sign in with the address in any casing, and with the handle', { skip }, async () => {
  const registered = await register()
  for (const identifier of [
    registered.email,
    registered.email.toUpperCase(),
    `  ${registered.email}  `,
    registered.handle,
    registered.handle.toUpperCase(),
  ]) {
    const response = await call('POST', '/auth/login', {
      body: { identifier, password: GOOD_PASSWORD },
    })
    assert.equal(response.status, 200, `${identifier} should sign in`)
    assert.ok(response.body['accessToken'])
  }
})

test('a wrong password is 401 and says nothing about whether the account exists', { skip }, async () => {
  const registered = await register()
  const wrong = await call('POST', '/auth/login', {
    body: { identifier: registered.email, password: OTHER_PASSWORD },
  })
  const unknown = await call('POST', '/auth/login', {
    body: { identifier: freshEmail(), password: OTHER_PASSWORD },
  })
  assert.equal(wrong.status, 401)
  assert.equal(unknown.status, 401)
  assert.deepEqual(
    (wrong.body['error'] as Record<string, unknown>)['message'],
    (unknown.body['error'] as Record<string, unknown>)['message'],
    'the two must be indistinguishable',
  )
})

test('refresh rotates, and a replayed token revokes the session', { skip }, async () => {
  const registered = await register()

  const first = await call('POST', '/auth/refresh', { body: { refreshToken: registered.refreshToken } })
  assert.equal(first.status, 200)
  const rotated = first.body['refreshToken'] as string
  assert.notEqual(rotated, registered.refreshToken)
  assert.equal(first.body['expiresIn'], 900)

  // Age the rotation past the grace window so this is a replay rather than a second tab.
  await sql`
    update refresh_tokens set rotated_at = now() - ${`${ROTATION_GRACE_MS + 5_000} milliseconds`}::interval
     where rotated_at is not null
  `
  const replay = await call('POST', '/auth/refresh', { body: { refreshToken: registered.refreshToken } })
  assert.equal(replay.status, 401)

  // The burn is the containment: the successor the legitimate client was holding dies too, so the
  // thief and the victim are both forced back to a real sign-in.
  const afterBurn = await call('POST', '/auth/refresh', { body: { refreshToken: rotated } })
  assert.equal(afterBurn.status, 401)

  const sessions = await sql<{ status: string; revoke_reason: string | null }[]>`
    select status, revoke_reason from sessions where user_id = ${registered.userId}
  `
  assert.equal(sessions[0]!.status, 'revoked')
  assert.equal(sessions[0]!.revoke_reason, 'refresh_reuse_detected')
})

test('the access token names the session, and signing out of it stops the refresh', { skip }, async () => {
  const email = freshEmail()
  const handle = freshHandle()
  const created = await call('POST', '/auth/register', {
    body: { email, handle, password: GOOD_PASSWORD },
    headers: { 'x-forwarded-for': '198.51.100.77' },
  })
  const registered = {
    accessToken: created.body['accessToken'] as string,
    refreshToken: created.body['refreshToken'] as string,
  }

  const claims = decodeJwt(registered.accessToken)
  const sessions = await call('GET', '/sessions', { token: registered.accessToken })
  const listed = sessions.body['sessions'] as Record<string, unknown>[]
  assert.equal(listed.length, 1)
  assert.equal(listed[0]!['id'], claims['sid'])
  assert.equal(listed[0]!['userAgentFamily'], 'Firefox')
  // A prefix, never the address. The client was 198.51.100.77 and what is surfaced is the /24 —
  // the risk signal without the personal identifier.
  assert.equal(listed[0]!['ipPrefix'], '198.51.100.0/24')

  assert.equal((await call('POST', '/auth/logout', { body: { refreshToken: registered.refreshToken } })).status, 204)
  assert.equal(
    (await call('POST', '/auth/refresh', { body: { refreshToken: registered.refreshToken } })).status,
    401,
  )
})

test('sign out everywhere ends every session, the caller included', { skip }, async () => {
  const registered = await register()
  const second = await call('POST', '/auth/login', {
    body: { identifier: registered.email, password: GOOD_PASSWORD },
  })
  const response = await call('DELETE', '/sessions', { token: registered.accessToken })
  assert.equal(response.status, 200)
  // Including the one that pressed it. A "sign out everywhere" that spares the button is not the
  // operation the user asked for — they pressed it because they believe a session is compromised.
  assert.equal(response.body['revoked'], 2)
  for (const token of [registered.refreshToken, second.body['refreshToken'] as string]) {
    assert.equal((await call('POST', '/auth/refresh', { body: { refreshToken: token } })).status, 401)
  }
})

/* ------------------------------------------------------------------ authentication faults */

test('a missing, malformed or expired token is 401 and never says which', { skip }, async () => {
  assert.equal((await call('GET', '/auth/me')).status, 401)
  assert.equal((await call('GET', '/auth/me', { token: 'not-a-jwt' })).status, 401)
  const { accessToken } = await register()
  assert.equal((await call('GET', '/auth/me', { token: `${accessToken}x` })).status, 401)

  const bodies = await Promise.all(
    [undefined, 'not-a-jwt'].map(async (token) => {
      const response = await call('GET', '/auth/me', token ? { token } : {})
      return (response.body['error'] as Record<string, unknown>)['code']
    }),
  )
  assert.deepEqual(bodies, ['unauthenticated', 'unauthenticated'])
})

test('every response carries the request id, and echoes a safe one', { skip }, async () => {
  const response = await call('GET', '/auth/me', { headers: { 'x-request-id': 'abc-123' } })
  assert.equal(response.headers.get('x-request-id'), 'abc-123')
  assert.equal((response.body['error'] as Record<string, unknown>)['requestId'], 'abc-123')

  // An unvalidated inbound id is a header-injection and log-forgery primitive at once, so anything
  // outside the safe alphabet is REPLACED rather than rejected — the caller does not need a 400
  // over this, and an id that reaches a log line unvalidated can forge a log entry.
  //
  // The CRLF payload that would actually split a response cannot be sent through `fetch`, which
  // refuses to serialise it — so the assertion is on the character class, which is the thing the
  // server checks and the thing that would have to be widened for CRLF to get through.
  for (const unsafe of ['has spaces', 'semi;colon', 'x'.repeat(65), 'quote"']) {
    const forged = await call('GET', '/auth/me', { headers: { 'x-request-id': unsafe } })
    assert.notEqual(forged.headers.get('x-request-id'), unsafe, unsafe)
    assert.match(forged.headers.get('x-request-id') ?? '', /^[A-Za-z0-9_-]{1,64}$/, unsafe)
  }
})

/* ------------------------------------------------------------------ MFA over HTTP */

test('enrol TOTP, then a code completes the sign-in', { skip }, async () => {
  const registered = await register()

  const enrolment = await call('POST', '/mfa/totp', { token: registered.accessToken, body: { label: 'Phone' } })
  assert.equal(enrolment.status, 201)
  const secret = base32Decode(enrolment.body['secret'] as string)!
  assert.match(enrolment.body['otpauthUri'] as string, /^otpauth:\/\/totp\//)

  const activation = await call('POST', `/mfa/totp/${enrolment.body['factorId'] as string}/activate`, {
    token: registered.accessToken,
    body: { code: totp(secret, Math.floor(Date.now() / 1000), DEFAULT_PARAMS) },
  })
  assert.equal(activation.status, 200, JSON.stringify(activation.body))

  // Sign-in now stops at the challenge. No session, no token: the password being right is ALL that
  // has been established.
  const login = await call('POST', '/auth/login', {
    body: { identifier: registered.email, password: GOOD_PASSWORD },
  })
  assert.equal(login.status, 200)
  assert.equal(login.body['mfaRequired'], true)
  assert.equal(login.body['accessToken'], undefined)
  assert.equal(login.body['refreshToken'], undefined)

  const step = Math.floor(Date.now() / 1000) + DEFAULT_PARAMS.stepSeconds
  const completed = await call('POST', '/auth/mfa', {
    body: { challenge: login.body['challenge'] as string, code: totp(secret, step, DEFAULT_PARAMS) },
  })
  assert.equal(completed.status, 200, JSON.stringify(completed.body))
  assert.ok(completed.body['accessToken'])

  // The method is recorded in `amr`, which is what lets a later policy demand a step-up.
  assert.deepEqual(decodeJwt(completed.body['accessToken'] as string)['amr'], ['pwd', 'totp'])
})

test('a wrong code spends the challenge, so it is not a guessing oracle', { skip }, async () => {
  const registered = await register()
  const enrolment = await call('POST', '/mfa/totp', { token: registered.accessToken, body: {} })
  const secret = base32Decode(enrolment.body['secret'] as string)!
  await call('POST', `/mfa/totp/${enrolment.body['factorId'] as string}/activate`, {
    token: registered.accessToken,
    body: { code: totp(secret, Math.floor(Date.now() / 1000), DEFAULT_PARAMS) },
  })

  const login = await call('POST', '/auth/login', {
    body: { identifier: registered.email, password: GOOD_PASSWORD },
  })
  const challenge = login.body['challenge'] as string

  assert.equal((await call('POST', '/auth/mfa', { body: { challenge, code: '000000' } })).status, 401)
  // A challenge that survives a wrong code is an unlimited offline-speed oracle against six digits.
  const retry = await call('POST', '/auth/mfa', {
    body: { challenge, code: totp(secret, Math.floor(Date.now() / 1000), DEFAULT_PARAMS) },
  })
  assert.equal(retry.status, 401, 'the challenge is spent whether or not the code was right')
})

test('WebAuthn answers 501 with a message that says what to do instead', { skip }, async () => {
  const { accessToken } = await register()
  for (const path of ['/mfa/webauthn/options', '/mfa/webauthn']) {
    const response = await call('POST', path, { token: accessToken, body: {} })
    // 501 rather than 404: a 404 says "no such thing here" and a client cannot tell it from a typo.
    // A stub that always succeeded would be a factor that is not a factor, which is the only
    // genuinely dangerous option of the three.
    assert.equal(response.status, 501, path)
    assert.equal((response.body['error'] as Record<string, unknown>)['message'], WEBAUTHN_NOT_IMPLEMENTED)
  }
})

test('removing the last factor is 403 without the password and 200 with it', { skip }, async () => {
  const registered = await register()
  const enrolment = await call('POST', '/mfa/totp', { token: registered.accessToken, body: {} })
  const secret = base32Decode(enrolment.body['secret'] as string)!
  const factorId = enrolment.body['factorId'] as string
  await call('POST', `/mfa/totp/${factorId}/activate`, {
    token: registered.accessToken,
    body: { code: totp(secret, Math.floor(Date.now() / 1000), DEFAULT_PARAMS) },
  })

  const refused = await call('DELETE', `/mfa/factors/${factorId}`, { token: registered.accessToken, body: {} })
  assert.equal(refused.status, 403)
  assert.equal((refused.body['error'] as Record<string, unknown>)['code'], 'reauthentication_required')

  // A session opened an hour ago is not proof that the person at the keyboard is the owner, which
  // is the whole point of the requirement — so the password must be presented in THIS request.
  const wrong = await call('DELETE', `/mfa/factors/${factorId}`, {
    token: registered.accessToken,
    body: { password: OTHER_PASSWORD },
  })
  assert.equal(wrong.status, 403)

  const removed = await call('DELETE', `/mfa/factors/${factorId}`, {
    token: registered.accessToken,
    body: { password: GOOD_PASSWORD },
  })
  assert.equal(removed.status, 200)
  assert.equal(removed.body['wasLastActive'], true)
})

/* ------------------------------------------------------------------ password recovery */

/**
 * **The timing test.**
 *
 * The route answers 202 identically for a known and an unknown address, and the RESPONSE TIME must
 * say no more than the body does. Measured on Nimbus against a relay that accepts and never speaks,
 * an unknown address answered in 10ms and a known one in 6015ms — the full attempt budget — which
 * is a reliable enumeration oracle produced entirely by awaiting the work.
 *
 * The assertion is on the MEDIAN of several rounds rather than a single pair, because a single
 * measurement on a shared machine is noise. The bound is generous for the same reason: what is
 * being caught is a difference of seconds, not of milliseconds.
 */
test('forgot-password answers 202 in the same time for a known and an unknown address', { skip }, async () => {
  const registered = await register()
  const rounds = 7

  const measure = async (email: string): Promise<number> => {
    const started = process.hrtime.bigint()
    const response = await call('POST', '/auth/password/forgot', { body: { email } })
    const elapsed = Number(process.hrtime.bigint() - started) / 1e6
    assert.equal(response.status, 202)
    // One string for both branches. It varies with the DEPLOYMENT, never with the account.
    assert.match(response.body['status'] as string, /If that account exists/)
    return elapsed
  }

  const median = (values: number[]): number => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)]!

  const known: number[] = []
  const unknown: number[] = []
  for (let round = 0; round < rounds; round += 1) {
    // Interleaved, so a machine that gets busy part-way through affects both samples equally.
    known.push(await measure(registered.email))
    unknown.push(await measure(freshEmail()))
  }

  const difference = Math.abs(median(known) - median(unknown))
  assert.ok(
    difference < 50,
    `a known and an unknown address must answer in the same time; median difference was ${difference.toFixed(1)}ms`,
  )

  // And the work still happened, after the response — which is what makes this a test of "answered
  // early" rather than of "did nothing". Nimbus's forgot-password looked up `lower(email)` against
  // rows written verbatim, found nothing, and returned the same deliberate 202, so the reset
  // silently did nothing and told the user it had worked.
  await new Promise((resolve) => setTimeout(resolve, 300))
  const unused = await sql<{ token_hash: string }[]>`
    select token_hash from password_reset_tokens
     where user_id = ${registered.userId} and used_at is null and expires_at > now()
  `
  // Exactly one, after seven requests: issuing SUPERSEDES rather than accumulates, because the
  // older token is the one most likely to have leaked into a mail client or a chat log.
  assert.equal(unused.length, 1, 'answering first must not mean never doing the work')
})

test('a malformed address gets the same 202, not a 400', { skip }, async () => {
  const response = await call('POST', '/auth/password/forgot', { body: { email: 'not-an-address' } })
  assert.equal(response.status, 202)
  assert.equal((await call('POST', '/auth/password/forgot', { body: {} })).status, 202)
})

test('spending a reset sets the password and revokes every session', { skip }, async () => {
  const registered = await register()
  await call('POST', '/auth/password/forgot', { body: { email: registered.email } })
  await new Promise((resolve) => setTimeout(resolve, 250))

  // The raw token exists only in the response of the delivery channel, and there is none — so the
  // test mints one the same way an operator would, through the same function the route uses.
  const { createPasswordResetToken, resetUrlFor } = await import('./passwordReset.ts')
  const issued = await createPasswordResetToken(db, registered.userId, null)

  // SD-04: the link is built from IDENTITY_PUBLIC_URL and never from the request Host header, and
  // the token rides in the fragment so it reaches no server log or Referer header.
  const url = resetUrlFor(issued.token)
  assert.ok(url.startsWith('https://account.test.cloudsforge.local/reset#token='))
  assert.ok(!url.includes('127.0.0.1'), 'the link must never follow the request host')

  const reset = await call('POST', '/auth/password/reset', {
    body: { token: issued.token, newPassword: OTHER_PASSWORD },
  })
  assert.equal(reset.status, 204)

  // Single use.
  assert.equal(
    (await call('POST', '/auth/password/reset', { body: { token: issued.token, newPassword: OTHER_PASSWORD } }))
      .status,
    401,
  )
  // Spending it revokes every refresh family, so whoever forced the reset does not survive it.
  assert.equal(
    (await call('POST', '/auth/refresh', { body: { refreshToken: registered.refreshToken } })).status,
    401,
  )
  assert.equal(
    (await call('POST', '/auth/login', { body: { identifier: registered.email, password: OTHER_PASSWORD } }))
      .status,
    200,
  )
})

test('changing a password keeps the calling session and ends the others', { skip }, async () => {
  const registered = await register()
  const other = await call('POST', '/auth/login', {
    body: { identifier: registered.email, password: GOOD_PASSWORD },
  })

  const wrong = await call('POST', '/auth/password', {
    token: registered.accessToken,
    body: { currentPassword: OTHER_PASSWORD, newPassword: 'a-brand-new-password-42' },
  })
  // NOT `unauthenticated`. This route answers 401 for two unrelated reasons, and a client that
  // cannot tell them apart shows "your session expired" to someone who simply mistyped.
  assert.equal(wrong.status, 401)
  assert.equal((wrong.body['error'] as Record<string, unknown>)['code'], 'bad_password')

  const changed = await call('POST', '/auth/password', {
    token: registered.accessToken,
    body: { currentPassword: GOOD_PASSWORD, newPassword: 'a-brand-new-password-42' },
  })
  assert.equal(changed.status, 200)
  assert.equal(changed.body['sessionsRevoked'], 1)

  // The person who just proved they know the password stays signed in; whoever knew the old one
  // does not.
  assert.equal(
    (await call('POST', '/auth/refresh', { body: { refreshToken: registered.refreshToken } })).status,
    200,
  )
  assert.equal(
    (await call('POST', '/auth/refresh', { body: { refreshToken: other.body['refreshToken'] as string } })).status,
    401,
  )
})

/* ------------------------------------------------------------------ service tokens */

/**
 * An operator, promoted the way the estate now has to promote one.
 *
 * This used to be a bare `update users set roles = '{player,admin}'`, and migration 12 refuses it:
 * the deferred trigger fires at the implicit commit of that one statement and raises 23514, so the
 * whole service suite went red the moment the guard landed. That failure is the guard working
 * rather than a harness problem — the statement it refused is character for character the one
 * `deploy/scripts/estate-bootstrap.sh:102` runs, which is the defect being closed.
 */
async function makeAdmin(): Promise<string> {
  const registered = await register()
  await grantAdmin(sql, registered.userId)
  const login = await call('POST', '/auth/login', {
    body: { identifier: registered.email, password: GOOD_PASSWORD },
  })
  return login.body['accessToken'] as string
}

/**
 * **SD-05: exactly the scopes requested, and no more.**
 *
 * This is what retires `PAY_SERVICE_TOKEN` and `KEYVAULT_SERVICE_TOKEN` — one bearer string each,
 * granting everything the service can do, with no identity, scope, expiry or audit trail.
 */
test('a service token carries exactly the scopes requested and nothing else', { skip }, async () => {
  const admin = await makeAdmin()
  // The suite's grant map allows settlement three scopes. This asks for one.
  const response = await call('POST', '/service-tokens', {
    token: admin,
    body: { service: 'settlement', scopes: ['ledger:post'] },
  })
  assert.equal(response.status, 201, JSON.stringify(response.body))
  assert.deepEqual(response.body['scopes'], ['ledger:post'])

  const claims = decodeJwt(response.body['token'] as string)
  assert.deepEqual(claims['scopes'], ['ledger:post'], 'not widened to the allowlist')
  assert.equal(claims['typ'], 'service')
  // `service:<name>` is how the runtime verifier decides this is not a user. A service token
  // accepted where a user token was expected makes `sub` look like a user id.
  assert.equal(claims['sub'], 'service:settlement')
  assert.equal(claims['exp']! - claims['iat']!, 600, 'SD-05: ten minutes; rotation IS expiry')

  // A least-privilege call site is actually least-privilege, not nominally so.
  const wider = await call('POST', '/service-tokens', {
    token: admin,
    body: { service: 'settlement', scopes: ['ledger:post', 'ledger:read'] },
  })
  assert.deepEqual(decodeJwt(wider.body['token'] as string)['scopes'], ['ledger:post', 'ledger:read'])
})

test('a scope the service was never granted is refused, and so is an unknown one', { skip }, async () => {
  const admin = await makeAdmin()
  // `market` is granted ledger:reserve and ledger:read, and nothing on custody.
  const refused = await call('POST', '/service-tokens', {
    token: admin,
    body: { service: 'market', scopes: ['custody:sign:treasury'] },
  })
  assert.equal(refused.status, 403)
  assert.equal((refused.body['error'] as Record<string, unknown>)['code'], 'scope_not_granted')

  // Fail-closed: a service absent from the map gets nothing at all.
  const unknownService = await call('POST', '/service-tokens', {
    token: admin,
    body: { service: 'whatever', scopes: ['ledger:read'] },
  })
  assert.equal(unknownService.status, 403)

  // There is no wildcard, deliberately: a credential that grants everything is a credential nobody
  // can reason about, which is exactly the property of the shared secret being replaced.
  for (const scope of ['custody:*', 'ledger:*', '*', 'ledger:everything']) {
    const response = await call('POST', '/service-tokens', {
      token: admin,
      body: { service: 'settlement', scopes: [scope] },
    })
    assert.equal(response.status, 400, scope)
    assert.equal((response.body['error'] as Record<string, unknown>)['code'], 'unknown_scope')
  }
  assert.ok(SCOPE_NAMES.length > 0)
})

test('issuing a service token requires the admin role and leaves a row naming the operator', { skip }, async () => {
  const ordinary = await register()
  const refused = await call('POST', '/service-tokens', {
    token: ordinary.accessToken,
    body: { service: 'settlement', scopes: ['ledger:read'] },
  })
  assert.equal(refused.status, 403)

  const admin = await makeAdmin()
  const issued = await call('POST', '/service-tokens', {
    token: admin,
    body: { service: 'settlement', scopes: ['ledger:read'] },
  })
  const rows = await sql<{ jti: string; service: string; scopes: string[]; issued_by: string | null }[]>`
    select jti, service, scopes, issued_by from service_token_issues
  `
  assert.equal(rows.length, 1)
  assert.equal(rows[0]!.jti, issued.body['jti'])
  assert.deepEqual(rows[0]!.scopes, ['ledger:read'])
  // "Which service was granted what, by whom, and when" is the first question of any incident, and
  // the one the two shared secrets could never answer.
  assert.ok(rows[0]!.issued_by)
})

test('a service token is refused where a user token is required', { skip }, async () => {
  const admin = await makeAdmin()
  const issued = await call('POST', '/service-tokens', {
    token: admin,
    body: { service: 'settlement', scopes: ['ledger:read'] },
  })
  // `typ` is the discriminant and it is checked before anything else. Accepting this would make
  // `sub` — a service name — look like a user id to every lookup after it.
  const response = await call('GET', '/auth/me', { token: issued.body['token'] as string })
  assert.equal(response.status, 403)
})

/* ------------------------------------------------------------------ platform roles */

/**
 * A service token for admin-api holding `identity:admin`, minted the real way.
 *
 * Not a hand-built principal. `parseServiceGrants` refuses an unknown scope at import
 * (`env.ts:141`), so a token that comes out of this function is proof that `identity:admin` is in
 * the contracts registry and that identity can actually mint it — which is the half a fake
 * principal cannot prove, and the half that was missing from thirty-nine scopes estate-wide.
 */
async function adminApiToken(scopes: string[] = ['identity:admin']): Promise<string> {
  const admin = await makeAdmin()
  const issued = await call('POST', '/service-tokens', {
    token: admin,
    body: { service: 'admin-api', scopes },
  })
  assert.equal(issued.status, 201, JSON.stringify(issued.body))
  return issued.body['token'] as string
}

test('the route admin-api answers 501 without: a service token holding identity:admin promotes', { skip }, async () => {
  const subject = await register()
  const token = await adminApiToken()
  const approvalId = randomUUID()

  const response = await call('PUT', `/internal/users/${subject.userId}/roles`, {
    token,
    body: {
      roles: ['player', 'admin'],
      actor: 'operator:ada',
      reason: 'approved by two operators in the queue',
      approvalId,
    },
  })
  assert.equal(response.status, 200, JSON.stringify(response.body))
  assert.deepEqual(response.body['granted'], ['admin'])

  // The promotion is real, and it carries its authorisation.
  const me = await call('POST', '/auth/login', {
    body: { identifier: subject.email, password: GOOD_PASSWORD },
  })
  assert.deepEqual(decodeJwt(me.body['accessToken'] as string)['roles'], ['admin', 'player'])

  const grants = await call('GET', `/internal/users/${subject.userId}/role-grants`, { token })
  assert.equal(grants.status, 200)
  const rows = grants.body['grants'] as Array<Record<string, unknown>>
  assert.equal(rows.length, 1)
  assert.equal(rows[0]?.['source'], 'approval')
  assert.equal(rows[0]?.['approvalId'], approvalId)
})

test('the promotion route refuses an operator token, a scopeless service token and no token', { skip }, async () => {
  const subject = await register()
  const body = {
    roles: ['player', 'admin'],
    actor: 'operator:ada',
    reason: 'straight to the promotion, skipping the queue',
    approvalId: randomUUID(),
  }
  const path = `/internal/users/${subject.userId}/roles`

  // An operator's OWN token, which is the one that reads like it ought to work. It must not: a
  // human who can promote directly is one pair of eyes on the estate's most consequential write,
  // which is exactly what admin-api's four-eyes queue exists to prevent.
  const operator = await makeAdmin()
  assert.equal((await call('PUT', path, { token: operator, body })).status, 403)

  // A service token for a service that holds a different scope entirely.
  const wrongScope = await call('POST', '/service-tokens', {
    token: operator,
    body: { service: 'settlement', scopes: ['ledger:read'] },
  })
  assert.equal(
    (await call('PUT', path, { token: wrongScope.body['token'] as string, body })).status,
    403,
  )

  assert.equal((await call('PUT', path, { body })).status, 401)

  // None of the three wrote anything.
  const login = await call('POST', '/auth/login', {
    body: { identifier: subject.email, password: GOOD_PASSWORD },
  })
  assert.deepEqual(decodeJwt(login.body['accessToken'] as string)['roles'], ['player'])
})

test('the approval id is required, not optional — an unapproved promotion is a 400', { skip }, async () => {
  // An optional approval id would make the unapproved promotion the easy call and the approved one
  // the careful call, which is the wrong way round for the only route in the estate that can mint
  // an administrator.
  const subject = await register()
  const token = await adminApiToken()
  const path = `/internal/users/${subject.userId}/roles`

  assert.equal(
    (await call('PUT', path, {
      token,
      body: { roles: ['player', 'admin'], actor: 'operator:ada', reason: 'no approval' },
    })).status,
    400,
  )
  assert.equal(
    (await call('PUT', path, {
      token,
      body: {
        roles: ['player', 'admin'],
        actor: 'operator:ada',
        reason: 'not a uuid',
        approvalId: 'approval-7',
      },
    })).status,
    400,
  )
  assert.equal(
    (await call('PUT', path, {
      token,
      body: {
        roles: ['player', 'superuser'],
        actor: 'operator:ada',
        reason: 'inventing a role',
        approvalId: randomUUID(),
      },
    })).status,
    400,
  )
})

test('the route cannot spend the bootstrap slot, whatever it is asked for', { skip }, async () => {
  // The property the whole design rests on: an environment gets exactly ONE administrator that
  // answers to nothing, and this service is not able to create it. Every row this route writes says
  // 'approval' and carries an id, so the one-per-database bootstrap grant stays where the runbook
  // put it.
  const first = await register()
  const second = await register()
  const token = await adminApiToken()

  for (const subject of [first, second]) {
    const response = await call('PUT', `/internal/users/${subject.userId}/roles`, {
      token,
      body: {
        roles: ['player', 'admin'],
        actor: 'operator:ada',
        reason: 'both approved',
        approvalId: randomUUID(),
      },
    })
    assert.equal(response.status, 200, JSON.stringify(response.body))
  }

  // Three promotions have happened by now — the two above, plus the operator `adminApiToken` had to
  // make to mint its token — and not one of them was able to write a bootstrap row.
  const rows = await sql<{ source: string; n: number }[]>`
    select source, count(*)::int as n from platform_role_grants group by source order by source
  `
  assert.deepEqual([...rows], [{ source: 'approval', n: 3 }], 'no bootstrap row exists, and none can')
  const bootstrapped = await sql<{ n: number }[]>`
    select count(*)::int as n from platform_role_grants where source = 'bootstrap'
  `
  assert.equal(bootstrapped[0]?.n, 0, 'the slot the runbook owns is still unspent')
})

/* ------------------------------------------------------------------ the hand-off */

test('a hand-off code is minted for an allowlisted origin and redeemed once', { skip }, async () => {
  const registered = await register()
  const refused = await call('POST', '/auth/handoff', {
    token: registered.accessToken,
    body: { redirectOrigin: 'https://evil.example' },
  })
  assert.equal(refused.status, 403)

  const minted = await call('POST', '/auth/handoff', {
    token: registered.accessToken,
    body: { redirectOrigin: 'https://app.test.cloudsforge.local' },
  })
  assert.equal(minted.status, 201)
  const code = minted.body['code'] as string

  // A browser always sends Origin on a cross-site POST, so requiring it means a code lifted from
  // history is useless to a non-browser client.
  assert.equal((await call('POST', '/auth/handoff/redeem', { body: { code } })).status, 400)

  const redeemed = await call('POST', '/auth/handoff/redeem', {
    body: { code },
    headers: { origin: 'https://app.test.cloudsforge.local' },
  })
  assert.equal(redeemed.status, 200)
  assert.deepEqual(decodeJwt(redeemed.body['accessToken'] as string)['amr'], ['sso'])

  assert.equal(
    (await call('POST', '/auth/handoff/redeem', {
      body: { code },
      headers: { origin: 'https://app.test.cloudsforge.local' },
    })).status,
    401,
    'single use',
  )
})

/* ------------------------------------------------------------------ deletion */

test('deletion is a lifecycle: requested, published, then tombstoned', { skip }, async () => {
  const registered = await register()

  // The password again, for the same reason the last MFA factor needs it: this is the one operation
  // with no undo after the grace window.
  assert.equal((await call('DELETE', '/users/me', { token: registered.accessToken, body: {} })).status, 403)

  const requested = await call('DELETE', '/users/me', {
    token: registered.accessToken,
    body: { password: GOOD_PASSWORD },
  })
  assert.equal(requested.status, 202)
  assert.equal(requested.body['sessionsRevoked'], 1)

  const users = await sql<{ status: string; pending_deletion_at: Date | null }[]>`
    select status, pending_deletion_at from users where id = ${registered.userId}
  `
  assert.equal(users[0]!.status, 'pending_deletion')
  assert.ok(users[0]!.pending_deletion_at)

  // The event is written in the SAME transaction as the status change. Fourteen databases erase on
  // it, and a crash between the two would be an erasure that silently did not happen.
  const events = await sql<{ topic: string; key: string; payload: Record<string, unknown> }[]>`
    select topic, key, payload from outbox where topic = 'identity.user.deleted'
  `
  assert.equal(events.length, 1)
  assert.equal(events[0]!.key, registered.userId)
  assert.ok(events[0]!.payload['tombstoneAt'], 'a subscriber must know how long it has')

  // Every session, with no exception for the one that made the request.
  assert.equal(
    (await call('POST', '/auth/refresh', { body: { refreshToken: registered.refreshToken } })).status,
    401,
  )

  // The grace window is only meaningful if the real owner can get back in during it — which is why
  // `pending_deletion` is a state you may still authenticate from.
  const back = await call('POST', '/auth/login', {
    body: { identifier: registered.email, password: GOOD_PASSWORD },
  })
  assert.equal(back.status, 200)
  const cancelled = await call('POST', '/users/me/deletion/cancel', {
    token: back.body['accessToken'] as string,
  })
  assert.equal(cancelled.status, 200)
  assert.equal(
    (await sql<{ status: string }[]>`select status from users where id = ${registered.userId}`)[0]!.status,
    'active',
  )
})

test('a tombstone keeps only the id and the dates, and frees the address for reuse', { skip }, async () => {
  const registered = await register()
  await call('DELETE', '/users/me', { token: registered.accessToken, body: { password: GOOD_PASSWORD } })

  const { dueForTombstone, tombstoneAccount } = await import('./deletion.ts')
  // The suite runs with a zero-day grace, so the account is due immediately.
  const due = await dueForTombstone(db, 0)
  assert.deepEqual(due, [registered.userId])
  assert.equal(await tombstoneAccount(db, registered.userId), true)

  const rows = await sql<
    { status: string; email: string; handle: string; password_hash: string; roles: string[] }[]
  >`select status, email, handle, password_hash, roles from users where id = ${registered.userId}`
  const row = rows[0]!
  assert.equal(row.status, 'deleted')
  // `.invalid` is reserved by RFC 6761 and can never be a real domain, so a tombstone can never be
  // mailed by accident. The local part is a HASH of the id, not the id: putting the id in a column
  // shaped like an address invites a future join written by someone who assumes it is one.
  assert.match(row.email, /^[0-9a-f]{32}@deleted\.invalid$/)
  assert.ok(!row.email.includes(registered.userId))
  assert.match(row.handle, /^deleted_/)
  // Not a hash of anything: this cannot be produced by hashPassword and so cannot ever verify.
  assert.equal(row.password_hash, 'tombstone')
  assert.deepEqual(row.roles, [])

  /* Every child row is gone, and this is asserted table by table because assuming a cascade would
   * do it was a bug: every one of these declares `on delete cascade` from `users`, which is right
   * for a hard delete and does nothing at all for a tombstone. An UPDATE fires no cascade, so the
   * profile — display name, bio, country, links — survived erasure on a row marked `deleted`. */
  for (const table of ['profiles', 'devices', 'sessions', 'mfa_factors', 'mfa_challenges', 'password_reset_tokens']) {
    const remaining = await sql.unsafe(`select 1 from ${table} where user_id = $1`, [registered.userId])
    assert.equal((remaining as unknown[]).length, 0, `${table} still holds personal data`)
  }
  // The personal organisation goes with its owner; a shared one cannot reach here at all, because
  // `requestDeletion` refuses to start while this user is the sole owner of one.
  const organisations = await sql<{ organisation_id: string }[]>`
    select organisation_id from memberships where user_id = ${registered.userId}
  `
  assert.equal(organisations.length, 0)

  // And the address is free: a person who deletes their account and signs up again must be able to.
  const again = await call('POST', '/auth/register', {
    body: { email: registered.email, handle: freshHandle(), password: GOOD_PASSWORD },
  })
  assert.equal(again.status, 201)
})

test('a sole owner of a team cannot delete until they have handed it over', { skip }, async () => {
  const registered = await register()
  const id = (await sql<{ id: string }[]>`
    insert into organisations (id, slug, name, kind)
    values (gen_random_uuid(), ${`team-${Date.now()}`}, 'A team', 'team') returning id
  `)[0]!.id
  await sql`
    insert into memberships (organisation_id, user_id, role, accepted_at)
    values (${id}, ${registered.userId}, 'owner', now())
  `

  const response = await call('DELETE', '/users/me', {
    token: registered.accessToken,
    body: { password: GOOD_PASSWORD },
  })
  assert.equal(response.status, 409)
  const error = response.body['error'] as Record<string, unknown>
  assert.equal(error['code'], 'would_orphan_organisations')
  // Named, so the user can act on it rather than being told only that something is wrong.
  assert.equal((error['organisations'] as string[]).length, 1)
})

/* ------------------------------------------------------------------ rate limiting */

/**
 * The per-address ceiling on the credential-accepting routes.
 *
 * Stated honestly, this is the weaker of two controls: the gateway owns the real per-IP limit and
 * the per-account lock-out is what stops a distributed guessing run. What it adds is a ceiling on
 * how much work one address can make ONE process do — scrypt at N=16384 is memory-hard, and an
 * unauthenticated caller can otherwise invoke it as fast as it can open sockets.
 */
test('one address cannot register without bound', { skip }, async () => {
  const from = { 'x-forwarded-for': '198.51.100.200' }
  const statuses: number[] = []
  for (let attempt = 0; attempt < 7; attempt += 1) {
    const response = await call('POST', '/auth/register', {
      body: { email: freshEmail(), handle: freshHandle(), password: GOOD_PASSWORD },
      headers: from,
    })
    statuses.push(response.status)
    if (response.status === 429) {
      assert.ok(Number(response.headers.get('retry-after')) > 0, 'a 429 must say when to come back')
      assert.equal((response.body['error'] as Record<string, unknown>)['code'], 'rate_limited')
    }
  }
  assert.equal(statuses.filter((s) => s === 201).length, 5, 'five, then refusals')
  assert.ok(statuses.includes(429))

  // Keyed per route AND per address, so exhausting one route does not lock a caller out of the
  // others — a client that has been refused a registration must still be able to sign in.
  const login = await call('POST', '/auth/login', {
    body: { identifier: 'nobody@example.test', password: OTHER_PASSWORD },
    headers: from,
  })
  assert.equal(login.status, 401, 'a different route has its own budget')
})

test('minting a hand-off code is throttled, and a REFUSAL costs the same as a success', { skip }, async () => {
  // `/auth/handoff` had no entry in LIMITS at all while `/auth/handoff/redeem` had one, so the mint
  // half of the pair was uncapped. It matters more than an unthrottled authenticated route usually
  // does: minting is the estate's only probe of IDENTITY_HANDOFF_ORIGINS, and an uncapped one
  // enumerates the allowlist by the difference between 201 and 403.
  const registered = await register()
  const from = { 'x-forwarded-for': '198.51.100.201' }
  const statuses: number[] = []
  let retryAfter = 0

  for (let attempt = 0; attempt < 22; attempt += 1) {
    // EVERY call here is refused — `https://evil.example` is not on the suite's allowlist — so this
    // does not merely check that twenty successes are capped. It is the shape `micro-custody` was
    // found in: two paths threw plain `Error`s where refusals belonged, reached the route as 500s
    // writing no audit row, and its limiter counts audit rows — so a route that WAS in the throttle
    // table was an unlimited probe path in practice. Identity's limiter is taken in `handle()`
    // before `route.handle()` runs, so nothing the handler does or fails to do can decide whether a
    // request was counted. Twenty-two refusals must still produce a 429.
    const response = await call('POST', '/auth/handoff', {
      token: registered.accessToken,
      body: { redirectOrigin: 'https://evil.example' },
      headers: from,
    })
    statuses.push(response.status)
    if (response.status === 429) retryAfter = Number(response.headers.get('retry-after'))
  }

  assert.equal(statuses.filter((s) => s === 403).length, 20, 'twenty refusals, then the ceiling')
  assert.equal(statuses.filter((s) => s === 429).length, 2)
  assert.equal(statuses.filter((s) => s === 201).length, 0, 'not one of these may have minted')
  assert.ok(retryAfter > 0, 'a 429 must say when to come back')

  // The pair carries one number, because a mint and a redemption are two halves of ONE cross-surface
  // navigation. A caller that has exhausted its mints has not exhausted its redemptions: the code it
  // already holds must still be spendable, or the throttle would strand a user mid-sign-in.
  const redeem = await call('POST', '/auth/handoff/redeem', {
    body: { code: 'a'.repeat(64) },
    headers: { ...from, origin: 'https://app.test.cloudsforge.local' },
  })
  assert.equal(redeem.status, 401, 'the other half of the pair has its own budget')
})

/* ------------------------------------------------------------------ what must NOT be here */

test('identity serves no product surface', { skip }, async () => {
  // No dashboard, no launcher grid, no balance. Nimbus grew a 1076-line HTML portal that reads a
  // wallet balance, and the moment the service holding the estate's signing key also parses product
  // state and serves markup to browsers, the security boundary is gone.
  for (const path of ['/', '/portal', '/dashboard', '/reset', '/pay', '/balance', '/wallet']) {
    const response = await call('GET', path)
    assert.equal(response.status, 404, path)
  }
  const response = await call('GET', '/auth/me', { headers: { accept: 'text/html' } })
  assert.match(response.headers.get('content-type') ?? '', /application\/json/)
})
