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
import { HANDOFF_ORIGIN_REFUSED_CODE } from './handoff.ts'
import { requestEmailVerification } from './emailVerification.ts'
import { WEBAUTHN_NOT_IMPLEMENTED } from './mfa.ts'
import { DEFAULT_PARAMS, base32Decode, totp } from './totp.ts'
import { ROTATION_GRACE_MS } from './tokens.ts'
import type { Db } from './outbox.ts'

let sql: postgres.Sql
let db: Db
let server: Server
let origin: string

/* ------------------------------------------------------- the second server: Turnstile enabled */

/**
 * A SECOND server, identical to the first except that it has a registration challenge.
 *
 * Two servers rather than one mutable dependency, because "the route is exactly what it was when
 * Turnstile is not configured" is one of the properties under test and it is only worth anything if
 * something is actually running in that state. `server` above is that deployment — every other test
 * in this file drives it, and if the gate leaked into the unconfigured path they would all go red.
 *
 * Both share one database, so a service token minted through `server` verifies at `challenged`.
 */
let challenged: Server
let challengedOrigin: string

const CHALLENGE_HOSTNAME = 'hub.challenge.test'

/**
 * What Cloudflare answers next, and what it was asked.
 *
 * A `let` a test assigns rather than a fixed double: a fake that can only say `success: true`
 * proves nothing at all (micro-org#355, #356), so every case below has to be able to make
 * siteverify refuse, hang up, or answer something unreadable.
 */
/**
 * `Response` in this file is the local JSON-shaped interface a few lines up, so the real one has to
 * be named through `fetch`'s own return type rather than shadowed.
 */
type HttpResponse = Awaited<ReturnType<typeof fetch>>

let siteverify: (body: URLSearchParams) => HttpResponse = () => new Response('{}', { status: 200 })
let siteverifyCalls: URLSearchParams[] = []

const TURNSTILE_SECRET_FIXTURE = `0x4AAAAAAA${randomUUID().replaceAll('-', '')}`

function answers(payload: unknown): void {
  siteverify = () =>
    new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
}

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
    // The harness talks to the server directly, with no gateway to stamp `CF-Network`. Same
    // position as `pnpm dev`, and the same setting covers it — every route would otherwise answer
    // 500 `network_unknown`, which is deliberate for a real request and wrong for this one.
    singleNetwork: 'mainnet' as const,
    deletionGraceDays: 0,
    // NOT configured, which is the state every developer machine and every micro network is in.
    // Every other test in this file runs against it, so a gate that leaked into this path would
    // take the whole file down rather than hide.
    turnstile: null,
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`

  const challengedLifecycle = new Lifecycle({ drainDelayMs: 0, drainTimeoutMs: 1_000 })
  challengedLifecycle.markReady()
  challenged = createServer({
    lifecycle: challengedLifecycle,
    logger: new Logger({ service: 'identity-test-challenged', level: 'error', sink: () => {} }),
    metrics: registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics()))),
    sql: db,
    // The harness talks to the server directly, with no gateway to stamp `CF-Network`. Same
    // position as `pnpm dev`, and the same setting covers it — every route would otherwise answer
    // 500 `network_unknown`, which is deliberate for a real request and wrong for this one.
    singleNetwork: 'mainnet' as const,
    deletionGraceDays: 0,
    turnstile: {
      secret: TURNSTILE_SECRET_FIXTURE,
      siteKey: '0x4AAAAAAEMXmH8jdtxq8FYo',
      hostnames: [CHALLENGE_HOSTNAME],
    },
    // No network. The suite IS Cloudflare here, and it can refuse.
    turnstileFetch: async (_url, init) => {
      const body = new URLSearchParams(String(init.body))
      siteverifyCalls.push(body)
      return siteverify(body)
    },
  })
  await new Promise<void>((resolve) => challenged.listen(0, '127.0.0.1', () => resolve()))
  challengedOrigin = `http://127.0.0.1:${(challenged.address() as AddressInfo).port}`
})

after(async () => {
  if (!enabled) return
  await new Promise<void>((resolve) => server.close(() => resolve()))
  await new Promise<void>((resolve) => challenged.close(() => resolve()))
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
  options: { body?: unknown; token?: string; headers?: Record<string, string>; at?: string } = {},
): Promise<Response> {
  const response = await fetch(`${options.at ?? origin}${path}`, {
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

/**
 * A registered AND verified account, which is what most of this file needs to talk about.
 *
 * Registration answers 202 and mints nothing now — the account exists unverified and cannot sign
 * in. Everything below that is about sessions, MFA, organisations or deletion starts from a person
 * who has been through the whole front door, so the helper walks the link too.
 */
async function register(): Promise<Registered> {
  const email = freshEmail()
  const handle = freshHandle()
  const response = await call('POST', '/auth/register', {
    body: { email, handle, password: GOOD_PASSWORD },
  })
  assert.equal(response.status, 202, JSON.stringify(response.body))
  return { email, handle, ...(await verifyEmail(email)) }
}

/**
 * Spend a verification link the way the Hub page does: mint, then POST the token.
 *
 * **The token is produced by the code under test rather than written here.** It cannot be read back
 * out of the database — only its SHA-256 is stored, which is the property the whole design rests on
 * — so the suite calls the real mint and uses what it returns. That also means this walks the same
 * supersession path a resend does: the token registration minted is burned by this one.
 */
async function verifyEmail(
  email: string,
  headers: Record<string, string> = {},
): Promise<{ userId: string; accessToken: string; refreshToken: string }> {
  const rows = await sql<{ id: string; handle: string; email: string }[]>`
    select id, handle, email from users where email = lower(${email})
  `
  const user = rows[0]!
  const { token } = await requestEmailVerification(db, user)
  const response = await call('POST', '/auth/email/verify', { body: { token }, headers })
  assert.equal(response.status, 200, JSON.stringify(response.body))
  return {
    userId: user.id,
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
  assert.equal(created.status, 202)
  // The session is created by the VERIFICATION now, not by the registration, so the client context
  // this test is about — the address the device and the session record — is the one that spends the
  // link. Same browser, same address; the assertions below are unchanged.
  const registered = await verifyEmail(email, { 'x-forwarded-for': '198.51.100.77' })

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

/* ------------------------------------------------------------------ email verification */

/** The hash of the one live verification token for an address, or null. Never a raw token. */
async function liveVerificationHash(email: string): Promise<string | null> {
  const rows = await sql<{ token_hash: string }[]>`
    select t.token_hash from email_verification_tokens t
      join users u on u.id = t.user_id
     where t.consumed_at is null and t.expires_at > now() and u.email = lower(${email})
  `
  assert.ok(rows.length <= 1, 'one live token per account is a database constraint')
  return rows[0]?.token_hash ?? null
}

/*
 * The owner's report, from the live product: "i didn't receive any registration email and i was
 * able to login directly." Both halves are asserted below — registration mints nothing, and sign-in
 * is refused until the link is spent.
 */

test('registration answers 202 and mints NO session at all', { skip }, async () => {
  const email = freshEmail()
  const response = await call('POST', '/auth/register', {
    body: { email, handle: freshHandle(), password: GOOD_PASSWORD },
  })

  assert.equal(response.status, 202)
  assert.equal(response.body['verificationRequired'], true)
  // The normalised address, so "check your email" names the inbox the mail actually went to.
  assert.equal(response.body['email'], email.toLowerCase())
  assert.match(response.body['status'] as string, /verification link/)

  // The defect, asserted as the absence it is. These two fields being present is what let an
  // unproved address use the platform.
  assert.equal(response.body['accessToken'], undefined, 'registration must not mint a session')
  assert.equal(response.body['refreshToken'], undefined)

  // And not merely absent from the body: no session row exists to be resumed by any other route.
  const sessions = await sql<{ id: string }[]>`
    select s.id from sessions s join users u on u.id = s.user_id where u.email = ${email.toLowerCase()}
  `
  assert.equal(sessions.length, 0)
  const user = (await sql<{ email_verified_at: Date | null }[]>`
    select email_verified_at from users where email = ${email.toLowerCase()}
  `)[0]!
  assert.equal(user.email_verified_at, null, 'the account exists and is unverified')
})

test('an unverified account is refused at sign-in — and a verified one is not', { skip }, async () => {
  const email = freshEmail()
  const handle = freshHandle()
  assert.equal(
    (await call('POST', '/auth/register', { body: { email, handle, password: GOOD_PASSWORD } })).status,
    202,
  )

  const refused = await call('POST', '/auth/login', { body: { identifier: email, password: GOOD_PASSWORD } })
  assert.equal(refused.status, 403)
  const error = refused.body['error'] as Record<string, unknown>
  // A code the client can branch on, because there is something useful to offer: a resend. A bare
  // `forbidden` tells a sign-in form to give up.
  assert.equal(error['code'], 'email_unverified')
  assert.ok(error['requestId'], "the estate's envelope is { error: { code, message, requestId } }")
  assert.equal(refused.body['accessToken'], undefined)

  // THE OTHER HALF, and it is what stops this test passing against a service that refuses
  // everyone: the SAME account, the SAME password, after the link is spent.
  await verifyEmail(email)
  const allowed = await call('POST', '/auth/login', { body: { identifier: email, password: GOOD_PASSWORD } })
  assert.equal(allowed.status, 200, JSON.stringify(allowed.body))
  assert.ok(allowed.body['accessToken'])
})

test('the verification link signs the user in, and the link then works no more', { skip }, async () => {
  const email = freshEmail()
  const handle = freshHandle()
  await call('POST', '/auth/register', { body: { email, handle, password: GOOD_PASSWORD } })

  const userId = (await sql<{ id: string }[]>`select id from users where email = ${email.toLowerCase()}`)[0]!.id
  // Minted by the code under test — the table holds only a SHA-256, so there is no other way to
  // obtain one, and a literal here would be a token that could never redeem.
  const { token } = await requestEmailVerification(db, { id: userId, handle, email: email.toLowerCase() })

  const verified = await call('POST', '/auth/email/verify', { body: { token } })
  assert.equal(verified.status, 200)
  assert.ok(verified.body['accessToken'])
  assert.ok(verified.body['refreshToken'])
  assert.equal(verified.body['expiresIn'], 900)
  const user = verified.body['user'] as Record<string, unknown>
  assert.equal(user['id'], userId)
  assert.ok(user['emailVerifiedAt'], 'the response carries the stamp that was just written')

  // An ordinary session, indistinguishable from one a sign-in would have made: it lists, it
  // refreshes, and it carries `pwd` rather than some second credential kind.
  const claims = decodeJwt(verified.body['accessToken'] as string)
  assert.deepEqual(claims['amr'], ['pwd'])
  const sessions = await call('GET', '/sessions', { token: verified.body['accessToken'] as string })
  assert.equal((sessions.body['sessions'] as unknown[]).length, 1)

  // Single use, driven: the same link again. Two people holding one link must not both get in.
  const again = await call('POST', '/auth/email/verify', { body: { token } })
  assert.equal(again.status, 401)
  assert.equal((again.body['error'] as Record<string, unknown>)['code'], 'unauthenticated')
})

test('a token that was never real is refused exactly like a spent one', { skip }, async () => {
  const invented = await call('POST', '/auth/email/verify', { body: { token: 'not-a-token-anyone-issued' } })
  assert.equal(invented.status, 401)
  // Expired, spent and never real read identically. Separating them would tell a guesser that a
  // guess had once been right.
  assert.equal(
    (invented.body['error'] as Record<string, unknown>)['message'],
    'that verification link is invalid or has expired',
  )
  // A missing token is a malformed request rather than a refusal, which says nothing about tokens.
  assert.equal((await call('POST', '/auth/email/verify', { body: {} })).status, 400)
})

test('there is NO GET route that spends a verification token', { skip }, async () => {
  // The link a scanner pre-fetches is a page on Hub, not a route here. If this service ever grows a
  // GET that consumes a token, a corporate mail filter opening the link burns it before the user
  // ever sees the email — and the user's own report is that the account "does not work".
  assert.equal((await call('GET', '/auth/email/verify?token=anything')).status, 404)
  assert.equal((await call('GET', '/auth/email/verify')).status, 404)
})

test('resend is an oracle in neither status nor body, whatever the account is', { skip }, async () => {
  const unverifiedEmail = freshEmail()
  await call('POST', '/auth/register', {
    body: { email: unverifiedEmail, handle: freshHandle(), password: GOOD_PASSWORD },
  })
  const verified = await register()
  // Registration ALREADY minted a live token for the unverified account, so "a live token exists"
  // is true whether or not this route does anything — which is how the first version of this test
  // passed against a resend route that had been mutated to do nothing at all. What proves the work
  // happened is that the live token is a DIFFERENT one afterwards.
  const before = await liveVerificationHash(unverifiedEmail)
  assert.ok(before, 'registration mints one')

  const bodies: string[] = []
  for (const identifier of [
    unverifiedEmail, // exists and needs a link
    verified.email, // exists and does not
    verified.handle, // the same account, by handle
    freshEmail(), // no such account
    'not-an-address', // not even well formed
  ]) {
    const response = await call('POST', '/auth/email/verify/resend', { body: { identifier } })
    assert.equal(response.status, 202, `${identifier} must not be distinguishable by status`)
    bodies.push(JSON.stringify(response.body))
  }
  // A missing identifier gets the same answer as a present one, for the same reason.
  const empty = await call('POST', '/auth/email/verify/resend', { body: {} })
  assert.equal(empty.status, 202)
  bodies.push(JSON.stringify(empty.body))

  assert.equal(new Set(bodies).size, 1, `every branch must answer identically: ${bodies.join(' | ')}`)

  // And the work still happened for the one account that needed it — otherwise this is a test of a
  // route that always answers 202 and never does anything, which is the shape of Nimbus's
  // forgot-password defect.
  await new Promise((resolve) => setTimeout(resolve, 300))
  const after = await liveVerificationHash(unverifiedEmail)
  assert.ok(after, 'answering first must not mean never doing the work')
  assert.notEqual(after, before, 'a resend mints a NEW link and supersedes the old one')

  // Nothing was minted for the account that is already verified: that link would sign in whoever
  // asked for it, and the request naming the address is unauthenticated.
  const forVerified = await sql<{ user_id: string }[]>`
    select user_id from email_verification_tokens
     where user_id = ${verified.userId} and consumed_at is null
  `
  assert.equal(forVerified.length, 0)
})

test('the link that LEAVES the service is the one that signs the user in', { skip }, async () => {
  // The whole journey, walked through the seam rather than around it: register, be refused, ask for
  // another link, take the URL out of the event `notify` will render, and spend it.
  //
  // This is the one test that reads a token the way a recipient does. Everywhere else the suite
  // mints through the module, which proves the route but not the payload — and a `verifyUrl` that
  // is subtly wrong (identity's own origin, a query string, an un-encoded token) would pass every
  // other test in this file while mailing every user a link that does nothing.
  const email = freshEmail()
  await call('POST', '/auth/register', {
    body: { email, handle: freshHandle(), password: GOOD_PASSWORD },
  })
  assert.equal(
    (await call('POST', '/auth/login', { body: { identifier: email, password: GOOD_PASSWORD } })).status,
    403,
  )
  assert.equal(
    (await call('POST', '/auth/email/verify/resend', { body: { identifier: email } })).status,
    202,
  )
  await new Promise((resolve) => setTimeout(resolve, 300))

  const events = await sql<{ payload: Record<string, unknown> }[]>`
    select payload from outbox
     where topic = 'identity.email.verification_requested' order by occurred_at desc limit 1
  `
  const verifyUrl = events[0]!.payload['verifyUrl'] as string
  assert.match(verifyUrl, /^https:\/\/hub\.test\.cloudsforge\.local\/account\/verify#token=/)
  // Exactly what the Hub page does: read `location.hash`, post what is after it. The token is in
  // the FRAGMENT, so nothing between the mailbox and the browser ever saw it.
  const token = decodeURIComponent(new URL(verifyUrl).hash.slice('#token='.length))

  const verified = await call('POST', '/auth/email/verify', { body: { token } })
  assert.equal(verified.status, 200, JSON.stringify(verified.body))
  const me = await call('GET', '/auth/me', { token: verified.body['accessToken'] as string })
  assert.equal(me.status, 200)
  assert.ok((me.body['user'] as Record<string, unknown>)['emailVerifiedAt'])
})

test('asking for another link is throttled per address', { skip }, async () => {
  const from = { 'x-forwarded-for': '198.51.100.201' }
  const statuses: number[] = []
  for (let attempt = 0; attempt < 7; attempt += 1) {
    statuses.push(
      (await call('POST', '/auth/email/verify/resend', { body: { identifier: freshEmail() }, headers: from }))
        .status,
    )
  }
  // Uncapped, this route is a way to make the estate send mail to a third party repeatedly — so it
  // carries the same 5 that `/auth/password/forgot` and `/auth/register` do.
  assert.equal(statuses.filter((s) => s === 202).length, 5, 'five, then refusals')
  assert.ok(statuses.includes(429))
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

  // SD-04: the link is built from IDENTITY_ACCOUNT_URL — Hub's origin, where the page that spends
  // the token actually lives — and never from the request Host header, and the token rides in the
  // fragment so it reaches no server log or Referer header. It used to be built from
  // IDENTITY_PUBLIC_URL, which on both estates is `http://identity:4000`: an internal compose
  // address, over plain HTTP, routing no such path.
  const url = resetUrlFor(issued.token)!
  assert.ok(url.startsWith('https://hub.test.cloudsforge.local/account/reset#token='))
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

/**
 * **A password the policy refuses must not burn the link.**
 *
 * The route redeemed the token and only then judged the new password, so a weak choice answered 400
 * against a link that was already spent, and the retry the 400 explicitly invites answered 401.
 * The user is told "that password is not acceptable", picks a better one, and is then told their
 * reset link is invalid — with no way to tell that their own first attempt destroyed it. The only
 * repair available to them is to ask for another mail, which is also how one person's typo turns
 * into the estate mailing them repeatedly.
 *
 * Validating first is safe because the redemption is still the single-use gate: it is a conditional
 * `update ... returning`, so two requests that both pass validation still leave exactly one winner.
 */
test('a rejected password leaves the reset link usable', { skip }, async () => {
  const registered = await register()
  const { createPasswordResetToken } = await import('./passwordReset.ts')
  const issued = await createPasswordResetToken(db, registered.userId, null)

  const refused = await call('POST', '/auth/password/reset', {
    body: { token: issued.token, newPassword: 'short' },
  })
  assert.equal(refused.status, 400)
  // NOT 401 on the retry. This is the whole test.
  const accepted = await call('POST', '/auth/password/reset', {
    body: { token: issued.token, newPassword: OTHER_PASSWORD },
  })
  assert.equal(accepted.status, 204, 'a refused password must not have spent the link')

  // And it is spent now, exactly once.
  assert.equal(
    (await call('POST', '/auth/password/reset', { body: { token: issued.token, newPassword: OTHER_PASSWORD } }))
      .status,
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
 * `deploy/scripts/estate-bootstrap.sh` runs, which is the defect being closed.
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

test('a mistyped service name is a bad request, not a fault', { skip }, async () => {
  /*
   * This route answered **500 `internal`** for this input. `createServiceCredential` refused with
   * a bare `Error` — correctly, since a credential for a service with no grants could never mint
   * a token — but a bare `Error` has no arm in the mapper, so it fell through to the last line.
   * The operator was told identity was broken when the truth was that they had typed a name the
   * estate does not configure, and those two readings lead to opposite next actions.
   *
   * `estate-bootstrap.sh` mints a credential per service by label, so this arrives in the middle
   * of a deploy the first time a service is renamed upstream.
   */
  const admin = await makeAdmin()
  const response = await call('POST', '/service-credentials', {
    token: admin,
    body: { service: 'not-a-service', label: 'x' },
  })
  assert.equal(response.status, 400)
  const error = response.body['error'] as Record<string, unknown>
  assert.equal(error['code'], 'unknown_service')
  // The name back, so the answer is actionable in one read rather than after a grep.
  assert.match(String(error['message']), /not-a-service/)

  /*
   * And NOT 403, which is what the neighbouring `UnknownServiceError` arm gives — deliberately.
   * The predicate behind both is the same missing `IDENTITY_SERVICE_TOKEN_GRANTS` entry, but
   * `POST /service-tokens` is asked to mint a token that ACTS AS a service and refuses an
   * authorisation; this route is asked to create a credential FOR a service that does not exist.
   * `deploy/scripts/estate-verify.sh` asserts the 403 on the other route against the live
   * estate, so the two must not be collapsed into one status.
   */
  const acting = await call('POST', '/service-tokens', {
    token: admin,
    body: { service: 'not-a-service', scopes: ['ledger:read'] },
  })
  assert.equal(acting.status, 403)
  assert.equal((acting.body['error'] as Record<string, unknown>)['code'], 'scope_not_granted')
})

test('a credential for a service the estate DOES configure is still created', { skip }, async () => {
  // The negative above is only worth anything next to a positive: a route that refused every
  // service would satisfy it, and would be a worse defect than the one being fixed.
  const admin = await makeAdmin()
  const created = await call('POST', '/service-credentials', {
    token: admin,
    body: { service: 'settlement', label: 'the negative half' },
  })
  assert.equal(created.status, 201)
  assert.equal(created.body['service'], 'settlement')
  // Returned exactly once, and only its digest is stored.
  assert.match(String(created.body['secret']), /^cfsc_/)
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
 * (`env.ts`), so a token that comes out of this function is proof that `identity:admin` is in
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

test('the allowlist refusal and the stale-session refusal are DIFFERENT on the wire', { skip }, async () => {
  /*
   * micro-org#480, and the whole of it. `POST /auth/handoff` refuses in two ways and they have
   * nothing to do with each other:
   *
   *   401 unauthenticated       — the bearer is missing, malformed, or EXPIRED. Nothing is wrong
   *                               with the estate. Sign in again.
   *   403 handoff_origin_refused — the origin is genuinely not on IDENTITY_HANDOFF_ORIGINS. An
   *                               operator has to change a deployment.
   *
   * They answered `401 unauthenticated` and `403 forbidden`, which is already two different
   * answers — but `@cloudsforge/ui`'s `mintHandoffCode` collapses every non-2xx to `null`, so the
   * sign-in surface saw ONE outcome and picked the sentence for the second: "ask an operator to
   * add it to the hand-off allowlist". The owner hit it against `https://cloudsforge.online`,
   * which was on the allowlist the whole time and minted 201 when asked with a live token — what
   * they actually had was a fifteen-minute-old access token out of `localStorage` after a browser
   * restart.
   *
   * A distinct CODE is what lets that client stop guessing. This test is the contract: the two
   * refusals must never again be one string, whatever the statuses do.
   */
  const registered = await register()

  const staleSession = await call('POST', '/auth/handoff', {
    // Stands in for an expired token, and stands in for it honestly: `authenticateUser` refuses
    // both by the same path and `a missing, malformed or expired token is 401` above pins that the
    // three are one answer. What matters here is that a refusal of the CALLER never carries the
    // code that means a refusal of the ORIGIN.
    token: 'not-a-jwt',
    body: { redirectOrigin: 'https://app.test.cloudsforge.local' },
  })
  assert.equal(staleSession.status, 401, 'an unusable bearer is 401, even for an allowlisted origin')
  assert.equal(
    (staleSession.body['error'] as Record<string, unknown>)['code'],
    'unauthenticated',
    'a stale session must NOT be reported as an allowlist fault — this is the defect',
  )

  const unlistedOrigin = await call('POST', '/auth/handoff', {
    token: registered.accessToken,
    body: { redirectOrigin: 'https://evil.example' },
  })
  assert.equal(unlistedOrigin.status, 403)
  assert.equal(
    (unlistedOrigin.body['error'] as Record<string, unknown>)['code'],
    HANDOFF_ORIGIN_REFUSED_CODE,
    'the ONE answer a client may print "ask an operator to add it to the allowlist" for',
  )

  // And the two codes are not the same string, said outright rather than left to be inferred from
  // the two assertions above — this is the property, and a future rename that collapsed them would
  // pass both of those individually.
  assert.notEqual(
    (staleSession.body['error'] as Record<string, unknown>)['code'],
    (unlistedOrigin.body['error'] as Record<string, unknown>)['code'],
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
  for (const table of [
    'profiles',
    'devices',
    'sessions',
    'mfa_factors',
    'mfa_challenges',
    'password_reset_tokens',
    // Consumed as well as live. A spent verification row is still a row that says this address
    // existed and when it was proved, on an account whose status says the person is gone.
    'email_verification_tokens',
  ]) {
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
  assert.equal(again.status, 202)
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
  assert.equal(statuses.filter((s) => s === 202).length, 5, 'five, then refusals')
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

/* ------------------------------------------------------- the registration challenge (micro-org#361) */

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * These run against `challenged`, the second server, which has a Turnstile configuration and a
 * `siteverify` the test controls. The fake CAN REFUSE — a captcha double that only ever answers
 * `success: true` proves nothing, and the estate has shipped that defect twice already
 * (micro-org#355, #356).
 *
 * `server`, which every other test in this file drives, has `turnstile: null`. That is not a gap:
 * "a deployment with no Turnstile account registers people exactly as it did before" is a property
 * of this feature, and roughly a hundred tests above are its proof.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

/** Everything a solved widget on our own sign-up page would produce. */
const SOLVED = { success: true, action: 'signup', hostname: CHALLENGE_HOSTNAME }

/** A registration body with a token in it. The token is opaque; only the fake reads it. */
function registration(token?: string): Record<string, unknown> {
  return {
    email: freshEmail(),
    handle: freshHandle(),
    password: GOOD_PASSWORD,
    ...(token === undefined ? {} : { 'cf-turnstile-response': token }),
  }
}

async function challengeCount(outcome: string): Promise<number> {
  const text = await (await fetch(`${challengedOrigin}/metrics`)).text()
  const line = text
    .split('\n')
    .find((l) => l.startsWith(`identity_registration_challenge_total{outcome="${outcome}"}`))
  return line ? Number(line.slice(line.lastIndexOf(' ') + 1)) : 0
}

async function accountsWithEmail(email: string): Promise<number> {
  const rows = await sql<{ n: string }[]>`select count(*)::text as n from users where email = lower(${email})`
  return Number(rows[0]!.n)
}

beforeEach(() => {
  siteverifyCalls = []
  answers(SOLVED)
})

test('GET /auth/challenge publishes the site key at RUNTIME, and needs no credential', { skip }, async () => {
  // hub-web compiles NO configuration — `src/lib/hosts.ts` derives every address from
  // `window.location` so one image serves localhost, micro and mainnet. A site key baked into the
  // bundle would be the first thing to break that. It is asked by somebody who has no account yet,
  // so it takes no token.
  const response = await call('GET', '/auth/challenge', { at: challengedOrigin })
  assert.equal(response.status, 200, JSON.stringify(response.body))
  assert.equal(response.body['required'], true)
  assert.equal(response.body['provider'], 'turnstile')
  assert.equal(response.body['siteKey'], '0x4AAAAAAEMXmH8jdtxq8FYo')
  assert.equal(response.body['action'], 'signup')
  // The SITE key, which is public. Never the secret.
  assert.ok(!JSON.stringify(response.body).includes(TURNSTILE_SECRET_FIXTURE), 'the secret was published')
})

test('an unconfigured deployment answers required:false and registers exactly as before', { skip }, async () => {
  const response = await call('GET', '/auth/challenge')
  assert.equal(response.status, 200)
  assert.equal(response.body['required'], false)
  assert.equal(response.body['siteKey'], null, 'null rather than absent, so a client can tell them apart')

  // And the route itself is untouched: no token, no bearer, 202 and an account.
  const body = registration()
  const registered = await call('POST', '/auth/register', { body })
  assert.equal(registered.status, 202, JSON.stringify(registered.body))
  assert.equal(await accountsWithEmail(body['email'] as string), 1)
})

test('a solved challenge registers, and the token reaches siteverify with the secret', { skip }, async () => {
  const body = registration('a-solved-token')
  const before = await challengeCount('ok')
  const response = await call('POST', '/auth/register', { body, at: challengedOrigin })
  assert.equal(response.status, 202, JSON.stringify(response.body))
  assert.equal(await accountsWithEmail(body['email'] as string), 1)

  assert.equal(siteverifyCalls.length, 1, 'the token was verified server-side exactly once')
  assert.equal(siteverifyCalls[0]?.get('response'), 'a-solved-token')
  assert.equal(siteverifyCalls[0]?.get('secret'), TURNSTILE_SECRET_FIXTURE)
  assert.equal(await challengeCount('ok'), before + 1)
})

test('a registration with NO token is refused, creates nothing, and is a distinct code', { skip }, async () => {
  const body = registration()
  const before = await challengeCount('missing_token')
  const response = await call('POST', '/auth/register', { body, at: challengedOrigin })

  assert.equal(response.status, 403)
  assert.equal((response.body['error'] as Record<string, unknown>)['code'], 'challenge_required')
  assert.equal(siteverifyCalls.length, 0, 'nothing was asked of Cloudflare')
  assert.equal(await accountsWithEmail(body['email'] as string), 0, 'no account was created')
  assert.equal(await challengeCount('missing_token'), before + 1)
})

test('a token Cloudflare rejects is refused as challenge_failed, and no account appears', { skip }, async () => {
  // The case the whole feature exists for. `timeout-or-duplicate` is what a REPLAYED token earns:
  // Cloudflare redeems a token at siteverify, so it is single-use.
  answers({ success: false, 'error-codes': ['timeout-or-duplicate'] })
  const body = registration('a-spent-token')
  const before = await challengeCount('rejected')
  const response = await call('POST', '/auth/register', { body, at: challengedOrigin })

  assert.equal(response.status, 403)
  assert.equal((response.body['error'] as Record<string, unknown>)['code'], 'challenge_failed')
  assert.equal(await accountsWithEmail(body['email'] as string), 0)
  assert.equal(await challengeCount('rejected'), before + 1)
})

test('a token solved for another action, or on another site, is refused', { skip }, async () => {
  // Both are `success: true` at Cloudflare. The sitekey is public, so a widget on somebody else's
  // page mints tokens that are genuinely solved — the action and the hostname are the only things
  // that say WHICH form and WHOSE page.
  for (const payload of [
    { ...SOLVED, action: 'login' },
    { ...SOLVED, hostname: 'evil.example' },
    { ...SOLVED, hostname: `${CHALLENGE_HOSTNAME}.evil.example` },
  ]) {
    answers(payload)
    const body = registration('a-genuinely-solved-token')
    const response = await call('POST', '/auth/register', { body, at: challengedOrigin })
    assert.equal(response.status, 403, JSON.stringify(payload))
    assert.equal(
      (response.body['error'] as Record<string, unknown>)['code'],
      'challenge_failed',
      JSON.stringify(payload),
    )
    assert.equal(await accountsWithEmail(body['email'] as string), 0, JSON.stringify(payload))
  }
})

test('a Turnstile outage FAILS CLOSED, as 503 and not as a silent pass', { skip }, async () => {
  // ══════════════════════════════════════════════════════════════════════════════════════════════
  // THIS IS THE ASSERTION THAT ENCODES THE ARGUMENT, AND micro-org#361 ARGUES THE OTHER WAY.
  //
  // The issue recommends fail-OPEN for registration — "a captcha vendor's outage should not stop a
  // real person from opening an account". Overridden on the measurement in the same issue: this
  // estate has NO organic registrations to lose, so fail-open's beneficiaries are today an empty
  // set while the population it admits is exactly the one the gate exists to stop. The day that
  // stops being true, THIS TEST is the thing to change, deliberately, rather than the code
  // quietly. See the header of turnstile.ts.
  //
  // 503 rather than 403 because nothing about the caller was wrong and a client should retry; an
  // operator who cannot tell "a bot was stopped" from "Cloudflare was unreachable" can act on
  // neither.
  // ══════════════════════════════════════════════════════════════════════════════════════════════
  const outages: (() => HttpResponse)[] = [
    () => {
      throw Object.assign(new Error('aborted'), { name: 'TimeoutError' })
    },
    () => new Response('bad gateway', { status: 502 }),
    () => new Response('<html>maintenance</html>', { status: 200 }),
  ]
  const before = await challengeCount('upstream_failure')
  for (const outage of outages) {
    siteverify = outage
    const body = registration('a-token-nobody-can-check')
    const response = await call('POST', '/auth/register', { body, at: challengedOrigin })
    assert.equal(response.status, 503, JSON.stringify(response.body))
    assert.equal((response.body['error'] as Record<string, unknown>)['code'], 'challenge_unavailable')
    assert.equal(await accountsWithEmail(body['email'] as string), 0, 'an outage created an account')
  }
  assert.equal(await challengeCount('upstream_failure'), before + outages.length)
})

test('a SERVICE PRINCIPAL registers with no token at all, and nothing else does', { skip }, async () => {
  // ══════════════════════════════════════════════════════════════════════════════════════════════
  // THE BYPASS IS THE PRINCIPAL, NOT A HEADER. `beacon` registers synthetic accounts every few
  // minutes and cannot solve a captcha; the shortcut would be a header it sets or a shared string
  // in its environment, and either is a credential that never expires, cannot be revoked without a
  // redeploy, and is forgeable by anyone who can send bytes.
  //
  // A service token has none of those properties: 600 seconds, signed by this service, revocable
  // by deleting the credential.
  // ══════════════════════════════════════════════════════════════════════════════════════════════
  const admin = await makeAdmin()
  const minted = await call('POST', '/service-tokens', {
    token: admin,
    body: { service: 'settlement', scopes: ['ledger:read'] },
  })
  assert.equal(minted.status, 201, JSON.stringify(minted.body))
  const serviceToken = minted.body['token'] as string

  const body = registration()
  const response = await call('POST', '/auth/register', {
    body,
    token: serviceToken,
    at: challengedOrigin,
  })
  assert.equal(response.status, 202, JSON.stringify(response.body))
  assert.equal(await accountsWithEmail(body['email'] as string), 1)
  assert.equal(siteverifyCalls.length, 0, 'a service principal was sent to Cloudflare anyway')
})

test('a USER token is not a bypass, and neither is a garbage bearer', { skip }, async () => {
  // A leaked access token must not become a registration cannon, and a browser extension injecting
  // a stale bearer must not be able to stop a person opening an account — so an unusable bearer
  // falls THROUGH to the challenge rather than becoming a 401 on a public sign-up route.
  const user = await register()
  for (const token of [user.accessToken, 'not-a-token', 'a.b.c']) {
    const body = registration()
    const refused = await call('POST', '/auth/register', { body, token, at: challengedOrigin })
    assert.equal(refused.status, 403, `${token.slice(0, 6)} bypassed the challenge`)
    assert.equal(
      (refused.body['error'] as Record<string, unknown>)['code'],
      'challenge_required',
      'it should have fallen through to the challenge, not 401',
    )
    assert.equal(await accountsWithEmail(body['email'] as string), 0)

    // …and the same principal WITH a solved token gets through, so the refusal above is the
    // challenge and not the bearer.
    const withToken = registration('a-solved-token')
    const allowed = await call('POST', '/auth/register', { body: withToken, token, at: challengedOrigin })
    assert.equal(allowed.status, 202, JSON.stringify(allowed.body))
  }
})

test('the challenge is taken BEFORE anything is created, so it is not an existence oracle', { skip }, async () => {
  // A caller who cannot pass the gate must not be able to use the route to learn which addresses
  // and handles are taken: `registerUser`'s 409 is an existence oracle and a field-level 400 is a
  // weaker one. So an unchallenged request that is ALSO a duplicate answers the challenge refusal.
  const existing = registration('a-solved-token')
  assert.equal((await call('POST', '/auth/register', { body: existing, at: challengedOrigin })).status, 202)

  answers({ success: false, 'error-codes': ['invalid-input-response'] })
  const duplicate = await call('POST', '/auth/register', {
    body: { ...existing, 'cf-turnstile-response': 'a-bad-token' },
    at: challengedOrigin,
  })
  assert.equal(duplicate.status, 403, 'a duplicate leaked through the gate as a 409')
  assert.equal((duplicate.body['error'] as Record<string, unknown>)['code'], 'challenge_failed')

  // The same with a body that is not a valid registration at all: still the challenge, still not a
  // 400 naming the field. The CODE is asserted, not just the status — `that registration is not
  // valid` is a 400, so a route that validated first would be caught by the status, but a route
  // that validated first and happened to answer 403 for some other reason would not.
  const malformed = await call('POST', '/auth/register', {
    body: { email: 'not-an-address', handle: '!', password: 'x', 'cf-turnstile-response': 'a-bad-token' },
    at: challengedOrigin,
  })
  assert.equal(malformed.status, 403, 'a malformed unchallenged registration was validated first')
  assert.equal(
    (malformed.body['error'] as Record<string, unknown>)['code'],
    'challenge_failed',
    'the answer names the FIELD that is wrong, which tells an unchallenged caller what this ' +
      'service thinks of a body it should not have read at all',
  )

  // And with no token at all, which is the shape a scripted caller actually sends.
  const unchallenged = await call('POST', '/auth/register', {
    body: { email: 'not-an-address', handle: '!', password: 'x' },
    at: challengedOrigin,
  })
  assert.equal(unchallenged.status, 403)
  assert.equal(
    (unchallenged.body['error'] as Record<string, unknown>)['code'],
    'challenge_required',
    'a caller with no token learned that this body is malformed',
  )
  assert.deepEqual(unchallenged.body['fields'], undefined, 'a field-level 400 leaked through the gate')
})

test('an over-long token is refused without asking Cloudflare', { skip }, async () => {
  // An unauthenticated caller who can make this service post 64KB to a third party has an
  // amplifier. `MAX_BODY_BYTES` is 64KB, and Turnstile's own ceiling is 2048.
  const body = registration('a'.repeat(4096))
  const response = await call('POST', '/auth/register', { body, at: challengedOrigin })
  assert.equal(response.status, 403)
  assert.equal((response.body['error'] as Record<string, unknown>)['code'], 'challenge_required')
  assert.equal(siteverifyCalls.length, 0)
})

test('no refusal, and no metric label, ever contains the token or the secret', { skip }, async () => {
  answers({ success: false, 'error-codes': ['invalid-input-response'] })
  const token = 'a-token-that-must-not-be-echoed'
  const response = await call('POST', '/auth/register', {
    body: registration(token),
    at: challengedOrigin,
  })
  const rendered = JSON.stringify(response.body)
  assert.ok(!rendered.includes(token), `the refusal echoed the token: ${rendered}`)
  assert.ok(!rendered.includes(TURNSTILE_SECRET_FIXTURE), 'the refusal echoed the secret')

  const metrics = await (await fetch(`${challengedOrigin}/metrics`)).text()
  assert.ok(!metrics.includes(token), 'the metric carried the token as a label')
  assert.ok(!metrics.includes(TURNSTILE_SECRET_FIXTURE), 'the metric carried the secret as a label')
  // The label set stays the four documented outcomes — an unbounded label is a cardinality bomb on
  // a route an unauthenticated caller controls.
  for (const line of metrics.split('\n')) {
    if (!line.startsWith('identity_registration_challenge_total{')) continue
    assert.match(line, /outcome="(ok|missing_token|rejected|upstream_failure)"/, line)
  }
})

test('the rate limit still stands in front of the challenge', { skip }, async () => {
  // The gate is an ADDITION to the limiter, not a replacement for it — and the limiter is taken at
  // dispatch, so a challenge refusal costs a caller exactly what a success does. Otherwise an
  // attacker gets unlimited free attempts by simply failing them.
  const from = { 'x-forwarded-for': '203.0.113.90' }
  answers({ success: false, 'error-codes': ['invalid-input-response'] })
  const seen: number[] = []
  for (let i = 0; i < 8; i += 1) {
    const response = await call('POST', '/auth/register', {
      body: registration('a-bad-token'),
      headers: from,
      at: challengedOrigin,
    })
    seen.push(response.status)
  }
  assert.ok(seen.includes(429), `refusals were free: ${seen.join(',')}`)
})
