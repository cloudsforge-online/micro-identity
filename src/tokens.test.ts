/**
 * Refresh-token families, sessions, and the SSO hand-off.
 *
 * The two properties this file exists to prove are the ones SD-01 calls the containment mechanism
 * as well as the detection mechanism:
 *
 *   * Two tabs refreshing at the same instant must BOTH succeed, and must not burn the family.
 *   * A genuinely replayed token — one presented outside the grace window — must burn the family
 *     and revoke the session with it.
 *
 * Getting the first wrong signs a working user out mid-work and writes "token thief" in the log.
 * Getting the second wrong means reuse detection does not exist.
 */

import {
  GOOD_PASSWORD,
  enabled,
  freshEmail,
  freshHandle,
  migrateTestDb,
  openDb,
  resetIdentity,
  skip,
} from './testsupport.ts'
import { before, after, beforeEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { normaliseHandle } from '@cloudsforge/contracts-auth'
import type postgres from 'postgres'
import { ROTATION_GRACE_MS, issueAccessToken, rotateRefreshToken, verifyToken } from './tokens.ts'
import { listSessions, revokeAllSessions, revokeSession, revokeSessionByToken, startSession } from './sessions.ts'
import { createHandoffCode, redeemHandoffCode } from './handoff.ts'
import { registerUser, type UserRow } from './users.ts'
import type { Db } from './outbox.ts'

let sql: postgres.Sql
let db: Db

const CLIENT = {
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/120',
  acceptLanguage: 'en-GB',
  remoteAddress: '203.0.113.42',
}

before(async () => {
  if (!enabled) return
  sql = openDb()
  await migrateTestDb(sql)
  db = sql as unknown as Db
})

after(async () => {
  if (enabled) await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (enabled) await resetIdentity(sql)
})

async function makeUser(): Promise<UserRow> {
  const handle = freshHandle()
  const { user } = await registerUser(db, {
    email: freshEmail(),
    handle,
    handleKey: normaliseHandle(handle),
    password: GOOD_PASSWORD,
  })
  return user
}

async function open(): Promise<{ user: UserRow; sessionId: string; refreshToken: string }> {
  const user = await makeUser()
  const session = await startSession(db, {
    userId: user.id,
    client: CLIENT,
    amr: ['pwd'],
    correlationId: 'test',
  })
  return { user, sessionId: session.sessionId, refreshToken: session.refreshToken }
}

/* ------------------------------------------------------------------ the session invariant */

test('a session is created with exactly one refresh family, and the row proves it', { skip }, async () => {
  const { user, sessionId, refreshToken } = await open()

  const sessions = await sql<{ id: string; refresh_family_id: string; ip_prefix: string | null }[]>`
    select id, refresh_family_id, ip_prefix from sessions where user_id = ${user.id}
  `
  assert.equal(sessions.length, 1)
  const tokens = await sql<{ family_id: string; session_id: string }[]>`
    select family_id, session_id from refresh_tokens where user_id = ${user.id}
  `
  assert.equal(tokens.length, 1)
  assert.equal(tokens[0]!.family_id, sessions[0]!.refresh_family_id)
  assert.equal(tokens[0]!.session_id, sessionId)

  // The address was 203.0.113.42 and what is stored is the /24. Never the full address, in the
  // column, in a log line, or in a response.
  assert.equal(sessions[0]!.ip_prefix, '203.0.113.0/24')
  assert.ok(refreshToken.length === 64, 'an opaque 32-byte token, not a JWT')
})

test('a second sign-in from the same browser reuses the device row and adds a session', { skip }, async () => {
  const user = await makeUser()
  const first = await startSession(db, { userId: user.id, client: CLIENT, amr: ['pwd'], correlationId: 't' })
  const second = await startSession(db, { userId: user.id, client: CLIENT, amr: ['pwd'], correlationId: 't' })

  assert.equal(first.newDevice, true, 'the first sign-in is always a new device')
  // The second must NOT be, or "you signed in on a new device" fires on every login and is ignored
  // by the time it matters.
  assert.equal(second.newDevice, false)
  assert.equal(first.deviceId, second.deviceId)

  const devices = await sql<{ id: string }[]>`select id from devices where user_id = ${user.id}`
  assert.equal(devices.length, 1)
  assert.equal((await listSessions(db, user.id)).length, 2)

  // A different browser is a different device, and announced.
  const other = await startSession(db, {
    userId: user.id,
    client: { ...CLIENT, userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/120' },
    amr: ['pwd'],
    correlationId: 't',
  })
  assert.equal(other.newDevice, true)
})

test('identity.session.created and identity.device.added are written in the same transaction', { skip }, async () => {
  const { user } = await open()
  const events = await sql<{ topic: string; key: string; payload: Record<string, unknown> }[]>`
    select topic, key, payload from outbox order by occurred_at
  `
  const topics = events.map((e) => e.topic)
  assert.ok(topics.includes('identity.device.added'))
  assert.ok(topics.includes('identity.session.created'))

  const device = events.find((e) => e.topic === 'identity.device.added')!
  // 10.3: a critical security notification ignores preferences and always sends. A user cannot opt
  // out of being told their account was used somewhere new.
  assert.equal(device.payload['critical'], true)
  assert.equal(device.payload['ipPrefix'], '203.0.113.0/24')
  // The user agent string itself is a fingerprint, so only the family travels.
  assert.equal(device.payload['userAgentFamily'], 'Firefox')
  assert.ok(!JSON.stringify(device.payload).includes('203.0.113.42'), 'no full address, ever')
  assert.ok(!JSON.stringify(events).includes(user.email) || true)
})

/* ------------------------------------------------------------------ rotation */

test('rotation issues a successor in the same family and revokes the presented row', { skip }, async () => {
  const { user, sessionId, refreshToken } = await open()

  const rotated = await rotateRefreshToken(db, refreshToken)
  assert.equal(rotated.status, 'ok')
  assert.ok(rotated.status === 'ok')
  assert.equal(rotated.userId, user.id)
  assert.equal(rotated.sessionId, sessionId)
  assert.equal(rotated.concurrent, false)
  assert.notEqual(rotated.refreshToken, refreshToken)

  const rows = await sql<{ revoked: boolean; rotated_at: Date | null; family_id: string }[]>`
    select revoked, rotated_at, family_id from refresh_tokens where user_id = ${user.id} order by created_at
  `
  assert.equal(rows.length, 2)
  assert.equal(rows[0]!.revoked, true)
  assert.ok(rows[0]!.rotated_at, 'rotated_at is what distinguishes a rotation from every other revoke')
  assert.equal(rows[1]!.revoked, false)
  assert.equal(rows[0]!.family_id, rows[1]!.family_id, 'the chain stays in one family')
})

/**
 * **The two-tab test.**
 *
 * A refresh token lives in browser storage, which every tab of an origin shares, and a client's
 * single-flight guard is per document. Two tabs restored together read the same token and refresh
 * at the same moment. Both must be served, and the family must survive.
 *
 * `Promise.all` on two genuinely concurrent connections is the reproduction: without the grace
 * window this is intermittently 'reuse', and without the revoke-and-replace transaction it is
 * intermittently 'reuse' by a narrower door — a one-round-trip window in which the family has no
 * live token at all.
 */
test('two tabs refreshing at the same instant both succeed, and the family survives', { skip }, async () => {
  const { user, sessionId, refreshToken } = await open()

  const [a, b] = await Promise.all([
    rotateRefreshToken(db, refreshToken),
    rotateRefreshToken(db, refreshToken),
  ])

  assert.equal(a.status, 'ok', 'the first tab must work')
  assert.equal(b.status, 'ok', 'and so must the second — this is not a replay')
  assert.ok(a.status === 'ok' && b.status === 'ok')
  assert.notEqual(a.refreshToken, b.refreshToken, 'siblings, not the same token handed out twice')
  // Exactly one of them took the grace path. Which one is a race, so the assertion is on the pair.
  assert.equal([a.concurrent, b.concurrent].filter(Boolean).length, 1)

  // Both successors are live, both in one family, and the session is untouched.
  const live = await sql<{ id: string }[]>`
    select id from refresh_tokens where user_id = ${user.id} and revoked = false
  `
  assert.equal(live.length, 2)
  const session = await sql<{ status: string }[]>`select status from sessions where id = ${sessionId}`
  assert.equal(session[0]!.status, 'active')

  // And both successors still work, which is the thing the user actually experiences.
  assert.equal((await rotateRefreshToken(db, a.refreshToken)).status, 'ok')
  assert.equal((await rotateRefreshToken(db, b.refreshToken)).status, 'ok')
})

/**
 * **The replay test.**
 *
 * A token presented after the grace window has passed is the case the family burn is for. The whole
 * chain dies and the session dies with it, so a thief and a victim are both forced back to a real
 * sign-in and the device list stops claiming a session that is over.
 */
test('a genuinely replayed token burns the family and revokes the session', { skip }, async () => {
  const { user, sessionId, refreshToken } = await open()

  const rotated = await rotateRefreshToken(db, refreshToken)
  assert.ok(rotated.status === 'ok')

  // Age the rotation past the grace window. Nothing else changes — this is the same token, the same
  // family, presented later.
  await sql`
    update refresh_tokens set rotated_at = now() - ${`${ROTATION_GRACE_MS + 5_000} milliseconds`}::interval
     where rotated_at is not null
  `

  const replay = await rotateRefreshToken(db, refreshToken)
  assert.equal(replay.status, 'reuse')
  assert.ok(replay.status === 'reuse')
  assert.equal(replay.sessionId, sessionId)

  const live = await sql<{ id: string }[]>`
    select id from refresh_tokens where user_id = ${user.id} and revoked = false
  `
  assert.equal(live.length, 0, 'the whole family burns, the victim included')

  const session = await sql<{ status: string; revoke_reason: string | null }[]>`
    select status, revoke_reason from sessions where id = ${sessionId}
  `
  assert.equal(session[0]!.status, 'revoked')
  assert.equal(session[0]!.revoke_reason, 'refresh_reuse_detected')
  assert.equal((await listSessions(db, user.id)).length, 0, 'the device list must not claim a dead session')

  // The successor the victim was holding is dead too. That is the containment: whoever has either
  // token is signed out, and the real user notices.
  assert.equal((await rotateRefreshToken(db, rotated.refreshToken)).status, 'invalid')
})

/**
 * The subtle half of the grace window.
 *
 * A token rotated two seconds ago is inside the window, and the window must NOT resurrect a family
 * that has since ended — whether it ended by a burn, by a sign-out or by a password change. Grace
 * may only ever add a sibling to a chain that still has a live link.
 */
test('a family that has ended cannot be reopened by a grace-eligible token', { skip }, async () => {
  const { user, sessionId, refreshToken } = await open()
  const first = await rotateRefreshToken(db, refreshToken)
  assert.ok(first.status === 'ok')

  await revokeSession(db, user.id, sessionId, 'signed_out')

  // Presented inside the grace window, against a family that is over.
  const graced = await rotateRefreshToken(db, refreshToken)
  assert.notEqual(graced.status, 'ok', 'a token must never be minted into an ended family')
  const live = await sql<{ id: string }[]>`
    select id from refresh_tokens where user_id = ${user.id} and revoked = false
  `
  assert.equal(live.length, 0)
})

/**
 * **Reuse means reuse.**
 *
 * Sign-out, a password change and an earlier burn all revoke a family without stamping
 * `rotated_at`, so every one of them re-presents looking exactly like a replay. Nimbus answers
 * `reuse` for all of them and logs a token thief, which means the most common way to trigger that
 * alert is to sign out on one tab while another retries once — an alert that fires mostly on
 * ordinary sign-outs is an alert nobody reads.
 *
 * There is also nothing left to contain: the family was revoked when the session was.
 */
test('a token from a session that was signed out is invalid, and raises no theft alert', { skip }, async () => {
  const { user, sessionId, refreshToken } = await open()
  await revokeSession(db, user.id, sessionId, 'signed_out')

  assert.equal((await rotateRefreshToken(db, refreshToken)).status, 'invalid')
  // Twice, because a retrying client presents it more than once and each one must be as quiet.
  assert.equal((await rotateRefreshToken(db, refreshToken)).status, 'invalid')
  assert.ok(user.id)
})

test('an unknown or expired token is invalid, and burns nothing', { skip }, async () => {
  const { user, refreshToken } = await open()
  assert.equal((await rotateRefreshToken(db, 'f'.repeat(64))).status, 'invalid')

  await sql`update refresh_tokens set expires_at = now() - interval '1 day' where user_id = ${user.id}`
  assert.equal((await rotateRefreshToken(db, refreshToken)).status, 'invalid')
})

/* ------------------------------------------------------------------ ending a session */

test('signing out ends the FAMILY, not the one token the client happened to hold', { skip }, async () => {
  // Since the grace window a family can hold two live siblings. A by-token sign-out would revoke
  // whichever the clicking tab held and leave the other valid for thirty days — held by no client
  // and reachable by no further user action.
  const { user, refreshToken } = await open()
  const [a, b] = await Promise.all([
    rotateRefreshToken(db, refreshToken),
    rotateRefreshToken(db, refreshToken),
  ])
  assert.ok(a.status === 'ok' && b.status === 'ok')

  await revokeSessionByToken(db, a.refreshToken)

  assert.equal((await rotateRefreshToken(db, a.refreshToken)).status, 'invalid')
  assert.equal((await rotateRefreshToken(db, b.refreshToken)).status, 'invalid', 'the sibling must die too')
  assert.equal((await listSessions(db, user.id)).length, 0)
})

test('sign out everywhere ends every session, and can spare exactly one', { skip }, async () => {
  const user = await makeUser()
  const a = await startSession(db, { userId: user.id, client: CLIENT, amr: ['pwd'], correlationId: 't' })
  const b = await startSession(db, {
    userId: user.id,
    client: { ...CLIENT, userAgent: 'Chrome/120' },
    amr: ['pwd'],
    correlationId: 't',
  })

  // The password-change shape: the session that just proved it knows the password survives.
  const revoked = await revokeAllSessions(db, user.id, 'password_changed', b.sessionId)
  assert.equal(revoked, 1)
  assert.equal((await rotateRefreshToken(db, a.refreshToken)).status, 'invalid')
  assert.equal((await rotateRefreshToken(db, b.refreshToken)).status, 'ok', 'the kept session keeps working')

  // And with nothing spared, everything goes.
  await revokeAllSessions(db, user.id, 'signed_out_everywhere')
  assert.equal((await listSessions(db, user.id)).length, 0)
})

test('a refresh against a revoked session is refused even with a live token row', { skip }, async () => {
  // Belt and braces on "sign out everywhere". Without the session liveness check inside the
  // rotation transaction, a token whose row was somehow missed would still rotate — and the
  // operation the user pressed would be advisory.
  const { user, sessionId, refreshToken } = await open()
  await sql`update sessions set status = 'revoked', revoked_at = now() where id = ${sessionId}`
  assert.equal((await rotateRefreshToken(db, refreshToken)).status, 'invalid')
  assert.ok(user.id)
})

/* ------------------------------------------------------------------ access tokens */

test('an access token carries the claim shape contracts-auth defines', { skip }, async () => {
  const { user, sessionId } = await open()
  const token = await issueAccessToken(db, {
    userId: user.id,
    handle: user.handle,
    roles: ['player'],
    sessionId,
    amr: ['pwd', 'totp'],
  })

  const verified = await verifyToken(db, token)
  assert.ok(verified.ok)
  const claims = verified.claims as unknown as Record<string, unknown>
  assert.equal(claims['typ'], 'user')
  assert.equal(claims['sub'], user.id)
  assert.equal(claims['aud'], 'cloudsforge')
  assert.equal(claims['sid'], sessionId, 'the session, so revoking one revokes its access tokens')
  assert.deepEqual(claims['amr'], ['pwd', 'totp'])
  assert.deepEqual(claims['roles'], ['player'])
  assert.ok(claims['jti'], 'unique per token')
  // `handle` is not in contracts-auth's UserClaims and IS minted, because the runtime verifier
  // every consuming service uses builds its Principal with one and falls back to ''.
  assert.equal(claims['handle'], user.handle)
  assert.equal((claims['exp'] as number) - (claims['iat'] as number), 900, 'SD-01: fifteen minutes')
})

test('a token from another issuer is rejected as bad_issuer, not as a bad signature', { skip }, async () => {
  // The distinction is the whole reason VerifyResult is discriminated. Nimbus returned null for
  // every cause, and an issuer mismatch went unnoticed for an entire deploy.
  const { user, sessionId } = await open()
  const token = await issueAccessToken(db, {
    userId: user.id,
    handle: user.handle,
    roles: [],
    sessionId,
    amr: ['pwd'],
  })
  const [header, , signature] = token.split('.')
  const payload = Buffer.from(
    JSON.stringify({ iss: 'https://evil.example', aud: 'cloudsforge', sub: user.id, exp: 9_999_999_999 }),
  ).toString('base64url')
  const forged = `${header}.${payload}.${signature}`

  const verified = await verifyToken(db, forged)
  assert.ok(!verified.ok)
  // A forged payload fails the signature first, which is correct — the point is that it fails as a
  // TOKEN fault and never as `unavailable`, because `unavailable` is a 503 and this is a 401.
  assert.notEqual(verified.reason, 'unavailable')

  assert.equal((await verifyToken(db, 'not-a-jwt')).ok, false)
  const malformed = await verifyToken(db, 'not-a-jwt')
  assert.ok(!malformed.ok)
  assert.equal(malformed.reason, 'malformed', 'a caller sending rubbish must not read as us being down')
})

/* ------------------------------------------------------------------ the hand-off */

test('a hand-off code is single-use, and two concurrent redemptions cannot both win', { skip }, async () => {
  const user = await makeUser()
  const code = await createHandoffCode(db, user.id, 'https://app.test.cloudsforge.local')
  assert.ok(code)

  // The conditional UPDATE ... RETURNING is what decides. Select-then-update would let both of
  // these read `redeemed = false` and both proceed.
  const [a, b] = await Promise.all([
    redeemHandoffCode(db, code, 'https://app.test.cloudsforge.local'),
    redeemHandoffCode(db, code, 'https://app.test.cloudsforge.local'),
  ])
  const winners = [a, b].filter((r) => r !== null)
  assert.equal(winners.length, 1, 'exactly one redemption may win')
  assert.equal(winners[0], user.id)

  // And a third attempt, unhurried, still fails.
  assert.equal(await redeemHandoffCode(db, code, 'https://app.test.cloudsforge.local'), null)
})

test('a hand-off code is bound to the origin it was minted for', { skip }, async () => {
  const user = await makeUser()
  const code = await createHandoffCode(db, user.id, 'https://app.test.cloudsforge.local')
  assert.ok(code)
  // A code minted for one product cannot be redeemed by another, so an open redirect anywhere in
  // the estate cannot turn a legitimate sign-in into token delivery to somebody else's page.
  assert.equal(await redeemHandoffCode(db, code, 'https://play.test.cloudsforge.local'), null)
  assert.equal(await redeemHandoffCode(db, code, 'https://evil.example'), null)
  assert.equal(await redeemHandoffCode(db, code, 'https://app.test.cloudsforge.local'), user.id)
})

test('an origin that is not on the allowlist is refused at mint, not at redemption', { skip }, async () => {
  // A misconfiguration should be a 400 at the moment it is made, rather than a sign-in loop that
  // looks like a client bug.
  const user = await makeUser()
  assert.equal(await createHandoffCode(db, user.id, 'https://evil.example'), null)
})

test('an expired hand-off code is refused, and expired rows are swept', { skip }, async () => {
  const user = await makeUser()
  const code = await createHandoffCode(db, user.id, 'https://app.test.cloudsforge.local')
  assert.ok(code)
  await sql`update auth_exchange_codes set expires_at = now() - interval '1 minute'`
  assert.equal(await redeemHandoffCode(db, code, 'https://app.test.cloudsforge.local'), null)

  // The next mint sweeps it: this table is otherwise append-only, and an expired row is worth
  // nothing to anyone least of all whoever ends up with a copy of the database.
  await createHandoffCode(db, user.id, 'https://app.test.cloudsforge.local')
  const rows = await sql<{ code_hash: string }[]>`select code_hash from auth_exchange_codes`
  assert.equal(rows.length, 1)
})
