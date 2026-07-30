/**
 * MFA: enrolment, authentication, recovery codes, and the last-factor rule.
 *
 * SD-02. There is no MFA anywhere in the estate today, on a platform that custodies private keys
 * for five chains — including no MFA on the administrator accounts that can reach the custody
 * surface at all.
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
import { classifyFactorRemoval, normaliseHandle } from '@cloudsforge/contracts-auth'
import type postgres from 'postgres'
import {
  ReauthenticationRequiredError,
  activateTotp,
  authenticateMfa,
  consumeMfaChallenge,
  createMfaChallenge,
  enrolTotp,
  generateRecoveryCodes,
  hasActiveFactor,
  listFactors,
  remainingRecoveryCodes,
  removeFactor,
} from './mfa.ts'
import { DEFAULT_PARAMS, base32Decode, totp } from './totp.ts'
import { registerUser, type UserRow } from './users.ts'
import type { Db } from './outbox.ts'

let sql: postgres.Sql
let db: Db

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

/** Enrol and activate a TOTP factor, returning the seed so the test can generate codes. */
async function enrolAndActivate(user: UserRow): Promise<{ factorId: string; secret: Buffer }> {
  const enrolment = await enrolTotp(db, { userId: user.id, account: user.email, label: 'Phone' })
  const secret = base32Decode(enrolment.secret)!
  const code = totp(secret, Math.floor(Date.now() / 1000), DEFAULT_PARAMS)
  const activated = await activateTotp(db, {
    userId: user.id,
    factorId: enrolment.factorId,
    code,
    correlationId: 't',
  })
  assert.ok(activated.ok)
  return { factorId: enrolment.factorId, secret }
}

/* ------------------------------------------------------------------ enrolment */

test('enrolment is two steps: a pending factor that authenticates nothing, then activation', { skip }, async () => {
  const user = await makeUser()
  const enrolment = await enrolTotp(db, { userId: user.id, account: user.email, label: 'Phone' })

  // Pending, not active. Enrolling in one step would let a user store a secret their authenticator
  // never received — a mistyped or half-scanned code — and discover it when they are locked out.
  assert.equal(await hasActiveFactor(db, user.id), false)
  const pending = await listFactors(db, user.id)
  assert.equal(pending[0]!.status, 'pending')
  assert.equal(pending[0]!.kind, 'totp')

  const secret = base32Decode(enrolment.secret)!
  assert.equal(secret.length, 20, 'RFC 4226 recommends a 160-bit seed')

  // A wrong code does not activate it.
  const wrong = await activateTotp(db, {
    userId: user.id,
    factorId: enrolment.factorId,
    code: '000000',
    correlationId: 't',
  })
  assert.equal(wrong.ok, false)
  assert.equal(await hasActiveFactor(db, user.id), false)

  const code = totp(secret, Math.floor(Date.now() / 1000), DEFAULT_PARAMS)
  const activated = await activateTotp(db, {
    userId: user.id,
    factorId: enrolment.factorId,
    code,
    correlationId: 't',
  })
  assert.ok(activated.ok)
  assert.equal(activated.factor.status, 'active')
  assert.equal(await hasActiveFactor(db, user.id), true)
})

test('the TOTP seed is sealed at rest and never returned by a listing', { skip }, async () => {
  const user = await makeUser()
  await enrolAndActivate(user)

  const rows = await sql<{ secret_enc: string }[]>`select secret_enc from mfa_factors where kind = 'totp'`
  // A second factor whose shared secret sits in the clear is a second factor that a database read
  // computes, which would make MFA a control that defeats only the attacker who did not get that far.
  assert.match(rows[0]!.secret_enc, /^v1:[A-Za-z0-9+/]+={0,2}$/)

  // And there is no route back out: `listFactors` selects a literal null for the column, so no
  // caller can accidentally serialise it.
  const factors = await listFactors(db, user.id)
  assert.ok(!JSON.stringify(factors).includes('secret'))
})

test('re-enrolling replaces the active factor rather than colliding with the unique index', { skip }, async () => {
  const user = await makeUser()
  const first = await enrolAndActivate(user)
  const second = await enrolAndActivate(user)
  assert.notEqual(first.factorId, second.factorId)

  const factors = await listFactors(db, user.id)
  assert.equal(factors.filter((f) => f.status === 'active').length, 1)
  assert.equal(factors.find((f) => f.id === first.factorId)?.status, 'revoked')

  // The old device stops working the moment the new one is confirmed, which is what a user
  // replacing a lost phone is asking for.
  const stale = totp(first.secret, Math.floor(Date.now() / 1000), DEFAULT_PARAMS)
  const outcome = await authenticateMfa(db, { userId: user.id, code: stale })
  assert.equal(outcome.ok, false)
})

/* ------------------------------------------------------------------ authentication */

test('a TOTP code authenticates once and cannot be replayed', { skip }, async () => {
  const user = await makeUser()
  const { secret } = await enrolAndActivate(user)

  // Activation stamps `last_used_at` with the step it consumed, so the code that activated is
  // already spent. Move on a step to get a fresh one.
  const later = Math.floor(Date.now() / 1000) + DEFAULT_PARAMS.stepSeconds
  const code = totp(secret, later, DEFAULT_PARAMS)
  await sql`update mfa_factors set last_used_at = ${new Date((later - 60) * 1000)} where kind = 'totp'`

  const first = await authenticateMfa(db, { userId: user.id, code })
  // The code is for a step up to 30s in the future, which the ±1 window accepts.
  assert.ok(first.ok)
  assert.equal(first.method, 'totp')

  const replay = await authenticateMfa(db, { userId: user.id, code })
  assert.equal(replay.ok, false)
  assert.ok(!replay.ok)
  // Distinguished from a wrong code, because it is what a shoulder-surf or a real-time phishing
  // relay produces — and the route logs it as an attack signal rather than a typo.
  assert.equal(replay.reason, 'replayed')
})

test('a user with no factor cannot be authenticated by any code', { skip }, async () => {
  const user = await makeUser()
  const outcome = await authenticateMfa(db, { userId: user.id, code: '123456' })
  assert.equal(outcome.ok, false)
  assert.ok(!outcome.ok)
  assert.equal(outcome.reason, 'no_factor')
})

/* ------------------------------------------------------------------ recovery codes */

test('recovery codes are single-use, shown once, and stored only as hashes', { skip }, async () => {
  const user = await makeUser()
  const generated = await generateRecoveryCodes(db, { userId: user.id, correlationId: 't' })
  assert.equal(generated.codes.length, 10)
  assert.equal(new Set(generated.codes).size, 10)
  assert.equal(await remainingRecoveryCodes(db, user.id), 10)

  const stored = await sql<{ code_hash: string }[]>`select code_hash from mfa_recovery_codes`
  const raw = generated.codes.join(' ')
  for (const row of stored) {
    assert.match(row.code_hash, /^[0-9a-f]{64}$/)
    assert.ok(!raw.includes(row.code_hash), 'the stored value must not be the code')
  }

  const code = generated.codes[0]!
  const first = await authenticateMfa(db, { userId: user.id, code })
  assert.ok(first.ok)
  assert.equal(first.method, 'recovery_code')
  assert.equal(await remainingRecoveryCodes(db, user.id), 9)

  // Single use is the whole property.
  assert.equal((await authenticateMfa(db, { userId: user.id, code })).ok, false)
})

test('two concurrent presentations of one recovery code cannot both win', { skip }, async () => {
  // The conditional UPDATE ... RETURNING is what decides. Select-then-update would let both of
  // these succeed, and a single-use credential that can be used twice is not single-use.
  const user = await makeUser()
  const generated = await generateRecoveryCodes(db, { userId: user.id, correlationId: 't' })
  const code = generated.codes[0]!

  const [a, b] = await Promise.all([
    authenticateMfa(db, { userId: user.id, code }),
    authenticateMfa(db, { userId: user.id, code }),
  ])
  assert.equal([a.ok, b.ok].filter(Boolean).length, 1)
  assert.equal(await remainingRecoveryCodes(db, user.id), 9)
})

test('regenerating revokes the old set in the same breath as writing the new one', { skip }, async () => {
  const user = await makeUser()
  const old = await generateRecoveryCodes(db, { userId: user.id, correlationId: 't' })
  const fresh = await generateRecoveryCodes(db, { userId: user.id, correlationId: 't' })

  // A set printed a year ago and lost in a drawer must stop working, which is the opposite of what
  // leaving both live would do — and is what the user believed they were doing by regenerating.
  assert.equal((await authenticateMfa(db, { userId: user.id, code: old.codes[0]! })).ok, false)
  assert.ok((await authenticateMfa(db, { userId: user.id, code: fresh.codes[0]! })).ok)
  assert.equal(await remainingRecoveryCodes(db, user.id), 9)

  const factors = await listFactors(db, user.id)
  assert.equal(factors.filter((f) => f.kind === 'recovery_code' && f.status === 'active').length, 1)
})

test('regenerating a recovery set emits a critical event', { skip }, async () => {
  // An attacker who has the password and regenerates the codes has just locked the real owner out
  // of their own recovery path, and this event is the only signal of it.
  const user = await makeUser()
  await sql`delete from outbox`
  await generateRecoveryCodes(db, { userId: user.id, correlationId: 't' })
  const events = await sql<{ topic: string; payload: Record<string, unknown> }[]>`
    select topic, payload from outbox where topic = 'identity.mfa.changed'
  `
  assert.equal(events.length, 1)
  assert.equal(events[0]!.payload['change'], 'recovery_codes_regenerated')
  assert.equal(events[0]!.payload['critical'], true)
})

/* ------------------------------------------------------------------ the last-factor rule */

test('removing an ordinary factor is permitted without re-authentication', { skip }, async () => {
  const user = await makeUser()
  const totpFactor = await enrolAndActivate(user)
  await generateRecoveryCodes(db, { userId: user.id, correlationId: 't' })

  const removed = await removeFactor(db, {
    userId: user.id,
    factorId: totpFactor.factorId,
    reauthenticated: false,
    correlationId: 't',
  })
  assert.equal(removed.wasLastActive, false)
  assert.equal(removed.remainingActive, 1)
  assert.equal(await hasActiveFactor(db, user.id), true)
})

/**
 * **The last-factor rule.** 04-domain-model section 1.3 and SD-02.
 *
 * `classifyFactorRemoval` returns a union rather than a boolean precisely so the branch that would
 * silently drop a user to password-only does not type-check unless it is written, and both
 * obligations it carries — re-authentication and a notification — are discharged here.
 */
test('removing the LAST active factor is refused without re-authentication', { skip }, async () => {
  const user = await makeUser()
  const { factorId } = await enrolAndActivate(user)

  await assert.rejects(
    removeFactor(db, { userId: user.id, factorId, reauthenticated: false, correlationId: 't' }),
    ReauthenticationRequiredError,
  )
  assert.equal(await hasActiveFactor(db, user.id), true, 'the refusal must not half-apply')
})

test('removing the last active factor with re-authentication emits a CRITICAL event', { skip }, async () => {
  const user = await makeUser()
  const { factorId } = await enrolAndActivate(user)
  await sql`delete from outbox`

  const removed = await removeFactor(db, {
    userId: user.id,
    factorId,
    reauthenticated: true,
    correlationId: 't',
  })
  assert.equal(removed.wasLastActive, true)
  assert.equal(await hasActiveFactor(db, user.id), false)

  const events = await sql<{ topic: string; key: string; payload: Record<string, unknown> }[]>`
    select topic, key, payload from outbox where topic = 'identity.mfa.changed'
  `
  assert.equal(events.length, 1)
  assert.equal(events[0]!.payload['change'], 'last_factor_removed')
  // 10.3: a critical security notification ignores preferences and always sends. Dropping to
  // password-only is exactly the change a user must be told about even if they have muted
  // everything, because the person who did it may not be them.
  assert.equal(events[0]!.payload['critical'], true)
  // Keyed on the user, not the factor: ordering is per (topic, key), so "enrolled then removed"
  // must not be reorderable by a consumer into "removed then enrolled".
  assert.equal(events[0]!.key, user.id)
})

test('the classification is asked about the resulting set, so demote and remove cannot diverge', { skip }, async () => {
  // The contracts-auth helper is the single decision, and this pins its shape: a caller who wrote
  // a per-operation check would catch only the operation they wrote it for.
  const user = await makeUser()
  const { factorId } = await enrolAndActivate(user)
  const factors = await listFactors(db, user.id)

  assert.equal(classifyFactorRemoval(factors, factorId).kind, 'last_active')
  assert.equal(classifyFactorRemoval(factors, 'no-such-factor').kind, 'not_found')

  await removeFactor(db, { userId: user.id, factorId, reauthenticated: true, correlationId: 't' })
  // Revoked rather than deleted: a user asking "what happened to my account" deserves an answer,
  // and a row that is gone cannot give one.
  assert.equal(classifyFactorRemoval(await listFactors(db, user.id), factorId).kind, 'already_revoked')

  // And a second removal is not an error — the second click of a double-click must not be a failure
  // the user has to interpret.
  const again = await removeFactor(db, {
    userId: user.id,
    factorId,
    reauthenticated: false,
    correlationId: 't',
  })
  assert.equal(again.wasLastActive, false)
})

/* ------------------------------------------------------------------ the login challenge */

test('a challenge is single-use, stored hashed, and expires', { skip }, async () => {
  const user = await makeUser()
  const challenge = await createMfaChallenge(db, user.id)

  const rows = await sql<{ challenge_hash: string }[]>`select challenge_hash from mfa_challenges`
  assert.match(rows[0]!.challenge_hash, /^[0-9a-f]{64}$/)
  assert.notEqual(rows[0]!.challenge_hash, challenge)

  assert.equal(await consumeMfaChallenge(db, challenge), user.id)
  // Spent. A challenge that survives is an unlimited offline-speed oracle against a six-digit
  // secret, which is why the route spends it before it checks the code.
  assert.equal(await consumeMfaChallenge(db, challenge), null)

  const second = await createMfaChallenge(db, user.id)
  await sql`update mfa_challenges set expires_at = now() - interval '1 minute' where consumed_at is null`
  assert.equal(await consumeMfaChallenge(db, second), null)
})
