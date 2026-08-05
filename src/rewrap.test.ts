/**
 * The rehearsal for #188: a full `IDENTITY_KEY_SECRET` rotation, against a real database, with the
 * negative controls that make the positive result mean something.
 *
 * **WHY THE NEGATIVE CONTROLS ARE THE POINT.** A rotation test that only asserts "after rotating,
 * the seed still opens" passes just as happily when nothing was ever encrypted, when both keyrings
 * hold the same secret, or when the code silently fell back to a key it should not have. Two
 * controls close that off, and they are the two failures that actually occur:
 *
 *   1. **A WRONG KEY MUST FAIL.** If a keyring holding the wrong secret can open a blob, the
 *      envelope is not doing anything and every other assertion here is vacuous.
 *   2. **A NEW KEY WITHOUT A DRAIN MUST FAIL.** This is the one that matters. Removing the old
 *      secret before `rewrapOnce` has drained leaves blobs that nothing in the world can read. It
 *      has already happened once in this estate — 509 orphaned blobs, recovered only because an old
 *      secret survived in public git history. For a TOTP seed there is no such luck: the seed is in
 *      the blob and in the user's authenticator, nowhere else. This test asserts that skipping the
 *      drain BREAKS, so that the drain can never be quietly dropped as an optimisation.
 *
 * The end-to-end proof drives the real path — `enrolTotp`, `activateTotp`, `authenticateMfa` — and
 * authenticates with a code computed from the secret the USER's authenticator app holds, which was
 * captured at enrolment and never re-read from the database. That is what "MFA still works for
 * existing users" has to mean: not that a blob decrypts, but that a code from an app enrolled
 * before the rotation is still accepted after the old secret has been removed.
 *
 * No secret, seed or key value is ever asserted on, printed or logged here — only counts, booleans
 * and version numbers.
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
import { randomUUID } from 'node:crypto'
import { before, after, beforeEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { normaliseHandle } from '@cloudsforge/contracts-auth'
import type postgres from 'postgres'
import { Keyring, installKeyring, versionOf } from './keyEnvelope.ts'
import { activateTotp, authenticateMfa, enrolTotp } from './mfa.ts'
import { DEFAULT_PARAMS, base32Decode, totp } from './totp.ts'
import { getSigningKey } from './keys.ts'
import { forgetSigningKeys } from './keys.ts'
import { remainingCount, rewrapOnce, verifyAllReadable } from './rewrap.ts'
import { registerUser, type UserRow } from './users.ts'
import type { Db } from './outbox.ts'
import { Logger } from '@cloudsforge/telemetry'

let sql: postgres.Sql
let db: Db

/*
 * Three distinct secrets, all long enough and none of them a placeholder.
 *
 * `V1` is deliberately the same literal `testsupport.ts` puts in `IDENTITY_KEY_SECRET`, so a
 * keyring built here at v1 is byte-identical to the one the service builds from the environment.
 * That equality is what lets a blob written by the ordinary code path be drained by this test.
 */
const SECRET_V1 = 'test-key-secret-0123456789abcdef0123456789'
const SECRET_V2 = 'rotated-key-secret-fedcba9876543210fedcba98'
const SECRET_WRONG = 'a-completely-unrelated-secret-0000111122223333'

const ringV1 = new Keyring(new Map([[1, SECRET_V1]]), 1)
/** Mid-rotation: holds both, seals under the new one. This is the state the service runs in. */
const ringBoth = new Keyring(
  new Map([
    [1, SECRET_V1],
    [2, SECRET_V2],
  ]),
  2,
)
/** After step 4: the old secret is gone. Only a fully drained database survives this. */
const ringV2Only = new Keyring(new Map([[2, SECRET_V2]]), 2)
const ringWrong = new Keyring(new Map([[1, SECRET_WRONG]]), 1)

const logger = new Logger({ service: 'identity-test', level: 'error', version: 'test', env: 'test' })

before(async () => {
  if (!enabled) return
  sql = openDb()
  await migrateTestDb(sql)
  db = sql as unknown as Db
})

after(async () => {
  if (enabled) await sql.end({ timeout: 5 })
  installKeyring(null)
})

beforeEach(async () => {
  if (!enabled) return
  await resetIdentity(sql)
  // Every test starts in the pre-rotation world: one secret, sealing at v1.
  installKeyring(ringV1)
  forgetSigningKeys()
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

/**
 * Enrol and activate a TOTP factor the way a user does, and return what their AUTHENTICATOR holds.
 *
 * The base32 secret is captured from the enrolment response — the only moment it is ever legitimately
 * outside the envelope — and everything afterwards is computed from that copy, never from the
 * database. A test that re-read the seed from the database after rotating would be asserting that
 * the database agrees with itself.
 */
async function enrolAndActivate(user: UserRow): Promise<{ factorId: string; appSecret: Buffer }> {
  const enrolment = await enrolTotp(db, {
    userId: user.id,
    account: 'rotation@example.test',
    label: 'Rotation Test Phone',
  })
  const appSecret = base32Decode(enrolment.secret)
  assert.ok(appSecret, 'the enrolment secret must be decodable base32')
  const code = totp(appSecret, Math.floor(Date.now() / 1000), DEFAULT_PARAMS)
  const activation = await activateTotp(db, {
    userId: user.id,
    factorId: enrolment.factorId,
    code,
    correlationId: randomUUID(),
  })
  assert.equal(activation.ok, true, 'the factor must activate before the rotation')
  return { factorId: enrolment.factorId, appSecret }
}

/**
 * A code that the replay guard will accept, from the app's copy of the seed.
 *
 * Activation stamps `last_used_at` with the step it consumed, so the code that activated is already
 * spent and re-presenting it inside the same 30-second window is a REPLAY, not a bad code. That is
 * the guard working, and it is orthogonal to the rotation — but it made the first version of this
 * file flaky, passing alone and failing in a full run purely on whether the two calls landed either
 * side of a step boundary.
 *
 * So the step is moved on deliberately and the guard's high-water mark rewound, exactly as
 * `mfa.test.ts:160-164` does. This neutralises the replay guard and NOTHING else: the code is still
 * computed from the authenticator's copy of the seed and still goes through the real
 * `authenticateMfa` path, so what the assertion tests is unchanged.
 */
async function freshCode(appSecret: Buffer): Promise<{ code: string }> {
  const later = Math.floor(Date.now() / 1000) + DEFAULT_PARAMS.stepSeconds
  await sql`update mfa_factors set last_used_at = ${new Date((later - 60) * 1000)} where kind = 'totp'`
  // A step up to 30s ahead, which the ±1 window accepts.
  return { code: totp(appSecret, later, DEFAULT_PARAMS) }
}

/* ─────────────────────────────────────────────── the negative controls, stated first ────────── */

test('NEGATIVE CONTROL: a wrong key cannot open a blob', { skip }, () => {
  const blob = ringV1.sealAs(1, 'totp-seed', 'factor-a', 'a-seed-value')
  // Same version, same purpose, same id — only the secret differs. If this did not throw, the
  // envelope would be decorative and every other assertion in this file would be vacuous.
  assert.throws(() => ringWrong.open('totp-seed', 'factor-a', blob))
  // And the right key does open it, so the throw above is about the secret and not about the blob.
  assert.equal(ringV1.open<string>('totp-seed', 'factor-a', blob), 'a-seed-value')
})

test('NEGATIVE CONTROL: a new key without a drain cannot open old blobs', { skip }, () => {
  const blob = ringV1.sealAs(1, 'totp-seed', 'factor-a', 'a-seed-value')
  assert.equal(versionOf(blob), 1)

  // Step 4 performed without step 3: the old secret has been removed while a v1 blob still exists.
  // The failure names the missing VERSION, so an operator is told which step they skipped rather
  // than being shown a bare GCM authentication error.
  assert.throws(
    () => ringV2Only.open('totp-seed', 'factor-a', blob),
    /no key secret for envelope version v1/,
  )

  // Mid-rotation, holding both, the same blob opens. That is the difference the drain window buys.
  assert.equal(ringBoth.open<string>('totp-seed', 'factor-a', blob), 'a-seed-value')
})

test('a keyring refuses a write version it holds no secret for', { skip }, () => {
  // Sealing under a version this process cannot open would manufacture the orphans on purpose.
  assert.throws(() => new Keyring(new Map([[1, SECRET_V1]]), 2), /no key secret for the write version v2/)
  assert.throws(() => new Keyring(new Map(), 1), /at least one secret/)
})

/* ─────────────────────────────────────────────── the drain, end to end ──────────────────────── */

test('the drain rewraps every blob, and only then is the old secret removable', { skip }, async () => {
  const user = await makeUser()
  await enrolAndActivate(user)
  // Force a signing key to exist, so the drain has one of each kind to move.
  await getSigningKey(db)

  const before = await remainingCount(db, 2)
  assert.ok(before >= 2, `both blob kinds must exist before the drain (got ${before})`)

  // WITHOUT the drain, removing the old secret orphans exactly those blobs. Asserted before the
  // drain runs, so this is a statement about the data and not about the order of the assertions.
  const orphaned = await verifyAllReadable(db, ringV2Only)
  assert.equal(orphaned.unreadable, before, 'every un-drained blob must be unreadable under v2 alone')
  assert.equal(orphaned.keys + orphaned.seeds, 0)

  installKeyring(ringBoth)
  const report = await rewrapOnce({ sql: db, keyring: ringBoth, logger })

  assert.equal(report.failures, 0, 'no blob may fail to rewrap')
  assert.equal(report.remaining, 0, 'the drain must finish')
  assert.ok(report.keys >= 1, 'at least one signing key was rewrapped')
  assert.ok(report.seeds >= 1, 'at least one TOTP seed was rewrapped')
  assert.equal(report.keys + report.seeds, before, 'every blob below the target was drained')

  // The verification is a DECRYPTION under the new secret ALONE — the state after step 4.
  const verified = await verifyAllReadable(db, ringV2Only)
  assert.equal(verified.unreadable, 0, 'every blob must be readable under the new secret alone')
  assert.equal(verified.keys + verified.seeds, before)

  // And it is genuinely at the new version, not merely still readable because v1 was reused.
  const stamps = await sql<{ blob: string }[]>`
    select private_jwk_enc as blob from signing_keys
    union all select secret_enc from mfa_factors where secret_enc is not null
  `
  for (const row of stamps) assert.equal(versionOf(row.blob), 2)
})

test('the drain is idempotent and resumable', { skip }, async () => {
  const user = await makeUser()
  await enrolAndActivate(user)
  await getSigningKey(db)

  installKeyring(ringBoth)
  const first = await rewrapOnce({ sql: db, keyring: ringBoth, logger })
  assert.equal(first.remaining, 0)

  // A second pass must find nothing to do rather than rewriting rows — which is what makes a
  // crashed run safe to simply re-run.
  const second = await rewrapOnce({ sql: db, keyring: ringBoth, logger })
  assert.equal(second.keys, 0)
  assert.equal(second.seeds, 0)
  assert.equal(second.failures, 0)
  assert.equal(second.remaining, 0)
})

/* ─────────────────────────────── what the whole exercise is actually for ────────────────────── */

test(
  'a TOTP factor enrolled BEFORE the rotation still authenticates after the old secret is gone',
  { skip },
  async () => {
    const user = await makeUser()
    // What the user's authenticator app holds. Captured at enrolment, never re-read.
    const { appSecret } = await enrolAndActivate(user)
    await getSigningKey(db)

    // ── the rotation ──────────────────────────────────────────────────────────────────────
    installKeyring(ringBoth) // step 2: hold both, seal under v2
    const report = await rewrapOnce({ sql: db, keyring: ringBoth, logger }) // step 3: DRAIN
    assert.equal(report.failures, 0)
    assert.equal(report.remaining, 0)
    installKeyring(ringV2Only) // step 4: the old secret is gone for ever

    // ── the proof ─────────────────────────────────────────────────────────────────────────
    // A fresh code from the app's copy of the seed, through the real authentication path.
    const { code } = await freshCode(appSecret)
    const outcome = await authenticateMfa(db, { userId: user.id, code })
    assert.equal(outcome.ok, true, 'the pre-rotation authenticator must still be accepted')
    assert.ok(outcome.ok && outcome.method === 'totp', 'and accepted AS a TOTP code')
  },
)

test(
  'SKIPPING THE DRAIN destroys the factor — the failure this whole design prevents',
  { skip },
  async () => {
    const user = await makeUser()
    const { appSecret } = await enrolAndActivate(user)

    // Steps 2 and 4 with step 3 omitted: the operator added the new secret, cut over, and removed
    // the old one without ever draining.
    installKeyring(ringV2Only)

    // A code that would OTHERWISE be accepted — fresh step, replay guard rewound — so that the
    // rejection below is attributable to the unreadable seed and to nothing else. Without this the
    // test would pass just as happily because the code was a replay, which would make it a test
    // that proves the drain matters by accident.
    const { code } = await freshCode(appSecret)
    // The seed is now unreadable. Whatever the surface does with that — reject or raise — it must
    // NOT accept the code, because the value it would have to compare against no longer exists.
    let accepted: boolean
    try {
      const outcome = await authenticateMfa(db, { userId: user.id, code })
      accepted = outcome.ok
    } catch {
      accepted = false
    }
    assert.equal(accepted, false, 'an undrained rotation must not silently keep working')

    // And the damage is exactly as described in #188: the blob is unreadable, permanently.
    const orphaned = await verifyAllReadable(db, ringV2Only)
    assert.ok(orphaned.unreadable >= 1, 'the seed blob is orphaned')
  },
)
