/**
 * Shared setup for the tests.
 *
 * **A database test runs only against a database whose name says it is a test database.** That is
 * not a convenience: `resetIdentity` truncates every table, and requiring "test" in the name is the
 * difference between a red build and an emptied environment. For this service in particular,
 * pointing the suite at the wrong database would delete every account on the platform and every
 * signing key the estate verifies against.
 *
 * **This module must be imported FIRST in every test file**, before anything that reaches `env.ts`.
 * `env.ts` validates at import and exits the process on a missing variable, so the assignments
 * below have to happen before that module is evaluated. ES modules are evaluated in the order their
 * imports are declared, and this file deliberately imports nothing that touches `env.ts` — adding
 * such an import here would break every test file at once, in a way whose only symptom is a
 * process that exits with a configuration error.
 *
 * Not a test file itself — it is excluded from the build and contains no `test()` call.
 */

import postgres from 'postgres'
import { createHash, randomUUID } from 'node:crypto'
import { migrate, type Sql as DbSql } from '@cloudsforge/db'
import { MIGRATIONS } from './migrations.ts'

const url = process.env['IDENTITY_TEST_DATABASE_URL']

/** Both halves are required: a URL, and a URL that names a test database. */
export const enabled = Boolean(url && /test/i.test(url))

export const skip = enabled ? false : 'set IDENTITY_TEST_DATABASE_URL (name must contain "test")'

/**
 * A secret fixture: DERIVED rather than written down, and DETERMINISTIC rather than random.
 *
 * ── Why it is no longer a literal ──────────────────────────────────────────────────────────────
 *
 * The value that stood in `IDENTITY_KEY_SECRET` below was
 * `test-key-secret-0123456789abcdef0123456789`, and the comment beside it said it was "long enough
 * to pass the boot check and not one of the refused placeholders". Both were true, and that is the
 * whole problem: it is a hyphenated, hand-typed, word-bearing string, which is precisely the shape
 * of the 40-character placeholder that reached 44 containers as micro-org #142. The suite ran every
 * one of its cases against it and `env.test.ts` asserted it was acceptable, so the fixture was not
 * neutral — it was the defect, pinned.
 *
 * `@cloudsforge/secrets` refuses it now (the alphabet check fires on the first hyphen), so a
 * literal here would take the whole suite down. That is the guard working: a fixture a placeholder
 * can creep back into is a fixture that will eventually be copied into a deployment.
 *
 * ── Why it is a HASH and not `randomBytes` ─────────────────────────────────────────────────────
 *
 * Because this particular fixture must be STABLE. It is the key-encryption key: a blob sealed in
 * one place has to open in another, `rewrap.test.ts` builds a keyring at v1 that must be
 * byte-identical to the one `env.ts` builds from this variable, and `node --test` runs each FILE in
 * its own process — so `randomBytes` here would produce a different KEK per file and the equality
 * that makes the rotation rehearsal mean anything would quietly stop holding.
 *
 * A SHA-512 digest gives both properties at once: the same value every run, and a value in the
 * base64 alphabet with 64 bytes behind it and measured entropy of 5.4 bits per character — clear of
 * the 4.0 floor with margin, and impossible to mistake for something typed. No literal is left for
 * anyone to copy.
 *
 * Exported because `rewrap.test.ts` needs the same v1 value and used to carry its own copy of the
 * literal. Two copies of a fixture drift exactly as fast as two copies of a check.
 */
export function testSecret(purpose: string): string {
  return createHash('sha512').update(`identity-test:${purpose}`).digest('base64')
}

/** The suite's key-encryption key at v1. `rewrap.test.ts` builds its `ringV1` from this. */
export const TEST_KEY_SECRET_V1 = testSecret('IDENTITY_KEY_SECRET_V1')

/*
 * The configuration the suite runs under.
 *
 * Set with `??=` so a caller who has already exported one of these keeps it — which is how the
 * database URL reaches `env.ts` when the service itself is booted from a test.
 */
process.env['IDENTITY_DATABASE_URL'] ??= url ?? 'postgres://cloudsforge@127.0.0.1:5432/identity_test'
process.env['IDENTITY_ISSUER'] ??= 'https://identity.test.cloudsforge.local'
process.env['IDENTITY_KEY_SECRET'] ??= TEST_KEY_SECRET_V1
process.env['IDENTITY_PUBLIC_URL'] ??= 'https://account.test.cloudsforge.local'
/*
 * Hub's origin, so the suite exercises the branch a configured deployment runs: a verification
 * event that carries a `verifyUrl`. The unset branch is not tested by unsetting this — `env.ts`
 * validates at import and a test cannot take a variable back afterwards — but through
 * `buildVerifyUrl`, which takes the origin as an argument for exactly that reason.
 */
process.env['IDENTITY_ACCOUNT_URL'] ??= 'https://hub.test.cloudsforge.local'
process.env['IDENTITY_HANDOFF_ORIGINS'] ??= 'https://app.test.cloudsforge.local,https://play.test.cloudsforge.local'
// Also derived rather than written — it was `test-outbox-signing-secret-0123456789`, the same
// hyphenated shape and refused for the same reason. Nothing seals under it, so it needs no
// stability across files; it is derived anyway so there is one way to make a fixture here.
process.env['OUTBOX_SIGNING_SECRET'] ??= testSecret('OUTBOX_SIGNING_SECRET')
process.env['IDENTITY_SERVICE_TOKEN_GRANTS'] ??= JSON.stringify({
  settlement: ['custody:sign:deposit', 'ledger:post', 'ledger:read'],
  market: ['ledger:reserve', 'ledger:read'],
  // The only holder of `identity:admin`, and the reason the entry is here rather than in a test's
  // fixture: `parseServiceGrants` refuses an unknown scope at import, so a suite that can mint this
  // token is a suite that has proved the scope is in the contracts registry. A fake principal would
  // have proved nothing — that is the exact shape of blindness the estate's scope audit exists for.
  'admin-api': ['identity:admin'],
})
process.env['LOG_LEVEL'] ??= 'error'

/** Every table this service owns. The order does not matter because CASCADE is used. */
const ALL_TABLES = [
  'mfa_recovery_codes',
  'mfa_challenges',
  'mfa_factors',
  'refresh_tokens',
  'sessions',
  'devices',
  'memberships',
  'organisations',
  'password_reset_tokens',
  'email_verification_tokens',
  'auth_exchange_codes',
  'login_attempts',
  'service_token_issues',
  'service_credentials',
  'platform_role_grants',
  'profiles',
  'users',
  'signing_keys',
  'outbox_deliveries',
  'event_subscriptions',
  'outbox',
  'inbox',
  'jobs',
].join(', ')

export function openDb(max = 8): postgres.Sql {
  if (!enabled) throw new Error('database tests are disabled')
  return postgres(url!, { max, onnotice: () => {} })
}

/**
 * Bring the schema up. Idempotent, so every test file may call it and only the first does work.
 *
 * Deliberately runs the real `MIGRATIONS` rather than a hand-written fixture schema. A fixture would
 * let the constraints drift out of the tests that are supposed to prove they hold — and for this
 * service the constraints ARE the design: one session per refresh family, one active factor per
 * kind, one spelling of an address.
 */
export async function migrateTestDb(sql: postgres.Sql): Promise<void> {
  await migrate(sql as unknown as DbSql, MIGRATIONS, { service: 'identity-test' })
}

/**
 * Empty every table, and forget the memoised signing key with them.
 *
 * The second half is not optional. `keys.ts` caches the active key for thirty seconds, so a suite
 * that truncates `signing_keys` would keep signing with a row that no longer exists and the next
 * verification would fail for a reason that has nothing to do with the test.
 */
export async function resetIdentity(sql: postgres.Sql): Promise<void> {
  await sql.unsafe(`truncate ${ALL_TABLES} restart identity cascade`)
  const { forgetSigningKeys } = await import('./keys.ts')
  forgetSigningKeys()
}

/**
 * Promote a user to `admin` the way the estate now has to: the grant row and the role in ONE
 * transaction.
 *
 * Before migration 12 every suite that needed an operator wrote `update users set roles =
 * '{player,admin}'` and that is now refused at COMMIT, which is the guard working rather than a
 * test-harness inconvenience. It is here rather than copied into three files so that if the shape
 * of a legitimate promotion ever changes, exactly one place says what it is.
 *
 * `source` defaults to `'approval'` because that is what every administrator after the first is:
 * the `'bootstrap'` grant is one per database for ever, and a helper that spent it by default
 * would make the second call in any test fail for a reason that has nothing to do with the test.
 */
export async function grantAdmin(
  sql: postgres.Sql,
  userId: string,
  source: 'bootstrap' | 'approval' = 'approval',
): Promise<string | null> {
  const approvalId = source === 'approval' ? randomUUID() : null
  await sql.begin(async (tx) => {
    await tx`
      insert into platform_role_grants (user_id, role, source, approval_id, actor, reason)
      values (${userId}, 'admin', ${source}, ${approvalId}, 'test-suite', 'promoted by the suite')
    `
    await tx`update users set roles = '{player,admin}' where id = ${userId}`
  })
  return approvalId
}

let counter = 0

/** A fresh identifier per call, so tests never collide on a reused address by accident. */
export function freshEmail(prefix = 'user'): string {
  counter += 1
  return `${prefix}-${process.pid}-${Date.now()}-${counter}@example.test`
}

export function freshHandle(prefix = 'user'): string {
  counter += 1
  // Handles are 3–20 characters of `[a-zA-Z0-9_-]`, so this has to stay short: the process id and a
  // counter are enough to be unique within a run, and the table is truncated between them.
  return `${prefix}${process.pid % 10_000}x${counter}`.slice(0, 20)
}

/** A password that passes `checkPassword` — long enough, varied, and containing no identifier. */
export const GOOD_PASSWORD = 'quill-vault-ember-73'
export const OTHER_PASSWORD = 'lantern-forge-tide-91'
