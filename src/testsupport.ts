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
import { randomUUID } from 'node:crypto'
import { migrate, type Sql as DbSql } from '@cloudsforge/db'
import { MIGRATIONS } from './migrations.ts'

const url = process.env['IDENTITY_TEST_DATABASE_URL']

/** Both halves are required: a URL, and a URL that names a test database. */
export const enabled = Boolean(url && /test/i.test(url))

export const skip = enabled ? false : 'set IDENTITY_TEST_DATABASE_URL (name must contain "test")'

/*
 * The configuration the suite runs under.
 *
 * Set with `??=` so a caller who has already exported one of these keeps it — which is how the
 * database URL reaches `env.ts` when the service itself is booted from a test.
 *
 * `IDENTITY_KEY_SECRET` is a fixed literal on purpose. Sealing and opening must agree across every
 * test in a file and across every file, and a random secret per process would make a fixture
 * written by one test unreadable by the next. It is long enough to pass the boot check and it is
 * not one of the refused placeholders — which is itself asserted in `env.test.ts`, because a
 * placeholder that boots in the suite is a placeholder that reaches production.
 */
process.env['IDENTITY_DATABASE_URL'] ??= url ?? 'postgres://cloudsforge@127.0.0.1:5432/identity_test'
process.env['IDENTITY_ISSUER'] ??= 'https://identity.test.cloudsforge.local'
process.env['IDENTITY_KEY_SECRET'] ??= 'test-key-secret-0123456789abcdef0123456789'
process.env['IDENTITY_PUBLIC_URL'] ??= 'https://account.test.cloudsforge.local'
process.env['IDENTITY_HANDOFF_ORIGINS'] ??= 'https://app.test.cloudsforge.local,https://play.test.cloudsforge.local'
process.env['OUTBOX_SIGNING_SECRET'] ??= 'test-outbox-signing-secret-0123456789'
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
