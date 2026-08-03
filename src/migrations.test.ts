/**
 * The schema, asserted as text.
 *
 * These run without a database because they are about what the DDL SAYS. The invariants that need a
 * database to prove — one session per family, one active factor per kind, one spelling of an
 * address — are asserted against a live one in the suites that exercise them.
 */

import './testsupport.ts'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checksumOf } from '@cloudsforge/db'
import { BASELINE_VERSION, MIGRATIONS, SCHEMA_VERSION } from './migrations.ts'

const sql = MIGRATIONS.map((m) => m.up).join('\n')

/**
 * The DDL with `--` comments removed.
 *
 * Assertions that a migration does NOT contain something must run against the statements, not the
 * prose: these migrations explain their reasoning at length, and a comment saying why a column is
 * absent contains the name of the absent column.
 */
const statementsOf = (text: string): string => text.replace(/--[^\n]*/g, '')

test('versions are unique and ascending', () => {
  const versions = MIGRATIONS.map((m) => m.version)
  assert.deepEqual(versions, [...versions].sort((a, b) => a - b))
  assert.equal(new Set(versions).size, versions.length, 'a duplicate version makes the run refuse')
})

test('SCHEMA_VERSION is the highest migration, so a new one raises the boot assertion', () => {
  assert.equal(SCHEMA_VERSION, Math.max(...MIGRATIONS.map((m) => m.version)))
})

test('a new service baselines nothing', () => {
  // Identity is built fresh rather than migrated in place: Nimbus's database keeps serving Nimbus
  // until the cutover. A non-zero baseline would record migrations as applied without running them.
  assert.equal(BASELINE_VERSION, 0)
})

test('checksums are stable, which is what makes an edited migration refuse to run', () => {
  for (const m of MIGRATIONS) {
    assert.equal(checksumOf(m), checksumOf({ ...m, up: `\n  ${m.up}  \n` }), `${m.name} is whitespace-sensitive`)
  }
})

test('every table the service reads or writes is created', () => {
  for (const table of [
    'jobs',
    'outbox',
    'event_subscriptions',
    'outbox_deliveries',
    'inbox',
    'users',
    'profiles',
    'signing_keys',
    'devices',
    'sessions',
    'refresh_tokens',
    'mfa_factors',
    'mfa_recovery_codes',
    'mfa_challenges',
    'organisations',
    'memberships',
    'login_attempts',
    'password_reset_tokens',
    'auth_exchange_codes',
    'service_token_issues',
    'platform_role_grants',
  ]) {
    assert.match(sql, new RegExp(`create table if not exists ${table}\\b`), `${table} is missing`)
  }
})

/* ------------------------------------------------------------------ the invariants */

test('EMAIL: uniqueness is on lower(email), and the rows are normalised before it is created', () => {
  const migration = MIGRATIONS.find((m) => m.name === 'email_normalisation')
  assert.ok(migration, 'the normalisation migration is the point of this service')
  // The order is the whole thing: creating the index first would fail on exactly the rows the
  // update exists to fix.
  const update = migration.up.indexOf('update users set email')
  const index = migration.up.indexOf('create unique index')
  assert.ok(update >= 0 && index > update, 'normalise, THEN constrain')
  assert.match(migration.up, /create unique index if not exists users_email_lower_uniq on users \(lower\(email\)\)/)
  // And the users table must NOT carry a plain unique on email, which would make the two disagree
  // about which spellings collide.
  const users = MIGRATIONS.find((m) => m.name === 'users')!
  assert.doesNotMatch(statementsOf(users.up), /email\s+text\s+not null\s+unique/)
})

test('SESSIONS: exactly one session per refresh family, enforced by the database', () => {
  // The invariant the whole of sessions.ts rests on. A family that outlives its session is a
  // credential nothing surfaces and nothing can revoke.
  assert.match(sql, /constraint sessions_refresh_family_uniq unique \(refresh_family_id\)/)
})

test('SESSIONS: the column is a prefix, and nothing in the DDL invites a full address', () => {
  assert.match(sql, /ip_prefix\s+text/)
  assert.doesNotMatch(statementsOf(sql), /\bip_address\b|\bremote_addr\b/)
})

test('MFA: sms is not an admissible kind, and cannot become one by accident', () => {
  // SIM-swap makes it a weaker factor than the password it is meant to strengthen. A kind that is
  // in neither the check constraint nor contracts-auth's union is a kind nothing can accept.
  assert.match(sql, /mfa_factors_kind_chk check \(kind in \('totp', 'webauthn', 'recovery_code'\)\)/)
  assert.doesNotMatch(statementsOf(sql), /'sms'/)
})

test('MFA: at most one active TOTP factor and one active recovery set per user', () => {
  assert.match(
    sql,
    /create unique index if not exists mfa_factors_one_active_per_kind[\s\S]*?where status = 'active' and kind in \('totp', 'recovery_code'\)/,
  )
})

test('KEYS: the private half is NOT NULL and there is no plaintext column to fall back to', () => {
  assert.match(sql, /private_jwk_enc\s+text\s+not null/)
  // Nimbus keeps a plaintext `private_jwk` column purely so a boot pass can empty it, and its own
  // comment says it exists to be dropped. A database created here never held the key in the clear,
  // so the column would only be somewhere for a future bug to write.
  assert.doesNotMatch(statementsOf(sql), /private_jwk\s+jsonb/)
})

test('KEYS: the publication index is ordered (created_at, kid) — the SD-14 split-brain fix', () => {
  assert.match(
    sql,
    /create index if not exists signing_keys_publication_idx\s+on signing_keys \(created_at, kid\)/,
  )
  assert.match(sql, /signing_keys_status_chk check \(status in \('active', 'published', 'retired'\)\)/)
})

test('USERS: the lifecycle states are the closed set the domain model names', () => {
  assert.match(
    sql,
    /users_status_chk check \(\s*status in \('active', 'suspended', 'locked', 'pending_deletion', 'deleted'\)\s*\)/,
  )
  // The two columns the deletion lifecycle needs. Without them a "deleted" user is indistinguishable
  // from one that was never created, and the grace window has no clock.
  assert.match(sql, /pending_deletion_at timestamptz/)
  assert.match(sql, /deleted_at\s+timestamptz/)
})

test('USERS: hash_algo exists and is NOT NULL, so no row can be unverifiable', () => {
  // A nullable work factor is a row that cannot be verified and cannot be upgraded — which is the
  // position Nimbus is in for every row it has.
  assert.match(sql, /hash_algo\s+text\s+not null/)
})

test('ORGANISATIONS: the roles are the closed set, and the owner rule is NOT a table constraint', () => {
  assert.match(sql, /memberships_role_chk check \(role in \('owner', 'admin', 'member', 'billing', 'read'\)\)/)
  // Asserted as an absence on purpose. The at-least-one-owner rule is a statement about the
  // resulting SET after a change, and a row-level check cannot see the other rows at the moment it
  // runs. Anyone who "fixes" this by adding a constraint has misunderstood it; the enforcement is
  // in organisations.ts, under a lock.
  const organisations = MIGRATIONS.find((m) => m.name === 'organisations')!
  assert.doesNotMatch(statementsOf(organisations.up), /owner_count|at_least_one_owner/)
})

/* ---------------------------------------------------- the first administrator (migration 12) */

/*
 * These are text assertions and they are the weaker half deliberately.
 *
 * `platformRoles.test.ts` proves the behaviour against a real Postgres — a second bootstrap
 * refused, an unapproved promotion refused, both from a raw connection. What CANNOT be proved there
 * is an absence: that nobody has quietly softened the DDL in a way that leaves the behaviour intact
 * on the happy paths the suite happens to walk. That is what these read.
 */

const roleGrants = MIGRATIONS.find((m) => m.name === 'platform_role_grants')!

test('BOOTSTRAP: one grant with source=bootstrap per database, enforced by a PARTIAL unique index', () => {
  // The whole security property. A unique index on `source` alone would cap approved grants at one
  // as well, which would make a second administrator impossible — and four-eyes approval needs two.
  assert.match(
    roleGrants.up,
    /create unique index if not exists platform_role_grants_one_bootstrap\s+on platform_role_grants \(source\) where source = 'bootstrap';/,
  )
  // Capping ADMINISTRATORS is the mistake this design exists to avoid, so nothing may constrain
  // users.roles by count.
  assert.doesNotMatch(statementsOf(roleGrants.up), /one_admin|admin_count|count\(\*\) *[<=]/)
})

test('BOOTSTRAP: the promotion guard is a DEFERRED constraint trigger, not a CHECK and not a handler', () => {
  // A CHECK cannot reference another table, and a non-deferred trigger would dictate statement
  // order inside the transaction. Both facts are why this is the shape it is.
  assert.match(
    roleGrants.up,
    /create constraint trigger users_roles_need_a_grant\s+after insert or update of roles on users\s+deferrable initially deferred/,
  )
  // INSERT as well as UPDATE: a row created already privileged would otherwise walk past it.
  assert.match(roleGrants.up, /after insert or update of roles on users/)
})

test('BOOTSTRAP: the grant must be written in the SAME transaction as the promotion', () => {
  // Without this clause a demoted administrator is re-promotable for ever on the row that
  // authorised the first promotion — one approval, unlimited grants.
  assert.match(roleGrants.up, /g\.granted_at = transaction_timestamp\(\)/)
  assert.match(roleGrants.up, /granted_at  timestamptz not null default transaction_timestamp\(\)/)
})

test('BOOTSTRAP: the grant table is append-only, so the one-shot cannot be re-armed', () => {
  assert.match(
    roleGrants.up,
    /create trigger platform_role_grants_immutable\s+before update or delete on platform_role_grants/,
  )
})

test('BOOTSTRAP: an approval grant carries an approval id and a bootstrap grant does not', () => {
  // An equality rather than two implications: `source='approval'` with a null id is an
  // unauthorised grant wearing the authorised source.
  assert.match(
    roleGrants.up,
    /platform_role_grants_approval_pairing\s+check \(\(source = 'approval'\) = \(approval_id is not null\)\)/,
  )
  assert.match(roleGrants.up, /platform_role_grants_source_known\s+check \(source in \('bootstrap', 'approval'\)\)/)
  // Neither may be blank. An audit row with no actor and no reason records that something happened
  // and nothing about who or why, which is the state migration 12 exists to leave behind.
  assert.match(roleGrants.up, /platform_role_grants_actor_present check \(btrim\(actor\) <> ''\)/)
  assert.match(roleGrants.up, /platform_role_grants_reason_present check \(btrim\(reason\) <> ''\)/)
})

test('BOOTSTRAP: the privileged set in the CHECK and in the trigger are the same list', () => {
  // Three copies of one list — here twice, and PRIVILEGED_ROLES in platformRoles.ts. The two in the
  // DDL are compared here; platformRoles.test.ts compares the module's against the database's.
  assert.match(roleGrants.up, /platform_role_grants_role_known check \(role in \('admin'\)\)/)
  assert.match(roleGrants.up, /privileged constant text\[\] := array\['admin'\]/)
  // `player` is every account's default. A grant requirement on it would spend the one-per-database
  // bootstrap slot on somebody's sign-up and refuse every registration after the first.
  assert.doesNotMatch(statementsOf(roleGrants.up), /array\['admin', ?'player'\]|role in \('admin', ?'player'\)/)
})

test('BOOTSTRAP: the grant survives its user — no cascade erases the record of a promotion', () => {
  assert.match(roleGrants.up, /user_id     uuid        not null references users \(id\),/)
  const statements = statementsOf(roleGrants.up)
  assert.ok(!statements.includes('on delete cascade'), 'a cascade would delete the audit trail')
})

test('nothing stores a credential in the clear', () => {
  const statements = statementsOf(sql)
  // Every secret in this schema is either a SHA-256 hash of something unguessable or an AES-256-GCM
  // envelope. A column named for the secret itself would be the one that breaks that.
  for (const forbidden of ['password text', 'secret text not null default', 'private_key', 'totp_secret']) {
    assert.ok(!statements.includes(forbidden), `${forbidden} must not appear`)
  }
  assert.match(sql, /token_hash\s+text/)
  assert.match(sql, /code_hash\s+text/)
  assert.match(sql, /challenge_hash text/)
  assert.match(sql, /fingerprint_hash\s+text/)
})
