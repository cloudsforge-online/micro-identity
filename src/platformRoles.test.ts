/**
 * The first-administrator bootstrap, proved **at the database**.
 *
 * Every assertion below that matters is a raw SQL statement on a plain connection, not a request to
 * a route. That is not stylistic. The threat model for a privilege escalation in this estate
 * explicitly includes someone holding a psql connection — it has to, because the bootstrap is
 * itself a database step run by a human — so the route is the layer the attacker is assumed to be
 * past. A guard proved only through `PUT /internal/users/:id/roles` would be a guard proved in the
 * one place it does not need to hold.
 *
 * The statement these tests are about is `deploy/scripts/estate-bootstrap.sh:102`:
 *
 *     update users set roles = array['admin'] where email = '<the operator>';
 *
 * It appears below character for character, twice, and both times it is refused.
 *
 * Every check here was broken deliberately and watched fail before it landed — the index dropped,
 * the trigger dropped, the same-transaction clause relaxed to "any grant row", the append-only
 * trigger removed. Each one turned a passing test red, and the notes on the individual tests say
 * which. This estate keeps producing checks that cannot fail; a security test that has never been
 * observed failing is a claim, not a proof.
 */

import { GOOD_PASSWORD, enabled, freshEmail, freshHandle, grantAdmin, migrateTestDb, openDb, resetIdentity, skip } from './testsupport.ts'
import { after, before, beforeEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import type postgres from 'postgres'
import { uuidv7 } from './ids.ts'
import {
  PLATFORM_ROLES,
  PRIVILEGED_ROLES,
  UnknownPlatformRoleError,
  UserNotFoundError,
  listGrantsFor,
  setPlatformRoles,
} from './platformRoles.ts'
import type { Db } from './outbox.ts'

let sql: postgres.Sql
let db: Db

before(async () => {
  if (!enabled) return
  sql = openDb(8)
  await migrateTestDb(sql)
  db = sql as unknown as Db
})

after(async () => {
  if (enabled) await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (enabled) await resetIdentity(sql)
})

/**
 * A user row, written directly.
 *
 * Deliberately not `registerUser`: these tests are about what the DATABASE permits, and going
 * through the service to set up a database test would make the setup share a code path with the
 * thing under test.
 */
async function makeUser(prefix = 'op'): Promise<{ id: string; email: string }> {
  const id = uuidv7()
  const email = freshEmail(prefix)
  const handle = freshHandle(prefix)
  await sql`
    insert into users (id, email, handle, handle_key, password_hash, hash_algo, roles)
    values (${id}, ${email}, ${handle}, ${handle.toLowerCase()}, 'not-a-hash', 'test', ${['player']})
  `
  return { id, email }
}

/** The SQLSTATE of a failure, or `null` if the statement unexpectedly succeeded. */
async function sqlstateOf(run: () => Promise<unknown>): Promise<string | null> {
  try {
    await run()
    return null
  } catch (err) {
    return (err as { code?: string }).code ?? `not a postgres error: ${String(err)}`
  }
}

/* ------------------------------------------------------------------ the bootstrap is one-shot */

test('THE BOOTSTRAP: the grant and the promotion in one transaction, and it works', { skip }, async () => {
  const operator = await makeUser()

  await sql.begin(async (tx) => {
    await tx`
      insert into platform_role_grants (user_id, role, source, actor, reason)
      values (${operator.id}, 'admin', 'bootstrap', 'estate-bootstrap.sh',
              'first operator of this environment; no approval queue can exist before one')
    `
    await tx`update users set roles = array['player','admin'] where email = ${operator.email}`
  })

  const rows = await sql<{ roles: string[] }[]>`select roles from users where id = ${operator.id}`
  assert.deepEqual(rows[0]?.roles, ['player', 'admin'], 'the estate has its first administrator')

  const grants = await listGrantsFor(db, operator.id)
  assert.equal(grants.length, 1)
  assert.equal(grants[0]?.source, 'bootstrap')
  assert.equal(grants[0]?.approval_id, null, 'nothing approved the first one, and nothing could')
})

test('A SECOND BOOTSTRAP IS REFUSED AT THE INDEX — from a raw connection, for a different user', { skip }, async () => {
  // THE security property. Broken by dropping platform_role_grants_one_bootstrap: this test then
  // passes the second bootstrap and returns null, which is what red looks like here.
  const first = await makeUser('first')
  const second = await makeUser('second')

  await sql.begin(async (tx) => {
    await tx`
      insert into platform_role_grants (user_id, role, source, actor, reason)
      values (${first.id}, 'admin', 'bootstrap', 'estate-bootstrap.sh', 'the first operator')
    `
    await tx`update users set roles = array['player','admin'] where id = ${first.id}`
  })

  const code = await sqlstateOf(() =>
    sql.begin(async (tx) => {
      await tx`
        insert into platform_role_grants (user_id, role, source, actor, reason)
        values (${second.id}, 'admin', 'bootstrap', 'estate-bootstrap.sh', 'a second first operator')
      `
      await tx`update users set roles = array['player','admin'] where id = ${second.id}`
    }),
  )
  assert.equal(code, '23505', 'the partial unique index, not a handler, is what refuses this')

  const rows = await sql<{ roles: string[] }[]>`select roles from users where id = ${second.id}`
  assert.deepEqual(rows[0]?.roles, ['player'], 'and the whole transaction rolled back')
})

test('the one-shot cannot be re-armed: the grant table refuses DELETE and UPDATE', { skip }, async () => {
  // Without the append-only trigger the index above is worth nothing — `delete from
  // platform_role_grants where source = 'bootstrap'` and the lever is back. Broken by dropping
  // platform_role_grants_immutable: both codes below come back null.
  const operator = await makeUser()
  await sql`
    insert into platform_role_grants (user_id, role, source, actor, reason)
    values (${operator.id}, 'admin', 'bootstrap', 'estate-bootstrap.sh', 'the first operator')
  `

  assert.equal(
    await sqlstateOf(() => sql`delete from platform_role_grants where source = 'bootstrap'`),
    '23514',
    'deleting the bootstrap row would re-arm the one-shot',
  )
  assert.equal(
    await sqlstateOf(() => sql`update platform_role_grants set source = 'approval'`),
    '23514',
    'and rewriting it would launder an unapproved grant into an approved one',
  )

  const rows = await sql<{ n: number }[]>`
    select count(*)::int as n from platform_role_grants where source = 'bootstrap'
  `
  assert.equal(rows[0]?.n, 1, 'the row is still there')
})

/* ------------------------------------------------- an unapproved escalation is refused */

test('THE MANUAL UPDATE, character for character, is refused', { skip }, async () => {
  // deploy/scripts/estate-bootstrap.sh:102. Broken by dropping users_roles_need_a_grant: this
  // statement then succeeds and the assertion on `roles` below fails.
  const operator = await makeUser()

  const code = await sqlstateOf(
    () => sql`update users set roles = array['admin'] where email = ${operator.email}`,
  )
  assert.equal(code, '23514', 'no grant row, no role — decided by the database')

  const rows = await sql<{ roles: string[] }[]>`select roles from users where id = ${operator.id}`
  assert.deepEqual(rows[0]?.roles, ['player'], 'and nothing was written')
})

test('the refusal lands at COMMIT, so no ordering inside the transaction escapes it', { skip }, async () => {
  // The DEFERRED half. The update genuinely succeeds as a statement — asserted inside the
  // transaction — and the transaction still cannot commit. Broken by making the trigger a plain
  // (non-deferred) AFTER trigger: the statement then fails in place, `observed` is never read, and
  // the test fails at the assertion rather than at the commit.
  const operator = await makeUser()
  let observed: string[] | undefined

  const code = await sqlstateOf(() =>
    sql.begin(async (tx) => {
      await tx`update users set roles = array['admin'] where id = ${operator.id}`
      const seen = await tx<{ roles: string[] }[]>`select roles from users where id = ${operator.id}`
      observed = seen[0]?.roles
    }),
  )

  assert.deepEqual(observed, ['admin'], 'the statement itself was allowed — the check is deferred')
  assert.equal(code, '23514', 'and COMMIT is where it is refused')
  const rows = await sql<{ roles: string[] }[]>`select roles from users where id = ${operator.id}`
  assert.deepEqual(rows[0]?.roles, ['player'])
})

test('either order inside one transaction is accepted — the promotion may precede its grant', { skip }, async () => {
  // The other side of DEFERRED, and the reason it is not merely a stricter check: a caller that
  // updates first and audits second must still be able to commit, or the constraint would dictate
  // statement order to every future writer.
  const operator = await makeUser()

  await sql.begin(async (tx) => {
    await tx`update users set roles = array['player','admin'] where id = ${operator.id}`
    await tx`
      insert into platform_role_grants (user_id, role, source, approval_id, actor, reason)
      values (${operator.id}, 'admin', 'approval', ${randomUUID()}, 'admin-api', 'four eyes said so')
    `
  })

  const rows = await sql<{ roles: string[] }[]>`select roles from users where id = ${operator.id}`
  assert.deepEqual(rows[0]?.roles, ['player', 'admin'])
})

test('a grant from an EARLIER transaction authorises nothing — one approval, one promotion', { skip }, async () => {
  // The hole in "some grant row exists": an administrator who is demoted could otherwise be
  // re-promoted for ever on the strength of the row that authorised the first promotion. Broken by
  // relaxing the trigger's `g.granted_at = transaction_timestamp()` to a bare existence check: the
  // re-promotion then succeeds and `code` is null.
  const operator = await makeUser()
  await grantAdmin(sql, operator.id)

  await sql`update users set roles = array['player'] where id = ${operator.id}`
  const demoted = await sql<{ roles: string[] }[]>`select roles from users where id = ${operator.id}`
  assert.deepEqual(demoted[0]?.roles, ['player'], 'losing a role never needs a grant')

  const code = await sqlstateOf(
    () => sql`update users set roles = array['player','admin'] where id = ${operator.id}`,
  )
  assert.equal(code, '23514', 'the spent approval does not authorise a second promotion')
})

test('an INSERT that arrives already privileged is refused too', { skip }, async () => {
  // The update path is the one the runbook uses, so it is the one a check written from the incident
  // would cover. A row created with the role skips it entirely unless the trigger fires on INSERT.
  const id = uuidv7()
  const email = freshEmail('born')
  const handle = freshHandle('born')
  const code = await sqlstateOf(
    () => sql`
      insert into users (id, email, handle, handle_key, password_hash, hash_algo, roles)
      values (${id}, ${email}, ${handle}, ${handle.toLowerCase()}, 'not-a-hash', 'test', ${['admin']})
    `,
  )
  assert.equal(code, '23514')
  const rows = await sql<{ n: number }[]>`select count(*)::int as n from users where id = ${id}`
  assert.equal(rows[0]?.n, 0)
})

test('an ordinary registration is untouched — the guard is on privilege, not on roles', { skip }, async () => {
  // The check that keeps the check honest. A trigger that demanded a grant for `player` would
  // spend the one-per-database bootstrap slot on somebody's sign-up, and every account after the
  // first would fail to register.
  const first = await makeUser('reg1')
  const second = await makeUser('reg2')
  const rows = await sql<{ roles: string[] }[]>`
    select roles from users where id in (${first.id}, ${second.id})
  `
  assert.equal(rows.length, 2)
  for (const row of rows) assert.deepEqual(row.roles, ['player'])
})

/* ------------------------------------------------------------------ the shape of a grant row */

test("an 'approval' grant without an approval id is refused, and a bootstrap with one is too", { skip }, async () => {
  // The pairing is an equality rather than two implications. `source='approval'` with a null id is
  // an unauthorised grant wearing the authorised source; `source='bootstrap'` with an id claims the
  // first administrator was approved by a queue that could not have existed.
  const operator = await makeUser()

  assert.equal(
    await sqlstateOf(
      () => sql`
        insert into platform_role_grants (user_id, role, source, actor, reason)
        values (${operator.id}, 'admin', 'approval', 'admin-api', 'no approval id')
      `,
    ),
    '23514',
  )
  assert.equal(
    await sqlstateOf(
      () => sql`
        insert into platform_role_grants (user_id, role, source, approval_id, actor, reason)
        values (${operator.id}, 'admin', 'bootstrap', ${randomUUID()}, 'x', 'approved bootstrap')
      `,
    ),
    '23514',
  )
  assert.equal(
    await sqlstateOf(
      () => sql`
        insert into platform_role_grants (user_id, role, source, actor, reason)
        values (${operator.id}, 'admin', 'self-service', 'x', 'a third source')
      `,
    ),
    '23514',
    'the source vocabulary is closed',
  )
  assert.equal(
    await sqlstateOf(
      () => sql`
        insert into platform_role_grants (user_id, role, source, approval_id, actor, reason)
        values (${operator.id}, 'admin', 'approval', ${randomUUID()}, 'admin-api', '   ')
      `,
    ),
    '23514',
    'a blank reason is not a reason',
  )
})

test('the privileged set the trigger enforces is the set the table admits and the module names', { skip }, async () => {
  // Three copies of one list — the CHECK constraint, the trigger's `privileged` array and
  // PRIVILEGED_ROLES — and the two that can be reached from here are compared. A trigger guarding
  // a role the table refuses to record would make that role ungrantable rather than guarded.
  const operator = await makeUser()
  for (const role of PRIVILEGED_ROLES) {
    assert.equal(
      await sqlstateOf(() => sql`update users set roles = ${[role]} where id = ${operator.id}`),
      '23514',
      `${role} is privileged, so it needs a grant`,
    )
  }
  for (const role of PLATFORM_ROLES.filter((r) => !PRIVILEGED_ROLES.includes(r))) {
    await sql`update users set roles = ${[role]} where id = ${operator.id}`
  }
  assert.equal(
    await sqlstateOf(
      () => sql`
        insert into platform_role_grants (user_id, role, source, approval_id, actor, reason)
        values (${operator.id}, 'player', 'approval', ${randomUUID()}, 'x', 'a grant for player')
      `,
    ),
    '23514',
    'and an unprivileged role is not recordable as a grant',
  )
})

/* ------------------------------------------------------------------ the approval route's write */

test('setPlatformRoles writes source=approval with the approval id, in one transaction', { skip }, async () => {
  const operator = await makeUser()
  const approvalId = randomUUID()

  const change = await setPlatformRoles(db, {
    userId: operator.id,
    roles: ['player', 'admin'],
    actor: 'operator:ada',
    reason: 'on call for the September rotation',
    approvalId,
    correlationId: 'req-1',
  })
  assert.deepEqual(change.granted, ['admin'])
  assert.deepEqual(change.revoked, [])
  assert.deepEqual(change.roles, ['admin', 'player'])

  const grants = await listGrantsFor(db, operator.id)
  assert.equal(grants.length, 1)
  assert.equal(grants[0]?.source, 'approval')
  assert.equal(grants[0]?.approval_id, approvalId, 'two operators signed for this one')
  assert.equal(grants[0]?.actor, 'operator:ada')

  // The bus, in the same transaction as both. admin-api's operator log is fed by the bus, so a
  // promotion that never reaches a topic is one the estate audit of record cannot show.
  const events = await sql<{ topic: string; key: string; actor: string; payload: Record<string, unknown> }[]>`
    select topic, key, actor, payload from outbox
  `
  assert.equal(events.length, 1)
  assert.equal(events[0]?.topic, 'identity.role.changed')
  assert.equal(events[0]?.key, operator.id, 'keyed by the person whose authority changed')
  assert.equal(events[0]?.actor, 'operator:ada')
  assert.deepEqual(events[0]?.payload['granted'], ['admin'])
  assert.equal(events[0]?.payload['approvalId'], approvalId)
})

test('a second administrator is ordinary — capping admins at one would break four eyes', { skip }, async () => {
  // The distinction the whole design turns on. One BOOTSTRAPPED administrator per estate, for ever;
  // any number of approved ones, because an approval queue that needs two operators cannot work in
  // an estate that can only ever have one.
  const first = await makeUser('first')
  const second = await makeUser('second')

  await sql.begin(async (tx) => {
    await tx`
      insert into platform_role_grants (user_id, role, source, actor, reason)
      values (${first.id}, 'admin', 'bootstrap', 'estate-bootstrap.sh', 'the first operator')
    `
    await tx`update users set roles = array['player','admin'] where id = ${first.id}`
  })
  await setPlatformRoles(db, {
    userId: second.id,
    roles: ['player', 'admin'],
    actor: 'operator:ada',
    reason: 'the second pair of eyes',
    approvalId: randomUUID(),
  })

  const admins = await sql<{ n: number }[]>`
    select count(*)::int as n from users where 'admin' = any (roles)
  `
  assert.equal(admins[0]?.n, 2)
  const bootstrapped = await sql<{ n: number }[]>`
    select count(*)::int as n from platform_role_grants where source = 'bootstrap'
  `
  assert.equal(bootstrapped[0]?.n, 1, 'exactly one of them answers to nothing')
})

test('withdrawing a role writes no grant and emits the loss', { skip }, async () => {
  const operator = await makeUser()
  await grantAdmin(sql, operator.id)
  await sql`delete from outbox`

  const change = await setPlatformRoles(db, {
    userId: operator.id,
    roles: ['player'],
    actor: 'operator:ada',
    reason: 'left the on-call rotation',
    approvalId: randomUUID(),
  })
  assert.deepEqual(change.revoked, ['admin'])
  assert.deepEqual(change.granted, [])
  assert.equal((await listGrantsFor(db, operator.id)).length, 1, 'no grant row for a withdrawal')

  const events = await sql<{ payload: Record<string, unknown> }[]>`select payload from outbox`
  assert.deepEqual(events[0]?.payload['revoked'], ['admin'])
})

test('an unknown role is refused before anything is written, and an unknown user is a 404', { skip }, async () => {
  const operator = await makeUser()
  await assert.rejects(
    () =>
      setPlatformRoles(db, {
        userId: operator.id,
        roles: ['player', 'superuser'],
        actor: 'operator:ada',
        reason: 'nice try',
        approvalId: randomUUID(),
      }),
    UnknownPlatformRoleError,
  )
  const rows = await sql<{ roles: string[] }[]>`select roles from users where id = ${operator.id}`
  assert.deepEqual(rows[0]?.roles, ['player'])

  await assert.rejects(
    () =>
      setPlatformRoles(db, {
        userId: uuidv7(),
        roles: ['admin'],
        actor: 'operator:ada',
        reason: 'nobody',
        approvalId: randomUUID(),
      }),
    UserNotFoundError,
  )
})

test('the suite is running against a database rather than passing vacuously', { skip }, async () => {
  // Every assertion above is a SQLSTATE from a real server. If the trigger were absent the codes
  // would be nulls, so this only guards against the checks never running at all.
  assert.equal(enabled, true)
  const rows = await sql<{ tgname: string }[]>`
    select tgname from pg_trigger
     where tgname in ('users_roles_need_a_grant', 'platform_role_grants_immutable')
     order by tgname
  `
  assert.deepEqual(
    rows.map((row) => row.tgname),
    ['platform_role_grants_immutable', 'users_roles_need_a_grant'],
  )
  const index = await sql<{ indexname: string }[]>`
    select indexname from pg_indexes where indexname = 'platform_role_grants_one_bootstrap'
  `
  assert.equal(index.length, 1)
  assert.ok(GOOD_PASSWORD.length > 0)
})
