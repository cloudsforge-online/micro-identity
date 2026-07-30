/**
 * The signing key: bootstrap, publication order and the rotation state machine.
 *
 * SD-14 names the split-brain defect this file is written against: on a fresh database two replicas
 * each generated a keypair with a different random `kid`, both inserted, and an unordered
 * `select ... limit 1` made the JWKS nondeterministic across replicas — a consumer cached one key
 * and rejected every token minted by the other.
 */

import { enabled, migrateTestDb, openDb, resetIdentity, skip } from './testsupport.ts'
import { before, after, beforeEach, test } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import {
  PUBLISH_BEFORE_ACTIVE_MS,
  activateSigningKey,
  forgetSigningKeys,
  getJwks,
  getSigningKey,
  listSigningKeys,
  mintSigningKey,
  retireSigningKey,
} from './keys.ts'
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

test('an empty database bootstraps exactly one active key', { skip }, async () => {
  const key = await getSigningKey(db)
  assert.match(key.kid, /^[0-9a-f]{16}$/)
  assert.equal(key.publicJwk.alg, 'RS256')
  assert.equal(key.publicJwk.use, 'sig')
  assert.equal(key.publicJwk.kid, key.kid)
  // The public JWK is public and must carry no private material. `d` is the RSA private exponent;
  // if it were here, `/.well-known/jwks.json` would publish the estate's forging credential.
  for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
    assert.equal((key.publicJwk as unknown as Record<string, unknown>)[secret], undefined, `${secret} leaked`)
  }
  const keys = await listSigningKeys(db)
  assert.equal(keys.length, 1)
  assert.equal(keys[0]!.status, 'active')
})

/**
 * **The SD-14 test.**
 *
 * Two bootstraps racing on an empty database, each on its own connection so they are genuinely
 * concurrent rather than serialised by a shared one. The advisory lock in `getSigningKey` is what
 * makes the second one find the first one's key instead of minting a second.
 *
 * The in-process cache is cleared before each half so both actually reach the database — otherwise
 * this would pass by memoisation and prove nothing.
 */
test('two concurrent bootstraps on an empty database produce ONE key', { skip }, async () => {
  forgetSigningKeys()
  const [first, second] = await Promise.all([
    (async () => {
      forgetSigningKeys()
      return getSigningKey(db)
    })(),
    (async () => {
      forgetSigningKeys()
      return getSigningKey(db)
    })(),
  ])

  const rows = await sql<{ kid: string }[]>`select kid from signing_keys`
  assert.equal(rows.length, 1, 'two active keys is the split-brain defect itself')
  assert.equal(first.kid, second.kid)
})

test('JWKS is deterministically ordered across two concurrent bootstraps', { skip }, async () => {
  // Both documents are fetched concurrently on a database that has no key yet, so each call may be
  // the one that bootstraps. Whichever wins, the two documents must be byte-identical: consumers
  // cache this by comparing what they fetched with what they held, and a set that shuffles makes
  // that comparison meaningless.
  forgetSigningKeys()
  const [a, b] = await Promise.all([
    (async () => {
      forgetSigningKeys()
      return getJwks(db)
    })(),
    (async () => {
      forgetSigningKeys()
      return getJwks(db)
    })(),
  ])
  assert.equal(JSON.stringify(a), JSON.stringify(b))
  assert.equal(a.keys.length, 1)
})

test('JWKS publishes every non-retired key, ordered by (created_at, kid)', { skip }, async () => {
  await getSigningKey(db)
  const second = await mintSigningKey(db)
  const third = await mintSigningKey(db)
  forgetSigningKeys()

  const document = await getJwks(db)
  assert.equal(document.keys.length, 3, 'a published key must be fetchable before it signs')

  const expected = await sql<{ kid: string }[]>`
    select kid from signing_keys where status <> 'retired' order by created_at, kid
  `
  assert.deepEqual(
    document.keys.map((k) => k.kid),
    expected.map((r) => r.kid),
  )

  // Repeated calls are byte-identical, and — the part Nimbus's active-first partition does not give
  // — the order does not change when the ACTIVE key changes. A document that reshuffles for a
  // reason unrelated to its membership invalidates every consumer's cache on every rotation step.
  const again = await getJwks(db)
  assert.equal(JSON.stringify(document), JSON.stringify(again))

  await sql`update signing_keys set status_changed_at = now() - ${`${PUBLISH_BEFORE_ACTIVE_MS + 1000} milliseconds`}::interval where kid = ${second.kid}`
  await activateSigningKey(db, second.kid)
  const afterActivation = await getJwks(db)
  assert.deepEqual(
    afterActivation.keys.map((k) => k.kid),
    document.keys.map((k) => k.kid),
    'activation changes which key signs, not which keys are published or in what order',
  )
  assert.ok(third.kid)
})

test('a retired key leaves the document and nothing else does', { skip }, async () => {
  const active = await getSigningKey(db)
  const spare = await mintSigningKey(db)
  forgetSigningKeys()

  const outcome = await retireSigningKey(db, spare.kid)
  assert.equal(outcome.status, 'ok')
  const document = await getJwks(db)
  assert.deepEqual(
    document.keys.map((k) => k.kid),
    [active.kid],
  )
  // Nothing deletes a row: the kid of a key that ever signed is worth keeping so an old token in a
  // log can be attributed to the key that made it.
  const all = await listSigningKeys(db)
  assert.equal(all.length, 2)
  assert.equal(all.find((k) => k.kid === spare.kid)?.published, false)
})

test('the active key cannot be retired — nothing else could sign', { skip }, async () => {
  const active = await getSigningKey(db)
  assert.equal((await retireSigningKey(db, active.kid)).status, 'is_active')
  assert.equal((await retireSigningKey(db, 'no-such-kid')).status, 'not_found')
})

/**
 * The publish window, enforced rather than written in a runbook.
 *
 * The operator rotating a key BECAUSE it leaked is exactly the operator most likely to skip the
 * wait, and activating early mints tokens under a `kid` no consumer has fetched — every service in
 * the estate then rejects every request until its JWKS cache turns over. A self-inflicted outage
 * that looks exactly like a key compromise.
 */
test('a key that has not been published long enough refuses to activate', { skip }, async () => {
  await getSigningKey(db)
  const fresh = await mintSigningKey(db)

  const tooSoon = await activateSigningKey(db, fresh.kid)
  assert.equal(tooSoon.status, 'too_soon')
  assert.ok(tooSoon.status === 'too_soon')
  assert.ok(new Date(tooSoon.activatableAt).getTime() > Date.now())
  assert.equal(fresh.activatableAt, tooSoon.activatableAt, 'the list and the refusal must agree')

  // Wind the clock back past the window and it is permitted.
  await sql`
    update signing_keys set status_changed_at = now() - ${`${PUBLISH_BEFORE_ACTIVE_MS + 1000} milliseconds`}::interval
     where kid = ${fresh.kid}
  `
  const activated = await activateSigningKey(db, fresh.kid)
  assert.equal(activated.status, 'ok')

  const keys = await listSigningKeys(db)
  assert.equal(keys.filter((k) => k.status === 'active').length, 1, 'exactly one key signs')
  assert.equal(keys.find((k) => k.kid === fresh.kid)?.status, 'active')
  // The demoted key stays PUBLISHED, so the tokens it minted in the last fifteen minutes keep
  // verifying. Retiring it in the same step is the flag day this whole machine exists to avoid.
  assert.equal(keys.filter((k) => k.status === 'published').length, 1)
})

test('activation refuses a key that is not published, and one that already signs', { skip }, async () => {
  const active = await getSigningKey(db)
  assert.equal((await activateSigningKey(db, active.kid)).status, 'is_active')
  assert.equal((await activateSigningKey(db, 'no-such-kid')).status, 'not_found')

  const spare = await mintSigningKey(db)
  await retireSigningKey(db, spare.kid)
  assert.equal((await activateSigningKey(db, spare.kid)).status, 'not_published')
})

test('the private half is sealed at rest and never selected into the document', { skip }, async () => {
  await getSigningKey(db)
  const rows = await sql<{ private_jwk_enc: string; public_jwk: Record<string, unknown> }[]>`
    select private_jwk_enc, public_jwk from signing_keys
  `
  const row = rows[0]!
  // `v1:` + base64. Anyone who can read this table gets ciphertext, which is the read-only vector
  // encryption at rest actually closes: a stolen dump, a SELECT-only injection, a copied backup.
  assert.match(row.private_jwk_enc, /^v1:[A-Za-z0-9+/]+={0,2}$/)
  assert.ok(!row.private_jwk_enc.includes('RSA'))
  assert.equal(row.public_jwk['d'], undefined)
})
