/**
 * **The ten-minute cliff, and the proof that it is over.**
 *
 * THE DEFECT THIS FILE EXISTS FOR. Service tokens expire in ten minutes. Consuming services read
 * theirs from an environment variable at boot and nothing re-minted it, because nothing COULD:
 * `POST /service-tokens` requires the `admin` role, so the only issuer in the estate was a human.
 * The estate therefore worked perfectly for the first ten minutes of any deployment and then every
 * service-to-service call on the money tier began failing with expired credentials.
 *
 * WHY NO EXISTING SUITE CAUGHT IT, which is the part worth internalising. Every service's tests
 * mint a fresh token as they start and finish well inside ten minutes, so a token is never asked to
 * survive its own lifetime. **A test that mints a token and immediately uses it proves nothing
 * about this defect** — that is precisely the shape that let it through two reviews and twenty-one
 * suites. The test below is deliberately the other shape: it drives the clock PAST the expiry of a
 * token it already holds, asserts that the token it holds is now dead, and only then asserts that
 * the service can still obtain a working one.
 *
 * A SIMULATED CLOCK, NOT A WAIT. `mock.timers` moves `Date` only — jose reads `Date.now()` to
 * decide expiry, so an eleven-minute jump is indistinguishable to it from eleven real minutes, and
 * the suite still runs in milliseconds. `setTimeout` is deliberately NOT mocked: postgres.js drives
 * its socket timeouts from it, and freezing those would hang the connection rather than test it.
 */

import {
  enabled,
  migrateTestDb,
  openDb,
  resetIdentity,
  skip,
} from './testsupport.ts'
import { before, after, beforeEach, mock, test } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import { SERVICE_TTL_SECONDS, verifyToken } from './tokens.ts'
import {
  InvalidCredentialError,
  UnconfiguredServiceError,
  createServiceCredential,
  exchangeServiceCredential,
  listServiceCredentials,
  revokeServiceCredential,
} from './serviceCredentials.ts'
import { listServiceTokenIssues } from './serviceTokens.ts'
import type { Db } from './outbox.ts'

let sql: postgres.Sql
let db: Db

/** `settlement` is in the suite's `IDENTITY_SERVICE_TOKEN_GRANTS` — see testsupport.ts. */
const SERVICE = 'settlement'
const GRANTED = ['custody:sign:deposit', 'ledger:post', 'ledger:read']

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

/** Every test that moves the clock must put it back, or the next test inherits the future. */
function withClockAdvancedBy<T>(ms: number, body: () => Promise<T>): Promise<T> {
  mock.timers.enable({ apis: ['Date'], now: new Date(Date.now() + ms) })
  return body().finally(() => mock.timers.reset())
}

const mint = (secret: string) =>
  exchangeServiceCredential(db, { secret, correlationId: 'test-correlation' })

/* ────────────────────────────────────────────────────────────────────────────────────────────────
 * THE REGRESSION TEST FOR THE CLIFF.
 *
 * This is the test that would have caught it. Before the credential exchange existed it could not
 * even be written: there was no call a service could make to obtain a second token, so the final
 * assertion had no subject.
 * ──────────────────────────────────────────────────────────────────────────────────────────────── */

test(
  'a service can still mint AFTER the token it booted with has expired — the ten-minute cliff',
  { skip },
  async () => {
    const credential = await createServiceCredential(db, {
      service: SERVICE,
      label: 'the boot credential',
      createdBy: null,
    })

    // T+0. This is the token a container would have been handed at boot.
    const atBoot = await mint(credential.secret)
    assert.equal(atBoot.service, SERVICE)
    assert.equal((await verifyToken(db, atBoot.token)).ok, true, 'the boot token works at T+0')

    // T+11min — past SERVICE_TTL_SECONDS, and the moment the estate used to fall over.
    await withClockAdvancedBy((SERVICE_TTL_SECONDS + 60) * 1000, async () => {
      // FIRST: the cliff itself, reproduced. If this ever stops being 'expired' then the TTL has
      // been lengthened and the security property SD-05 bought has been traded away — which is the
      // wrong fix for this defect and must fail here rather than pass quietly.
      const stale = await verifyToken(db, atBoot.token)
      assert.equal(stale.ok, false, 'the boot token MUST be dead by now')
      assert.equal(stale.ok === false && stale.reason, 'expired')

      // SECOND: the fix. The credential is not a token and did not expire with it, so the service
      // mints a live replacement for itself — no operator, no restart, no redeploy.
      const afterTheCliff = await mint(credential.secret)
      const fresh = await verifyToken(db, afterTheCliff.token)
      assert.equal(fresh.ok, true, 'a service must be able to obtain a token past the first expiry')
      assert.equal(fresh.ok === true && fresh.claims.sub, `service:${SERVICE}`)
      assert.notEqual(afterTheCliff.token, atBoot.token, 'a genuinely new token, not the old one')
    })
  },
)

test('the TTL is unchanged: a minted token really does die in ten minutes', { skip }, async () => {
  // Guards the repair against its own worst temptation. The cheap way to make the cliff go away is
  // to raise SERVICE_TTL_SECONDS, so the constant is asserted rather than assumed.
  assert.equal(SERVICE_TTL_SECONDS, 10 * 60)

  const credential = await createServiceCredential(db, {
    service: SERVICE,
    label: 'ttl',
    createdBy: null,
  })
  const issued = await mint(credential.secret)
  assert.equal(issued.expiresInSeconds, SERVICE_TTL_SECONDS)

  // One second before expiry it is alive; one minute after, it is not.
  await withClockAdvancedBy((SERVICE_TTL_SECONDS - 1) * 1000, async () => {
    assert.equal((await verifyToken(db, issued.token)).ok, true, 'alive at T+599s')
  })
  await withClockAdvancedBy((SERVICE_TTL_SECONDS + 60) * 1000, async () => {
    assert.equal((await verifyToken(db, issued.token)).ok, false, 'dead at T+660s')
  })
})

test('two replicas exchanging the same credential both get working tokens', { skip }, async () => {
  // N replicas boot from ONE credential and each needs its own live token. A single-use exchange
  // with reuse detection — the shape rotateRefreshToken uses for browser tabs — would read the
  // second replica's perfectly legitimate startup as a replay and burn the credential. Nothing may
  // be consumed here, so replicas never contend and no lease is needed.
  const credential = await createServiceCredential(db, {
    service: SERVICE,
    label: 'shared by replicas',
    createdBy: null,
  })

  const [a, b] = await Promise.all([mint(credential.secret), mint(credential.secret)])
  assert.notEqual(a.jti, b.jti, 'each replica gets its own credential, not a shared one')
  assert.equal((await verifyToken(db, a.token)).ok, true)
  assert.equal((await verifyToken(db, b.token)).ok, true, 'the second replica must not be burned')

  // And the credential is still usable afterwards — a third replica, or a restart, still works.
  assert.equal((await verifyToken(db, (await mint(credential.secret)).token)).ok, true)
})

test('the service minted for comes from the row, never from the request', { skip }, async () => {
  // The containment property. If a caller could name its own service, holding any credential in the
  // estate would mint for `settlement` and hand the least-privileged service the treasury scopes.
  // `exchangeServiceCredential` takes no service argument at all; this asserts the consequence.
  const credential = await createServiceCredential(db, {
    service: SERVICE,
    label: 'scoped',
    createdBy: null,
  })
  const issued = await mint(credential.secret)
  assert.equal(issued.service, SERVICE)

  // And it cannot reach outside its own allowlist even by asking politely.
  await assert.rejects(
    exchangeServiceCredential(db, {
      secret: credential.secret,
      scopes: ['custody:sign:treasury'],
      correlationId: 'test-correlation',
    }),
    /may not be issued/,
  )
})

test('omitting scopes yields exactly the allowlist, and no wildcard exists', { skip }, async () => {
  const credential = await createServiceCredential(db, {
    service: SERVICE,
    label: 'default scopes',
    createdBy: null,
  })
  const issued = await mint(credential.secret)
  assert.deepEqual([...issued.scopes].sort(), [...GRANTED].sort())
})

test('a requested lifetime may shorten but can never lengthen', { skip }, async () => {
  const credential = await createServiceCredential(db, {
    service: SERVICE,
    label: 'ttl bounds',
    createdBy: null,
  })

  const short = await exchangeServiceCredential(db, {
    secret: credential.secret,
    ttlSeconds: 30,
    correlationId: 'test-correlation',
  })
  assert.equal(short.expiresInSeconds, 30)
  await withClockAdvancedBy(45_000, async () => {
    assert.equal((await verifyToken(db, short.token)).ok, false, 'a 30s token dies in 30s')
  })

  // THE ONE THAT MATTERS. A caller asking for a day gets ten minutes.
  const greedy = await exchangeServiceCredential(db, {
    secret: credential.secret,
    ttlSeconds: 86_400,
    correlationId: 'test-correlation',
  })
  assert.equal(greedy.expiresInSeconds, SERVICE_TTL_SECONDS)
  await withClockAdvancedBy((SERVICE_TTL_SECONDS + 60) * 1000, async () => {
    assert.equal((await verifyToken(db, greedy.token)).ok, false, 'the ceiling is not negotiable')
  })
})

test('a revoked credential mints nothing, and revocation is idempotent', { skip }, async () => {
  const credential = await createServiceCredential(db, {
    service: SERVICE,
    label: 'to be revoked',
    createdBy: null,
  })
  const before = await mint(credential.secret)

  assert.equal(await revokeServiceCredential(db, credential.id), true)
  await assert.rejects(mint(credential.secret), InvalidCredentialError)

  // Tokens already minted stay valid until they expire. That is the ten minutes doing its job: the
  // upper bound on a compromised service's remaining access is one token lifetime.
  assert.equal((await verifyToken(db, before.token)).ok, true)
  await withClockAdvancedBy((SERVICE_TTL_SECONDS + 60) * 1000, async () => {
    assert.equal((await verifyToken(db, before.token)).ok, false, 'contained within one lifetime')
  })

  // Idempotent, and the FIRST timestamp survives — an incident asks when containment began.
  const [firstRevocation] = await listServiceCredentials(db)
  assert.equal(await revokeServiceCredential(db, credential.id), true)
  const [second] = await listServiceCredentials(db)
  assert.equal(second?.revokedAt, firstRevocation?.revokedAt)
})

test('an unknown credential is refused, and looks identical to a revoked one', { skip }, async () => {
  await assert.rejects(mint('cfsc_not-a-real-credential'), InvalidCredentialError)

  const credential = await createServiceCredential(db, {
    service: SERVICE,
    label: 'oracle check',
    createdBy: null,
  })
  await revokeServiceCredential(db, credential.id)

  // Same error type and same message for both. Telling a caller "that one exists but is revoked"
  // confirms a valid secret to whoever stole it.
  const unknown = await mint('cfsc_still-not-real').catch((err: Error) => err.message)
  const revoked = await mint(credential.secret).catch((err: Error) => err.message)
  assert.equal(unknown, revoked)
})

test('a credential for a service with no grants cannot be created at all', { skip }, async () => {
  // Fail-closed. A credential that could never mint is a secret an operator holds believing it
  // works, and it would fail at the worst possible moment instead of at creation.
  await assert.rejects(
    createServiceCredential(db, { service: 'not-a-service', label: 'x', createdBy: null }),
    /no scopes are configured/,
  )
})

test('and the refusal is typed, so the route can answer 400 rather than 500', { skip }, async () => {
  /*
   * The refusal above was a bare `Error`. A bare `Error` has no arm in `src/server.ts`'s mapper,
   * so it fell through to the last line — 500 `internal`, "the request could not be completed".
   * An operator who mistyped a service name was told identity was faulty, and those two readings
   * lead to opposite next actions: one waits and retries, the other fixes the name.
   *
   * `estate-bootstrap.sh` mints a credential per service by label, so this is not hypothetical:
   * a service renamed upstream arrives here in the middle of a deploy.
   *
   * The class is asserted rather than only the message, because the message is what was already
   * being matched above and it never distinguished the two — the type is the part the mapper
   * branches on, and the part a rename cannot silently undo.
   */
  const err = await createServiceCredential(db, {
    service: 'not-a-service',
    label: 'x',
    createdBy: null,
  }).then(
    () => null,
    (e: unknown) => e,
  )
  assert.ok(err instanceof UnconfiguredServiceError, `threw ${String(err)}`)
  // The name the caller actually typed, carried on the error rather than only inside a sentence,
  // so anything mapping this has the value without parsing prose.
  assert.equal(err.service, 'not-a-service')
  assert.match(err.message, /not-a-service/)
})

test('a service that IS configured is not caught by that refusal', { skip }, async () => {
  // The guard above is only worth anything if it can also let something through — a check that
  // refuses everything is indistinguishable from a check that is wired to the wrong flag.
  const ok = await createServiceCredential(db, {
    service: SERVICE,
    label: 'the negative half',
    createdBy: null,
  })
  assert.equal(ok.service, SERVICE)
})

test('every machine issuance is in the ledger and names its credential', { skip }, async () => {
  // SD-05's first question is "which service was granted what, by whom, and when". Now that a
  // machine can mint, "by whom" has a second shape, and it must still be answerable.
  const credential = await createServiceCredential(db, {
    service: SERVICE,
    label: 'audited',
    createdBy: null,
  })
  const issued = await mint(credential.secret)

  const issues = await listServiceTokenIssues(db)
  const row = issues.find((i) => i.jti === issued.jti)
  assert.ok(row, 'the issuance is in the ledger')
  assert.equal(row.service, SERVICE)
  assert.equal(row.issuedBy, null, 'no operator asked for this one')

  const [link] = await sql<{ issued_by_credential: string | null }[]>`
    select issued_by_credential from service_token_issues where jti = ${issued.jti}
  `
  assert.equal(link?.issued_by_credential, credential.id, 'the ledger names the credential')

  // And the secret itself is nowhere in the database — only its digest was ever stored.
  const rows = await sql<{ n: string }[]>`
    select count(*)::text as n from service_credentials where secret_hash = ${credential.secret}
  `
  assert.equal(rows[0]?.n, '0', 'the raw secret is not stored')
})

test('using a credential records when it was last used', { skip }, async () => {
  // A credential unused since a deploy is either a service that is down or one that never adopted
  // the provider. Both are things an operator should see without reading logs.
  const credential = await createServiceCredential(db, {
    service: SERVICE,
    label: 'liveness',
    createdBy: null,
  })
  assert.equal((await listServiceCredentials(db))[0]?.lastUsedAt, null)
  await mint(credential.secret)
  assert.notEqual((await listServiceCredentials(db))[0]?.lastUsedAt, null)
})
