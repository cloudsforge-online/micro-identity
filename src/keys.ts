/**
 * The RS256 signing key: where it is kept, which one signs, and how one is replaced without signing
 * anybody out.
 *
 * Carried forward from Nimbus's `keys.ts`, which SD-01 records as having "no defect to fix". Two
 * things are changed and both are named below: the bootstrap takes an advisory lock, and the JWKS
 * order is `created_at, kid` with no partition (SD-14).
 *
 * AT REST the private half is AES-256-GCM under a scrypt-derived key — see keyEnvelope.ts for what
 * that does and does not buy. Nothing in this file writes the private half anywhere else and
 * nothing returns it: `SigningKey.privateKey` is a jose `KeyLike`, not bytes.
 *
 * WHICH ONE SIGNS is the single row with status `active`. Which ones VERIFY is every row that is
 * not `retired`, which is what `getJwks()` publishes. Those are different questions, and treating
 * them as one is what made rotation impossible without a flag day.
 *
 * SO A ROTATION IS THREE STEPS, none of which drops a request:
 *
 *   1. `POST /admin/signing-keys`   mints a key as `published`. It is in the JWKS immediately and
 *                                   signs nothing.
 *   2. wait one access-token TTL    every consumer's JWKS cache now has it. `activateSigningKey`
 *                                   ENFORCES this rather than trusting the operator to have counted.
 *   3. `POST .../:kid/activate`     it starts signing; the old key becomes `published`, so the
 *                                   tokens it already minted keep verifying until they expire.
 *                                   `.../:kid/retire` drops it from the document once they have.
 */

import { randomBytes } from 'node:crypto'
import { exportJWK, generateKeyPair, importJWK, type JWK, type KeyLike } from 'jose'
import type { Logger } from '@cloudsforge/telemetry'
import { open, seal } from './keyEnvelope.ts'
import type { Db, Tx } from './outbox.ts'

export type SigningKeyStatus = 'active' | 'published' | 'retired'

export interface SigningKey {
  readonly kid: string
  /** Signs access tokens. A `KeyLike`, never bytes, and never returned by a route. */
  readonly privateKey: KeyLike | Uint8Array
  /** The public JWK, with kid/alg/use, as served at the JWKS endpoint. */
  readonly publicJwk: JWK
}

/**
 * How long the active key is reused before the table is consulted again.
 *
 * Every login and every refresh signs a token, so this is a hot path and the read has to be
 * amortised. Thirty seconds is the whole cost of a rotation propagating across instances, and it is
 * safe to be that lazy for one reason: the key being activated has already been in the JWKS for an
 * access-token TTL, so a straggler still signing with the previous key for another half a minute
 * mints tokens every consumer can still verify.
 */
const CACHE_TTL_MS = 30_000

/**
 * How long a key must have been published before it may be activated.
 *
 * One access-token TTL (15m, see tokens.ts) plus a margin for consumers that cache the JWKS a
 * little longer than they should. Activating sooner mints tokens under a `kid` verifiers have not
 * fetched yet, and the symptom is every service 401ing every request until its cache turns over: a
 * self-inflicted outage that looks exactly like a key compromise.
 */
export const PUBLISH_BEFORE_ACTIVE_MS = 20 * 60_000

/**
 * How stale a verifier cache may be before an unknown `kid` forces a re-read.
 *
 * The `kid` in a token header is attacker-chosen, so a miss must not be a free database query:
 * without this floor, a stream of tokens carrying random kids is a stream of SELECTs. One second is
 * far shorter than a rotation and far longer than a burst.
 */
const VERIFIER_MISS_RELOAD_MS = 1_000

/**
 * The advisory-lock key the bootstrap serialises on.
 *
 * Any 64-bit constant would do; this one is chosen so that a
 * `select * from pg_locks where locktype = 'advisory'` during a stuck boot shows a value an operator
 * can search this repository for and find this comment.
 *
 * A `number` rather than a `bigint` because postgres.js's parameter types do not admit one, and it
 * is far inside `Number.MAX_SAFE_INTEGER`.
 */
const BOOTSTRAP_LOCK_KEY = 0x1de7_1741

let cached: { key: SigningKey; at: number } | null = null
let verifiers: { keys: Map<string, KeyLike | Uint8Array>; at: number } | null = null

/**
 * Forget the memoised active key, so the next signature re-reads the table.
 *
 * Exported because activation is not the only caller that needs it: a suite that empties
 * `signing_keys` between cases would otherwise keep signing with a row that no longer exists. It is
 * safe to call at any time — the cost is one SELECT — and it cannot be used to change WHICH key
 * signs, only to notice sooner that it changed. Instances that did not call it notice within
 * `CACHE_TTL_MS`.
 *
 * It drops the VERIFIER cache too. Those are two caches over one table and a caller who wants the
 * table re-read wants both.
 */
export function forgetSigningKeys(): void {
  cached = null
  verifiers = null
}

interface KeyRow {
  readonly kid: string
  readonly private_jwk_enc: string
  readonly public_jwk: Record<string, unknown>
}

async function toSigningKey(row: KeyRow): Promise<SigningKey> {
  const jwk = open<JWK>('signing-key', row.kid, row.private_jwk_enc)
  return {
    kid: row.kid,
    privateKey: await importJWK(jwk, 'RS256'),
    publicJwk: row.public_jwk as unknown as JWK,
  }
}

/** Generate a keypair and store it in `status`. Returns the new kid. */
async function mint(sql: Db | Tx, status: SigningKeyStatus): Promise<string> {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true })
  const kid = randomBytes(8).toString('hex')
  const privateJwk = await exportJWK(privateKey)
  const publicJwk = await exportJWK(publicKey)
  publicJwk.kid = kid
  publicJwk.alg = 'RS256'
  publicJwk.use = 'sig'

  await sql`
    insert into signing_keys (kid, private_jwk_enc, public_jwk, status)
    values (
      ${kid},
      -- Sealed before it is handed to the driver, so the plaintext never reaches a query log, a
      -- connection trace or a statement-level slow log.
      ${seal('signing-key', kid, privateJwk)},
      ${sql.json(publicJwk as unknown as Record<string, never>)},
      ${status}
    )
  `
  return kid
}

/**
 * The key that signs. Bootstraps one against an empty table.
 *
 * Cached for `CACHE_TTL_MS`.
 *
 * **THE BOOTSTRAP IS LOCKED, AND THAT IS THE SD-14 FIX.** Nimbus's version selects the active key,
 * finds none, and mints — with nothing serialising the two halves. On a fresh database two replicas
 * booting together therefore both find no active key and both insert one, each with its own random
 * `kid`, and `onConflictDoNothing()` conflicts on nothing because the primary key IS the kid. The
 * estate then has two active signing keys, and Nimbus's deterministic `ORDER BY created_at, kid`
 * limit 1 makes every replica agree on which of them signs — but it does not undo the second row.
 * Taking `pg_advisory_xact_lock` around "look, and mint if there is nothing" makes the second
 * replica wait, re-read inside the lock, and find the first replica's key.
 *
 * The double read is not redundant: the first is outside the lock and is the fast path every
 * subsequent call takes, and the second is inside it and is the one that is correct under a race.
 */
export async function getSigningKey(sql: Db): Promise<SigningKey> {
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.key

  const active = await sql<KeyRow[]>`
    select kid, private_jwk_enc, public_jwk
      from signing_keys
     where status = 'active'
     -- Oldest first, kid as the tie-break: a total order, so every instance picks the same row
     -- without coordinating, and the key that has been signing longest keeps signing rather than a
     -- boot race changing the answer.
     order by created_at, kid
     limit 1
  `
  const row = active[0]
  if (row) {
    const key = await toSigningKey(row)
    cached = { key, at: Date.now() }
    return key
  }

  // Empty table (first boot), or an operator retired everything. Either way this service cannot
  // mint a token without a key, so make one — under the lock, exactly once across every replica.
  const bootstrapped = await sql.begin(async (tx) => {
    await tx`select pg_advisory_xact_lock(${BOOTSTRAP_LOCK_KEY})`
    const inside = await tx<KeyRow[]>`
      select kid, private_jwk_enc, public_jwk
        from signing_keys
       where status = 'active'
       order by created_at, kid
       limit 1
    `
    const existing = inside[0]
    if (existing) return { row: existing }

    const kid = await mint(tx, 'active')
    const created = await tx<KeyRow[]>`
      select kid, private_jwk_enc, public_jwk from signing_keys where kid = ${kid}
    `
    return { row: created[0]! }
  })

  const key = await toSigningKey(bootstrapped.row)
  cached = { key, at: Date.now() }
  return key
}

/**
 * The JWKS document: every key that is not retired, in a deterministic order.
 *
 * NOT just the signing key. A verifier keyed by `kid` needs the public half of whatever minted the
 * token in front of it, and during a rotation that is not the key currently signing — in one
 * direction because the new key must be fetchable before it signs, and in the other because the old
 * key's tokens outlive its last signature by up to their TTL.
 *
 * **THE ORDER IS `created_at, kid` AND NOTHING ELSE (SD-14).** Nimbus sorts by the same pair and
 * then partitions the result to put the active key first. That is deterministic too, and it has a
 * property this does not want: the document REORDERS ITSELF on activation, without any key being
 * added or removed. Consumers cache this by comparing what they fetched with what they held, and a
 * set that reshuffles for a reason unrelated to its contents makes that comparison useless — the
 * cache is invalidated on every rotation step rather than on every change of membership. A total
 * order over a stable pair means the document is byte-identical across instances AND across time
 * for as long as its membership is unchanged. Nothing needs the active key first: a verifier
 * selects by `kid`, and a document is not a preference list.
 */
export async function getJwks(sql: Db): Promise<{ keys: JWK[] }> {
  const rows = await sql<{ public_jwk: Record<string, unknown> }[]>`
    select public_jwk
      from signing_keys
     where status <> 'retired'
     order by created_at, kid
  `

  if (rows.length === 0) {
    // No key has ever been generated, or every one was retired. Generating on demand keeps the
    // document consistent with what a login would mint a millisecond later, rather than publishing
    // an empty set and teaching every consumer to cache "this issuer has no keys".
    const key = await getSigningKey(sql)
    return { keys: [key.publicJwk] }
  }
  return { keys: rows.map((r) => r.public_jwk as unknown as JWK) }
}

/**
 * The public key a token signed BY THIS SERVICE should be verified against.
 *
 * Identity verifies its own tokens locally instead of fetching its own JWKS over a socket, and that
 * shortcut used to mean "verify against whatever is signing right now". That is the one thing a
 * rotation deliberately makes untrue: the moment a replacement key is activated, every token minted
 * in the previous fifteen minutes was signed by a key that is still published, still in the
 * document every other service verifies against — and would have been rejected here. The operator
 * who clicked activate is holding one of those tokens, so the symptom of a correct rotation was the
 * console 401ing at the admin who performed it while every other service went on accepting the same
 * token happily.
 *
 * NOT a weakening: the set is exactly the non-retired keys. Retiring a key still ends it here, in
 * the same breath as it leaves the JWKS.
 */
export async function getVerificationKey(sql: Db, kid: string | undefined): Promise<KeyLike | Uint8Array> {
  if (!verifiers || Date.now() - verifiers.at >= CACHE_TTL_MS) {
    verifiers = await loadVerifiers(sql)
  }
  if (kid) {
    const hit = verifiers.keys.get(kid)
    if (hit) return hit
    // A kid this process has not seen. Either another instance minted a key seconds ago, or the
    // header is forged — and only the first deserves a query, so the re-read is floored.
    if (Date.now() - verifiers.at >= VERIFIER_MISS_RELOAD_MS) {
      verifiers = await loadVerifiers(sql)
      const retry = verifiers.keys.get(kid)
      if (retry) return retry
    }
  }
  // No kid, or one nothing published. Hand back the active key so the answer is a signature failure
  // — which is the caller's doing and a 401 — rather than an error, which would read as this
  // service being unavailable and answer 503.
  return importJWK((await getSigningKey(sql)).publicJwk as JWK, 'RS256')
}

async function loadVerifiers(sql: Db): Promise<{ keys: Map<string, KeyLike | Uint8Array>; at: number }> {
  const { keys } = await getJwks(sql)
  const map = new Map<string, KeyLike | Uint8Array>()
  for (const jwk of keys) {
    if (!jwk.kid) continue
    map.set(jwk.kid, await importJWK(jwk, 'RS256'))
  }
  return { keys: map, at: Date.now() }
}

/* ------------------------------------------------------------------------ rotation */

export interface SigningKeyRecord {
  readonly kid: string
  readonly status: SigningKeyStatus
  readonly createdAt: string
  readonly statusChangedAt: string
  /** True while this key is in the JWKS. */
  readonly published: boolean
  /** When it may be activated. Null unless it is waiting out the publish window. */
  readonly activatableAt: string | null
}

interface RecordRow {
  readonly kid: string
  readonly status: SigningKeyStatus
  readonly created_at: Date
  readonly status_changed_at: Date
}

const toRecord = (row: RecordRow): SigningKeyRecord => ({
  kid: row.kid,
  status: row.status,
  createdAt: row.created_at.toISOString(),
  statusChangedAt: row.status_changed_at.toISOString(),
  published: row.status !== 'retired',
  activatableAt:
    row.status === 'published'
      ? new Date(row.status_changed_at.getTime() + PUBLISH_BEFORE_ACTIVE_MS).toISOString()
      : null,
})

/** Every signing key, public metadata only. The private half is not selected. */
export async function listSigningKeys(sql: Db): Promise<SigningKeyRecord[]> {
  const rows = await sql<RecordRow[]>`
    select kid, status, created_at, status_changed_at from signing_keys order by created_at, kid
  `
  return rows.map(toRecord)
}

/** Mint a replacement key. Published immediately; signs nothing yet. */
export async function mintSigningKey(sql: Db): Promise<SigningKeyRecord> {
  const kid = await mint(sql, 'published')
  const rows = await sql<RecordRow[]>`
    select kid, status, created_at, status_changed_at from signing_keys where kid = ${kid}
  `
  return toRecord(rows[0]!)
}

export type KeyTransition =
  | { readonly status: 'ok'; readonly keys: SigningKeyRecord[] }
  | { readonly status: 'not_found' }
  | { readonly status: 'is_active' }
  | { readonly status: 'not_published' }
  | { readonly status: 'too_soon'; readonly activatableAt: string }

/**
 * Make a published key the signing key. The current signer becomes `published`.
 *
 * REFUSES a key that has not been published for `PUBLISH_BEFORE_ACTIVE_MS`, and that refusal is the
 * point of the design rather than an inconvenience to route around: activating early mints tokens
 * under a `kid` no consumer has fetched, and every service in the estate then rejects every request
 * until its JWKS cache turns over. The operator rotating a key BECAUSE it leaked is exactly the
 * operator most likely to skip the wait, so the wait is enforced here instead of written in a
 * runbook. The way to end a leaked key sooner is to activate the replacement and then retire the
 * old one, which costs only the tokens it has already minted — at most fifteen minutes of them.
 */
export async function activateSigningKey(sql: Db, kid: string): Promise<KeyTransition> {
  const outcome = await sql.begin(async (tx) => {
    // Serialised against a concurrent activation and against the bootstrap, so "demote the old,
    // promote the new" cannot interleave with another pair and leave two active keys.
    await tx`select pg_advisory_xact_lock(${BOOTSTRAP_LOCK_KEY})`
    const rows = await tx<RecordRow[]>`
      select kid, status, created_at, status_changed_at from signing_keys where kid = ${kid}
    `
    const row = rows[0]
    if (!row) return { result: { status: 'not_found' } as KeyTransition }
    if (row.status === 'active') return { result: { status: 'is_active' } as KeyTransition }
    if (row.status !== 'published') return { result: { status: 'not_published' } as KeyTransition }

    const readyAt = row.status_changed_at.getTime() + PUBLISH_BEFORE_ACTIVE_MS
    if (Date.now() < readyAt) {
      return {
        result: {
          status: 'too_soon',
          activatableAt: new Date(readyAt).toISOString(),
        } as KeyTransition,
      }
    }

    // Demote first. If the second statement fails the transaction rolls back both, which is the
    // whole reason they are in one — the other order, autocommitted, leaves two active keys and
    // then which one signs depends on which instance you ask.
    await tx`
      update signing_keys set status = 'published', status_changed_at = now()
       where status = 'active' and kid <> ${kid}
    `
    await tx`update signing_keys set status = 'active', status_changed_at = now() where kid = ${kid}`
    return { result: { status: 'ok' } as KeyTransition }
  })

  if (outcome.result.status !== 'ok') return outcome.result
  // This process is the one that changed it; the others notice within CACHE_TTL_MS.
  forgetSigningKeys()
  return { status: 'ok', keys: await listSigningKeys(sql) }
}

/** Drop a key from the JWKS. Refuses the active one — nothing else could sign. */
export async function retireSigningKey(sql: Db, kid: string): Promise<KeyTransition> {
  const rows = await sql<RecordRow[]>`
    select kid, status, created_at, status_changed_at from signing_keys where kid = ${kid}
  `
  const row = rows[0]
  if (!row) return { status: 'not_found' }
  if (row.status === 'active') return { status: 'is_active' }

  await sql`update signing_keys set status = 'retired', status_changed_at = now() where kid = ${kid}`

  // Retiring is the operator saying "stop honouring this key", usually because it leaked, so this
  // process must stop honouring it now rather than at the end of a cache window it cannot see.
  forgetSigningKeys()
  return { status: 'ok', keys: await listSigningKeys(sql) }
}

/**
 * Establish the signing key at boot, and report what is published.
 *
 * **IT BOOTSTRAPS, and that is the point rather than a side effect.** `getSigningKey` is called
 * first so a cold database has a key before the socket opens: generating an RSA keypair takes long
 * enough to be noticeable, and doing it lazily puts it inside whichever user happens to sign in
 * first — while the balancer already believes this replica is ready. Listing without bootstrapping
 * would log `active: []` on a fresh deployment and leave the work where it was.
 *
 * The report is a line rather than nothing, because the most confusing failure in this area is a
 * service that started perfectly and is verifying against a document the operator did not expect.
 * Kids only: a public JWK is public, and a log line is still not the place for a key.
 */
export async function logKeyState(sql: Db, log: Logger): Promise<void> {
  await getSigningKey(sql)
  const keys = await listSigningKeys(sql)
  log.info('signing keys', {
    active: keys.filter((k) => k.status === 'active').map((k) => k.kid),
    published: keys.filter((k) => k.status === 'published').map((k) => k.kid),
    retired: keys.filter((k) => k.status === 'retired').length,
  })
}
