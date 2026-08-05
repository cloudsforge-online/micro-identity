/**
 * The rewrap pass — the second half of #188, and the thing that makes `IDENTITY_KEY_SECRET_V<n>`
 * rotatable rather than merely supplementable.
 *
 * A version in the envelope on its own only lets old blobs keep decrypting. It does not RETIRE the
 * old secret, and a secret that can never be retired has not been rotated. #188 is filed against a
 * published key: leaving it load-bearing for ever means the disclosure is never actually closed.
 *
 * **OMITTING THIS STEP IS THE DEFECT, NOT AN OPTIMISATION.** It has already happened once in this
 * estate: a rotation that added a new secret and removed the old one without draining orphaned 509
 * blobs, and they were recoverable only because the old secret happened to survive in public git
 * history. That is luck, not a recovery procedure, and for `mfa_factors.secret_enc` there would be
 * no luck available — a TOTP seed exists in its blob and in the user's authenticator app, and
 * nowhere else in the world.
 *
 * THE ROTATION, END TO END:
 *
 *   1. Generate a new secret and add `IDENTITY_KEY_SECRET_V<n+1>`. Leave V<n> in place.
 *   2. Set `IDENTITY_KEY_VERSION=<n+1>` and restart. New blobs seal under it immediately; every
 *      existing blob still opens under V<n>.
 *   3. Let this pass drain, until `remainingCount` is zero.
 *   4. Only then remove `IDENTITY_KEY_SECRET_V<n>`. THAT is the moment the disclosure closes.
 *
 * IT IS RESTARTABLE AND IT CANNOT LOSE A SEED. Per row the new blob is computed in memory and
 * written in a single `update`, so a crash leaves the row either wholly old or wholly new — there
 * is no torn state, and the next pass selects whatever is still below the target. The operation is
 * idempotent and the only cost of a crash is doing one row twice.
 *
 * THE SELECTION IS ON THE BLOB'S OWN STAMP, not on a version column. Identity has no `key_version`
 * column and does not need one: the stamp is a prefix of the stored text, so `not like 'v<n>:%'` is
 * an exact predicate over exactly the stragglers. That removes a whole class of bug custody had to
 * reason about — a row whose column disagrees with its blob — because there is only one place the
 * version is recorded.
 */

import type { Logger } from '@cloudsforge/telemetry'
import type { JWK } from 'jose'
import { keyring as processKeyring, versionOf, type Keyring } from './keyEnvelope.ts'
import type { Db } from './outbox.ts'

export interface RewrapDeps {
  readonly sql: Db
  readonly keyring: Keyring
  readonly logger: Logger
}

export interface RewrapReport {
  /** `signing_keys` rows re-sealed under the target version by this batch. */
  readonly keys: number
  /** `mfa_factors` TOTP seeds re-sealed under the target version by this batch. */
  readonly seeds: number
  /** Rows that could not be re-sealed. A non-zero count must stop the rotation. */
  readonly failures: number
  /** Blobs still below the target across both tables, AFTER this batch. Drains to zero. */
  readonly remaining: number
}

/**
 * One batch.
 *
 * Bounded rather than "everything", because each row costs a full scrypt derivation to open plus
 * another to seal, and this runs against a live database. An unbounded pass on a large
 * `mfa_factors` would hold a core for as long as the table is big.
 */
export async function rewrapOnce(deps: RewrapDeps, batchSize = 100): Promise<RewrapReport> {
  const target = deps.keyring.writeVersion
  const stale = `v${target}:%`
  let keys = 0
  let seeds = 0
  let failures = 0

  const signingKeys = await deps.sql<{ kid: string; private_jwk_enc: string }[]>`
    select kid, private_jwk_enc from signing_keys
     where private_jwk_enc not like ${stale}
     order by created_at limit ${batchSize}
  `
  for (const row of signingKeys) {
    try {
      // Opened by the stamp the blob itself carries, re-sealed under the target. A blob already at
      // the target is not selected above, so this never rewrites needless rows.
      const jwk = deps.keyring.open<JWK>('signing-key', row.kid, row.private_jwk_enc)
      const rewrapped = deps.keyring.sealAs(target, 'signing-key', row.kid, jwk)
      await deps.sql`update signing_keys set private_jwk_enc = ${rewrapped} where kid = ${row.kid}`
      keys += 1
    } catch (err) {
      // Counted and logged, never thrown: one unreadable blob must not stop the rotation of every
      // other. A row that keeps failing stays below the target, so `remaining` never reaches zero
      // and the rotation visibly does not finish — which is the correct alarm, and is what stops
      // an operator proceeding to step 4.
      failures += 1
      deps.logger.error('rewrap failed for a signing key', {
        kid: row.kid,
        from: safeVersion(row.private_jwk_enc),
        to: target,
        err: err instanceof Error ? err.message : String(err),
      })
    }
  }

  const factors = await deps.sql<{ id: string; secret_enc: string }[]>`
    select id, secret_enc from mfa_factors
     where secret_enc is not null and secret_enc not like ${stale}
     order by created_at limit ${batchSize}
  `
  for (const row of factors) {
    try {
      // The seed is a base64 string inside the envelope. It is moved from one envelope to another
      // and never logged, never returned, and never compared — see the constraint in the header of
      // `mfa.ts`: a TOTP seed that reaches a log is a second factor that the log defeats.
      const seed = deps.keyring.open<string>('totp-seed', row.id, row.secret_enc)
      const rewrapped = deps.keyring.sealAs(target, 'totp-seed', row.id, seed)
      await deps.sql`update mfa_factors set secret_enc = ${rewrapped} where id = ${row.id}`
      seeds += 1
    } catch (err) {
      failures += 1
      deps.logger.error('rewrap failed for a TOTP seed', {
        factorId: row.id,
        from: safeVersion(row.secret_enc),
        to: target,
        err: err instanceof Error ? err.message : String(err),
      })
    }
  }

  return { keys, seeds, failures, remaining: await remainingCount(deps.sql, target) }
}

/** The version on a blob, for a log line, without throwing inside an error handler. */
function safeVersion(blob: string): number | null {
  try {
    return versionOf(blob)
  } catch {
    return null
  }
}

/**
 * How many blobs are still below the target. The gauge an operator watches to zero before removing
 * the old secret — and the number that goes in the issue as evidence.
 */
export async function remainingCount(sql: Db, target: number): Promise<number> {
  const stale = `v${target}:%`
  const rows = await sql<{ n: number }[]>`
    select
      (select count(*) from signing_keys where private_jwk_enc not like ${stale})
    + (select count(*) from mfa_factors  where secret_enc is not null and secret_enc not like ${stale}) as n
  `
  return Number(rows[0]?.n ?? 0)
}

/**
 * Prove every blob opens under the CURRENT keyring, by opening all of them.
 *
 * This is the verification step, and it is deliberately not "count the rows whose prefix looks
 * right". A prefix says which secret a blob claims to need; only a decryption proves that secret
 * is held and that the ciphertext authenticates under it. The distinction is the whole difference
 * between a rotation that was checked and one that merely appeared to succeed, which is the defect
 * class behind most of this tracker.
 *
 * Returns counts only. Nothing it decrypts is returned, logged or retained.
 */
export async function verifyAllReadable(
  sql: Db,
  ring: Keyring = processKeyring(),
): Promise<{ keys: number; seeds: number; unreadable: number }> {
  let keys = 0
  let seeds = 0
  let unreadable = 0

  for (const row of await sql<{ kid: string; private_jwk_enc: string }[]>`
    select kid, private_jwk_enc from signing_keys
  `) {
    try {
      ring.open<JWK>('signing-key', row.kid, row.private_jwk_enc)
      keys += 1
    } catch {
      unreadable += 1
    }
  }

  for (const row of await sql<{ id: string; secret_enc: string }[]>`
    select id, secret_enc from mfa_factors where secret_enc is not null
  `) {
    try {
      ring.open<string>('totp-seed', row.id, row.secret_enc)
      seeds += 1
    } catch {
      unreadable += 1
    }
  }

  return { keys, seeds, unreadable }
}
