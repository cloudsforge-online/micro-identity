/**
 * The rewrap CLI — step 3 of an `IDENTITY_KEY_SECRET_V<n>` rotation.
 *
 * A separate one-shot process, like `migrator.ts` and for the same reasons: it is slow, it is run
 * by an operator at a chosen moment, and it must be able to fail loudly without taking the service
 * with it. Never called from `index.ts`.
 *
 *   pnpm rewrap          drain until nothing remains below IDENTITY_KEY_VERSION, then verify
 *   pnpm rewrap --verify only verify: open every blob under the current keyring, change nothing
 *
 * Exits non-zero if anything is left unreadable or undrained, so a deploy step or a runbook can
 * gate on it. That gate is the point: it is what stops an operator reaching step 4 — removing the
 * old secret — while a blob that still needs it exists.
 *
 * Prints COUNTS AND VERSION NUMBERS ONLY. Never a secret, never a seed, never a key, never a
 * fingerprint of one. An operator reading this output learns how much work is left and nothing
 * whatsoever about the values.
 */

import postgres from 'postgres'
import { Logger } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { keyring } from './keyEnvelope.ts'
import type { Db } from './outbox.ts'
import { remainingCount, rewrapOnce, verifyAllReadable } from './rewrap.ts'

const log = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
}).child({ step: 'rewrap' })

const verifyOnly = process.argv.includes('--verify')
const sql = postgres(env.databaseUrl, { max: 2, onnotice: () => {} })
const ring = keyring()

try {
  const target = ring.writeVersion
  log.info('rewrap starting', {
    target,
    // The versions this process can OPEN. If the one a blob needs is missing, the drain will say so
    // per row rather than silently skipping it.
    holds: ring.versions,
    verifyOnly,
  })

  let drained = { keys: 0, seeds: 0, failures: 0 }
  if (!verifyOnly) {
    // Loop to exhaustion rather than one batch: a partial drain that reports success is exactly the
    // failure this file exists to prevent. Bounded by `remaining` strictly decreasing — if a batch
    // makes no progress, every row in it failed, and continuing would spin for ever.
    for (;;) {
      const before = await remainingCount(sql as unknown as Db, target)
      if (before === 0) break
      const report = await rewrapOnce({ sql: sql as unknown as Db, keyring: ring, logger: log })
      drained = {
        keys: drained.keys + report.keys,
        seeds: drained.seeds + report.seeds,
        failures: drained.failures + report.failures,
      }
      log.info('rewrap batch', { ...report })
      if (report.remaining >= before) {
        log.error('rewrap made no progress — every row in the batch failed', {
          remaining: report.remaining,
        })
        break
      }
    }
  }

  const remaining = await remainingCount(sql as unknown as Db, target)
  // The verification is a DECRYPTION of every blob, not a prefix count. A prefix says which secret
  // a blob claims to need; only opening it proves that secret is held and the ciphertext
  // authenticates. See `verifyAllReadable`.
  const verified = await verifyAllReadable(sql as unknown as Db, ring)

  log.info('rewrap complete', {
    target,
    drainedKeys: drained.keys,
    drainedSeeds: drained.seeds,
    failures: drained.failures,
    remainingBelowTarget: remaining,
    readableSigningKeys: verified.keys,
    readableTotpSeeds: verified.seeds,
    unreadable: verified.unreadable,
  })

  await sql.end({ timeout: 5 })
  if (remaining !== 0 || verified.unreadable !== 0 || drained.failures !== 0) {
    // Loud, and non-zero. Do NOT remove the old key secret after seeing this.
    process.exit(1)
  }
  process.exit(0)
} catch (err) {
  log.fatal('rewrap failed', { err })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}
