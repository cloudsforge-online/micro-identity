/**
 * Background work.
 *
 * Rule 8 of docs/ecosystem/03 section 2: every background timer is a leased job. There is no
 * `setInterval` in this repository doing domain work — the estate runs eight of them today, each
 * guarded only by a module-local boolean, which is a variable that by construction cannot be seen
 * by a second process.
 *
 * **The lease key names the contended resource, not the row.** Ask what would break if two of these
 * ran at once; whatever the answer names is the key.
 *
 *   | Work                | Key      | Why                                                        |
 *   |---------------------|----------|------------------------------------------------------------|
 *   | outbox.relay        | `stream` | The outbox stream. Keying on the event id would let two     |
 *   |                     |          | relays deliver the same batch to the same subscriber.       |
 *   | identity.tombstone  | `global` | The set of accounts past their grace window. Two runs would |
 *   |                     |          | both select the same batch; the update is conditional on    |
 *   |                     |          | `status = 'pending_deletion'` so the second would no-op,    |
 *   |                     |          | but they would still contend on every row lock for nothing. |
 *   | identity.sweep      | `global` | Expired credentials. Pure deletion, genuinely idempotent,   |
 *   |                     |          | and keyed globally only so it runs once rather than N times.|
 */

import { JobRunner, type JobQueue, type RunnerEvent } from '@cloudsforge/jobs'
import type { Logger } from '@cloudsforge/telemetry'
import { createRelay, type Db, type RelayDeps } from './outbox.ts'
import { dueForTombstone, tombstoneAccount } from './deletion.ts'

export const RELAY_KIND = 'outbox.relay'
export const TOMBSTONE_KIND = 'identity.tombstone'
export const SWEEP_KIND = 'identity.sweep'

/**
 * Jobs that must exist whether or not anything enqueued them, and how often they repeat.
 *
 * A recurring job is a producer plus a leased job, never a timer. The producer is the boot seed
 * below plus the reschedule on completion — so the interval survives a restart, is visible in a
 * table an operator can query, and is claimed by exactly one replica.
 *
 * The tombstone sweep runs hourly rather than by the minute. Its input changes once a day at most
 * per account, and the grace window is measured in days: running it more often would be work with
 * nothing to find, and running it less often would let an erasure the user was promised drift by
 * more than the deadline in the event that announced it.
 */
export const RECURRING: ReadonlyArray<{ kind: string; key: string; everyMs: number }> = [
  { kind: RELAY_KIND, key: 'stream', everyMs: 1_000 },
  { kind: TOMBSTONE_KIND, key: 'global', everyMs: 60 * 60_000 },
  { kind: SWEEP_KIND, key: 'global', everyMs: 15 * 60_000 },
]

/** Enqueue the recurring set at boot. `keep` means N replicas booting together produce one row. */
export async function seedRecurring(queue: JobQueue): Promise<void> {
  for (const job of RECURRING) {
    await queue.enqueue({ kind: job.kind, key: job.key, onConflict: 'keep' })
  }
}

/**
 * Re-arm a recurring job once it has finished.
 *
 * It cannot re-arm itself from inside its own handler: the runner deletes the row on success AFTER
 * the handler returns, so a self-enqueue would be deleted a moment later and the schedule would
 * stop. Doing it from the completion event is the only point at which the row is gone.
 *
 * A dead-lettered recurring job is deliberately NOT re-armed. The row stays, `jobs_dead_total`
 * increments and `jobs_overdue` climbs, which is how an operator finds out. Silently rescheduling a
 * job that has failed its full attempt budget hides a permanent fault behind a busy loop.
 */
export function rescheduleRecurring(queue: JobQueue, logger: Logger): (event: RunnerEvent) => void {
  const byKind = new Map(RECURRING.map((r) => [r.kind, r]))
  return (event) => {
    if (event.type !== 'completed') return
    const recurring = event.kind ? byKind.get(event.kind) : undefined
    if (!recurring) return
    void queue
      .enqueue({
        kind: recurring.kind,
        key: recurring.key,
        runAt: new Date(Date.now() + recurring.everyMs),
        onConflict: 'earliest',
      })
      .catch((err: unknown) =>
        logger.error('failed to re-arm recurring job', { kind: recurring.kind, err }),
      )
  }
}

export interface JobDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly signingSecret: string
  readonly deletionGraceDays: number
}

export function registerHandlers(runner: JobRunner, deps: JobDeps): JobRunner {
  const relayDeps: RelayDeps = {
    sql: deps.sql,
    logger: deps.logger.child({ job: RELAY_KIND }),
    signingSecret: deps.signingSecret,
  }
  runner.register(RELAY_KIND, createRelay(relayDeps))

  /**
   * Step 3 of the deletion lifecycle.
   *
   * One account at a time, with a heartbeat between them: the batch is bounded, but each tombstone
   * is a transaction touching several tables, and a lease that expires mid-run would hand the rest
   * of the batch to a second replica.
   */
  runner.register(TOMBSTONE_KIND, async (_job, ctx) => {
    const due = await dueForTombstone(deps.sql, deps.deletionGraceDays)
    for (const userId of due) {
      if (ctx.signal.aborted) return
      const done = await tombstoneAccount(deps.sql, userId)
      if (done) {
        // The one line an auditor looks for. No address, no handle — by this point neither exists,
        // which is the point, and logging what was erased would defeat the erasure.
        deps.logger.info('account tombstoned', { audit: 'user_tombstoned', userId })
      }
      await ctx.heartbeat()
    }
  })

  /**
   * Expired credentials.
   *
   * Every one of these tables has an opportunistic sweep at its own write path already, which is
   * enough while the service is busy and does nothing at all while it is not. This is the other
   * half: a deployment that stops being used still stops holding expired hand-off codes, spent
   * challenges and dead reset tokens.
   *
   * Refresh tokens are swept on a much longer horizon than they expire. A row that is thirty days
   * past its expiry is still the only evidence that a family existed, and reuse detection reads it:
   * deleting it the moment it expires would turn a replayed token into `invalid` rather than into a
   * family burn, which is a detection silently lost.
   */
  runner.register(SWEEP_KIND, async (_job, ctx) => {
    const codes = await deps.sql`delete from auth_exchange_codes where expires_at < now() returning code_hash`
    if (ctx.signal.aborted) return
    const challenges = await deps.sql`delete from mfa_challenges where expires_at < now() returning challenge_hash`
    if (ctx.signal.aborted) return
    const resets = await deps.sql`
      delete from password_reset_tokens where expires_at < now() - interval '7 days' returning token_hash
    `
    if (ctx.signal.aborted) return
    const tokens = await deps.sql`
      delete from refresh_tokens where expires_at < now() - interval '90 days' returning id
    `
    if (codes.length + challenges.length + resets.length + tokens.length > 0) {
      deps.logger.info('expired credentials swept', {
        handoffCodes: codes.length,
        mfaChallenges: challenges.length,
        resetTokens: resets.length,
        refreshTokens: tokens.length,
      })
    }
  })

  return runner
}
