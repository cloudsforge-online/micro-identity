/**
 * Per-account sign-in throttling with exponential lock-out.
 *
 * Carried forward from Nimbus's `loginThrottle.ts` unchanged in behaviour.
 *
 * **Per account, not per IP, and both are needed.** The route rate limit caps one address; this is
 * what an attacker rotating through a botnet still runs into, because the thing being attacked is
 * one account and the counter follows it rather than the connection.
 *
 * **Keyed on the lower-cased identifier, and rows exist for identifiers that do not.** Counting
 * failures for unknown addresses is what stops a lock-out response from being an oracle: if only
 * real accounts could be locked out, "429" would answer the question the 401 is written not to.
 * That the key is lower-cased matters more here than it looks — a per-account throttle keyed on the
 * address as typed is a throttle an attacker resets by changing the capitalisation.
 */

import type { Db } from './outbox.ts'

/** How many attempts before the lock-out engages at all. */
const FREE_ATTEMPTS = 5

/** The first lock. Each further failure doubles it. */
const BASE_LOCK_MS = 60_000

/**
 * The ceiling.
 *
 * Fifteen minutes rather than something longer, because past this point the lock-out has stopped
 * being a control on the attacker and started being one on the user: an unbounded doubling means a
 * stranger who knows your address can keep you out of your own account for ever, at no cost to
 * themselves. Fifteen minutes reduces an online guessing rate to roughly nothing while leaving a
 * real user a way back in without a support ticket.
 */
const MAX_LOCK_MS = 15 * 60_000

const key = (identifier: string): string => identifier.trim().toLowerCase()

/** Milliseconds left on an active lock-out, or 0. */
export async function lockoutRemainingMs(sql: Db, identifier: string): Promise<number> {
  const rows = await sql<{ locked_until: Date | null }[]>`
    select locked_until from login_attempts where email = ${key(identifier)}
  `
  const until = rows[0]?.locked_until?.getTime()
  return until ? Math.max(0, until - Date.now()) : 0
}

export interface FailedLogin {
  readonly failures: number
  /** How long the account is now locked for; 0 while inside the free attempts. */
  readonly lockedForMs: number
}

/**
 * Count a failed attempt and extend the lock-out once past the free attempts.
 *
 * Returns what it decided rather than logging it here: the route holds the request-scoped logger,
 * and a lock-out that engages silently is indisputably the most interesting event this file has.
 */
export async function recordFailedLogin(sql: Db, identifier: string): Promise<FailedLogin> {
  const k = key(identifier)
  const rows = await sql<{ failures: number }[]>`
    insert into login_attempts (email, failures) values (${k}, 1)
    on conflict (email) do update set failures = login_attempts.failures + 1, updated_at = now()
    returning failures
  `
  const failures = rows[0]?.failures ?? 1
  if (failures < FREE_ATTEMPTS) return { failures, lockedForMs: 0 }

  const lockMs = Math.min(MAX_LOCK_MS, BASE_LOCK_MS * 2 ** (failures - FREE_ATTEMPTS))
  await sql`
    update login_attempts set locked_until = ${new Date(Date.now() + lockMs)} where email = ${k}
  `
  return { failures, lockedForMs: lockMs }
}

/** Wipe the counter after a successful sign-in, or after a reset the user was locked out of. */
export async function clearLoginFailures(sql: Db, identifier: string): Promise<void> {
  await sql`delete from login_attempts where email = ${key(identifier)}`
}
