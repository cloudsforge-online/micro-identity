/**
 * Password reset — tier 1 of SD-04's three recovery tiers.
 *
 * Carried forward from Nimbus's `passwordReset.ts`, which SD-04 records as already getting the hard
 * parts right and says is "retained unchanged". Three of those parts are load-bearing and each one
 * is a defect somewhere else in the estate's history:
 *
 *   1. **The route answers 202 BEFORE doing any work**, so the endpoint is not a timing oracle for
 *      whether an address has an account. See the route in server.ts for why that is not paranoia:
 *      awaiting the work made an unknown address answer in ~10ms and a known one in the full
 *      attempt budget the moment a mail relay was slow.
 *   2. **The link is built from a configured public URL and NEVER from the request `Host`
 *      header.** While nothing delivered mail this was a latent bug; wiring a relay turns it into
 *      unauthenticated account takeover, because a forged `Host` has the deployment's own relay send
 *      the victim a genuine, correctly branded reset email whose button points at the attacker.
 *      The fragment does not save it — the attacker's page reads `location.hash`.
 *   3. **Spending it revokes every refresh family**, so a session held by whoever forced the reset
 *      does not survive it.
 *
 * The token is 32 random bytes, stored only as its SHA-256, and redeemed by a conditional
 * `UPDATE ... RETURNING` so two racing redemptions cannot both win. The lookup is a primary-key
 * match on the HASH, never a comparison against the secret, so how long it takes says nothing about
 * how much of a guessed token was right.
 *
 * TTL is thirty minutes rather than the hand-off code's sixty seconds: this one has to survive being
 * read out of a mail client and typed into a browser.
 */

import { createHash, randomBytes } from 'node:crypto'
import { env } from './env.ts'
import type { Db } from './outbox.ts'

const TOKEN_TTL_MS = 30 * 60_000

const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex')

export interface IssuedReset {
  /** The raw token. This is the only moment it exists outside the recipient's mailbox. */
  readonly token: string
  readonly expiresAt: Date
}

/**
 * Mint a single-use reset token, burning any the user already holds.
 *
 * Issuing supersedes rather than accumulates: two "I forgot" clicks must not leave two live tokens,
 * because the older one is the one most likely to have leaked into a mail client or a chat log.
 *
 * **SUPERSESSION IS ATOMIC, UNDER A LOCK ON THE USER, and the reason is this route's own shape.**
 * The caller answers 202 and does this work detached, so an impatient user clicking twice produces
 * two of these running at once — genuinely concurrently, not merely quickly. As "revoke, then
 * insert" they interleave: both revoke, each seeing a set that does not yet contain the other's row,
 * and both insert. The account is then left with two live reset tokens, which is precisely what
 * superseding exists to prevent, arriving by the one door the fire-and-forget design opens.
 */
export async function createPasswordResetToken(
  sql: Db,
  userId: string,
  issuedBy: string | null,
): Promise<IssuedReset> {
  const token = randomBytes(32).toString('hex')
  const expiresAt = new Date(Date.now() + TOKEN_TTL_MS)

  await sql.begin(async (tx) => {
    await tx`select pg_advisory_xact_lock(hashtext(${userId})::bigint)`
    // Opportunistic sweep, as the hand-off code does. A reset table is append-only otherwise, and
    // an expired row is worth nothing to anyone least of all whoever ends up with a copy.
    await tx`delete from password_reset_tokens where expires_at < now()`
    await tx`
      update password_reset_tokens set used_at = now()
       where user_id = ${userId} and used_at is null
    `
    await tx`
      insert into password_reset_tokens (token_hash, user_id, issued_by, expires_at)
      values (${hashToken(token)}, ${userId}, ${issuedBy}, ${expiresAt})
    `
  })
  return { token, expiresAt }
}

/**
 * The absolute reset link carrying a token.
 *
 * **THE HOST COMES FROM CONFIGURATION, NOT FROM THE REQUEST**, and that is the whole of this
 * function. It takes no request at all, which is stronger than taking one and ignoring it: there is
 * nothing here for a future edit to reach for. `IDENTITY_PUBLIC_URL` is validated at boot to be an
 * origin, so this cannot produce a relative or a path-carrying link either.
 *
 * **THE TOKEN GOES AFTER THE '#', NOT AFTER THE '?'.** A fragment is the one part of a URL a
 * browser keeps to itself: it is not in the request line, so it reaches no server log, no
 * reverse-proxy access log and no `Referer` on the next navigation. Nimbus used `?token=` and the
 * consequence was that its own "incoming request" log line wrote the live credential to stdout on
 * the very request that spends it, from where Lantern lifted it into an indexed column and every
 * backup. The telemetry package redacts query values now, and these two defences protect different
 * things: the redaction covers OUR logs, and the fragment covers everything between the user's
 * browser and us, which we do not run and cannot redact.
 */
export function resetUrlFor(token: string): string {
  return `${env.publicUrl}/reset#token=${encodeURIComponent(token)}`
}

/** Redeem a reset token exactly once. Returns the user id, or null. */
export async function redeemPasswordResetToken(sql: Db, token: string): Promise<string | null> {
  const rows = await sql<{ user_id: string }[]>`
    update password_reset_tokens set used_at = now()
     where token_hash = ${hashToken(token)} and used_at is null and expires_at > now()
    returning user_id
  `
  return rows[0]?.user_id ?? null
}

/**
 * Burn every outstanding reset token for a user.
 *
 * Called when a reset completes and when a password is changed the ordinary way: an unused reset
 * link that still works after the password has moved on is a standing back door, and it is held by
 * whoever asked for it rather than by whoever owns the account.
 */
export async function revokePasswordResetTokens(sql: Db, userId: string): Promise<void> {
  await sql`
    update password_reset_tokens set used_at = now()
     where user_id = ${userId} and used_at is null
  `
}

export interface PendingReset {
  readonly userId: string
  readonly email: string
  readonly handle: string
  /** Null when the user asked for it themselves. */
  readonly issuedBy: string | null
  readonly createdAt: string
  readonly expiresAt: string
}

/**
 * Outstanding, unexpired, unused reset tokens — the operator's view of who is waiting.
 *
 * It cannot show the tokens themselves; nothing can, they are only stored as hashes. What it can
 * show is that a request was made, which is what the undelivered mode below needs.
 */
export async function listPendingResets(sql: Db): Promise<PendingReset[]> {
  const rows = await sql<
    {
      user_id: string
      email: string
      handle: string
      issued_by: string | null
      created_at: Date
      expires_at: Date
    }[]
  >`
    select t.user_id, u.email, u.handle, t.issued_by, t.created_at, t.expires_at
      from password_reset_tokens t
      join users u on u.id = t.user_id
     where t.used_at is null and t.expires_at > now()
     order by t.created_at desc
     limit 100
  `
  return rows.map((row) => ({
    userId: row.user_id,
    email: row.email,
    handle: row.handle,
    issuedBy: row.issued_by,
    createdAt: row.created_at.toISOString(),
    expiresAt: row.expires_at.toISOString(),
  }))
}

/* ------------------------------------------------------------------------ delivery */

/**
 * DELIVERY IS A SEAM, AND IT IS DELIBERATELY NOT SMTP IN THIS SERVICE.
 *
 * Nimbus speaks SMTP directly, which was right when it was the only service that sent anything. In
 * the target architecture `notify` owns every outbound channel and identity holds `notify:send`, so
 * putting a mail transport here would build the second copy of a thing whose entire purpose is to
 * be the only copy — and would put a network dependency with a six-second attempt budget on the
 * one route that must never let its timing vary.
 *
 * Until `notify` exists, the supported mode is the one Nimbus already supports and every deployment
 * ran for years: **nothing is sent, the request is recorded, and an operator issues the link.**
 * `listPendingResets` is how they see who is waiting. That is a real deployment mode rather than an
 * unimplemented one, and it is the reason `RESET_REQUEST_STATUS` never promises an email.
 *
 * Three rules the seam is written under, all three load-bearing:
 *
 *   - The reset URL is the only copy of the token in existence. It is not logged, not persisted,
 *     and not allowed into an error message.
 *   - **Nothing here may throw.** The caller has already answered 202 and there is no request left
 *     to fail; an escaping rejection is an unhandled one. Failure is reported by return value.
 *   - A different outcome for a known and an unknown address — in status, body or timing — is an
 *     enumeration oracle, so the status string varies with the DEPLOYMENT and never with the
 *     account.
 */
export interface ResetDelivery {
  readonly delivered: boolean
  /** What carried it, for the log line. `none` when nothing is configured to. */
  readonly channel: 'none' | 'notify'
}

/** The body of the 202. One string for both branches, always. */
export const RESET_REQUEST_STATUS =
  'If that account exists, a reset has been recorded. It expires in 30 minutes and works once.'

export interface DeliveryLogger {
  info(message: string, fields?: Record<string, unknown>): void
  warn(message: string, fields?: Record<string, unknown>): void
}

export async function deliverPasswordReset(
  log: DeliveryLogger,
  recipient: { readonly userId: string },
): Promise<ResetDelivery> {
  // Not an error. This is the deployment mode the operator console exists for.
  //
  // The user id is logged and the address is NOT, which is the one place this departs from Nimbus's
  // line: it logged the email at warn on every request, so a log search for an address returned the
  // fact that somebody had asked to reset it. The id joins to the row for an operator and says
  // nothing to anyone reading the log for other reasons.
  log.warn('password reset requested but nothing is configured to deliver it', {
    audit: 'password_reset_undelivered',
    userId: recipient.userId,
    fix: 'No delivery channel is configured. Issue the link from the operator console until `notify` is deployed and identity holds the `notify:send` scope.',
  })
  return { delivered: false, channel: 'none' }
}
