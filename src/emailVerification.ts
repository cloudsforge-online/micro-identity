/**
 * Email verification — proving that the person who typed an address can read mail sent to it.
 *
 * ## The defect this closes
 *
 * `users.email_verified_at` has existed since migration 3, `toPublicUser` has published it as
 * `emailVerifiedAt` since the file was written (users.ts:56), and **nothing in this service ever
 * wrote it**. There was no verification route in the whole table, `POST /auth/register` minted a
 * session on the spot (server.ts, the register route), and `signInRefusal` (users.ts:222) refused
 * only `suspended`, `locked` and `deleted` — so an address nobody had proved control of could sign
 * in for ever. Confirmed against the live estate rather than inferred: a registration against
 * https://nimbus.cloudsforge.online/auth/register was followed by a 200 from `POST /auth/login`
 * carrying `emailVerifiedAt: null`, and no mail arrived because nothing sends any.
 *
 * ## THE LINK IS A PAGE, AND THE TOKEN IS IN THE FRAGMENT
 *
 *     https://hub.<apex>/account/verify#token=<64 hex characters>
 *
 * `resetUrlFor` (passwordReset.ts:98) already puts a reset token after the '#' and records why: a
 * fragment is the one part of a URL a browser keeps to itself, so it is not in the request line and
 * reaches no server log, no reverse-proxy access log and no `Referer` on the next navigation.
 * Nimbus used `?token=` and its own "incoming request" log line wrote the live credential to stdout
 * on the very request that spent it. That reasoning is inherited here in full.
 *
 * **The second reason is specific to a link that arrives by mail, and it is the stronger one.** A
 * corporate mail scanner, a link-preview bot and an over-eager mail client all pre-fetch what they
 * are sent. Browsers never transmit a fragment, and neither do they — a pre-fetch of this URL is
 * `GET /account/verify` with nothing after it, which loads a static SPA shell and consumes nothing.
 * The page then POSTs the token to `POST /auth/email/verify`.
 *
 * That is a better answer to "a GET that mutates is a trap" than switching verbs on a route would
 * be. Moving the token to a POST body with the link still carrying it in the query string leaves
 * the credential in the pre-fetcher's request; putting it in the fragment means **on a pre-fetch
 * the credential never reaches the wire at all**. There is deliberately NO GET route in this
 * service that consumes a token.
 *
 * ## Twenty-four hours, not thirty minutes
 *
 * A password reset is requested by someone sitting at the form who is waiting for the mail, so
 * thirty minutes (passwordReset.ts:33) is generous. A verification link is read on a phone, in the
 * morning, after the mail sat in a provider queue or a spam folder somebody eventually checked.
 * Twenty-four hours is the shortest window that does not routinely fail a person who signs up at
 * night, and the exposure it buys is bounded by everything else here: the token is single-use, it
 * is stored only as a hash, and minting a new one burns the old.
 *
 * ## Never logged
 *
 * The raw token exists in exactly one place — the return value of `requestEmailVerification` — and
 * from there it goes into the event payload and nowhere else. Not into a log line, not into an
 * error message, not into a metric label, not into the database. Every refusal below is logged by
 * its caller without the value that was refused.
 *
 * ## Delivery: the outbox, because identity does not speak SMTP
 *
 * passwordReset.ts:173-179 states the estate's position and this follows it exactly: `notify` owns
 * every outbound channel, so a mail transport here would build the second copy of a thing whose
 * whole purpose is to be the only copy. The fact leaves as `identity.email.verification_requested`
 * through `withOutbox`, in the SAME transaction as the token row — rule 5 of docs/ecosystem/03 §2 —
 * so a crash cannot leave a token nobody was told about or an email for a token that does not
 * exist.
 *
 * **This puts a live credential in another service's database, and that is accepted here.** The
 * `verifyUrl` in the payload contains the token, so `notify` stores it in its own outbox/inbox
 * rows for as long as it keeps them. Three things make that the right trade rather than a
 * concession:
 *
 *   1. It is the SAME trade the estate already makes for every notification: template parameters
 *      travel in the event, and a reset or a verification link IS the parameter.
 *   2. The credential is single-use and expires in 24 hours, and proves control of a mailbox rather
 *      than granting standing access to anything.
 *   3. The alternative is identity speaking SMTP, which passwordReset.ts:173-179 rejects by name —
 *      duplicated transport, duplicated templates, and a network dependency on the routes whose
 *      timing must not vary.
 */

import { createHash, randomBytes } from 'node:crypto'
import { env } from './env.ts'
import { withOutbox, type Db, type Tx } from './outbox.ts'
// One logger shape for both delivery seams. passwordReset.ts declared it first and this is the same
// contract — a second, structurally identical interface would be two things to keep in step.
import type { DeliveryLogger } from './passwordReset.ts'

/** See the header. Twenty-four hours, and the reasoning is not interchangeable with the reset's. */
const TOKEN_TTL_MS = 24 * 60 * 60_000

const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex')

export interface IssuedVerification {
  /**
   * The raw token. **The only moment it exists outside the recipient's mailbox.**
   *
   * The routes deliberately discard it: the copy that matters has already been put into the event
   * payload by the time this returns. It is returned rather than swallowed because a mint that
   * hides its own output cannot be tested — the alternative is a test that reads the hash out of
   * the table and cannot produce the value that redeems it.
   */
  readonly token: string
  readonly expiresAt: Date
  /** False when `IDENTITY_ACCOUNT_URL` is unset, so no link could be built. See `buildVerifyUrl`. */
  readonly linkable: boolean
}

/**
 * The absolute verification link, or null when no origin is configured.
 *
 * **THE HOST COMES FROM CONFIGURATION, NOT FROM THE REQUEST.** This takes no request at all, which
 * is stronger than taking one and ignoring it: there is nothing here for a future edit to reach
 * for. passwordReset.ts:12-16 records what the alternative costs — while nothing delivered mail a
 * `Host`-derived link was a latent bug, and wiring a relay turns it into unauthenticated account
 * takeover, because a forged `Host` has the deployment's own relay send the victim a genuine,
 * correctly branded email whose button points at the attacker. For a link that proves control of a
 * mailbox that is not a theoretical concern: the attacker's page reads `location.hash` and verifies
 * the address for them.
 *
 * Split from `verifyUrlFor` so both branches are testable without touching `process.env`: `env` is
 * validated at import, so a test cannot unset the variable after the fact.
 */
export function buildVerifyUrl(accountUrl: string | null, token: string): string | null {
  if (!accountUrl) return null
  // The fragment, never the query. See the header — a mail scanner's pre-fetch is `GET
  // /account/verify` and carries nothing.
  return `${accountUrl}/account/verify#token=${encodeURIComponent(token)}`
}

export function verifyUrlFor(token: string): string | null {
  return buildVerifyUrl(env.accountUrl, token)
}

/**
 * Mint a single-use verification token and publish the request to send it — one transaction.
 *
 * ## Supersession, atomic, under a lock on the user
 *
 * Issuing supersedes rather than accumulates: two "resend" clicks must not leave two live tokens,
 * because the older one is the one most likely to have leaked into a mail client, a chat log or a
 * scanner's cache. The advisory lock is required for the reason `createPasswordResetToken` gives at
 * passwordReset.ts:49-54 and it applies here unchanged — as "revoke, then insert" two concurrent
 * mints interleave, both stamping a set that does not yet contain the other's row and both
 * inserting, which produces exactly the state superseding exists to prevent. The resend route
 * answers 202 before doing its work, so "genuinely concurrent" is the ordinary case rather than an
 * unlucky one.
 *
 * `email_verification_tokens_one_live` (migration 13) is the second half of the same rule: a
 * partial unique index on `(user_id) where consumed_at is null`, so even if a future edit drops the
 * lock the second insert raises 23505 instead of quietly creating a state the design says cannot
 * exist.
 *
 * ## Why this is not folded into `registerUser`
 *
 * It runs in its own transaction, so a crash between the two leaves an account that exists and
 * unverified with no mail sent. That is recoverable — `POST /auth/email/verify/resend` is exactly
 * the repair — whereas the couplings the alternative buys are not: `registerUser` is also called by
 * the operator tool and by tests, and neither should mail anybody.
 */
export async function requestEmailVerification(
  sql: Db,
  user: { readonly id: string; readonly handle: string; readonly email: string },
  correlationId?: string,
): Promise<IssuedVerification> {
  const token = randomBytes(32).toString('hex')
  const expiresAt = new Date(Date.now() + TOKEN_TTL_MS)
  const verifyUrl = verifyUrlFor(token)

  await withOutbox(sql, 'identity', async (tx, emit) => {
    await mintVerificationToken(tx, user.id, token, expiresAt)
    emit({
      topic: 'identity.email.verification_requested',
      // Keyed by the user, as every identity topic is: `activity` reads the owner straight off the
      // envelope key, and ordering is per key — two verification requests for one account must be
      // ordered with respect to each other, and a token id in this position would match nobody.
      key: user.id,
      payload: {
        userId: user.id,
        // The handle, not the display name: the greeting is built on it, and a display name is a
        // profile field the user can change to something a greeting should not have been built on.
        // Same reasoning as `identity.user.registered` (users.ts:150-153).
        handle: user.handle,
        email: user.email,
        expiresAt: expiresAt.toISOString(),
        // Always present, so a consumer branches on a field that is always there rather than on the
        // absence of one. False means the deployment has not set IDENTITY_ACCOUNT_URL and no link
        // could be built — see the field on `Env`.
        linkable: verifyUrl !== null,
        ...(verifyUrl === null ? {} : { verifyUrl }),
      },
      // The account acts for itself. A verification is asked for by whoever holds the address, and
      // `system` would lose the one attribution available.
      actor: `user:${user.id}`,
      ...(correlationId === undefined ? {} : { correlationId }),
    })
  })

  return { token, expiresAt, linkable: verifyUrl !== null }
}

/** The row, inside the caller's transaction. Private: the lock only means anything with the emit. */
async function mintVerificationToken(
  tx: Tx,
  userId: string,
  token: string,
  expiresAt: Date,
): Promise<void> {
  await tx`select pg_advisory_xact_lock(hashtext(${userId})::bigint)`
  // Opportunistic sweep, as the reset and hand-off tables do. An expired token is worth nothing to
  // anyone least of all to whoever ends up with a copy, and it would otherwise sit under the
  // partial unique index blocking the supersede below.
  await tx`delete from email_verification_tokens where expires_at < now()`
  await tx`
    update email_verification_tokens set consumed_at = now()
     where user_id = ${userId} and consumed_at is null
  `
  await tx`
    insert into email_verification_tokens (token_hash, user_id, expires_at)
    values (${hashToken(token)}, ${userId}, ${expiresAt})
  `
}

/**
 * Redeem a verification token exactly once, and mark the address proved.
 *
 * **The refusal is the UPDATE itself, not a check before one.** One conditional statement decides
 * whether this caller is the one that spends the token — `redeemPasswordResetToken`
 * (passwordReset.ts:103-110) is the pattern — so two redemptions racing on the same link cannot
 * both win: the second matches no row because the first has already stamped `consumed_at`. A read
 * followed by a write would let both through, and both would mint a session.
 *
 * The stamp on `users` is in the same transaction, and it is `coalesce`d rather than overwritten:
 * an address verified once has a first-proved-at date, and a later verification (an address change,
 * a second link that raced) must not move it.
 *
 * Returns the user id, or null. **Expired, already spent and never real are one answer**, because
 * they read identically to the person holding the link and distinguishing them would say whether a
 * guessed token had ever existed.
 */
export async function redeemEmailVerification(sql: Db, token: string): Promise<string | null> {
  const outcome = await sql.begin(async (tx) => {
    const rows = await tx<{ user_id: string }[]>`
      update email_verification_tokens set consumed_at = now()
       where token_hash = ${hashToken(token)} and consumed_at is null and expires_at > now()
      returning user_id
    `
    const userId = rows[0]?.user_id ?? null
    if (userId === null) return { userId: null }
    await tx`
      update users set email_verified_at = coalesce(email_verified_at, now())
       where id = ${userId}
    `
    return { userId }
  })
  return outcome.userId
}

/** Burn every outstanding verification token for a user. */
export async function revokeEmailVerificationTokens(sql: Db, userId: string): Promise<void> {
  await sql`
    update email_verification_tokens set consumed_at = now()
     where user_id = ${userId} and consumed_at is null
  `
}

/* ------------------------------------------------------------------------ what the routes say */

/**
 * The body of the 202 from `POST /auth/register`.
 *
 * Registration no longer mints a session, and this string is the whole of what the user is told.
 * It names the wait rather than the mechanism: a person who does not receive the mail needs to know
 * how long it is good for, and "24 hours" is the one operational fact worth carrying in copy.
 */
export const VERIFICATION_REQUIRED_STATUS =
  'Check your email for a verification link. It expires in 24 hours and works once.'

/**
 * The body of the 202 from `POST /auth/email/verify/resend`. **One string for both branches.**
 *
 * Shaped exactly like `RESET_REQUEST_STATUS` (passwordReset.ts:203) and for the same reason: a
 * different answer for a known and an unknown address — in status, body OR timing — is an
 * enumeration oracle. This route also has a second oracle the reset route does not: whether the
 * account is ALREADY verified. "That address is already confirmed" tells an unauthenticated caller
 * both that the account exists and how far along it is, so the string is silent about that too.
 */
export const VERIFICATION_RESEND_STATUS =
  'If that account exists and still needs confirming, a new verification link has been recorded. It expires in 24 hours and works once.'

/**
 * Report what the delivery seam managed, for an operator reading the log.
 *
 * The user id is logged and **the address is not**, which is the same line `deliverPasswordReset`
 * draws (passwordReset.ts:216-220): Nimbus logged the email on every request, so a log search for
 * an address returned the fact that somebody had asked about it. The id joins to the row for an
 * operator and says nothing to anyone reading the log for other reasons. The token appears in
 * neither branch.
 *
 * Nothing here throws. Both callers have already answered, and an escaping rejection would be an
 * unhandled one.
 */
export function reportVerificationDelivery(
  log: DeliveryLogger,
  outcome: { readonly userId: string; readonly linkable: boolean },
): void {
  if (outcome.linkable) {
    log.info('email verification requested', {
      audit: 'email_verification_requested',
      userId: outcome.userId,
    })
    return
  }
  // Not an error, and not a failed registration: the event is on the bus and carries `linkable:
  // false`, so `notify` knows why it has nothing to link to. What an operator needs is the name of
  // the variable that would fix it.
  log.warn('email verification requested but no link could be built', {
    audit: 'email_verification_unlinkable',
    userId: outcome.userId,
    fix: 'IDENTITY_ACCOUNT_URL is unset, so the verification email has no link in it. Set it to the origin that serves /account/verify (Hub).',
  })
}
