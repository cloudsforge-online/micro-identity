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
import { withOutbox, type Db, type Tx } from './outbox.ts'

const TOKEN_TTL_MS = 30 * 60_000

const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex')

export interface IssuedReset {
  /** The raw token. This is the only moment it exists outside the recipient's mailbox. */
  readonly token: string
  readonly expiresAt: Date
  /** False when `IDENTITY_ACCOUNT_URL` is unset, so no link could be built. See `buildResetUrl`. */
  readonly linkable: boolean
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
    await mintResetToken(tx, userId, token, issuedBy, expiresAt)
  })
  return { token, expiresAt, linkable: env.accountUrl !== null }
}

/**
 * The rows, inside the caller's transaction.
 *
 * Private, and split out for the reason `mintVerificationToken` is (emailVerification.ts): the
 * advisory lock above only means anything if everything that must be atomic with it is inside the
 * same transaction. `deliverPasswordReset` needs the outbox row in there too, and a second public
 * "mint" that took its own transaction would be the door through which that stops being true.
 */
async function mintResetToken(
  tx: Tx,
  userId: string,
  token: string,
  issuedBy: string | null,
  expiresAt: Date,
): Promise<void> {
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
}

/**
 * The absolute reset link carrying a token, or null when no account origin is configured.
 *
 * **THE HOST COMES FROM CONFIGURATION, NOT FROM THE REQUEST**, and that is half of this function.
 * It takes no request at all, which is stronger than taking one and ignoring it: there is nothing
 * here for a future edit to reach for. A `Host`-derived link is unauthenticated account takeover —
 * a forged header has the deployment's own relay mail the victim a genuine, correctly branded reset
 * whose button points at the attacker, and the fragment does not save it because the attacker's
 * page reads `location.hash` itself.
 *
 * **THE ORIGIN IS HUB'S, NOT THIS SERVICE'S, AND THAT WAS A LIVE DEFECT.** This was built from
 * `env.publicUrl` — identity's own address — for the whole life of the file. `env.ts` says on the
 * field itself that `publicUrl` is "right for identity's own routes and wrong for this one", and on
 * both estates its value is `http://identity:4000`: a host on the internal compose network, over
 * plain HTTP, on a service that routes no `/reset`. While nothing delivered mail that was invisible.
 * The moment `notify` started sending, it became a reset email that mails every locked-out user a
 * plaintext link their browser cannot resolve — the flow reported as working while being incapable
 * of working at all. `IDENTITY_ACCOUNT_URL` is Hub's public origin, it is what the verification link
 * already uses, and `/account/reset` is a page Hub serves.
 *
 * **THE TOKEN GOES AFTER THE '#', NOT AFTER THE '?'.** A fragment is the one part of a URL a
 * browser keeps to itself: it is not in the request line, so it reaches no server log, no
 * reverse-proxy access log and no `Referer` on the next navigation. Nimbus used `?token=` and the
 * consequence was that its own "incoming request" log line wrote the live credential to stdout on
 * the very request that spends it, from where Lantern lifted it into an indexed column and every
 * backup. The telemetry package redacts query values now, and these two defences protect different
 * things: the redaction covers OUR logs, and the fragment covers everything between the user's
 * browser and us, which we do not run and cannot redact. It also decides how the link survives
 * MAIL: a scanner that pre-fetches what it is sent issues `GET /account/reset` carrying nothing, so
 * the single-use credential is not spent before the human ever sees it.
 *
 * Null rather than a link built from some other origin, for the reason `buildVerifyUrl` gives:
 * `IDENTITY_ACCOUNT_URL` is optional and stays optional, and a broken link is worse than none.
 * notify's rule refuses to send a reset with no link — the whole body of that mail is the button,
 * and sending it without one is the shape of a phishing message, sent by us.
 *
 * Split from `resetUrlFor` so both branches are testable without touching `process.env`: `env` is
 * validated at import, so a test cannot unset the variable after the fact.
 */
export function buildResetUrl(accountUrl: string | null, token: string): string | null {
  if (!accountUrl) return null
  return `${accountUrl}/account/reset#token=${encodeURIComponent(token)}`
}

export function resetUrlFor(token: string): string | null {
  return buildResetUrl(env.accountUrl, token)
}

/**
 * The account a live token belongs to, WITHOUT spending it.
 *
 * ## Why the route needs this, and what it cost not to have it
 *
 * The new password cannot be judged until the account is known — `checkPassword` compares it
 * against the handle and the address, which is the check that stops somebody resetting to their own
 * email — and the only thing the request carries that names an account is the token. So the route
 * used to redeem first and validate second, and a password the policy refused therefore answered
 * 400 having ALREADY destroyed the link that carried it. The retry that the 400 explicitly invites
 * answered 401, with nothing to tell the user that their own first attempt was what killed it. The
 * only repair available to them is to request another mail, which is also the loop that has the
 * estate mail one person repeatedly because they picked a short password once.
 *
 * ## Why this does not weaken single use
 *
 * A peek is not a use, and the gate is unchanged: `redeemPasswordResetToken` is still a conditional
 * `update ... returning` and still the only thing that spends anything. Two requests that both peek
 * successfully and both pass validation still race on that update, and it still has exactly one
 * winner — the loser is refused, as it was before. What has moved is only the point at which a
 * REJECTED request stops, and a request that is going to be rejected must not consume the
 * credential it was rejected for.
 *
 * Same predicate as the redemption, deliberately: a peek that accepted a token the redemption would
 * refuse would be a way to ask whether a spent or expired token had ever been real.
 */
export async function peekPasswordResetToken(sql: Db, token: string): Promise<string | null> {
  const rows = await sql<{ user_id: string }[]>`
    select user_id from password_reset_tokens
     where token_hash = ${hashToken(token)} and used_at is null and expires_at > now()
  `
  return rows[0]?.user_id ?? null
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
 * the target architecture `notify` owns every outbound channel, so putting a mail transport here
 * would build the second copy of a thing whose entire purpose is to be the only copy — and would
 * put a network dependency with a six-second attempt budget on the one route that must never let
 * its timing vary.
 *
 * ## The seam is closed, and it is closed onto the path verification already uses
 *
 * This header used to say "until `notify` exists, nothing is sent and an operator issues the link",
 * and that was a real deployment mode rather than an unimplemented one. **The precondition has been
 * met**: `micro-notify` runs on both estates, and the registration → verification → sign-in loop
 * proves identity can already make it send a real message. So this now takes the SAME road, and
 * deliberately not a second one:
 *
 *     mint the token and emit `identity.password.reset_requested` in ONE transaction
 *       → outbox relay → notify `POST /ingest` (HMAC over the raw bytes)
 *       → `RULES['identity.password.reset_requested']` → `security.password_reset` → SMTP.
 *
 * There is no other road available and that is not an accident: notify's only inbound producer path
 * is the signed `/ingest` route, and `POST /admin/broadcasts` REFUSES any template carrying a
 * `secretParams` by construction (notify/src/server.ts, the broadcast guard). A direct
 * identity → notify call would be a mechanism this estate does not have.
 *
 * ## Why the URL is on the event, with #184 open and saying it should not be
 *
 * #184 is right that a live single-use credential on the bus is retained in two databases, and its
 * remedy — emit a reference, let the sender redeem the link at send time — is the right shape for
 * `identity.email.verification_requested`. **It cannot be the shape here, for a reason specific to
 * this table:** the reset token is stored ONLY as its SHA-256 (see `mintResetToken`), so identity
 * physically cannot serve the link back later. Reference-and-redeem for a reset means keeping the
 * raw token in `password_reset_tokens`, which is strictly worse than what #184 already describes —
 * it turns a 30-minute exposure in an outbox row into a permanent one in the credential table.
 *
 * Two things bound it instead, and the second is new.
 *
 * **The TTL**, which is the one place the estate already does what #184 asks for: thirty minutes,
 * not twenty-four hours. #184's own second remedy is "shorten the TTL"; this path was written at
 * 1/48th of the verification window from the start, so a retained row is dead within half an hour
 * of being written.
 *
 * **The sweep does not RETAIN it** — `redactExpiredSecrets` in outbox.ts. #184's real complaint is
 * not that a credential travels, it is that nothing ever removes it: 160 outbox rows and 148 notify
 * rows hold one for ever because no code path was ever going to touch them again. Dead-within-30-
 * minutes is an argument about exploitability and it does not answer that. Stripping the link out
 * of the outbox row once its token has expired does: the rows still accumulate, and what they
 * accumulate is `linkable: false` and a user id rather than a credential. It costs nothing, because
 * by then the string it removes could not reset anything anyway.
 *
 * Four rules the seam is written under, all four load-bearing:
 *
 *   - The reset URL is the only copy of the token in existence outside the event it is emitted on.
 *     It is not logged, not persisted in this service, and not allowed into an error message.
 *   - **A caught error is NEVER logged as an object.** `withOutbox` binds the payload as a query
 *     parameter, and postgres.js attaches `query` and `parameters` to the errors it throws — so
 *     `log.warn(msg, { err })` on this path would write the reset URL to stdout, which is exactly
 *     the incident `resetUrlFor` was written to prevent. Only `name` and `code` escape, and they
 *     are scalars the driver sets.
 *   - **Nothing here may throw.** The caller has already answered 202 and there is no request left
 *     to fail; an escaping rejection is an unhandled one. Failure is reported by return value.
 *   - A different outcome for a known and an unknown address — in status, body or timing — is an
 *     enumeration oracle, so the status string varies with the DEPLOYMENT and never with the
 *     account.
 */
export interface ResetDelivery {
  readonly delivered: boolean
  /** What carried it, for the log line. `none` when the request could not be published. */
  readonly channel: 'none' | 'notify'
}

/** The body of the 202. One string for both branches, always. */
export const RESET_REQUEST_STATUS =
  'If that account exists, a reset has been recorded. It expires in 30 minutes and works once.'

export interface DeliveryLogger {
  info(message: string, fields?: Record<string, unknown>): void
  warn(message: string, fields?: Record<string, unknown>): void
}

/**
 * Mint a reset token and publish the request to send it — one transaction, as verification does.
 *
 * The event and the row land together for rule 5 of docs/ecosystem/03 §2, and here that rule has
 * teeth in both directions: a committed token nobody was told about is a user who waits for mail
 * that will never come, and a committed event for a token that does not exist is a mail whose link
 * is dead on arrival. `withOutbox` collects the emit and writes it inside the same `begin`, so
 * neither state is reachable.
 *
 * Not folded into `createPasswordResetToken`: that one is the operator's mint, called where the
 * link is handed over by another route entirely, and it must not mail anybody.
 */
export async function requestPasswordReset(
  sql: Db,
  user: { readonly id: string; readonly handle: string; readonly email: string },
  issuedBy: string | null,
  correlationId?: string,
): Promise<IssuedReset> {
  const token = randomBytes(32).toString('hex')
  const expiresAt = new Date(Date.now() + TOKEN_TTL_MS)
  // Built here and put on the event, and nowhere else. It can be null: `IDENTITY_ACCOUNT_URL` is
  // optional, and a deployment that has not set it gets `linkable: false` rather than a link to a
  // host nobody can reach. notify refuses to send on that branch, which shows up as a producer
  // defect in its own metrics instead of as mail with a dead button.
  const resetUrl = resetUrlFor(token)

  await withOutbox(sql, 'identity', async (tx, emit) => {
    await mintResetToken(tx, user.id, token, issuedBy, expiresAt)
    emit({
      topic: 'identity.password.reset_requested',
      // Keyed by the user, as every identity topic is: `activity` reads the owner straight off the
      // envelope key, and ordering is per key — two reset requests for one account must be ordered
      // with respect to each other, and supersession makes the later one the only live token.
      key: user.id,
      payload: {
        userId: user.id,
        // The handle, not the display name, for the reason `identity.email.verification_requested`
        // gives: the greeting is built on it and a display name is a field the user can change to
        // something a greeting should not have been built on.
        handle: user.handle,
        // notify learns the address from this event as it does from the verification one. That
        // matters more here than there: every account that predates verification has no target row
        // in notify at all, and a reset is exactly the message such an account needs.
        email: user.email,
        expiresAt: expiresAt.toISOString(),
        // Whether an operator issued it, never WHICH operator. The recipient is told a reset was
        // started for them; naming the staff member who did it is an internal fact in a mailbox.
        issuedByOperator: issuedBy !== null,
        // Always present, so a consumer branches on a field that is always there rather than on the
        // absence of one — the same shape `identity.email.verification_requested` carries. The
        // sweep sets it back to false when it strips a spent link, so a replayed event is refused
        // rather than rendered with an empty href.
        linkable: resetUrl !== null,
        ...(resetUrl === null ? {} : { resetUrl }),
      },
      // The account acts for itself when it asked, and the operator is named on the envelope rather
      // than in the payload when they did — `activity` reads actors, mail bodies do not.
      actor: issuedBy === null ? `user:${user.id}` : `operator:${issuedBy}`,
      ...(correlationId === undefined ? {} : { correlationId }),
    })
  })

  return { token, expiresAt, linkable: resetUrl !== null }
}

/**
 * The whole of delivery, from the caller's point of view, and it cannot throw.
 *
 * The user id is logged and the address is NOT, which is the one place this departs from Nimbus's
 * line: it logged the email at warn on every request, so a log search for an address returned the
 * fact that somebody had asked to reset it. The id joins to the row for an operator and says
 * nothing to anyone reading the log for other reasons. The token appears in no branch.
 *
 * The failure branch is a `warn` and not an `error` on purpose, and it is genuinely recoverable:
 * the transaction rolled back, so no token was minted, and the user's next click starts over.
 */
export async function deliverPasswordReset(
  sql: Db,
  log: DeliveryLogger,
  user: { readonly id: string; readonly handle: string; readonly email: string },
  issuedBy: string | null,
  correlationId?: string,
): Promise<ResetDelivery> {
  try {
    await requestPasswordReset(sql, user, issuedBy, correlationId)
    log.info('password reset requested', {
      audit: 'password_reset_requested',
      userId: user.id,
    })
    return { delivered: true, channel: 'notify' }
  } catch (err) {
    // NOT `{ err }`. See rule 2 in the header: postgres.js hangs `query` and `parameters` off its
    // errors, and one of those parameters is the payload holding the reset URL.
    log.warn('password reset could not be published', {
      audit: 'password_reset_undelivered',
      userId: user.id,
      errorName: err instanceof Error ? err.name : 'unknown',
      errorCode: typeof (err as { code?: unknown })?.code === 'string' ? (err as { code: string }).code : null,
      fix: 'The token and its outbox row are written in one transaction, so nothing was minted and the user can ask again. Check the identity database and the outbox relay.',
    })
    return { delivered: false, channel: 'none' }
  }
}
