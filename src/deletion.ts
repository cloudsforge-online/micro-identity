/**
 * Account deletion as a lifecycle: `pending_deletion` → publish → tombstone.
 *
 * **None of this exists in the estate today**, which means the platform has no GDPR erasure path at
 * all — and 04-domain-model section 0 is explicit that "soft delete does not exist" and that erasure
 * is a distinct, audited operation driven by `identity.user.deleted`.
 *
 * WHY IT IS THREE STATES AND NOT A `DELETE`. A user id appears in fourteen databases with no
 * cross-service foreign keys, by design (section 11). Deleting the row here would leave every one of
 * them holding an id that resolves to nothing, and no signal that it ever should have been erased.
 * The invariant the model states — "a user row is never hard-deleted while any service still holds
 * records referencing it" — is only satisfiable if the event goes out first and the row survives
 * long enough for a subscriber that failed and retried to have something to reconcile against.
 *
 *   1. **Request.** Status becomes `pending_deletion`, every session is revoked, and
 *      `identity.user.deleted` is written **in the same transaction**. A publish after commit is a
 *      publish that is skipped when the process dies in between — for this topic, an erasure that
 *      silently did not happen.
 *   2. **Grace.** `IDENTITY_DELETION_GRACE_DAYS`, default seven. Subscribers erase; a deletion
 *      driven by a hijacked session can be cancelled by its real owner, who has been signed out
 *      everywhere and will notice.
 *   3. **Tombstone.** The row keeps only its id and its dates. Everything that identifies a person
 *      — address, handle, credential, profile, factors — is gone or overwritten.
 *
 * WHAT THE TOMBSTONE KEEPS AND WHY. The `id` and the timestamps, and nothing else. The id is the
 * thing fourteen databases reference, and keeping it is what lets a later question — "was this
 * subject erased, or did it never exist" — be answered at all. A row that vanished entirely makes
 * every stale reference indistinguishable from data corruption.
 */

import { createHash } from 'node:crypto'
import { withOutbox, type Db } from './outbox.ts'
import { organisationsOrphanedBy } from './organisations.ts'
import { emitSessionRevoked } from './sessions.ts'

/** The user is the sole owner of an organisation that is not theirs alone. */
export class WouldOrphanOrganisationsError extends Error {
  readonly organisations: readonly string[]
  constructor(organisations: readonly string[]) {
    super(
      `hand over or close these organisations first, or they will be left with no owner: ${organisations.join(', ')}`,
    )
    this.name = 'WouldOrphanOrganisationsError'
    this.organisations = organisations
  }
}

export class NotPendingDeletionError extends Error {
  constructor() {
    super('this account is not scheduled for deletion')
    this.name = 'NotPendingDeletionError'
  }
}

export interface DeletionRequested {
  readonly userId: string
  readonly tombstoneAt: string
  readonly sessionsRevoked: number
}

/**
 * Step 1. Mark the account, revoke everything, and publish — atomically.
 *
 * Refused when the user is the last owner of a shared organisation. That check is here rather than
 * left to the database because `memberships` cascades on delete: the last-owner invariant cannot
 * see a cascade and cannot refuse one, so the only place to catch it is before the lifecycle starts.
 * The alternative is discovering, a week later, that a team's billing and projects belong to nobody.
 */
export async function requestDeletion(
  sql: Db,
  input: { userId: string; graceDays: number; correlationId: string; actor: string },
): Promise<DeletionRequested> {
  const stranded = await organisationsOrphanedBy(sql, input.userId)
  if (stranded.length > 0) throw new WouldOrphanOrganisationsError(stranded)

  const tombstoneAt = new Date(Date.now() + input.graceDays * 24 * 60 * 60 * 1000)

  return withOutbox(sql, 'identity', async (tx, emit) => {
    const updated = await tx<{ id: string }[]>`
      update users
         set status = 'pending_deletion', pending_deletion_at = now()
       where id = ${input.userId} and status <> 'deleted'
      returning id
    `
    if (updated.length === 0) throw new NotPendingDeletionError()

    // Every session, with no exception for the one making the request: an account being deleted has
    // no session worth keeping, and leaving one live would let the deletion be reversed by whoever
    // started it rather than by whoever owns the account.
    const sessions = await tx<{ id: string }[]>`
      update sessions
         set status = 'revoked', revoked_at = now(), revoke_reason = 'account_deletion_requested'
       where user_id = ${input.userId} and status = 'active'
      returning id
    `
    await tx`
      update refresh_tokens t set revoked = true
        from sessions s
       where s.id = t.session_id and s.user_id = ${input.userId} and t.revoked = false
    `
    // Announced like every other revocation. `account_deletion_requested` is not `signed_out`, so
    // notify alerts on it — which is correct and is the point: if somebody ELSE asked for this
    // account to be deleted, the alert on every device losing access is how the owner finds out
    // while the grace window is still open and the deletion can still be cancelled.
    for (const session of sessions) {
      emitSessionRevoked(emit, {
        sessionId: session.id,
        userId: input.userId,
        reason: 'account_deletion_requested',
        correlationId: input.correlationId,
      })
    }

    emit({
      topic: 'identity.user.deleted',
      key: input.userId,
      payload: {
        userId: input.userId,
        // The deadline travels with the event so a subscriber knows how long it has, rather than
        // having to know this service's configuration.
        tombstoneAt: tombstoneAt.toISOString(),
        reason: 'user_requested',
      },
      actor: input.actor,
      correlationId: input.correlationId,
    })

    return {
      userId: input.userId,
      tombstoneAt: tombstoneAt.toISOString(),
      sessionsRevoked: sessions.length,
    }
  })
}

/**
 * Cancel a pending deletion, inside the grace window.
 *
 * The window exists so this is possible. Sessions are NOT restored — they were revoked and a
 * revocation is final — so the user signs in again, which is the proof of ownership that makes the
 * cancellation trustworthy.
 */
export async function cancelDeletion(sql: Db, userId: string): Promise<boolean> {
  const rows = await sql<{ id: string }[]>`
    update users set status = 'active', pending_deletion_at = null
     where id = ${userId} and status = 'pending_deletion'
    returning id
  `
  return rows.length > 0
}

/**
 * Step 3. Tombstone one account. Idempotent.
 *
 * **The email and handle are overwritten rather than nulled**, and that is not cosmetic. Both are
 * `not null` and both carry unique indexes; nulling is impossible, and leaving them would keep the
 * person's address in the database for ever — the opposite of erasure. Replacing them with a value
 * derived from the id frees the real address for reuse (a person who deletes their account and
 * signs up again must be able to) while keeping the indexes satisfied.
 *
 * The replacement is a HASH of the id rather than the id itself. The id is public; putting it in a
 * column shaped like an address invites a future join written by someone who assumes it is one.
 * `.invalid` is reserved by RFC 6761 and can never be a real domain, so a tombstone can never be
 * mailed by accident.
 *
 * **THE CHILD ROWS ARE DELETED EXPLICITLY, and assuming otherwise was a bug this file had.** Every
 * table here declares `on delete cascade` from `users`, which is exactly right for a hard delete and
 * does nothing at all for a tombstone — a tombstone is an UPDATE, and an UPDATE fires no cascade. The
 * profile survived erasure, complete with display name, bio and country, on a row marked `deleted`.
 * The lesson generalises: a lifecycle that ends in a state rather than in a missing row cannot lean
 * on referential actions for any part of its meaning.
 */
export async function tombstoneAccount(sql: Db, userId: string): Promise<boolean> {
  const opaque = createHash('sha256').update(`tombstone:${userId}`).digest('hex').slice(0, 32)
  const outcome = await sql.begin(async (tx) => {
    // The old address is returned so the rows keyed on it — rather than on the id — can be cleared
    // in the same transaction. Reading it after the update would read the tombstone.
    const rows = await tx<{ id: string; email: string }[]>`
      with previous as (select id, email from users where id = ${userId})
      update users
         set status = 'deleted',
             deleted_at = now(),
             email = ${`${opaque}@deleted.invalid`},
             handle = ${`deleted_${opaque.slice(0, 12)}`},
             handle_key = ${`deleted_${opaque.slice(0, 12)}`},
             -- Not a hash of anything. A row whose password_hash is a valid-looking scrypt output
             -- is a row somebody could, in principle, authenticate against; this cannot be produced
             -- by hashPassword and so cannot ever verify.
             password_hash = 'tombstone',
             hash_algo = 'tombstone',
             roles = '{}',
             email_verified_at = null,
             last_seen_at = null,
             pending_deletion_at = null
        from previous
       where users.id = previous.id and users.status = 'pending_deletion'
      returning users.id, previous.email
    `
    if (rows.length === 0) return { done: false }
    const previousEmail = rows[0]!.email

    // The profile is the sharp one: display name, bio, country, links. Everything a product renders
    // about a person, on a row whose status says they are gone.
    await tx`delete from profiles where user_id = ${userId}`
    // A device row is a fingerprint hash and a browser family — a record of what somebody used.
    // Sessions cascade their refresh tokens, and factors cascade their recovery codes, so those two
    // deletes cover four tables between them.
    await tx`delete from devices where user_id = ${userId}`
    await tx`delete from sessions where user_id = ${userId}`
    await tx`delete from mfa_factors where user_id = ${userId}`
    await tx`delete from mfa_challenges where user_id = ${userId}`
    await tx`delete from password_reset_tokens where user_id = ${userId}`
    await tx`delete from auth_exchange_codes where user_id = ${userId}`
    // Keyed on the address rather than the id, so it would otherwise outlive the address itself.
    await tx`delete from login_attempts where email = ${previousEmail}`

    /* The personal organisation goes with its owner, and only the personal one.
     *
     * `requestDeletion` refuses to start if this user is the sole owner of anything shared, so by
     * the time execution reaches here every remaining membership is either a personal organisation
     * or one that has another owner. Deleting the memberships and then the now-empty personal
     * organisations is safe in that order; doing it the other way would cascade the memberships out
     * from under the check that made it safe. */
    const personal = await tx<{ id: string }[]>`
      select o.id from organisations o
        join memberships m on m.organisation_id = o.id
       where m.user_id = ${userId} and o.kind = 'personal'
    `
    await tx`delete from memberships where user_id = ${userId}`
    for (const organisation of personal) {
      await tx`delete from organisations where id = ${organisation.id}`
    }
    return { done: true }
  })
  return outcome.done
}

/** Accounts whose grace window has elapsed and are ready to be tombstoned. */
export async function dueForTombstone(sql: Db, graceDays: number, limit = 100): Promise<string[]> {
  const rows = await sql<{ id: string }[]>`
    select id from users
     where status = 'pending_deletion'
       and pending_deletion_at is not null
       and pending_deletion_at <= now() - make_interval(days => ${graceDays})
     order by pending_deletion_at
     limit ${limit}
  `
  return rows.map((row) => row.id)
}
