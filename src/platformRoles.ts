/**
 * Platform roles, and the audit record that authorises every one of them.
 *
 * `users.roles` is identity's column, so the guard on it is identity's to build. Migration 12 is
 * where the actual security property lives — a partial unique index that permits exactly one
 * `source = 'bootstrap'` grant per database for ever, and a deferred constraint trigger that
 * refuses any row which GAINS a privileged role without a grant row written in the same
 * transaction. Read that migration first; this file is the one legitimate way to satisfy it from
 * inside the service, not the place the rule is decided.
 *
 * That split is the whole point. The threat model for a privilege escalation includes an operator
 * holding a psql connection — it has to, because the estate's bootstrap is itself a database step —
 * and a check that lives only here would be a check that the attacker is already past. Everything
 * below could be deleted and a second unapproved administrator would still be impossible.
 *
 * ## Why there is no bootstrap function here
 *
 * There deliberately is not one, and it is not an omission. `admin-api/src/actions.ts` argues that
 * a service which can mint its own first administrator is a service whose compromise grants the
 * estate, and that admin-api's four-eyes queue cannot authorise the FIRST grant because approving
 * one requires an operator who already holds the role. Both halves of that argument apply here
 * exactly as they apply there. The first grant is a runbook step run against the database by a
 * human, once; migration 12 carries the transaction verbatim. A deploy-time bootstrap token was
 * weighed and refused in `admin-api/src/bootstrap.test.ts` — it would live in an environment file,
 * so a leaked compose file would be a full compromise, and unlike a database grant it leaves no row
 * behind. Nothing here re-opens it.
 *
 * ## Why the route is a SERVICE lane and not `authenticateAdmin`
 *
 * `PUT /internal/users/:id/roles` is reachable only by a service token holding `identity:admin` —
 * in practice admin-api's approval executor, carrying an approval id, which is two operators'
 * signatures. An operator's own token is refused, and that refusal is the design: a human with the
 * `admin` role who could promote directly would be a single pair of eyes, which is precisely what
 * the approval queue exists to stop.
 */

import type { Role } from '@cloudsforge/contracts-auth'
import { withOutbox, type Db } from './outbox.ts'

/**
 * The roles a grant row is required for.
 *
 * The same list as `platform_role_grants_role_known` and as the trigger's `privileged` array in
 * migration 12 — three copies, in the two places that can enforce and the one that can explain,
 * asserted equal in `migrations.test.ts`. `player` is deliberately absent: every account gets it at
 * registration, so requiring a grant for it would mean a grant row per user, and the first such row
 * would spend the one-per-database bootstrap slot on somebody's sign-up.
 */
export const PRIVILEGED_ROLES: readonly Role[] = Object.freeze(['admin'])

/** Every role `users.roles` may contain. `contracts-auth`'s `Role` union, as a runtime value. */
export const PLATFORM_ROLES: readonly Role[] = Object.freeze(['player', 'admin'])

export function isPrivilegedRole(role: string): boolean {
  return (PRIVILEGED_ROLES as readonly string[]).includes(role)
}

export function isPlatformRole(role: string): role is Role {
  return (PLATFORM_ROLES as readonly string[]).includes(role)
}

/** The subject does not exist. Answered 404 — there is nothing to promote. */
export class UserNotFoundError extends Error {
  constructor(userId: string) {
    super(`no user ${userId}`)
    this.name = 'UserNotFoundError'
  }
}

/** A role string that is not a platform role. Answered 400, and never written. */
export class UnknownPlatformRoleError extends Error {
  readonly roles: readonly string[]
  constructor(roles: readonly string[]) {
    super(`not platform roles: ${roles.join(', ')} (known: ${PLATFORM_ROLES.join(', ')})`)
    this.name = 'UnknownPlatformRoleError'
    this.roles = roles
  }
}

export interface RoleChangeInput {
  readonly userId: string
  /** The COMPLETE resulting set, not a delta. A partial update cannot express a revocation. */
  readonly roles: readonly string[]
  /** Who asked. An operator identifier out of admin-api's queue, not this service's caller. */
  readonly actor: string
  readonly reason: string
  /** admin-api's approval id: two operators signed for this. Written onto every grant row. */
  readonly approvalId: string
  readonly correlationId?: string
}

export interface RoleChange {
  readonly userId: string
  readonly previousRoles: readonly Role[]
  readonly roles: readonly Role[]
  /** Privileged roles newly held, each of which left a `platform_role_grants` row behind. */
  readonly granted: readonly Role[]
  readonly revoked: readonly Role[]
}

/**
 * Set a user's platform roles, writing a grant row for every privileged role they gain.
 *
 * One transaction, and it has to be: the deferred trigger refuses the update at COMMIT unless the
 * grant rows are in the same transaction, so a future edit that moves the insert out — or forgets
 * it — fails loudly at the database rather than quietly producing an untrailed administrator. That
 * is the reason the audit is not merely "written next to" the promotion but genuinely inseparable
 * from it.
 *
 * The row is locked FOR UPDATE before the previous set is read. Without it two concurrent calls
 * both compute `granted` against the same starting set, and the second silently writes no grant row
 * for a role it believes was already held — the trigger would then pass, because the first
 * transaction's row exists and (crucially) is not from this transaction, so it would actually
 * REFUSE. Either way the lock is what makes the outcome a decision rather than a race.
 */
export async function setPlatformRoles(sql: Db, input: RoleChangeInput): Promise<RoleChange> {
  const unknown = input.roles.filter((role) => !isPlatformRole(role))
  if (unknown.length > 0) throw new UnknownPlatformRoleError(unknown)
  // De-duplicated so a caller cannot smuggle a second copy of a role past a length comparison, and
  // ordered so the stored array and the emitted payload do not depend on request key order.
  const next = [...new Set(input.roles)].filter(isPlatformRole).sort()

  return withOutbox(sql, 'identity', async (tx, emit) => {
    const rows = await tx<{ id: string; roles: readonly Role[] }[]>`
      select id, roles from users where id = ${input.userId} for update
    `
    const row = rows[0]
    if (!row) throw new UserNotFoundError(input.userId)

    const previous = [...row.roles].sort()
    const granted = next.filter((role) => !previous.includes(role))
    const revoked = previous.filter((role) => !next.includes(role))

    for (const role of granted.filter(isPrivilegedRole)) {
      // `source = 'approval'` and never 'bootstrap'. The bootstrap slot is one per database for
      // ever and belongs to the runbook; a service that could spend it is a service that could mint
      // an administrator answering to nothing, which is the whole thing this design refuses.
      await tx`
        insert into platform_role_grants (user_id, role, source, approval_id, actor, reason)
        values (${input.userId}, ${role}, 'approval', ${input.approvalId}, ${input.actor}, ${input.reason})
      `
    }

    await tx`update users set roles = ${next as Role[]} where id = ${input.userId}`

    emit({
      topic: 'identity.role.changed',
      // `user_id`, matching every other identity topic that is about a person. `activity` reads the
      // owner straight off the key, and a key holding anything else files the fact in nobody's feed
      // — the defect `identity.session.created` was found to have.
      key: input.userId,
      payload: {
        userId: input.userId,
        roles: next,
        previousRoles: previous,
        granted,
        revoked,
        approvalId: input.approvalId,
        reason: input.reason,
      },
      actor: input.actor,
      ...(input.correlationId === undefined ? {} : { correlationId: input.correlationId }),
    })

    return { userId: input.userId, previousRoles: previous, roles: next, granted, revoked }
  })
}

export interface PlatformRoleGrantRow {
  readonly id: string
  readonly user_id: string
  readonly role: string
  readonly source: 'bootstrap' | 'approval'
  readonly approval_id: string | null
  readonly actor: string
  readonly reason: string
  readonly granted_at: Date
}

/**
 * The grants a user holds, newest first.
 *
 * Read-only and unfiltered: an administrator's promotion history is exactly the thing an incident
 * asks about, and hiding a revoked-then-regranted role behind a "current" view would answer the
 * wrong question.
 */
export async function listGrantsFor(
  sql: Db,
  userId: string,
): Promise<readonly PlatformRoleGrantRow[]> {
  return sql<PlatformRoleGrantRow[]>`
    select id, user_id, role, source, approval_id, actor, reason, granted_at
      from platform_role_grants
     where user_id = ${userId}
     order by granted_at desc, id
  `
}
