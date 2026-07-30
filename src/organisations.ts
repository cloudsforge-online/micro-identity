/**
 * Organisations, memberships and the one invariant that makes them safe to depend on.
 *
 * 04-domain-model section 1.5. None of this exists in the estate today, and it is needed by the
 * developer platform (projects belong to organisations), by the marketplace (verified project
 * teams) and by billing (who pays).
 *
 * **EVERY USER GETS A `personal` ORGANISATION AT REGISTRATION.** Not for tidiness: it means there
 * is never a code path anywhere in the estate that has to handle "this subject has no
 * organisation". A nullable owner is a null check in twenty-two services, nineteen of which will be
 * written and three of which will not.
 *
 * **AN ORGANISATION ALWAYS HAS AT LEAST ONE OWNER.** The last owner can neither leave nor be
 * demoted. This is not expressible as a table constraint — it is a statement about the resulting
 * set after a change, and a row-level check cannot see the other rows at the moment it runs — so it
 * is enforced here, under a lock, using contracts-auth's `wouldOrphanOrganisation`. That function
 * is asked about the RESULT rather than about the departing member on purpose: "demote the last
 * owner" and "remove the last owner" are the same fault, and a check written per-operation catches
 * only the one it was written for.
 */

import {
  ownersOf,
  wouldOrphanOrganisation,
  type Membership,
  type MembershipShape,
  type Organisation,
  type OrganisationRole,
} from '@cloudsforge/contracts-auth'
import { uuidv7 } from './ids.ts'
import type { Db, Tx } from './outbox.ts'

/** The change was refused because it would leave the organisation with nobody answerable for it. */
export class LastOwnerError extends Error {
  readonly organisationId: string
  constructor(organisationId: string) {
    super('an organisation must always have at least one owner')
    this.name = 'LastOwnerError'
    this.organisationId = organisationId
  }
}

export class OrganisationNotFoundError extends Error {
  constructor(id: string) {
    super(`no organisation ${id}`)
    this.name = 'OrganisationNotFoundError'
  }
}

/** The actor is not permitted to change memberships here. */
export class NotAnAdminError extends Error {
  constructor() {
    super('only an owner or an admin of this organisation may change its memberships')
    this.name = 'NotAnAdminError'
  }
}

interface OrganisationRow {
  readonly id: string
  readonly slug: string
  readonly name: string
  readonly kind: Organisation['kind']
  readonly status: Organisation['status']
  readonly created_at: Date
}

const toOrganisation = (row: OrganisationRow): Organisation => ({
  id: row.id,
  slug: row.slug,
  name: row.name,
  kind: row.kind,
  status: row.status,
  createdAt: row.created_at.toISOString(),
})

interface MembershipRow {
  readonly organisation_id: string
  readonly user_id: string
  readonly role: OrganisationRole
  readonly invited_by: string | null
  readonly accepted_at: Date | null
}

const toMembership = (row: MembershipRow): Membership => ({
  organisationId: row.organisation_id,
  userId: row.user_id,
  role: row.role,
  invitedBy: row.invited_by,
  acceptedAt: row.accepted_at?.toISOString() ?? null,
})

/**
 * A slug from a handle. Lower-cased, safe characters only, and suffixed on collision.
 *
 * The suffix is the first eight characters of the organisation's own id rather than a counter: a
 * counter needs a read to find the next free value and two concurrent registrations both read the
 * same one. The id is already unique and already generated, so the collision path costs no extra
 * round trip and cannot itself collide.
 */
export function slugFor(handle: string, organisationId: string, collided = false): string {
  const base =
    handle
      .toLowerCase()
      .replace(/[^a-z0-9-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 32) || 'user'
  return collided ? `${base}-${organisationId.replace(/-/g, '').slice(0, 8)}` : base
}

/**
 * Create a user's personal organisation and make them its owner, inside the registration
 * transaction.
 *
 * `accepted_at` is set immediately: nobody invited them, they are the organisation. An owner whose
 * `accepted_at` is null does not count towards the invariant (see `ownersOf`), so leaving it null
 * here would create an organisation that is orphaned the moment it exists.
 */
export async function createPersonalOrganisation(
  tx: Tx,
  input: { userId: string; handle: string },
): Promise<Organisation> {
  const id = uuidv7()
  const insert = async (slug: string): Promise<OrganisationRow[]> =>
    tx<OrganisationRow[]>`
      insert into organisations (id, slug, name, kind)
      values (${id}, ${slug}, ${input.handle}, 'personal')
      returning id, slug, name, kind, status, created_at
    `

  let rows: OrganisationRow[]
  try {
    rows = await insert(slugFor(input.handle, id))
  } catch (err) {
    // A handle is unique and a slug is derived from it, so this is reachable only when the derived
    // slug collides with a TEAM organisation somebody named freely. Retrying once with the
    // disambiguated form is enough by construction: the suffix comes from a unique id.
    if ((err as { code?: string }).code !== '23505') throw err
    rows = await insert(slugFor(input.handle, id, true))
  }

  await tx`
    insert into memberships (organisation_id, user_id, role, accepted_at)
    values (${id}, ${input.userId}, 'owner', now())
  `
  return toOrganisation(rows[0]!)
}

export async function listOrganisationsFor(
  sql: Db,
  userId: string,
): Promise<(Organisation & { role: OrganisationRole })[]> {
  const rows = await sql<(OrganisationRow & { role: OrganisationRole })[]>`
    select o.id, o.slug, o.name, o.kind, o.status, o.created_at, m.role
      from organisations o
      join memberships m on m.organisation_id = o.id
     where m.user_id = ${userId} and m.accepted_at is not null
     order by o.created_at
  `
  return rows.map((row) => ({ ...toOrganisation(row), role: row.role }))
}

export async function listMemberships(sql: Db, organisationId: string): Promise<Membership[]> {
  const rows = await sql<MembershipRow[]>`
    select organisation_id, user_id, role, invited_by, accepted_at
      from memberships where organisation_id = ${organisationId} order by created_at
  `
  return rows.map(toMembership)
}

export interface ChangeMembershipInput {
  readonly organisationId: string
  /** Who is making the change. Must be an owner or an admin of this organisation. */
  readonly actorUserId: string
  readonly userId: string
  /** `null` removes the membership entirely. */
  readonly nextRole: OrganisationRole | null
}

/**
 * Change or remove one membership, refusing anything that would orphan the organisation.
 *
 * **THE LOCK IS NOT DECORATION.** Read-then-write on a set invariant is the textbook race: two
 * owners resign at the same moment, each transaction reads a membership set containing two owners,
 * each concludes that one will remain, and both commit. The organisation ends with nobody
 * answerable for it, its billing and its projects, and nothing in the schema can express that it is
 * wrong. `pg_advisory_xact_lock` on the organisation id serialises the pair, so the second one
 * reads the first one's result and is refused.
 *
 * The actor check is inside the same transaction and the same lock, so an admin cannot be demoted
 * out from under their own in-flight change.
 */
export async function changeMembership(sql: Db, input: ChangeMembershipInput): Promise<Membership[]> {
  const outcome = await sql.begin(async (tx) => {
    await tx`select pg_advisory_xact_lock(hashtext(${input.organisationId})::bigint)`

    const exists = await tx<{ id: string }[]>`
      select id from organisations where id = ${input.organisationId}
    `
    if (exists.length === 0) throw new OrganisationNotFoundError(input.organisationId)

    const rows = await tx<MembershipRow[]>`
      select organisation_id, user_id, role, invited_by, accepted_at
        from memberships where organisation_id = ${input.organisationId}
    `
    const memberships: MembershipShape[] = rows.map((row) => ({
      userId: row.user_id,
      role: row.role,
      acceptedAt: row.accepted_at?.toISOString() ?? null,
    }))

    const actor = memberships.find((m) => m.userId === input.actorUserId)
    const changingSelf = input.actorUserId === input.userId

    /* LEAVING is the only self-change that needs no authority, and the exemption is written to cover
     * exactly that and nothing else.
     *
     * A member must be able to walk away from an organisation without asking its admins, so
     * `nextRole === null` is always permitted — the orphan check below still refuses if they are the
     * last owner, so they may leave but not leave it empty.
     *
     * Exempting every self-change instead is a privilege escalation, and a quiet one: an admin
     * could set their OWN role to `owner`, which makes "admin" mean "owner with an extra step" and
     * leaves the last-owner rule protecting a set anyone already inside can join. A member could do
     * the same. The distinction is the direction of the change, not who is making it. */
    const leaving = changingSelf && input.nextRole === null
    if (!leaving) {
      if (!actor || actor.acceptedAt === null || (actor.role !== 'owner' && actor.role !== 'admin')) {
        throw new NotAnAdminError()
      }
      // An admin may not create an owner — including by naming themselves.
      if (actor.role === 'admin' && input.nextRole === 'owner') throw new NotAnAdminError()
    }

    if (wouldOrphanOrganisation(memberships, { userId: input.userId, nextRole: input.nextRole })) {
      throw new LastOwnerError(input.organisationId)
    }

    if (input.nextRole === null) {
      await tx`
        delete from memberships
         where organisation_id = ${input.organisationId} and user_id = ${input.userId}
      `
    } else {
      await tx`
        insert into memberships (organisation_id, user_id, role, invited_by, accepted_at)
        values (
          ${input.organisationId},
          ${input.userId},
          ${input.nextRole},
          ${changingSelf ? null : input.actorUserId},
          ${changingSelf ? new Date() : null}
        )
        on conflict (organisation_id, user_id) do update set role = excluded.role
      `
    }

    const after = await tx<MembershipRow[]>`
      select organisation_id, user_id, role, invited_by, accepted_at
        from memberships where organisation_id = ${input.organisationId} order by created_at
    `
    return { memberships: after.map(toMembership) }
  })
  return outcome.memberships
}

/**
 * Accept an outstanding invitation.
 *
 * Separate from `changeMembership` because it is the one transition an invitee performs on their
 * own membership without being a member yet, and folding it into the general path would mean the
 * actor check had to admit a caller who is not in the set.
 */
export async function acceptMembership(
  sql: Db,
  organisationId: string,
  userId: string,
): Promise<Membership | null> {
  const rows = await sql<MembershipRow[]>`
    update memberships set accepted_at = now()
     where organisation_id = ${organisationId} and user_id = ${userId} and accepted_at is null
    returning organisation_id, user_id, role, invited_by, accepted_at
  `
  return rows[0] ? toMembership(rows[0]) : null
}

/**
 * Would removing this user from every organisation they belong to orphan any of them?
 *
 * Asked before account deletion. Deleting a user is a `delete cascade` on `memberships`, which the
 * invariant cannot see and cannot refuse — so it is checked here, and the answer names the
 * organisations that would be stranded rather than saying only that something is wrong. A user who
 * is the sole owner of a team must hand it over before they can leave the platform.
 *
 * Personal organisations are exempt: they are deleted with their owner, and there is nobody to hand
 * one to.
 */
export async function organisationsOrphanedBy(sql: Db, userId: string): Promise<string[]> {
  const rows = await sql<(MembershipRow & { kind: Organisation['kind']; slug: string })[]>`
    select m.organisation_id, m.user_id, m.role, m.invited_by, m.accepted_at, o.kind, o.slug
      from memberships m
      join organisations o on o.id = m.organisation_id
     where o.kind <> 'personal'
       and m.organisation_id in (select organisation_id from memberships where user_id = ${userId})
  `
  const byOrganisation = new Map<string, { slug: string; members: MembershipShape[] }>()
  for (const row of rows) {
    const entry = byOrganisation.get(row.organisation_id) ?? { slug: row.slug, members: [] }
    entry.members.push({
      userId: row.user_id,
      role: row.role,
      acceptedAt: row.accepted_at?.toISOString() ?? null,
    })
    byOrganisation.set(row.organisation_id, entry)
  }

  const stranded: string[] = []
  for (const [organisationId, entry] of byOrganisation) {
    // `ownersOf` on the set with this user removed. Expressed through the same helper the change
    // path uses so the two cannot disagree about what "has an owner" means.
    const remaining = entry.members.filter((m) => m.userId !== userId)
    if (entry.members.some((m) => m.userId === userId) && ownersOf(remaining).length === 0) {
      stranded.push(entry.slug || organisationId)
    }
  }
  return stranded
}
