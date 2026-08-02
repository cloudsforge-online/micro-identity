/**
 * Registration, organisations, and the two invariants that make the rest of the estate able to
 * depend on them: one spelling of an address, and an organisation that always has an owner.
 */

import {
  GOOD_PASSWORD,
  enabled,
  freshEmail,
  freshHandle,
  migrateTestDb,
  openDb,
  resetIdentity,
  skip,
} from './testsupport.ts'
import { before, after, beforeEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { normaliseHandle, ownersOf, wouldOrphanOrganisation } from '@cloudsforge/contracts-auth'
import type postgres from 'postgres'
import {
  LastOwnerError,
  NotAnAdminError,
  OrganisationNotFoundError,
  changeMembership,
  listMemberships,
  listOrganisationsFor,
  organisationsOrphanedBy,
} from './organisations.ts'
import { ConflictError, findUserByIdentifier, registerUser, type UserRow } from './users.ts'
import { uuidv7 } from './ids.ts'
import type { Db } from './outbox.ts'

let sql: postgres.Sql
let db: Db

before(async () => {
  if (!enabled) return
  sql = openDb()
  await migrateTestDb(sql)
  db = sql as unknown as Db
})

after(async () => {
  if (enabled) await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (enabled) await resetIdentity(sql)
})

async function makeUser(email = freshEmail(), handle = freshHandle()): Promise<UserRow> {
  const { user } = await registerUser(db, {
    email,
    handle,
    handleKey: normaliseHandle(handle),
    password: GOOD_PASSWORD,
  })
  return user
}

/** A team organisation with `owner` as its owner, which is the shape the invariant protects. */
async function makeTeam(owner: UserRow): Promise<string> {
  const id = uuidv7()
  await sql`
    insert into organisations (id, slug, name, kind) values (${id}, ${`team-${id.slice(0, 8)}`}, 'A team', 'team')
  `
  await sql`
    insert into memberships (organisation_id, user_id, role, accepted_at)
    values (${id}, ${owner.id}, 'owner', now())
  `
  return id
}

/* ------------------------------------------------------------------ registration */

test('registration writes the user, the profile and a personal organisation atomically', { skip }, async () => {
  const handle = freshHandle()
  const email = freshEmail()
  const { user, organisation } = await registerUser(db, {
    email,
    handle,
    handleKey: normaliseHandle(handle),
    password: GOOD_PASSWORD,
  })

  assert.equal(user.email, email.toLowerCase())
  assert.equal(user.status, 'active')
  assert.deepEqual(user.roles, ['player'])
  assert.ok(user.hash_algo.startsWith('scrypt$'), 'the work factor is recorded, so it is upgradable')

  const profiles = await sql<{ user_id: string }[]>`select user_id from profiles where user_id = ${user.id}`
  assert.equal(profiles.length, 1, 'a user with no profile is a user no product can render')

  // Every user gets a personal organisation, so there is never a code path anywhere in the estate
  // that has to handle "this subject has no organisation".
  assert.equal(organisation.kind, 'personal')
  const memberships = await listMemberships(db, organisation.id)
  assert.equal(memberships.length, 1)
  assert.equal(memberships[0]!.role, 'owner')
  // Accepted immediately: nobody invited them, they ARE the organisation. An owner whose accepted_at
  // is null does not count towards the invariant, so leaving it null would create an organisation
  // that is orphaned the moment it exists.
  assert.ok(memberships[0]!.acceptedAt)
  assert.equal(ownersOf(memberships.map((m) => ({ ...m }))).length, 1)
})

/**
 * **`identity.user.registered` had never once been emitted.**
 *
 * The registry declares the topic. `notify` renders it as the first thing the platform ever says
 * to someone, `activity` files it as "Your account was created." and `analytics` counts it as the
 * denominator of every onboarding cohort. All three were holding code for a message no producer
 * ever sent, and the only thing at the end of a grep was the route's `audit: 'user_registered'`
 * log line — which is why it survived: something with the right words in it was always found.
 *
 * The event is asserted to be in the outbox in the same transaction as the account, because that
 * is what makes the registry's description of it ("an account exists, with its personal
 * organisation already created") true rather than merely intended.
 */
test('registration puts identity.user.registered on the bus, keyed by the user', { skip }, async () => {
  const handle = freshHandle()
  await sql`delete from outbox`

  const { user, organisation } = await registerUser(db, {
    email: freshEmail(),
    handle,
    handleKey: normaliseHandle(handle),
    password: GOOD_PASSWORD,
  })

  const events = await sql<{ topic: string; key: string; payload: Record<string, unknown> }[]>`
    select topic, key, payload from outbox where topic = 'identity.user.registered'
  `
  assert.equal(events.length, 1, 'three services classify this topic and nothing emitted it')
  // Keyed by the user. `activity` reads the owner straight off the key for this topic, so any
  // other key files every registration in nobody's feed.
  assert.equal(events[0]!.key, user.id)
  assert.equal(events[0]!.payload['userId'], user.id)
  // notify's template greets the user by handle, not by the profile display name — which is a
  // field a user can later change to something the greeting should not have been built on.
  assert.equal(events[0]!.payload['handle'], handle)
  // The organisation is named on the event because the registry's description promises it exists
  // by the time anyone reads this.
  assert.equal(events[0]!.payload['organisationId'], organisation.id)
  assert.equal(events[0]!.payload['organisationSlug'], organisation.slug)
})

test('a registration that loses the uniqueness race emits nothing', { skip }, async () => {
  // The event is written inside the transaction, so a conflict must take it with it. An outbox
  // row for an account that does not exist would have every consumer create a user that never
  // registered — the exact failure the same-transaction rule exists to prevent.
  const handle = freshHandle()
  const email = freshEmail()
  const input = { email, handle, handleKey: normaliseHandle(handle), password: GOOD_PASSWORD }
  await registerUser(db, input)
  await sql`delete from outbox`

  await assert.rejects(registerUser(db, input), ConflictError)

  const events = await sql`select 1 from outbox where topic = 'identity.user.registered'`
  assert.equal(events.length, 0)
})

/**
 * **The live defect this service closes.**
 *
 * Nimbus matches the address verbatim on register and login but `lower(email)` on forgot-password,
 * so an account created as `Sam@example.com` can be reset by someone who typed it in lowercase and
 * then cannot be signed into by them.
 */
test('an address is normalised on write, so every path finds one spelling', { skip }, async () => {
  const handle = freshHandle()
  const { user } = await registerUser(db, {
    email: '  Sam.Person@Example.TEST  ',
    handle,
    handleKey: normaliseHandle(handle),
    password: GOOD_PASSWORD,
  })
  assert.equal(user.email, 'sam.person@example.test')

  // Sign-in and recovery both look the normalised value up, and find the same row.
  const found = await findUserByIdentifier(db, 'sam.person@example.test', 'email')
  assert.equal(found?.id, user.id)
  const byHandle = await findUserByIdentifier(db, normaliseHandle(handle), 'handle')
  assert.equal(byHandle?.id, user.id)
})

test('a second account differing only by case is refused by the database', { skip }, async () => {
  await makeUser('Sam@Example.test', freshHandle())
  // The unique index on lower(email) is what actually decides — which is why registration does not
  // pre-check and then race, the way Nimbus does.
  await assert.rejects(makeUser('sam@EXAMPLE.TEST', freshHandle()), ConflictError)
  await assert.rejects(makeUser('SAM@example.test', freshHandle()), ConflictError)
})

test('a handle differing only by case is refused too', { skip }, async () => {
  await makeUser(freshEmail(), 'Alice42')
  // Without this, `Alice` and `alice` are two accounts and the second exists only to be mistaken
  // for the first.
  await assert.rejects(makeUser(freshEmail(), 'alice42'), ConflictError)
})

test('the conflict never says WHICH field collided', { skip }, async () => {
  // Distinguishing them would turn registration into an oracle for whether an address has an
  // account — the same thing the reset route is carefully shaped not to say.
  const user = await makeUser()
  try {
    await makeUser(user.email, freshHandle())
    assert.fail('expected a conflict')
  } catch (err) {
    assert.ok(err instanceof ConflictError)
    assert.ok(!err.message.includes(user.email))
    assert.match(err.message, /email address or handle/)
  }
})

test('two simultaneous registrations of one address produce one account', { skip }, async () => {
  const email = freshEmail()
  const results = await Promise.allSettled([
    makeUser(email, freshHandle()),
    makeUser(email, freshHandle()),
  ])
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1)
  const loser = results.find((r) => r.status === 'rejected')
  assert.ok(loser && loser.reason instanceof ConflictError, 'a lost race is a 409, not a 500')
})

/* ------------------------------------------------------------------ the owner invariant */

test('a member may be added, promoted and demoted by an owner', { skip }, async () => {
  const owner = await makeUser()
  const other = await makeUser()
  const organisationId = await makeTeam(owner)

  await changeMembership(db, { organisationId, actorUserId: owner.id, userId: other.id, nextRole: 'member' })
  let memberships = await listMemberships(db, organisationId)
  assert.equal(memberships.find((m) => m.userId === other.id)?.role, 'member')
  // An invitation is outstanding until it is accepted: an unaccepted owner is not yet an owner.
  assert.equal(memberships.find((m) => m.userId === other.id)?.acceptedAt, null)
  assert.equal(memberships.find((m) => m.userId === other.id)?.invitedBy, owner.id)

  await changeMembership(db, { organisationId, actorUserId: owner.id, userId: other.id, nextRole: 'admin' })
  memberships = await listMemberships(db, organisationId)
  assert.equal(memberships.find((m) => m.userId === other.id)?.role, 'admin')
})

/**
 * **The last-owner rule.**
 *
 * `wouldOrphanOrganisation` is asked about the RESULTING set rather than about the departing member,
 * because "demote the last owner" and "remove the last owner" are the same fault and a check written
 * per-operation catches only the one it was written for. Both are asserted here for that reason.
 */
test('the last owner can neither leave nor be demoted', { skip }, async () => {
  const owner = await makeUser()
  const organisationId = await makeTeam(owner)

  await assert.rejects(
    changeMembership(db, { organisationId, actorUserId: owner.id, userId: owner.id, nextRole: null }),
    LastOwnerError,
    'removing the last owner must be refused',
  )
  await assert.rejects(
    changeMembership(db, { organisationId, actorUserId: owner.id, userId: owner.id, nextRole: 'admin' }),
    LastOwnerError,
    'demoting the last owner is the same fault',
  )
  await assert.rejects(
    changeMembership(db, { organisationId, actorUserId: owner.id, userId: owner.id, nextRole: 'read' }),
    LastOwnerError,
  )

  const memberships = await listMemberships(db, organisationId)
  assert.equal(ownersOf(memberships.map((m) => ({ ...m }))).length, 1, 'the refusal must not half-apply')
})

test('an unaccepted owner does not satisfy the invariant', { skip }, async () => {
  const owner = await makeUser()
  const invitee = await makeUser()
  const organisationId = await makeTeam(owner)

  // An invitation nobody has answered cannot be the thing keeping an organisation alive: if it
  // counted, the last owner could leave by inviting an address that never replies.
  await sql`
    insert into memberships (organisation_id, user_id, role, invited_by)
    values (${organisationId}, ${invitee.id}, 'owner', ${owner.id})
  `
  await assert.rejects(
    changeMembership(db, { organisationId, actorUserId: owner.id, userId: owner.id, nextRole: null }),
    LastOwnerError,
  )

  // Once accepted, it does.
  await sql`
    update memberships set accepted_at = now()
     where organisation_id = ${organisationId} and user_id = ${invitee.id}
  `
  await changeMembership(db, { organisationId, actorUserId: owner.id, userId: owner.id, nextRole: null })
  const memberships = await listMemberships(db, organisationId)
  assert.equal(ownersOf(memberships.map((m) => ({ ...m }))).length, 1)
})

/**
 * Read-then-write on a set invariant is the textbook race, and this is the reproduction.
 *
 * Two owners resign at the same moment: each transaction reads a set containing two owners, each
 * concludes that one will remain, and both commit. The organisation ends with nobody answerable for
 * it, its billing or its projects, and nothing in the schema can express that it is wrong.
 */
test('two owners resigning at the same instant cannot both succeed', { skip }, async () => {
  const first = await makeUser()
  const second = await makeUser()
  const organisationId = await makeTeam(first)
  await sql`
    insert into memberships (organisation_id, user_id, role, accepted_at)
    values (${organisationId}, ${second.id}, 'owner', now())
  `

  const results = await Promise.allSettled([
    changeMembership(db, { organisationId, actorUserId: first.id, userId: first.id, nextRole: null }),
    changeMembership(db, { organisationId, actorUserId: second.id, userId: second.id, nextRole: null }),
  ])
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1)
  assert.ok(results.find((r) => r.status === 'rejected')?.reason instanceof LastOwnerError)

  const memberships = await listMemberships(db, organisationId)
  assert.equal(ownersOf(memberships.map((m) => ({ ...m }))).length, 1, 'the lock is what makes this true')
})

test('the helper agrees with the enforcement, for both shapes of the fault', { skip }, async () => {
  const only = [{ userId: 'a', role: 'owner' as const, acceptedAt: '2026-01-01T00:00:00.000Z' }]
  assert.equal(wouldOrphanOrganisation(only, { userId: 'a', nextRole: null }), true)
  assert.equal(wouldOrphanOrganisation(only, { userId: 'a', nextRole: 'admin' }), true)
  assert.equal(wouldOrphanOrganisation(only, { userId: 'b', nextRole: 'member' }), false)
})

/* ------------------------------------------------------------------ who may change what */

test('a plain member may not change anyone else, but may always leave', { skip }, async () => {
  const owner = await makeUser()
  const member = await makeUser()
  const bystander = await makeUser()
  const organisationId = await makeTeam(owner)
  for (const user of [member, bystander]) {
    await sql`
      insert into memberships (organisation_id, user_id, role, accepted_at)
      values (${organisationId}, ${user.id}, 'member', now())
    `
  }

  await assert.rejects(
    changeMembership(db, { organisationId, actorUserId: member.id, userId: bystander.id, nextRole: 'admin' }),
    NotAnAdminError,
  )
  // Leaving is always permitted: a member must be able to walk away without asking the admins.
  await changeMembership(db, { organisationId, actorUserId: member.id, userId: member.id, nextRole: null })
  assert.equal((await listMemberships(db, organisationId)).length, 2)
})

/**
 * Self-promotion, which is the escalation the "leaving is always permitted" exemption invites.
 *
 * If every self-change were exempt from the actor check, an admin could set their OWN role to
 * `owner` — making "admin" mean "owner with an extra step" and leaving the last-owner rule
 * protecting a set anyone already inside can join. A plain member could do the same. The exemption
 * is for the direction of the change, not for who is making it.
 */
test('an admin may not create an owner, including by naming themselves', { skip }, async () => {
  const owner = await makeUser()
  const admin = await makeUser()
  const member = await makeUser()
  const organisationId = await makeTeam(owner)
  await sql`
    insert into memberships (organisation_id, user_id, role, accepted_at)
    values (${organisationId}, ${admin.id}, 'admin', now())
  `
  await sql`
    insert into memberships (organisation_id, user_id, role, accepted_at)
    values (${organisationId}, ${member.id}, 'member', now())
  `

  await assert.rejects(
    changeMembership(db, { organisationId, actorUserId: admin.id, userId: admin.id, nextRole: 'owner' }),
    NotAnAdminError,
    'an admin must not self-promote',
  )
  await assert.rejects(
    changeMembership(db, { organisationId, actorUserId: admin.id, userId: member.id, nextRole: 'owner' }),
    NotAnAdminError,
    'nor promote anyone else to owner',
  )
  await assert.rejects(
    changeMembership(db, { organisationId, actorUserId: member.id, userId: member.id, nextRole: 'admin' }),
    NotAnAdminError,
    'and a member must not self-promote either',
  )

  // But an owner may, and an admin may still do everything below `owner`.
  await changeMembership(db, { organisationId, actorUserId: admin.id, userId: member.id, nextRole: 'billing' })
  await changeMembership(db, { organisationId, actorUserId: owner.id, userId: admin.id, nextRole: 'owner' })
  const memberships = await listMemberships(db, organisationId)
  assert.equal(memberships.find((m) => m.userId === admin.id)?.role, 'owner')
  assert.equal(memberships.find((m) => m.userId === member.id)?.role, 'billing')
})

test('an unknown organisation is not found rather than silently succeeding', { skip }, async () => {
  const user = await makeUser()
  await assert.rejects(
    changeMembership(db, { organisationId: uuidv7(), actorUserId: user.id, userId: user.id, nextRole: null }),
    OrganisationNotFoundError,
  )
})

/* ------------------------------------------------------------------ deletion's precondition */

test('deleting a sole owner of a TEAM is caught before the lifecycle starts', { skip }, async () => {
  // `memberships` cascades on delete, and the invariant cannot see a cascade and cannot refuse one.
  // The only place to catch it is before the deletion begins; the alternative is discovering a week
  // later that a team's billing and projects belong to nobody.
  const owner = await makeUser()
  await makeTeam(owner)
  const stranded = await organisationsOrphanedBy(db, owner.id)
  assert.equal(stranded.length, 1)
})

test('a personal organisation is exempt — there is nobody to hand it to', { skip }, async () => {
  const user = await makeUser()
  assert.deepEqual(await organisationsOrphanedBy(db, user.id), [])
  assert.equal((await listOrganisationsFor(db, user.id)).length, 1)
})

test('a team with a second owner strands nothing', { skip }, async () => {
  const first = await makeUser()
  const second = await makeUser()
  const organisationId = await makeTeam(first)
  await sql`
    insert into memberships (organisation_id, user_id, role, accepted_at)
    values (${organisationId}, ${second.id}, 'owner', now())
  `
  assert.deepEqual(await organisationsOrphanedBy(db, first.id), [])
})
