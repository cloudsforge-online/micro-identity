/**
 * The account itself: registration, lookup, and the two ways a password changes.
 *
 * **THE EMAIL IS NORMALISED ON WRITE, EVERY TIME, THROUGH ONE FUNCTION.** That is the live defect
 * this file exists to close. Nimbus matches the address verbatim on register and login but
 * `lower(email)` on forgot-password, so an account created as `Sam@example.com` can have its
 * password reset by someone who typed it in lowercase and then cannot be logged into by them — the
 * reset silently succeeds and the user is locked out of their own account by their own shift key.
 * `contracts-auth`'s `normaliseEmail` is the only normalisation in the estate, every write path
 * here goes through it, and migration 10 puts a unique index on `lower(email)` so a second spelling
 * cannot exist even if a future writer forgets.
 *
 * The handle gets the same treatment for the same reason, through `normaliseHandle`: without it
 * `Alice` and `alice` are two accounts and the second exists only to be mistaken for the first. The
 * casing the user chose is kept for display in `handle`; the uniqueness lives on `handle_key`.
 */

import { normaliseEmail, normaliseHandle, type Organisation, type PublicUser, type Role } from '@cloudsforge/contracts-auth'
import { uuidv7 } from './ids.ts'
import { CURRENT_ALGO, hashPassword, needsRehash, verifyPassword } from './passwords.ts'
import { createPersonalOrganisation } from './organisations.ts'
import type { Db, Tx } from './outbox.ts'

/** The email or the handle is already taken. Answered 409, and never says which. */
export class ConflictError extends Error {
  constructor() {
    super('that email address or handle is already in use')
    this.name = 'ConflictError'
  }
}

export interface UserRow {
  readonly id: string
  readonly email: string
  readonly email_verified_at: Date | null
  readonly handle: string
  readonly handle_key: string
  readonly password_hash: string
  readonly hash_algo: string
  readonly status: PublicUser['status']
  readonly roles: readonly Role[]
  readonly created_at: Date
  readonly last_seen_at: Date | null
}

/**
 * What identity returns about the authenticated user, TO that user.
 *
 * "Public" means free of secrets — never a password hash, never `hash_algo`, never an MFA secret.
 * It is not the shape other users see; that is a profile, which carries a visibility and no email.
 */
export function toPublicUser(row: UserRow): PublicUser {
  return {
    id: row.id,
    email: row.email,
    emailVerifiedAt: row.email_verified_at?.toISOString() ?? null,
    handle: row.handle,
    status: row.status,
    roles: row.roles,
    createdAt: row.created_at.toISOString(),
    lastSeenAt: row.last_seen_at?.toISOString() ?? null,
  }
}

export interface RegisterInput {
  /** Already validated and normalised by `validateRegistration`. */
  readonly email: string
  readonly handle: string
  readonly handleKey: string
  readonly password: string
}

export interface Registered {
  readonly user: UserRow
  readonly organisation: Organisation
}

/**
 * Create a user, their profile and their personal organisation — one transaction, or none of it.
 *
 * The three are one fact. A user with no profile is a user no product can render, and a user with
 * no organisation is the null case 04-domain-model exists to abolish; committing the first and
 * losing the others would produce exactly the half-built accounts the estate would then need a
 * repair script for.
 *
 * **The pre-check is deliberately absent.** Nimbus selects for an existing email or handle and then
 * inserts, which is a race it then has to catch anyway — its own comment records the lost race
 * rendering as a 500 rather than the 409 twelve lines above it. The unique indexes are the only
 * thing that actually decides, so this asks them directly and maps 23505. One round trip fewer, and
 * one fewer place for the two answers to disagree.
 */
export async function registerUser(sql: Db, input: RegisterInput): Promise<Registered> {
  // Normalised again here rather than trusted from the caller. This function is reachable from a
  // route, a test and an operator tool, and "the caller normalised it" is an assumption that holds
  // until the day somebody adds a fourth caller.
  const email = normaliseEmail(input.email)
  const handleKey = normaliseHandle(input.handle)
  const { hash, algo } = await hashPassword(input.password)
  const id = uuidv7()

  try {
    const outcome = await sql.begin(async (tx) => {
      const rows = await tx<UserRow[]>`
        insert into users (id, email, handle, handle_key, password_hash, hash_algo, roles)
        values (${id}, ${email}, ${input.handle}, ${handleKey}, ${hash}, ${algo}, ${['player']})
        returning id, email, email_verified_at, handle, handle_key, password_hash, hash_algo,
                  status, roles, created_at, last_seen_at
      `
      const user = rows[0]!
      await tx`insert into profiles (user_id, display_name) values (${id}, ${input.handle})`
      const organisation = await createPersonalOrganisation(tx, { userId: id, handle: input.handle })
      return { user, organisation }
    })
    return outcome
  } catch (err) {
    // 23505 is unique_violation. Both indexes — `users_email_lower_uniq` and `users_handle_key_uniq`
    // — land here, and the answer does not say which: distinguishing them would turn registration
    // into an oracle for whether an address has an account, which is the same thing the reset route
    // is carefully shaped to avoid saying.
    if ((err as { code?: string }).code === '23505') throw new ConflictError()
    throw err
  }
}

export async function findUserById(sql: Db | Tx, id: string): Promise<UserRow | null> {
  const rows = await sql<UserRow[]>`
    select id, email, email_verified_at, handle, handle_key, password_hash, hash_algo,
           status, roles, created_at, last_seen_at
      from users where id = ${id}
  `
  return rows[0] ?? null
}

/**
 * Look a user up by whatever they typed into the sign-in box.
 *
 * The identifier arrives already normalised by `validateLogin` — an email lowercased, a handle
 * lowercased to its uniqueness key — and is matched against the column that holds exactly one
 * spelling. That equality is the whole point: an account created from `Sam@Example.com` must be
 * reachable by every path that address can be typed into.
 */
export async function findUserByIdentifier(
  sql: Db,
  identifier: string,
  kind: 'email' | 'handle',
): Promise<UserRow | null> {
  // Two statements rather than one with an `or`, because a disjunction over two different unique
  // indexes cannot use either of them, and this is the query every sign-in and every brute-force
  // attempt runs.
  const rows =
    kind === 'email'
      ? await sql<UserRow[]>`
          select id, email, email_verified_at, handle, handle_key, password_hash, hash_algo,
                 status, roles, created_at, last_seen_at
            from users where email = ${identifier}
        `
      : await sql<UserRow[]>`
          select id, email, email_verified_at, handle, handle_key, password_hash, hash_algo,
                 status, roles, created_at, last_seen_at
            from users where handle_key = ${identifier}
        `
  return rows[0] ?? null
}

/**
 * Is this account allowed to sign in at all?
 *
 * Checked after the password, never before: answering "this account is suspended" to an unproven
 * caller tells them the address exists and that it is worth attacking. Returning a reason code
 * rather than a boolean so the route can say something true to a user who genuinely is suspended,
 * once they have proved they own it.
 */
export function signInRefusal(user: UserRow): 'suspended' | 'locked' | 'deleted' | null {
  if (user.status === 'active') return null
  if (user.status === 'pending_deletion') return null
  if (user.status === 'deleted') return 'deleted'
  return user.status
}

/**
 * Record the sign-in.
 *
 * Fire-and-forget from the caller's point of view, but awaited: `last_seen_at` is the column an
 * operator uses to decide whether an account is dormant, and a write that is dropped under load
 * makes an active account look abandoned.
 */
export async function touchLastSeen(sql: Db, userId: string): Promise<void> {
  await sql`update users set last_seen_at = now() where id = ${userId}`
}

/**
 * Rehash a password at the current work factor, if the row was written at an older one.
 *
 * **Called only from the sign-in path, and only after the password has verified**, because that is
 * the one moment in a credential's life when the plaintext is in hand. This is the whole reason
 * `hash_algo` is a column: without it there is no way to find the rows that need this, and raising
 * the work factor means a forced reset for every user on the platform.
 *
 * Failure is swallowed. The user has already authenticated; turning a housekeeping write into a
 * failed sign-in would be a self-inflicted outage over a column nobody is waiting on.
 */
export async function upgradeHashIfStale(
  sql: Db,
  user: UserRow,
  password: string,
  onError: (err: unknown) => void,
): Promise<void> {
  if (!needsRehash(user.hash_algo)) return
  try {
    const { hash, algo } = await hashPassword(password)
    await sql`
      update users set password_hash = ${hash}, hash_algo = ${algo}
       where id = ${user.id} and hash_algo = ${user.hash_algo}
    `
  } catch (err) {
    onError(err)
  }
}

/** Verify a password against a row, at the parameters that row records. */
export function checkPasswordAgainst(user: UserRow, password: string): Promise<boolean> {
  return verifyPassword(password, user.password_hash, user.hash_algo)
}

/**
 * Set a new password.
 *
 * Every caller must also revoke sessions and burn outstanding reset tokens; this function
 * deliberately does neither, so that the ordering stays visible at the call site. Getting it wrong
 * in one direction leaves the person who just changed their password signed out of the browser they
 * changed it in, and in the other leaves whoever knew the old password still signed in — and those
 * are different mistakes that want different code, not a flag.
 */
export async function setPassword(sql: Db, userId: string, password: string): Promise<void> {
  const { hash, algo } = await hashPassword(password)
  await sql`update users set password_hash = ${hash}, hash_algo = ${algo} where id = ${userId}`
}

export { CURRENT_ALGO }
