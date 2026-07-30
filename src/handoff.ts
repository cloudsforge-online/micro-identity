/**
 * The SSO hand-off: a 60-second, single-use, origin-bound code.
 *
 * Carried forward from Nimbus's `exchange.ts`, which SD-01 lists among the pieces that are correct.
 *
 * **The code carries no tokens.** Tokens are minted only when it is redeemed, and they come back in
 * a response body rather than in a URL. What travels through the browser — through an address bar,
 * a history entry, a referrer header and whatever else is watching — is worthless after sixty
 * seconds or one use.
 *
 * **It is bound to one origin at mint and matched at redemption.** A browser always sends `Origin`
 * on a cross-site POST, so requiring it means a code lifted out of history is useless to a
 * non-browser client, and a code minted for one product cannot be redeemed by another. The origin
 * must also be on the configured allowlist: without that, an open redirect anywhere in the estate
 * turns a legitimate sign-in into token delivery to somebody else's page.
 *
 * **Redemption is a conditional `UPDATE ... RETURNING`.** Not a select-then-update: two concurrent
 * redemptions of one code would both read `redeemed = false` and both proceed, and the answer to
 * "can this code be spent twice" would be "usually not". One statement, and the row lock decides.
 */

import { createHash, randomBytes } from 'node:crypto'
import { env } from './env.ts'
import type { Db } from './outbox.ts'

const CODE_TTL_MS = 60_000

const hashCode = (code: string): string => createHash('sha256').update(code).digest('hex')

/** Is this origin one the estate is allowed to hand tokens to? */
export function isAllowedOrigin(origin: string): boolean {
  return env.handoffOrigins.includes(origin)
}

/**
 * Mint a hand-off code for a user, bound to one redirect origin.
 *
 * Refuses an origin that is not on the allowlist rather than minting a code that cannot be
 * redeemed, so a misconfiguration is a 400 at the moment it is made instead of a sign-in loop that
 * looks like a client bug.
 */
export async function createHandoffCode(
  sql: Db,
  userId: string,
  redirectOrigin: string,
): Promise<string | null> {
  if (!isAllowedOrigin(redirectOrigin)) return null

  // Opportunistic sweep. This table is otherwise append-only, and an expired row is worth nothing
  // to anyone — least of all to whoever ends up with a copy of the database.
  await sql`delete from auth_exchange_codes where expires_at < now()`

  const code = randomBytes(32).toString('hex')
  await sql`
    insert into auth_exchange_codes (code_hash, user_id, redirect_origin, expires_at)
    values (
      ${hashCode(code)},
      ${userId},
      ${redirectOrigin},
      ${new Date(Date.now() + CODE_TTL_MS)}
    )
  `
  return code
}

/**
 * Redeem a code exactly once, from the origin it was issued for.
 *
 * Returns null for expired, already spent, and presented-from-the-wrong-origin alike. The three are
 * not distinguished to the caller: all of them read to the user as "sign-in bounced me", and
 * separating them would say whether a guessed code had ever existed.
 */
export async function redeemHandoffCode(
  sql: Db,
  code: string,
  origin: string,
): Promise<string | null> {
  const rows = await sql<{ user_id: string }[]>`
    update auth_exchange_codes set redeemed = true
     where code_hash = ${hashCode(code)}
       and redeemed = false
       and redirect_origin = ${origin}
       and expires_at > now()
    returning user_id
  `
  return rows[0]?.user_id ?? null
}
