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

/**
 * The error code `POST /auth/handoff` answers with when — and ONLY when — the allowlist refused.
 *
 * Spelled once, here beside the list it is about, because it is a CONTRACT with the sign-in
 * surface rather than an implementation detail of the route: hub-web prints "ask an operator to
 * add it to the hand-off allowlist", and that sentence is true of this code and of nothing else
 * this route can answer. See `HandoffOriginRefusedError` in server.ts for what printing it for a
 * 401 cost (micro-org#480).
 */
export const HANDOFF_ORIGIN_REFUSED_CODE = 'handoff_origin_refused'

const hashCode = (code: string): string => createHash('sha256').update(code).digest('hex')

/**
 * Is this origin one the estate is allowed to hand tokens to?
 *
 * The allowlist is a parameter with the configured list as its default, for one reason: **the
 * EMPTY allowlist is the shipped default and the case most worth proving, and it is the one case
 * a test cannot otherwise reach.** `env.ts` reads `process.env` once at import, and `testsupport.ts`
 * has already set two origins by the time any test file is evaluated — so without this parameter
 * the behaviour of `IDENTITY_HANDOFF_ORIGINS=` is a claim in a comment rather than something the
 * suite runs. A security control whose most important state is the one nobody has exercised is a
 * control nobody has tested. See `an EMPTY allowlist mints nothing at all` in `tokens.test.ts`.
 */
export function isAllowedOrigin(
  origin: string,
  allowlist: readonly string[] = env.handoffOrigins,
): boolean {
  return allowlist.includes(origin)
}

/**
 * Mint a hand-off code for a user, bound to one redirect origin.
 *
 * Refuses an origin that is not on the allowlist rather than minting a code that cannot be
 * redeemed, so a misconfiguration is a 400 at the moment it is made instead of a sign-in loop that
 * looks like a client bug.
 *
 * **An empty allowlist refuses every origin, and that is the intended production default.** The
 * membership test below is the only open-redirect guard in the estate's SSO — `hub-web` states
 * outright that it holds no second list, because a second list is a list that drifts
 * (`hub-web/src/lib/identity.ts`). "Empty means allow everything" is how an allowlist
 * becomes a redirector, so an unset variable must cost cross-surface sign-in rather than cost the
 * guard. What must NOT be empty is the deployment's value: see `.env.example`.
 */
export async function createHandoffCode(
  sql: Db,
  userId: string,
  redirectOrigin: string,
  allowlist: readonly string[] = env.handoffOrigins,
): Promise<string | null> {
  if (!isAllowedOrigin(redirectOrigin, allowlist)) return null

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
