/**
 * Access tokens, and the refresh-token family whose reuse detection is this service's containment
 * mechanism as well as its detection mechanism.
 *
 * Carried forward from Nimbus's `tokens.ts`. SD-01 records the design as correct and there is no
 * defect to fix; what changes is that a family is now attached to a `session` row (04-domain-model
 * section 1.4), so ending a session is one operation and the device list is truthful.
 *
 * The claim shape is `contracts-auth`'s `UserClaims`: `typ` discriminates user from service, `sid`
 * names the session so revoking a session revokes every access token minted under it, `amr` records
 * how the subject proved who they were so a step-up can be demanded later, and `jti` is unique so a
 * single credential can be revoked without revoking a family.
 */

import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { SignJWT, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose'
import { AUDIENCE } from '@cloudsforge/auth'
import type { AuthMethod, Claims, Role, Scope, UserClaims } from '@cloudsforge/contracts-auth'
import { env } from './env.ts'
import { getSigningKey, getVerificationKey } from './keys.ts'
import { uuidv7 } from './ids.ts'
import { withOutbox, type Db, type Tx } from './outbox.ts'
// sessions.ts imports `insertRefreshToken` from here, so this is a cycle. It is safe and
// deliberate: both sides are hoisted `function` declarations used only at call time, never at
// module-evaluation time. The alternative — spelling the emit out a second time — would give one
// topic two payload shapes to drift apart, which is the defect `identity.mfa.changed` already was.
import { emitSessionRevoked } from './sessions.ts'

/** SD-01. Fifteen minutes: long enough that refreshes are rare, short enough that theft expires. */
export const ACCESS_TTL_SECONDS = 15 * 60

/** SD-05. A service token is minted for a job, not for a day. */
export const SERVICE_TTL_SECONDS = 10 * 60

export const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000

export interface AccessSubject {
  readonly userId: string
  readonly handle: string
  readonly roles: readonly Role[]
  readonly sessionId: string
  readonly amr: readonly AuthMethod[]
}

/**
 * Sign an access token.
 *
 * `handle` is in the claims and is NOT in `contracts-auth`'s `UserClaims`. It is there because the
 * runtime `@cloudsforge/auth` verifier — the one every consuming service uses — builds its
 * `Principal` with a `handle` field and falls back to the empty string when the claim is absent.
 * Omitting it would give twenty-two services a principal whose handle is silently `''`, which is
 * the kind of value that reaches a UI before anyone notices. It is a display name, not an
 * authorisation input, and nothing decides anything from it.
 */
export async function issueAccessToken(sql: Db, subject: AccessSubject): Promise<string> {
  const key = await getSigningKey(sql)
  const claims: Omit<UserClaims, keyof import('@cloudsforge/contracts-auth').BaseClaims> & {
    handle: string
  } = {
    typ: 'user',
    roles: subject.roles,
    sid: subject.sessionId,
    amr: subject.amr,
    handle: subject.handle,
    // The network this token is FOR (micro-org#459 stage 2). Omitted when IDENTITY_NETWORK is
    // unset — see env.ts for why omission is the rollout story, and the runtime verifier for
    // where a mismatch becomes a 401.
    ...(env.network ? { net: env.network } : {}),
  }
  return new SignJWT({ ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: key.kid })
    .setSubject(subject.userId)
    .setIssuer(env.issuer)
    .setAudience(AUDIENCE)
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TTL_SECONDS}s`)
    .sign(key.privateKey)
}

/**
 * Clamp a requested service-token lifetime.
 *
 * **This can only ever SHORTEN.** `SERVICE_TTL_SECONDS` is the ceiling and nothing a caller sends
 * can raise it, which is why a caller-supplied lifetime is safe to accept at all: the security
 * property SD-05 bought — a leaked service token expires fast — is a maximum, and a caller asking
 * for less is asking for more of that property rather than less. A job that needs thirty seconds
 * should hold a credential for thirty seconds; that is the same "minted for a job, not for a day"
 * reasoning that set the ceiling, applied one level down.
 *
 * A non-integer, a zero or a negative is a caller error rather than a request for a short token,
 * and answering it with the ceiling would hand out a LONGER token than the caller believed it
 * asked for. `null` means "no preference" and takes the ceiling.
 */
export function clampServiceTtl(requested: number | null | undefined): number {
  if (requested === null || requested === undefined) return SERVICE_TTL_SECONDS
  if (!Number.isInteger(requested) || requested < 1) {
    throw new RangeError('ttlSeconds must be a positive integer number of seconds')
  }
  return Math.min(requested, SERVICE_TTL_SECONDS)
}

/** Sign a service token. See serviceTokens.ts for who may ask for one and with which scopes. */
export async function issueServiceToken(
  sql: Db,
  service: string,
  scopes: readonly Scope[],
  jti: string,
  ttlSeconds: number = SERVICE_TTL_SECONDS,
): Promise<string> {
  const key = await getSigningKey(sql)
  return new SignJWT({
    typ: 'service',
    scopes: [...scopes],
    // Same claim, same reasons, and on SERVICE tokens it is the load-bearing half: user tokens
    // cross estates by design once identity is shared, but a testnet service's ledger:post must
    // never pass at the mainnet ledger (micro-org#459 stage 2).
    ...(env.network ? { net: env.network } : {}),
  })
    .setProtectedHeader({ alg: 'RS256', kid: key.kid })
    // `service:<name>`, which is how the runtime verifier decides this is not a user. A service
    // token accepted where a user token was expected would make `sub` — a service name — look like
    // a user id, and every downstream lookup then runs against a user that does not exist.
    .setSubject(`service:${service}`)
    .setIssuer(env.issuer)
    .setAudience(AUDIENCE)
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(`${clampServiceTtl(ttlSeconds)}s`)
    .sign(key.privateKey)
}

const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex')

/**
 * Mint an opaque refresh token and store only its SHA-256.
 *
 * Thirty-two random bytes, never a JWT: a refresh token is presented to exactly one service and
 * must be revocable the instant it is spent, which is a property a stateless token does not have.
 * The raw value exists in this process for as long as it takes to write one response.
 */
export async function insertRefreshToken(
  exec: Db | Tx,
  input: { userId: string; sessionId: string; familyId: string },
): Promise<string> {
  const token = randomBytes(32).toString('hex')
  await exec`
    insert into refresh_tokens (id, user_id, session_id, token_hash, family_id, expires_at)
    values (
      ${uuidv7()},
      ${input.userId},
      ${input.sessionId},
      ${hashToken(token)},
      ${input.familyId},
      ${new Date(Date.now() + REFRESH_TTL_MS)}
    )
  `
  return token
}

/**
 * How long after a rotation the token it spent may be presented again without that counting as
 * theft.
 *
 * WHY THIS EXISTS. A refresh token lives in browser storage, which is shared by every tab of an
 * origin, and a client's single-flight guard is a module-level variable — per document, so two tabs
 * do not see each other. Two tabs restored together therefore read the same token and refresh at
 * the same moment. One wins; the other presents a token that was rotated a few hundred milliseconds
 * ago, and without a window that is indistinguishable from a replay, so the whole family is burned
 * — the winner's brand-new successor included. Both tabs are signed out mid-work, the operator log
 * claims a token thief, and the winner dies a second time up to fifteen minutes later when its
 * access token expires.
 *
 * WHY TEN SECONDS. It has to cover one refresh round trip — a few hundred ms on a good connection,
 * a couple of seconds on a bad one — and nothing else. It is NOT meant to cover a tab that was
 * asleep: a token replayed a minute later is the case the family burn is for, and it still burns.
 *
 * WHAT IT COSTS, stated plainly. Inside the window a stolen token is answered rather than detected,
 * so an attacker who replays within ten seconds of the victim's own rotation gets a live token and
 * no alarm is raised. That is the unavoidable price of any grace window.
 */
export const ROTATION_GRACE_MS = 10_000

/**
 * `concurrent` is true when the presented token had already been rotated, but so recently that this
 * is the second half of one refresh performed twice. The caller gets a working token either way;
 * the flag exists so the operator log can say which of the two happened, because logging "reuse
 * detected" for two tabs sends whoever reads it hunting a thief who does not exist.
 */
export type RotateResult =
  | {
      readonly status: 'ok'
      readonly userId: string
      readonly sessionId: string
      readonly refreshToken: string
      readonly concurrent: boolean
    }
  | { readonly status: 'reuse'; readonly userId: string; readonly sessionId: string }
  | { readonly status: 'invalid' }

interface SpentRow {
  readonly user_id: string
  readonly session_id: string
  readonly family_id: string
  readonly expires_at: Date
  readonly rotated_at: Date | null
  readonly revoked: boolean
}

/**
 * Rotate a refresh token: revoke the presented row and issue its successor in the same family.
 *
 * A token that is already revoked but not yet expired is normally proof that someone replayed a
 * spent token — the whole family is burned, the session is revoked, and both the thief and the
 * victim are forced back to a real login. The exception is a replay inside `ROTATION_GRACE_MS` of
 * this row's own rotation, which is two tabs refreshing at once; that gets a token of its own and
 * no burn.
 *
 * WHY A SIBLING AND NOT "THE SAME SUCCESSOR". Handing the second caller whatever the first caller
 * got would mean one rotation yields one token, which is tidier. We cannot: the successor is stored
 * as its SHA-256 and the raw bytes are gone the moment the first response is written, which is the
 * property that stops anyone with database access from minting a session. Storing them, even for
 * ten seconds, would trade a real guarantee for a bookkeeping convenience. So the second caller
 * gets a second token in the SAME family instead.
 *
 * THE TWO PLACES THAT COSTS SOMETHING, both of them real:
 *
 *   1. The family now holds more than one live token, so anything that ends a session has to end
 *      the FAMILY and not the one token it was handed. `revokeSessionByToken` does; a by-token
 *      sign-out would leave the other tab's sibling live and server-side valid for the rest of its
 *      thirty days, held by nobody and revocable by no user action.
 *   2. The victim's chain and a within-grace replayer's chain diverge for good. Each holds a token
 *      the other never presents, so neither ever re-presents a spent one and the burn never fires
 *      again for that thief. The cost of a replay inside ten seconds is therefore NOT bounded by
 *      ten seconds; it is a permanent undetected session, ended only by a sign-out, a password
 *      change or the family's thirty days. That is the price of not keeping raw successors in the
 *      database, and it is stated here rather than discovered later.
 *
 * Note what is NOT graced: `rotated_at` is written only here, so a token revoked by sign-out, by a
 * password change or by an earlier family burn has none, and presenting it burns the family exactly
 * as before.
 */
export async function rotateRefreshToken(
  sql: Db,
  token: string,
  correlationId: string,
): Promise<RotateResult> {
  const tokenHash = hashToken(token)
  // One clock for the whole call — the expiry test, the rotation stamp and the grace test have to
  // agree, and `Date.now()` read three times cannot disagree by much but can disagree at exactly
  // the boundary this hinges on.
  const now = new Date()

  /* REVOKE AND REPLACE IN ONE TRANSACTION, and the grace window is why.
   *
   * As two autocommitted statements this leaves a window — one round trip wide — in which the
   * family has NO live token: the presented row is already revoked and its successor is not yet
   * inserted. A concurrent rotation of the same token landing in that window takes the grace path,
   * asks whether the family is still alive, is told no, and burns it. That is precisely the two-tab
   * collision the grace window exists to stop, arriving by a narrower door. Committing both
   * statements together closes it in both directions: the loser's UPDATE blocks on this row's lock
   * until the winner commits, and by then the successor is visible to it.
   */
  const rotation = await sql.begin(async (tx) => {
    /* THE SESSION'S LIVENESS IS PART OF THE UPDATE'S OWN PREDICATE, not a check after it.
     *
     * A refresh presented against a session an operator suspended or the user signed out of is not
     * a rotation, and answering it would make "sign out everywhere" advisory. Checking that AFTER
     * the update and abandoning the result does not work, and the way it fails is instructive: the
     * update has already committed, so the token is left stamped `rotated_at` for a rotation that
     * never happened — and the caller's retry then reaches the replay path, finds a recently
     * rotated row, and reports REUSE. A user who signed out on one tab and whose other tab retried
     * once would be logged as a token thief. Putting the join in the predicate means a dead session
     * matches nothing and mutates nothing. */
    const rotated = await tx<{ user_id: string; session_id: string; family_id: string }[]>`
      update refresh_tokens t
         set revoked = true, rotated_at = ${now}
        from sessions s
       where s.id = t.session_id
         and s.status = 'active'
         and t.token_hash = ${tokenHash}
         and t.revoked = false
         and t.expires_at > ${now}
      returning t.user_id, t.session_id, t.family_id
    `
    const row = rotated[0]
    if (!row) return { value: null }

    const refreshToken = await insertRefreshToken(tx, {
      userId: row.user_id,
      sessionId: row.session_id,
      familyId: row.family_id,
    })
    await tx`update sessions set last_active_at = ${now} where id = ${row.session_id}`
    return { value: { userId: row.user_id, sessionId: row.session_id, refreshToken } }
  })

  if (rotation.value) {
    return {
      status: 'ok',
      userId: rotation.value.userId,
      sessionId: rotation.value.sessionId,
      refreshToken: rotation.value.refreshToken,
      concurrent: false,
    }
  }

  const rows = await sql<SpentRow[]>`
    select user_id, session_id, family_id, expires_at, rotated_at, revoked
      from refresh_tokens where token_hash = ${tokenHash} limit 1
  `
  const spent = rows[0]
  if (!spent || spent.expires_at.getTime() < now.getTime()) return { status: 'invalid' }

  /* A token that is STILL LIVE and did not rotate above can only be one thing: its session is no
   * longer active. That is a sign-out, a suspension or an earlier burn — not evidence of theft, and
   * emphatically not something to raise an alert about. Answering `invalid` here is what keeps the
   * reuse counter meaning "a replayed token" rather than "somebody signed out and their other tab
   * retried once". */
  if (!spent.revoked) return { status: 'invalid' }

  /* EVERYTHING BELOW DECIDES THE FATE OF ONE FAMILY, so it runs as one transaction under a lock on
   * that family. Two callers arriving here at once are a graced sibling and a burn, and interleaved
   * they undo each other: the grace path reads "the family is alive", the burn revokes every row it
   * can see, and then the grace path inserts a live token the burn's statement had already
   * snapshotted past — a family that was supposed to be over, quietly reopened, with the replayed
   * token's session in it. Row locks cannot express that, because the row in question does not
   * exist yet when the burn runs; an advisory lock keyed on the family can.
   *
   * `hashtext()` collides across families roughly once in four billion, and a collision costs one
   * caller a wait, not a wrong answer. The transaction form releases it on commit or rollback, so a
   * throw here cannot wedge a family. */
  return withOutbox(sql, 'identity', async (tx, emit) => {
      await tx`select pg_advisory_xact_lock(hashtext(${spent.family_id})::bigint)`

      /* A SESSION THAT IS ALREADY OVER IS NOT A THEFT REPORT.
       *
       * Sign-out, a password change and an earlier burn all revoke the family without stamping
       * `rotated_at`, so every one of them lands here looking exactly like a replay. Nimbus burns
       * and alerts for all of them, and the consequence is that the most common way to trigger
       * "refresh token reuse detected" is to sign out on one tab while another retries once. An
       * alert that fires mostly on ordinary sign-outs is an alert nobody reads, which is the same
       * defect the grace window was introduced to fix, arriving by a different door.
       *
       * There is also nothing left to contain: the family was revoked when the session was, so the
       * burn below would revoke zero rows. `invalid` is the whole of the truth here. Reuse is
       * reserved for a token re-presented against a session that is STILL ALIVE — which is the only
       * case where burning the family actually takes a credential away from somebody. */
      const session = await tx<{ status: string }[]>`
        select status from sessions where id = ${spent.session_id}
      `
      if (session[0]?.status !== 'active') return { status: 'invalid' } as RotateResult

      const rotatedAt = spent.rotated_at
      if (rotatedAt && now.getTime() - rotatedAt.getTime() <= ROTATION_GRACE_MS) {
        // AND the family must still be alive. Without this second condition the grace window
        // reopens a family that was burned seconds ago: a thief replays an older spent token, the
        // burn revokes everything, and then the victim's other tab presents a token rotated two
        // seconds before that — inside the window — and is handed a brand-new live token in the
        // family the burn was supposed to end. A burn has to be final, so grace can only ever add a
        // sibling to a chain that still has a live link. It also gives sign-out and a password
        // change the same finality for free.
        const alive = await tx<{ id: string }[]>`
          select id from refresh_tokens
           where family_id = ${spent.family_id} and revoked = false and expires_at > ${now}
           limit 1
        `
        // The session is known active by the check above, so aliveness is now purely a question about
      // the family: grace may only ever add a sibling to a chain that still has a live link.
      // Without it a thief replays an older spent token, the burn revokes everything, and then the
      // victim's other tab presents a token rotated two seconds before that — inside the window —
      // and is handed a brand-new live token in the family the burn was supposed to end.
      if (alive.length > 0) {
          // The other tab's refresh, arriving a moment late. It gets its own successor in the same
          // family; nothing is revoked, so the tab that won keeps working too. A caller stuck in a
          // retry loop cannot mint without bound: the window is measured from this row's single
          // rotation, not from the last grace.
          const refreshToken = await insertRefreshToken(tx, {
            userId: spent.user_id,
            sessionId: spent.session_id,
            familyId: spent.family_id,
          })
          await tx`update sessions set last_active_at = ${now} where id = ${spent.session_id}`
          return {
            status: 'ok',
            userId: spent.user_id,
            sessionId: spent.session_id,
            refreshToken,
            concurrent: true,
          } as RotateResult
        }
      }

      await tx`
        update refresh_tokens set revoked = true
         where family_id = ${spent.family_id} and revoked = false
      `
      // The session dies with its family. This is what makes the device list truthful after a
      // burn: a session still showing `active` for a family that has been revoked is a row telling
      // the user they are signed in somewhere they are not.
      await tx`
        update sessions
           set status = 'revoked', revoked_at = ${now}, revoke_reason = 'refresh_reuse_detected'
         where id = ${spent.session_id} and status = 'active'
      `
      /* THE EVENT THAT TELLS THE VICTIM. This is the case notify's critical rule on
       * `identity.session.revoked` exists for: a stolen refresh token was replayed, the family was
       * burned, and the person whose account it is has just been signed out of a device by
       * somebody else. Of the reasons this service revokes a session for, this is the only one
       * that is unambiguously an attack, and until now it announced nothing — the burn was visible
       * in an operator log and nowhere the user could see it.
       *
       * In the same transaction as the burn, so a crash cannot contain the theft and lose the
       * warning about it. */
      emitSessionRevoked(emit, {
        sessionId: spent.session_id,
        userId: spent.user_id,
        reason: 'refresh_reuse_detected',
        correlationId,
      })
      return { status: 'reuse', userId: spent.user_id, sessionId: spent.session_id } as RotateResult
    })
}

export type VerifyFailureReason =
  | 'expired'
  | 'bad_signature'
  | 'bad_issuer'
  | 'bad_audience'
  | 'malformed'
  | 'unavailable'

export interface VerifyFailure {
  readonly ok: false
  readonly reason: VerifyFailureReason
  readonly err: unknown
  /** The `iss` the token actually carries, populated only for `bad_issuer`. */
  readonly tokenIssuer?: string | null
}

export type VerifyResult = { readonly ok: true; readonly claims: Claims } | VerifyFailure

function classifyVerifyError(err: unknown): VerifyFailureReason {
  const { code, claim } = err as { code?: string; claim?: string }
  switch (code) {
    case 'ERR_JWT_EXPIRED':
      return 'expired'
    case 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED':
      return 'bad_signature'
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED':
      if (claim === 'iss') return 'bad_issuer'
      if (claim === 'aud') return 'bad_audience'
      return 'malformed'
    default:
      return 'malformed'
  }
}

/**
 * Verify a token this service minted, against the key its own header names.
 *
 * BY KID, not "whatever is signing now" — see `getVerificationKey`. The key that signed a token
 * minted fifteen minutes ago is not necessarily the key signing this second, and during a rotation
 * it is deliberately not.
 *
 * The result is discriminated because these causes are not interchangeable: an expired token, a
 * token minted under a different issuer, and this service's own database being unreachable are
 * three different things, and two of the three are our fault. A single null return for all of them
 * is how an issuer mismatch goes unnoticed for an entire deploy.
 */
export async function verifyToken(sql: Db, token: string): Promise<VerifyResult> {
  let kid: string | undefined
  try {
    kid = decodeProtectedHeader(token).kid
  } catch (err) {
    // Not a JWT at all. That is the caller's doing, so it must not be allowed to read as this
    // service being unavailable.
    return { ok: false, reason: 'malformed', err }
  }

  let publicKey: Awaited<ReturnType<typeof getVerificationKey>>
  try {
    publicKey = await getVerificationKey(sql, kid)
  } catch (err) {
    // Nothing here is the caller's doing, so this must never be answered 401.
    return { ok: false, reason: 'unavailable', err }
  }

  try {
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: env.issuer,
      audience: AUDIENCE,
      algorithms: ['RS256'],
    })
    return { ok: true, claims: payload as unknown as Claims }
  } catch (err) {
    const reason = classifyVerifyError(err)
    // jose says only "unexpected iss claim value"; naming both sides is the difference between a
    // log line and a diagnosis. Safe to decode unverified here — the token already parsed, which is
    // how we got this far.
    const tokenIssuer = reason === 'bad_issuer' ? (decodeJwt(token).iss ?? null) : undefined
    return { ok: false, reason, err, ...(tokenIssuer !== undefined ? { tokenIssuer } : {}) }
  }
}
