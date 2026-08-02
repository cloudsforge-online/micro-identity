/**
 * Sessions and devices — 04-domain-model section 1.4.
 *
 * **Neither exists in the estate today.** There are `refresh_tokens` rows and nothing that names or
 * surfaces them, so "where am I signed in" and "sign out everywhere" are both unanswerable
 * questions. That is not only a missing feature: a credential that nothing surfaces is a credential
 * a user cannot revoke, which makes every other control on the account worth less than it looks.
 *
 * The invariant that makes it work is one line of DDL — `sessions_refresh_family_uniq` — and every
 * function here is written to keep it true: exactly one session per refresh-token family. Ending a
 * session ends its family; burning a family ends its session (see tokens.ts).
 *
 * **The full IP address is never stored.** `truncateIp` from contracts-auth reduces it to a /24 or
 * a /48 before it reaches a column, a log line or a response. The prefix carries the whole of the
 * risk signal — "a sign-in from a network this account has never used" — and the rest is a personal
 * identifier with no retention policy attached.
 */

import { createHash } from 'node:crypto'
import { truncateIp } from '@cloudsforge/contracts-auth'
import type { AuthMethod, Session } from '@cloudsforge/contracts-auth'
import { uuidv7 } from './ids.ts'
import { insertRefreshToken } from './tokens.ts'
import { withOutbox, type Db, type Emit, type Tx } from './outbox.ts'

export interface ClientContext {
  readonly userAgent: string | null
  readonly acceptLanguage: string | null
  /** The remote address as the server saw it. Truncated here and never stored whole. */
  readonly remoteAddress: string | null
}

/**
 * Reduce a user agent to a family: "Firefox", "Safari", "iOS".
 *
 * Ordered longest-claim-first, because every browser's user-agent string lies about being every
 * other browser: Edge contains "Chrome" and "Safari", Chrome contains "Safari". Matching in the
 * wrong order labels every device "Safari" and makes the list the user reads actively misleading.
 *
 * Deliberately crude and deliberately not a library. The value is shown to a human trying to
 * recognise their own laptop, and a wrong-but-plausible family is a worse outcome than a missing
 * one — so anything unrecognised is `null` rather than a guess.
 */
export function userAgentFamily(userAgent: string | null): string | null {
  if (!userAgent) return null
  const ua = userAgent
  if (/Edg\//.test(ua)) return 'Edge'
  if (/OPR\/|Opera/.test(ua)) return 'Opera'
  if (/Firefox\//.test(ua)) return 'Firefox'
  if (/Chrome\//.test(ua)) return 'Chrome'
  if (/Safari\//.test(ua)) return 'Safari'
  if (/curl\//i.test(ua)) return 'curl'
  return null
}

export function osFamily(userAgent: string | null): string | null {
  if (!userAgent) return null
  const ua = userAgent
  // iPad and iPhone before Mac: iPadOS reports "Macintosh" in desktop mode, and an iPad listed as a
  // Mac is exactly the sort of detail that makes a user dismiss a genuine alert.
  if (/iPhone|iPad|iPod/.test(ua)) return 'iOS'
  if (/Android/.test(ua)) return 'Android'
  if (/Windows NT/.test(ua)) return 'Windows'
  if (/Mac OS X|Macintosh/.test(ua)) return 'macOS'
  if (/CrOS/.test(ua)) return 'ChromeOS'
  if (/Linux/.test(ua)) return 'Linux'
  return null
}

/**
 * A device fingerprint, hashed.
 *
 * **Stated honestly: this is a weak signal, and it is meant to be.** It is built from headers the
 * client controls, so it does not identify a device and cannot be relied on to. What it is good
 * enough for is the one thing the device list needs — grouping a user's own sign-ins from one
 * browser into one row instead of a new row per login, so "you signed in on a new device" fires on
 * something a person recognises rather than on every session.
 *
 * A stronger fingerprint would be worse, not better. Canvas or font enumeration would identify the
 * device across accounts and origins, which is precisely the tracking identifier
 * 04-domain-model asks us not to keep. The hash is stored rather than the inputs for the same
 * reason: the raw value is the identifier, the hash is only ever compared with itself.
 *
 * Scoped per user by the unique index on `(user_id, fingerprint_hash)`, so two users on one shared
 * machine get two device rows and neither learns anything about the other.
 */
export function fingerprintOf(client: ClientContext): string {
  return createHash('sha256')
    .update(`${client.userAgent ?? ''}\n${client.acceptLanguage ?? ''}`)
    .digest('hex')
}

interface DeviceRow {
  readonly id: string
  readonly first_seen_at: Date
  readonly last_seen_at: Date
}

/**
 * Find or create the device this request came from. Returns whether it is new.
 *
 * The upsert is `on conflict ... do update` rather than a select-then-insert, because two tabs
 * signing in together would both find nothing and both insert, and the loser's 23505 would fail a
 * login for a reason the user cannot act on.
 */
async function upsertDevice(
  tx: Tx,
  userId: string,
  client: ClientContext,
): Promise<{ id: string; isNew: boolean }> {
  const fingerprint = fingerprintOf(client)
  const rows = await tx<(DeviceRow & { inserted: boolean })[]>`
    insert into devices (id, user_id, fingerprint_hash, user_agent_family, os_family)
    values (
      ${uuidv7()},
      ${userId},
      ${fingerprint},
      ${userAgentFamily(client.userAgent)},
      ${osFamily(client.userAgent)}
    )
    on conflict (user_id, fingerprint_hash)
      do update set last_seen_at = now()
    returning id, first_seen_at, last_seen_at, (xmax = 0) as inserted
  `
  const row = rows[0]!
  // `xmax = 0` is true only for a row this statement inserted. It is the one way to tell an insert
  // from an update in an upsert's RETURNING, and getting it wrong would either announce a new
  // device on every login or never announce one at all.
  return { id: row.id, isNew: row.inserted }
}

export interface StartSessionInput {
  readonly userId: string
  readonly client: ClientContext
  /** How the subject proved who they were. Carried into every access token minted under it. */
  readonly amr: readonly AuthMethod[]
  readonly correlationId: string
}

export interface StartedSession {
  readonly sessionId: string
  readonly deviceId: string
  readonly refreshToken: string
  readonly newDevice: boolean
}

/**
 * Open a session: a device row, a session row, a refresh family and its first token — in one
 * transaction with the events that announce them.
 *
 * The family id is generated here rather than defaulted in the DDL so the session row and the
 * token row provably carry the same value, which is the invariant this whole file rests on.
 */
export async function startSession(sql: Db, input: StartSessionInput): Promise<StartedSession> {
  return withOutbox(sql, 'identity', async (tx, emit) => {
    const device = await upsertDevice(tx, input.userId, input.client)
    const sessionId = uuidv7()
    const familyId = uuidv7()
    const ipPrefix = input.client.remoteAddress ? truncateIp(input.client.remoteAddress) : null

    await tx`
      insert into sessions (id, user_id, device_id, refresh_family_id, ip_prefix, amr)
      values (
        ${sessionId},
        ${input.userId},
        ${device.id},
        ${familyId},
        ${ipPrefix},
        ${[...input.amr]}
      )
    `
    const refreshToken = await insertRefreshToken(tx, {
      userId: input.userId,
      sessionId,
      familyId,
    })

    if (device.isNew) {
      // Critical, and 10.3 says a critical security notification ignores preferences: a user cannot
      // opt out of being told their account was used somewhere new. The payload carries the family
      // and the prefix, never the user agent string or the address.
      emit({
        topic: 'identity.device.added',
        key: device.id,
        payload: {
          deviceId: device.id,
          userId: input.userId,
          userAgentFamily: userAgentFamily(input.client.userAgent),
          osFamily: osFamily(input.client.userAgent),
          ipPrefix,
          critical: true,
        },
        actor: `user:${input.userId}`,
        correlationId: input.correlationId,
      })
    }
    emit({
      topic: 'identity.session.created',
      key: sessionId,
      payload: {
        sessionId,
        userId: input.userId,
        deviceId: device.id,
        ipPrefix,
        amr: [...input.amr],
        newDevice: device.isNew,
      },
      actor: `user:${input.userId}`,
      correlationId: input.correlationId,
    })

    return { sessionId, deviceId: device.id, refreshToken, newDevice: device.isNew }
  })
}

interface SessionRow {
  readonly id: string
  readonly user_id: string
  readonly device_id: string | null
  readonly refresh_family_id: string
  readonly ip_prefix: string | null
  readonly created_at: Date
  readonly last_active_at: Date
  readonly revoked_at: Date | null
  readonly revoke_reason: string | null
}

const toSession = (row: SessionRow): Session => ({
  id: row.id,
  userId: row.user_id,
  deviceId: row.device_id,
  refreshFamilyId: row.refresh_family_id,
  ipPrefix: row.ip_prefix,
  createdAt: row.created_at.toISOString(),
  lastActiveAt: row.last_active_at.toISOString(),
  revokedAt: row.revoked_at?.toISOString() ?? null,
  revokeReason: row.revoke_reason,
})

/**
 * What the user sees under "where am I signed in".
 *
 * Active sessions only, and the device family alongside — a list that includes every session ever
 * revoked is a list nobody reads, and the point of surfacing this is that it is acted on.
 */
export async function listSessions(
  sql: Db,
  userId: string,
): Promise<(Session & { userAgentFamily: string | null; osFamily: string | null })[]> {
  const rows = await sql<(SessionRow & { user_agent_family: string | null; os_family: string | null })[]>`
    select s.id, s.user_id, s.device_id, s.refresh_family_id, s.ip_prefix, s.created_at,
           s.last_active_at, s.revoked_at, s.revoke_reason,
           d.user_agent_family, d.os_family
      from sessions s
      left join devices d on d.id = s.device_id
     where s.user_id = ${userId} and s.status = 'active'
     order by s.last_active_at desc
     limit 200
  `
  return rows.map((row) => ({
    ...toSession(row),
    userAgentFamily: row.user_agent_family,
    osFamily: row.os_family,
  }))
}

/**
 * End one session and every token in its family.
 *
 * BY FAMILY, NOT BY TOKEN. A family is a session, so "sign out" has always meant "end this family".
 * Revoking the single row the client presented was the same thing only while a family could hold
 * exactly one live token at a time; the rotation grace window breaks that, and a by-token sign-out
 * would leave the other tab's sibling valid for the remainder of its thirty days — held by no
 * client, presented by nobody, and unreachable by any further user action.
 *
 * Under the same family lock the grace path in `rotateRefreshToken` takes, and for the same reason:
 * without it a grace that has already decided the family is alive can insert its sibling after this
 * UPDATE has snapshotted the family, and the user's sign-out leaves a live token behind.
 *
 * Idempotent. Returns false when there was no such active session, which the route answers 204 for
 * anyway — signing out of something already signed out is not an error.
 */
export async function revokeSession(
  sql: Db,
  userId: string,
  sessionId: string,
  reason: string,
  correlationId: string,
): Promise<boolean> {
  // `withOutbox` rather than a bare `sql.begin`: the event has to be written in the SAME
  // transaction as the revocation, or a crash between them leaves a session that is over and a
  // user who is never told. That is the failure mode the outbox pattern exists for, and it matters
  // more here than almost anywhere — this is the event notify raises a CRITICAL security alert
  // from, so a dropped one is a takeover nobody is warned about.
  return withOutbox(sql, 'identity', async (tx, emit) => {
    const found = await tx<{ refresh_family_id: string }[]>`
      select refresh_family_id from sessions
       where id = ${sessionId} and user_id = ${userId} and status = 'active'
    `
    const familyId = found[0]?.refresh_family_id
    // No row means nothing was revoked, so nothing is announced. Emitting here would notify a user
    // every time a client retried a sign-out it had already completed.
    if (!familyId) return false

    await tx`select pg_advisory_xact_lock(hashtext(${familyId})::bigint)`
    await tx`
      update sessions set status = 'revoked', revoked_at = now(), revoke_reason = ${reason}
       where id = ${sessionId}
    `
    await tx`update refresh_tokens set revoked = true where family_id = ${familyId} and revoked = false`
    emitSessionRevoked(emit, { sessionId, userId, reason, correlationId })
    return true
  })
}

/**
 * Sign out everywhere: every session, every family, one statement each.
 *
 * This is the blast radius a password change is supposed to have — whoever knew the old password is
 * signed out of every product at once, rather than keeping a thirty-day session that rotates
 * happily past the change. It is also what makes the last-resort recovery path meaningful.
 *
 * `keepSessionId` exists for exactly one caller: a password change made BY the user, where the
 * session that just proved it knows the password is the one that should survive. Every other caller
 * passes nothing.
 */
export async function revokeAllSessions(
  sql: Db,
  input: {
    readonly userId: string
    readonly reason: string
    readonly correlationId: string
    readonly keepSessionId?: string
  },
): Promise<number> {
  /* AN OBJECT AND NOT FOUR POSITIONAL ARGUMENTS, because the positional form was written first and
   * was wrong within the hour. Adding `correlationId` before the optional `keepSessionId` made the
   * signature three adjacent strings, and a call that used to pass `keepSessionId` fourth silently
   * began passing it as the correlation id — the session the user asked to KEEP was revoked, and
   * every string type-checked perfectly. The suite caught it; nothing else would have.
   *
   * `reason` in particular decides whether a user gets a critical security alert, so a call site
   * that can quietly shift its arguments along by one is not an acceptable shape here. */
  const { userId, reason, correlationId } = input
  const keep = input.keepSessionId ?? null
  return withOutbox(sql, 'identity', async (tx, emit) => {
    const revoked = await tx<{ id: string }[]>`
      update sessions
         set status = 'revoked', revoked_at = now(), revoke_reason = ${reason}
       where user_id = ${userId}
         and status = 'active'
         and (${keep}::uuid is null or id <> ${keep}::uuid)
      returning id
    `
    // Revoked by session rather than by user so the kept session's family survives with it. The
    // join is on session_id, which is why that column exists on the token row at all.
    await tx`
      update refresh_tokens t
         set revoked = true
        from sessions s
       where s.id = t.session_id
         and s.user_id = ${userId}
         and s.status <> 'active'
         and t.revoked = false
    `
    // ONE EVENT PER SESSION, not one per operation. Each revoked row is a device losing access, and
    // notify dedupes on the session id precisely so that "sign out everywhere" produces one
    // notification per device rather than one for the lot — which is what a user needs to see to
    // tell how far a compromise reached.
    for (const session of revoked) {
      emitSessionRevoked(emit, { sessionId: session.id, userId, reason, correlationId })
    }
    return revoked.length
  })
}

/**
 * End the session a refresh token belongs to, whoever holds it.
 *
 * The presented row is matched whether or not it is already revoked, so signing out with a token
 * another tab has since rotated past still ends the session. That hands a stolen token the power to
 * sign its owner out, which it already had by a shorter path: presenting it to the refresh route
 * outside the grace window burns the same family and raises an alert while doing it.
 */
export async function revokeSessionByToken(
  sql: Db,
  token: string,
  correlationId: string,
): Promise<void> {
  const tokenHash = createHash('sha256').update(token).digest('hex')
  const rows = await sql<{ session_id: string; user_id: string }[]>`
    select session_id, user_id from refresh_tokens where token_hash = ${tokenHash} limit 1
  `
  const row = rows[0]
  if (!row) return
  // `signed_out` is the ONE reason notify treats as not-news, and this is the call site that earns
  // it: a user signing themselves out with the refresh token they are holding. Every other
  // revocation reason in this service raises a critical alert, which is the correct default — an
  // unrecognised reason is exactly when someone should look.
  await revokeSession(sql, row.user_id, row.session_id, 'signed_out', correlationId)
}

/**
 * Emit a session event from inside a caller's transaction. Kept here so the topics live together.
 *
 * **This topic stays, and the registry is what is incomplete.** It was found during a producer/
 * consumer audit as a topic nothing anywhere classifies, and the tempting repair was to delete it
 * or fold it into `identity.session.created` with a field. Both are wrong. A session ending is not
 * the same fact as a session starting, and three different things end one: a deliberate sign-out,
 * an operator or user revoking a session from the device list, and the refresh-family burn that
 * fires when a stolen token is replayed outside the grace window. The third is a security event a
 * user must be able to see, and today nothing downstream can tell it happened at all.
 *
 * **This function used to have no caller, and this paragraph used to claim the opposite.** It said
 * "the event is written and delivered; what is missing is a consumer allowed to name it". Neither
 * half was true. `revokeSession` and `revokeAllSessions` updated the session rows and emitted
 * nothing, so the event was never written at all — while `micro-notify` had landed a CRITICAL rule
 * on the topic and `micro-contracts` had registered it. Every topic check in `topics.ts` passed
 * throughout, because they reconcile topic NAMES and the name here was always spelled correctly.
 * `unreferencedEmitters` was added to close exactly that hole, and it fails if this function loses
 * its callers again.
 *
 * The reason string is what decides whether a user is warned: notify alerts on every reason EXCEPT
 * `signed_out`. So the value each call site passes is a security decision, not a label — see
 * `revokeSessionByToken` for the one case that is deliberately silent.
 *
 * Keyed on the session rather than the user: two revocations of the same session must stay in
 * order relative to each other, and a revocation has no ordering relationship to anything else.
 */
export function emitSessionRevoked(
  emit: Emit,
  input: { sessionId: string; userId: string; reason: string; correlationId: string },
): void {
  emit({
    topic: 'identity.session.revoked',
    key: input.sessionId,
    payload: { sessionId: input.sessionId, userId: input.userId, reason: input.reason },
    actor: `user:${input.userId}`,
    correlationId: input.correlationId,
  })
}
