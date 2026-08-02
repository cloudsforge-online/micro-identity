/**
 * The credential a service holds at rest so that it can mint its own tokens — **the fix for the
 * ten-minute cliff.**
 *
 * ── WHAT WAS BROKEN ───────────────────────────────────────────────────────────────────────────
 *
 * SD-05 gave every service a scoped token that expires in ten minutes (`SERVICE_TTL_SECONDS`) and
 * retired the two omnipotent shared secrets. It never gave a service a way to obtain its SECOND
 * token. `POST /service-tokens` requires the `admin` role, so the only principal that can mint is a
 * human operator, and the estate's answer was to mint twenty-one tokens at deploy time into
 * environment variables. Consuming services read theirs once at boot. Ten minutes later every
 * service-to-service call on the money tier fails with an expired credential.
 *
 * It survived review twice and every per-service suite, because a suite mints a fresh token as it
 * starts and then finishes in under ten minutes. Nothing that mints and immediately uses a token
 * can see this. It appeared the first time twenty-one services were brought up together.
 *
 * ── WHY A CREDENTIAL RATHER THAN A LONGER TTL ─────────────────────────────────────────────────
 *
 * The obvious repair is to raise the ten minutes, and it is the wrong one. The TTL is not a
 * limitation being worked around; it is the security property SD-05 was built to buy — a leaked
 * service token expires fast, and rotation IS expiry (SD-12), which is why there is no revocation
 * list for service tokens anywhere in this service. Lengthening it trades that property for
 * convenience and leaves the estate with exactly the same defect, arriving later and hurting more:
 * a token that lasts a day still expires on day two, and now a leaked one is useful for a day.
 *
 * The defect is not the lifetime. It is that **the thing a container holds at rest is a token** —
 * a bearer credential with a hard expiry and no way to renew. So change what it holds. A service
 * credential is long-lived by design and mints short-lived tokens on demand, which lets the ten
 * minutes stay exactly where it is and mean exactly what it meant.
 *
 * ── WHY THIS IS NOT `PAY_SERVICE_TOKEN` COMING BACK ───────────────────────────────────────────
 *
 * That objection deserves a straight answer, because a long-lived machine secret is precisely the
 * shape SD-05 retired. What made those two secrets indefensible, in the words of serviceTokens.ts:
 * "Neither has an identity, a scope, an expiry or an audit trail." Point by point:
 *
 *   * **Identity.** A row names exactly ONE service. `PAY_SERVICE_TOKEN` was held by three
 *     containers and named none of them, so the ledger could not say which one moved money.
 *   * **Scope.** A credential cannot mint outside `IDENTITY_SERVICE_TOKEN_GRANTS[service]`. It
 *     confers no authority itself — presenting one to any other service in the estate achieves
 *     nothing, because it is not a token and nothing but this route will look at it. It buys a
 *     scoped ten-minute token and nothing else. The old secret WAS the authority.
 *   * **Expiry.** Every token it mints still dies in ten minutes. The blast radius of a token
 *     leaking is unchanged from today.
 *   * **Audit trail.** Every exchange writes a `service_token_issues` row carrying
 *     `issued_by_credential`. "Which service was granted what, by whom, and when" stays answerable
 *     now that "whom" can be a machine.
 *
 * And one property the old secrets could never have: **revocation.** `revoked_at` takes a
 * compromised service offline within one token lifetime. A leaked service token today cannot be
 * recalled at all — it can only be waited out. This strictly improves containment.
 *
 * ── WHY THE EXCHANGE IS PARALLEL-SAFE, AND WHY THERE IS NO LEASE ───────────────────────────────
 *
 * Exchanging a credential does not consume, rotate or invalidate it. That is not laziness; it is
 * the requirement. N replicas of `wallet` boot from the same credential and each needs its OWN live
 * token in its OWN process memory. A single-use exchange with reuse detection — the shape
 * `rotateRefreshToken` uses for browser tabs — would be actively wrong here: the second replica's
 * exchange would look exactly like a replay, and the estate would burn the credential of a service
 * that was doing nothing but starting up.
 *
 * It is also why token refresh is NOT a leased job, despite this estate's rule that background work
 * is leased. A lease exists to stop two replicas contending over one shared resource. There is no
 * shared resource here: a token is per-process state, and the replica that won the lease would mint
 * a token the other replicas cannot see. Leasing this would produce a lease that is claimed
 * correctly, does its work correctly, and leaves every other replica on the cliff.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type { Scope } from '@cloudsforge/contracts-auth'
import { env } from './env.ts'
import { uuidv7 } from './ids.ts'
import { issueServiceTokenFor, type IssuedServiceToken } from './serviceTokens.ts'
import type { Db } from './outbox.ts'

/**
 * A distinctive prefix so a leaked credential is greppable.
 *
 * micro-org runs a `secret-hygiene` workflow across the estate, and a scanner can only match what
 * has a shape. A bare base64 blob in a paste or a log is indistinguishable from a hundred other
 * things; `cfsc_` is not. This costs nothing and is the difference between finding a leak and
 * hearing about one.
 */
export const CREDENTIAL_PREFIX = 'cfsc_'

/** Presented but not recognised, or recognised and revoked. The caller is told neither of those. */
export class InvalidCredentialError extends Error {
  constructor() {
    super('the service credential presented is not valid')
    this.name = 'InvalidCredentialError'
  }
}

/**
 * Digest a presented credential.
 *
 * SHA-256 and NOT scrypt, which is the opposite of `passwords.ts` and deliberate. The secret is 32
 * bytes from `randomBytes`: there is no dictionary and no human memory, so a deliberately slow
 * salted hash defends against an attack that cannot happen, while costing ~100ms on a path a
 * service takes every few minutes. An unsalted digest is also what makes the row FINDABLE by the
 * secret presented — a per-row salt would force a scan of every credential and a verify against
 * each. `refresh_tokens.token_hash` is the same decision for the same reason.
 */
const digest = (secret: string): string => createHash('sha256').update(secret).digest('hex')

export interface NewServiceCredential {
  readonly id: string
  readonly service: string
  readonly label: string
  /** Returned once, at creation, and never recoverable. Only the digest is stored. */
  readonly secret: string
}

/**
 * Mint a credential for a service.
 *
 * Fail-closed on an unknown service: a credential for something with no entry in
 * `IDENTITY_SERVICE_TOKEN_GRANTS` could never mint a single token, so creating one would leave an
 * operator holding a secret that silently does nothing. Refusing at creation says so immediately.
 */
export async function createServiceCredential(
  sql: Db,
  input: { service: string; label: string; createdBy: string | null },
): Promise<NewServiceCredential> {
  if (!env.serviceTokenGrants[input.service]) {
    throw new Error(`no scopes are configured for service '${input.service}'`)
  }
  // 32 bytes. base64url rather than hex so the string is shorter to handle without being any weaker.
  const secret = CREDENTIAL_PREFIX + randomBytes(32).toString('base64url')
  const id = uuidv7()
  await sql`
    insert into service_credentials (id, service, secret_hash, label, created_by)
    values (${id}, ${input.service}, ${digest(secret)}, ${input.label}, ${input.createdBy})
  `
  return { id, service: input.service, label: input.label, secret }
}

interface CredentialRow {
  readonly id: string
  readonly service: string
  readonly secret_hash: string
  readonly revoked_at: Date | null
}

/**
 * Resolve a presented credential to its row, or throw.
 *
 * The lookup is by digest, so a wrong secret matches nothing and the comparison below is belt and
 * braces against a future change that widens the query — but it is a constant-time comparison
 * anyway, because `===` on a digest leaks its matching prefix length and this is the one place an
 * attacker gets unlimited attempts.
 *
 * **Unknown and revoked are answered identically.** Telling a caller "that credential exists but is
 * revoked" confirms a valid secret to whoever stole it, which is a free oracle for nothing.
 */
async function resolve(sql: Db, presented: string): Promise<CredentialRow> {
  const hash = digest(presented)
  const rows = await sql<CredentialRow[]>`
    select id, service, secret_hash, revoked_at from service_credentials
     where secret_hash = ${hash} limit 1
  `
  const row = rows[0]
  if (!row || row.revoked_at !== null) throw new InvalidCredentialError()

  const a = Buffer.from(row.secret_hash, 'utf8')
  const b = Buffer.from(hash, 'utf8')
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new InvalidCredentialError()
  return row
}

export interface ExchangeInput {
  readonly secret: string
  /**
   * The scopes wanted. Omitted means the service's whole allowlist, which is what a long-running
   * service's token provider wants at boot — it cannot know which of its call sites will be reached.
   * A caller that knows better should say so and get a narrower token; `issueServiceTokenFor` does
   * not widen either way.
   */
  readonly scopes?: readonly string[] | undefined
  /** Clamped to `SERVICE_TTL_SECONDS`. May only shorten — see `clampServiceTtl`. */
  readonly ttlSeconds?: number | null | undefined
  readonly correlationId: string
}

/**
 * Exchange a credential for a short-lived service token. **This is the call that ends the cliff.**
 *
 * The service it mints for is read from the ROW, never from the request. A caller that could name
 * its own service would only have to hold any credential in the estate to mint for `settlement`,
 * which would make every allowlist advisory and hand the least-privileged service in the estate the
 * treasury signing scope.
 *
 * `last_used_at` is updated on the way through: a credential that has not been used since a deploy
 * is either a service that is down or one that never adopted the provider, and both are things an
 * operator should be able to see without reading logs.
 */
export async function exchangeServiceCredential(
  sql: Db,
  input: ExchangeInput,
): Promise<IssuedServiceToken> {
  const row = await resolve(sql, input.secret)

  const scopes =
    input.scopes && input.scopes.length > 0
      ? input.scopes
      : ((env.serviceTokenGrants[row.service] ?? []) as readonly Scope[])

  const issued = await issueServiceTokenFor(sql, {
    service: row.service,
    scopes,
    // A machine minted this. `issued_by` is an operator column and is left null rather than
    // pointing at whoever happened to create the credential months ago — that operator did not ask
    // for THIS token, and recording them as if they had would make the audit trail lie.
    issuedBy: null,
    issuedByCredential: row.id,
    correlationId: input.correlationId,
    ttlSeconds: input.ttlSeconds ?? null,
  })

  await sql`update service_credentials set last_used_at = now() where id = ${row.id}`
  return issued
}

export interface ServiceCredentialSummary {
  readonly id: string
  readonly service: string
  readonly label: string
  readonly createdBy: string | null
  readonly createdAt: string
  readonly lastUsedAt: string | null
  readonly revokedAt: string | null
}

/** Never the secret, and there is nothing to return: only its digest was ever stored. */
export async function listServiceCredentials(sql: Db): Promise<ServiceCredentialSummary[]> {
  const rows = await sql<
    {
      id: string
      service: string
      label: string
      created_by: string | null
      created_at: Date
      last_used_at: Date | null
      revoked_at: Date | null
    }[]
  >`
    select id, service, label, created_by, created_at, last_used_at, revoked_at
      from service_credentials order by created_at desc
  `
  return rows.map((row) => ({
    id: row.id,
    service: row.service,
    label: row.label,
    createdBy: row.created_by,
    createdAt: row.created_at.toISOString(),
    lastUsedAt: row.last_used_at?.toISOString() ?? null,
    revokedAt: row.revoked_at?.toISOString() ?? null,
  }))
}

/**
 * Revoke a credential. Idempotent, and the FIRST revocation's timestamp is kept — re-revoking must
 * not rewrite when containment actually began, which is the first thing an incident asks.
 *
 * Tokens already minted under it stay valid until they expire. That is the ten minutes doing its
 * job, and it is the whole reason the ceiling is worth defending: the upper bound on a compromised
 * service's remaining access is one token lifetime, not one deploy cycle.
 */
export async function revokeServiceCredential(sql: Db, id: string): Promise<boolean> {
  const rows = await sql<{ id: string }[]>`
    update service_credentials set revoked_at = coalesce(revoked_at, now())
     where id = ${id} returning id
  `
  return rows.length > 0
}
