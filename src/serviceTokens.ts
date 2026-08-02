/**
 * Scoped, short-lived service identity — SD-05. **This is what retires the two omnipotent shared
 * secrets.**
 *
 * What is being replaced: `PAY_SERVICE_TOKEN` is one bearer string, and holding it grants read,
 * debit, credit and liquidation over **every user's money**, with `userId` as a request parameter
 * rather than a token claim. Three containers hold it. `KEYVAULT_SERVICE_TOKEN` is the same shape
 * for custody: any holder can mint a treasury address, sweep every deposit into it, then drain it.
 * Neither has an identity, a scope, an expiry or an audit trail.
 *
 * **The `userId`-as-parameter design is correct and is kept.** A settlement running an hour after
 * the user has left has no user token to forward, and forcing one would mean either impersonating
 * users or holding their credentials — both worse. The defect was never the shape; it was that the
 * authorisation behind it was one unexpiring string. `@cloudsforge/auth`'s `subjectUserId` is the
 * other half of this: a service token acts for whoever it names, and now the ledger can record
 * *which* service moved the money.
 *
 * Three properties, and each one is a thing the shared secret could not do:
 *
 *   1. **Exactly the scopes asked for, and no more.** No wildcard is expressible — `contracts-auth`
 *      has no `custody:*` and `grantsScope` is exact-match — and the request is intersected with a
 *      per-service allowlist from configuration, so an operator cannot grant a scope a service was
 *      never supposed to hold. `grantsAllScopes` is asked about the whole set at once so a partial
 *      grant is a refusal rather than a quietly narrower token.
 *   2. **Ten minutes.** Rotation IS expiry (SD-12): there is no revocation list because nothing
 *      lives long enough to need one.
 *   3. **An issuance row.** The token itself is not stored — it is a signed JWT and storing it would
 *      recreate the thing being deleted — but its `jti`, its service, its scopes and the operator
 *      who asked for it are. "Which service was granted what, by whom, and when" is the question
 *      the two shared secrets could never answer, and it is the first question of any incident.
 */

import { grantsAllScopes, isScope, type Scope } from '@cloudsforge/contracts-auth'
import { env } from './env.ts'
import { clampServiceTtl, issueServiceToken } from './tokens.ts'
import type { Db } from './outbox.ts'

/** No configuration grants this service anything. Fail-closed: an unknown service gets no token. */
export class UnknownServiceError extends Error {
  readonly service: string
  constructor(service: string) {
    super(`no scopes are configured for service '${service}'`)
    this.name = 'UnknownServiceError'
    this.service = service
  }
}

/** The service exists in the allowlist but was not granted every scope it asked for. */
export class ScopeNotGrantedError extends Error {
  readonly service: string
  readonly refused: readonly string[]
  constructor(service: string, refused: readonly string[]) {
    super(`service '${service}' may not be issued: ${refused.join(', ')}`)
    this.name = 'ScopeNotGrantedError'
    this.service = service
    this.refused = refused
  }
}

/** A scope string that is not in the contracts registry at all. */
export class UnknownScopeError extends Error {
  readonly unknown: readonly string[]
  constructor(unknown: readonly string[]) {
    super(`unknown scopes: ${unknown.join(', ')}`)
    this.name = 'UnknownScopeError'
    this.unknown = unknown
  }
}

export interface IssueServiceTokenInput {
  readonly service: string
  readonly scopes: readonly string[]
  /**
   * The operator who asked, when a human asked. Null when a service minted for itself against a
   * credential, in which case `issuedByCredential` names the row instead — see serviceCredentials.ts.
   * Exactly one of the two is set, and between them the issuance ledger can always answer "by whom".
   */
  readonly issuedBy: string | null
  /** The `service_credentials` row that minted this, when a machine did. */
  readonly issuedByCredential?: string | null
  readonly correlationId: string
  /** Requested lifetime. Clamped to `SERVICE_TTL_SECONDS`; may only shorten. */
  readonly ttlSeconds?: number | null
}

export interface IssuedServiceToken {
  readonly token: string
  readonly jti: string
  readonly service: string
  /** Exactly what was requested. Asserted by the test, and by the round trip through the JWT. */
  readonly scopes: readonly Scope[]
  readonly expiresAt: string
  readonly expiresInSeconds: number
}

/**
 * Issue a service token.
 *
 * The order of the checks is the order that gives the most useful refusal: an unknown scope is a
 * caller typo and names the strings; an ungranted scope is a configuration question and names those
 * strings instead. Collapsing them into one "forbidden" would send an operator editing the wrong
 * file.
 *
 * **De-duplicated but not sorted, and not widened.** The token carries the caller's own set. A
 * service that asks for one scope gets a token that says one scope, even when its allowlist permits
 * six — which is what makes a least-privilege call site actually least-privilege rather than
 * nominally so.
 */
export async function issueServiceTokenFor(
  sql: Db,
  input: IssueServiceTokenInput,
): Promise<IssuedServiceToken> {
  const unknown = input.scopes.filter((scope) => !isScope(scope))
  if (unknown.length > 0) throw new UnknownScopeError(unknown)

  // Order-preserving de-duplication, so a request naming one scope twice cannot make a subset check
  // that counts disagree with a subset check that compares.
  const requested = [...new Set(input.scopes)] as Scope[]

  const granted = env.serviceTokenGrants[input.service]
  if (!granted) throw new UnknownServiceError(input.service)
  if (!grantsAllScopes(granted, requested)) {
    throw new ScopeNotGrantedError(
      input.service,
      requested.filter((scope) => !granted.includes(scope)),
    )
  }

  // The jti is minted here and written to the ledger BEFORE the token is signed, so a token that
  // exists always has a row. The other order would produce, on a crash between the two, a live
  // credential with no record of who asked for it — which is the exact property being retired.
  // Clamped BEFORE the ledger row is written, so `expires_at` in the audit trail is the expiry the
  // token actually carries. Writing the ceiling here and signing something shorter would make the
  // one record of an issuance disagree with the credential it records.
  const ttl = clampServiceTtl(input.ttlSeconds)

  const jti = crypto.randomUUID()
  const expiresAt = new Date(Date.now() + ttl * 1000)
  await sql`
    insert into service_token_issues
      (jti, service, scopes, issued_by, issued_by_credential, expires_at, correlation_id)
    values (
      ${jti}, ${input.service}, ${requested}, ${input.issuedBy},
      ${input.issuedByCredential ?? null}, ${expiresAt}, ${input.correlationId}
    )
  `

  const token = await issueServiceToken(sql, input.service, requested, jti, ttl)
  return {
    token,
    jti,
    service: input.service,
    scopes: requested,
    expiresAt: expiresAt.toISOString(),
    expiresInSeconds: ttl,
  }
}

export interface ServiceTokenIssue {
  readonly jti: string
  readonly service: string
  readonly scopes: readonly Scope[]
  readonly issuedBy: string | null
  readonly issuedAt: string
  readonly expiresAt: string
}

/**
 * Recent issuances.
 *
 * SD-05's verification names a dashboard panel showing postings by service, so that "a service
 * posting something it never posted before is visible". This is the identity-side half of that: a
 * service asking for a scope it has never asked for before is visible here, before it has used it.
 */
export async function listServiceTokenIssues(sql: Db, limit = 100): Promise<ServiceTokenIssue[]> {
  const rows = await sql<
    {
      jti: string
      service: string
      scopes: Scope[]
      issued_by: string | null
      issued_at: Date
      expires_at: Date
    }[]
  >`
    select jti, service, scopes, issued_by, issued_at, expires_at
      from service_token_issues order by issued_at desc limit ${limit}
  `
  return rows.map((row) => ({
    jti: row.jti,
    service: row.service,
    scopes: row.scopes,
    issuedBy: row.issued_by,
    issuedAt: row.issued_at.toISOString(),
    expiresAt: row.expires_at.toISOString(),
  }))
}
