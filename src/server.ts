/**
 * The HTTP surface.
 *
 * Plain `node:http`, following the service template. The parts that matter — request ids, RED
 * metrics, the child logger, the error shape, the auth-fault mapping — are framework-independent,
 * and identity is not the service in which to introduce a framework's opinions about body parsing.
 *
 * Four decisions in this file are load-bearing:
 *
 *   1. **A bad token is 401; a verifier that could not reach the database is 503.** Answering 401
 *      there would sign every user in the estate out because identity is having a bad minute. The
 *      discriminated `VerifyResult` from tokens.ts is what makes the distinction available at all —
 *      Nimbus returned null for both for a long time, and an issuer mismatch went unnoticed for an
 *      entire deploy as a result.
 *   2. **`POST /auth/password/forgot` answers 202 before doing any work.** See the route.
 *   3. **NO PRODUCT FEATURE LIVES HERE.** No dashboard, no launcher, no balance, no portal. Nimbus
 *      grew a 1076-line HTML portal that reads a wallet balance, and the moment identity renders a
 *      product surface the security boundary is gone: the service holding the estate's signing key
 *      is now also parsing product state and serving markup to browsers. Identity issues identity.
 *   4. **Every response is `cache-control: no-store`.** A cached 200 from an endpoint that answers
 *      questions about who you are is a wrong answer served to the next person.
 */

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import {
  isServiceClaims,
  isUserClaims,
  normaliseEmail,
  validateLogin,
  validateRegistration,
  type AuthMethod,
  type Claims,
  type OrganisationRole,
  type Role,
  type UserClaims,
} from '@cloudsforge/contracts-auth'
import type { Lifecycle } from '@cloudsforge/lifecycle'
import { Metrics, newRequestId, type Logger } from '@cloudsforge/telemetry'
import { checkPassword } from '@cloudsforge/contracts-auth'
import {
  activateSigningKey,
  getJwks,
  listSigningKeys,
  mintSigningKey,
  retireSigningKey,
} from './keys.ts'
import { clearLoginFailures, lockoutRemainingMs, recordFailedLogin } from './loginThrottle.ts'
import {
  FactorNotFoundError,
  ReauthenticationRequiredError,
  WEBAUTHN_NOT_IMPLEMENTED,
  activateTotp,
  authenticateMfa,
  consumeMfaChallenge,
  createMfaChallenge,
  enrolTotp,
  generateRecoveryCodes,
  hasActiveFactor,
  listFactors,
  remainingRecoveryCodes,
  removeFactor,
} from './mfa.ts'
import {
  LastOwnerError,
  NotAnAdminError,
  OrganisationNotFoundError,
  changeMembership,
  listMemberships,
  listOrganisationsFor,
} from './organisations.ts'
import {
  RESET_REQUEST_STATUS,
  createPasswordResetToken,
  deliverPasswordReset,
  redeemPasswordResetToken,
  resetUrlFor,
  revokePasswordResetTokens,
} from './passwordReset.ts'
import { createHandoffCode, redeemHandoffCode } from './handoff.ts'
import {
  ScopeNotGrantedError,
  UnknownScopeError,
  UnknownServiceError,
  issueServiceTokenFor,
} from './serviceTokens.ts'
import {
  CREDENTIAL_PREFIX,
  InvalidCredentialError,
  createServiceCredential,
  exchangeServiceCredential,
  listServiceCredentials,
  revokeServiceCredential,
} from './serviceCredentials.ts'
import {
  NotPendingDeletionError,
  WouldOrphanOrganisationsError,
  cancelDeletion,
  requestDeletion,
} from './deletion.ts'
import {
  listSessions,
  revokeAllSessions,
  revokeSession,
  revokeSessionByToken,
  startSession,
  type ClientContext,
} from './sessions.ts'
import { ROTATION_GRACE_MS, issueAccessToken, rotateRefreshToken, verifyToken } from './tokens.ts'
import {
  ConflictError,
  checkPasswordAgainst,
  findUserById,
  findUserByIdentifier,
  registerUser,
  setPassword,
  signInRefusal,
  toPublicUser,
  touchLastSeen,
  upgradeHashIfStale,
  type UserRow,
} from './users.ts'
import { isUuid } from './ids.ts'
import type { Db } from './outbox.ts'

export interface ServerDeps {
  readonly lifecycle: Lifecycle
  readonly logger: Logger
  readonly metrics: Metrics
  readonly sql: Db
  readonly deletionGraceDays: number
  /** Refresh sampled gauges immediately before `/metrics` renders. */
  readonly beforeScrape?: () => Promise<void>
}

/**
 * Domain metrics, declared rather than inferred from a log line — AD-20.
 *
 * `identity_refresh_reuse_total` is the one an alert fires on. It is not a health metric: every
 * increment is either a stolen refresh token or a client refreshing outside its own grace window,
 * and both want a human. The `concurrent` counter next to it is the non-event, separated so the
 * alert is not drowned by two browser tabs.
 */
export function registerServiceMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({
      name: 'identity_logins_total',
      help: 'Completed sign-ins, by the method that finished them',
      kind: 'counter',
      labels: ['amr'],
    })
    .register({
      name: 'identity_login_failures_total',
      help: 'Rejected sign-ins, by reason',
      kind: 'counter',
      labels: ['reason'],
    })
    .register({
      name: 'identity_refresh_reuse_total',
      help: 'Refresh families burned by a replayed token. Every increment wants a human.',
      kind: 'counter',
      labels: [],
    })
    .register({
      name: 'identity_refresh_concurrent_total',
      help: 'Refreshes answered inside the rotation grace window. Two browser tabs, not an attack.',
      kind: 'counter',
      labels: [],
    })
    .register({
      name: 'identity_service_tokens_issued_total',
      help: 'Service tokens minted, by service',
      kind: 'counter',
      labels: ['service'],
    })
    .register({
      name: 'identity_mfa_challenges_total',
      help: 'MFA step-ups, by outcome',
      kind: 'counter',
      labels: ['outcome'],
    })
}

const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/
const MAX_BODY_BYTES = 64 * 1024

interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
  readonly headers?: Readonly<Record<string, string>>
  /**
   * Work to run AFTER the response has been written.
   *
   * Exists for exactly one route — see `POST /auth/password/forgot` — and is deliberately awkward to
   * reach for. Nothing in here may throw usefully: the request is over, so a rejection is an
   * unhandled one, and the runner below catches and logs rather than trusting each caller.
   */
  readonly after?: () => Promise<void>
}

interface RequestContext {
  readonly req: IncomingMessage
  readonly url: URL
  readonly requestId: string
  readonly log: Logger
  readonly params: Readonly<Record<string, string>>
}

interface Route {
  readonly method: string
  /** `/mfa/factors/:id`. Used verbatim as the metric label, so cardinality is bounded. */
  readonly path: string
  readonly pattern: RegExp
  readonly handle: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>
}

/**
 * Compile `/mfa/factors/:id` into a matcher.
 *
 * The segment pattern excludes `/` so a parameter cannot swallow the rest of the path and make one
 * route answer for another — `/sessions/:id` matching `/sessions/x/y` would be a route the metric
 * label lies about at best.
 */
function compile(path: string): RegExp {
  const source = path
    .split('/')
    .map((segment) =>
      segment.startsWith(':')
        ? `(?<${segment.slice(1)}>[^/]+)`
        : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    )
    .join('/')
  return new RegExp(`^${source}$`)
}

/* ------------------------------------------------------------------------ errors */

class BadRequestError extends Error {
  readonly fields: readonly { field: string; code: string; message: string }[]
  constructor(message: string, fields: readonly { field: string; code: string; message: string }[] = []) {
    super(message)
    this.name = 'BadRequestError'
    this.fields = fields
  }
}

/** The caller presented no usable credential. Always 401, and never says which half was wrong. */
class UnauthenticatedError extends Error {
  constructor(message = 'a valid bearer token is required') {
    super(message)
    this.name = 'UnauthenticatedError'
  }
}

class ForbiddenError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ForbiddenError'
  }
}

class NotFoundError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NotFoundError'
  }
}

/** This service could not decide. 503, never 401. */
class UnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UnavailableError'
  }
}

class TooManyRequestsError extends Error {
  readonly retryAfterSeconds: number
  constructor(message: string, retryAfterSeconds: number) {
    super(message)
    this.name = 'TooManyRequestsError'
    this.retryAfterSeconds = retryAfterSeconds
  }
}

/* ------------------------------------------------------------------------ rate limiting */

/**
 * A fixed-window per-address limiter for the credential-accepting routes.
 *
 * **Stated plainly: this is per replica, and it is the weaker of two controls.** The gateway owns
 * the real per-IP limit, and the per-account lock-out in loginThrottle.ts is what actually stops a
 * distributed guessing run. What this adds is a ceiling on how much work one address can make ONE
 * process do — scrypt at N=16384 is a memory-hard function that an unauthenticated caller can
 * otherwise invoke as fast as it can open sockets, which is a denial-of-service primitive against
 * the service every other service depends on.
 *
 * A `Map` rather than anything shared: a limiter with a network dependency would put a hop in front
 * of sign-in, and the moment it is unreachable the choice is fail-open (no limit) or fail-closed (no
 * authentication for the estate). Neither is worth it for a control this is a backstop for.
 */
class WindowLimiter {
  readonly #hits = new Map<string, { count: number; resetAt: number }>()
  readonly #windowMs: number

  constructor(windowMs = 60_000) {
    this.#windowMs = windowMs
  }

  /** Returns seconds to wait, or 0. */
  take(key: string, max: number): number {
    const now = Date.now()
    const entry = this.#hits.get(key)
    if (!entry || entry.resetAt <= now) {
      // Swept here rather than on a timer, because rule 8 means there is no timer. The cost is one
      // pass over the map on the first request of a window, and the alternative is a table that
      // grows with every address that has ever connected.
      if (this.#hits.size > 10_000) {
        for (const [k, v] of this.#hits) if (v.resetAt <= now) this.#hits.delete(k)
      }
      this.#hits.set(key, { count: 1, resetAt: now + this.#windowMs })
      return 0
    }
    entry.count += 1
    if (entry.count <= max) return 0
    return Math.max(1, Math.ceil((entry.resetAt - now) / 1000))
  }
}

/* ------------------------------------------------------------------------ server */

export function createServer(deps: ServerDeps): Server {
  const routes = buildRoutes()
  const limiter = new WindowLimiter()
  let inFlight = 0

  return createHttpServer((req, res) => {
    const startedAt = process.hrtime.bigint()
    const presented = headerOf(req, 'x-request-id')
    const requestId = presented && SAFE_REQUEST_ID.test(presented) ? presented : newRequestId()

    // Echoed before anything can fail, so even a 500 carries the id the user will quote.
    res.setHeader('x-request-id', requestId)

    const url = new URL(req.url ?? '/', `http://${headerOf(req, 'host') ?? 'localhost'}`)
    const method = req.method ?? 'GET'

    let matched: Route | undefined
    let params: Record<string, string> = {}
    for (const route of routes) {
      if (route.method !== method) continue
      const match = route.pattern.exec(url.pathname)
      if (match) {
        matched = route
        params = { ...match.groups }
        break
      }
    }

    // Unmatched paths collapse to one label. Using the raw path would let any caller mint unbounded
    // time series and take the scrape target down with cardinality.
    const routeLabel = matched ? matched.path : 'unmatched'
    const log = deps.logger.child({ requestId, method, route: routeLabel })

    inFlight += 1
    deps.metrics.set('http_requests_in_flight', inFlight)

    const finish = (status: number) => {
      inFlight -= 1
      deps.metrics.set('http_requests_in_flight', inFlight)
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      deps.metrics.increment('http_requests_total', { method, route: routeLabel, status: String(status) })
      deps.metrics.observe('http_request_duration_ms', durationMs, { method, route: routeLabel })
    }

    const ctx: RequestContext = { req, url, requestId, log, params }
    void handle(matched, ctx, deps, limiter)
      .then((reply) => {
        send(res, reply, requestId)
        finish(reply.status)
        if (reply.after) {
          // The last guarantee. Everything a route defers is written not to throw, and this is what
          // stands between a mistake there and an unhandled rejection taking the process down.
          void reply.after().catch((err: unknown) => log.error('deferred work threw', { err }))
        }
      })
      .catch((err: unknown) => {
        log.error('request handler threw after mapping', { err })
        send(res, errorReply(500, 'internal', 'the request could not be completed', requestId), requestId)
        finish(500)
      })
  })
}

/** Per-route, per-window ceilings. Well under whatever the gateway allows. */
const LIMITS: Readonly<Record<string, number>> = {
  '/auth/register': 5,
  '/auth/login': 10,
  '/auth/mfa': 20,
  '/auth/refresh': 60,
  '/auth/password': 10,
  '/auth/password/forgot': 5,
  '/auth/password/reset': 10,
  '/auth/handoff/redeem': 20,
  '/mfa/totp': 10,
  '/mfa/totp/:id/activate': 20,
}

async function handle(
  route: Route | undefined,
  ctx: RequestContext,
  deps: ServerDeps,
  limiter: WindowLimiter,
): Promise<Reply> {
  if (!route) {
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  try {
    const max = LIMITS[route.path]
    if (max !== undefined) {
      const retryAfter = limiter.take(`${route.path}|${clientAddress(ctx.req) ?? 'unknown'}`, max)
      if (retryAfter > 0) {
        throw new TooManyRequestsError('too many requests; slow down', retryAfter)
      }
    }
    return await route.handle(ctx, deps)
  } catch (err) {
    if (err instanceof BadRequestError) {
      return {
        status: 400,
        body: {
          error: {
            code: 'bad_request',
            message: err.message,
            requestId: ctx.requestId,
            ...(err.fields.length > 0 ? { fields: err.fields } : {}),
          },
        },
      }
    }
    if (err instanceof UnauthenticatedError) {
      return errorReply(401, 'unauthenticated', err.message, ctx.requestId)
    }
    if (err instanceof ForbiddenError) {
      return errorReply(403, 'forbidden', err.message, ctx.requestId)
    }
    if (err instanceof NotFoundError) {
      return errorReply(404, 'not_found', err.message, ctx.requestId)
    }
    if (err instanceof ConflictError) {
      return errorReply(409, 'conflict', err.message, ctx.requestId)
    }
    if (err instanceof LastOwnerError) {
      // A distinct code, because a client can act on this one: it must offer to transfer ownership
      // rather than telling the user to try again.
      return errorReply(409, 'last_owner', err.message, ctx.requestId)
    }
    if (err instanceof WouldOrphanOrganisationsError) {
      return {
        status: 409,
        body: {
          error: {
            code: 'would_orphan_organisations',
            message: err.message,
            requestId: ctx.requestId,
            organisations: err.organisations,
          },
        },
      }
    }
    if (err instanceof ReauthenticationRequiredError) {
      return errorReply(403, 'reauthentication_required', err.message, ctx.requestId)
    }
    if (err instanceof NotAnAdminError) {
      return errorReply(403, 'forbidden', err.message, ctx.requestId)
    }
    if (err instanceof UnknownServiceError || err instanceof ScopeNotGrantedError) {
      return errorReply(403, 'scope_not_granted', err.message, ctx.requestId)
    }
    if (err instanceof UnknownScopeError) {
      return errorReply(400, 'unknown_scope', err.message, ctx.requestId)
    }
    if (err instanceof InvalidCredentialError) {
      // 401 and not 403: the caller failed to authenticate at all rather than being refused
      // something. Unknown and revoked land here identically — see `resolve`.
      return errorReply(401, 'unauthenticated', err.message, ctx.requestId)
    }
    if (err instanceof FactorNotFoundError || err instanceof OrganisationNotFoundError) {
      return errorReply(404, 'not_found', err.message, ctx.requestId)
    }
    if (err instanceof NotPendingDeletionError) {
      return errorReply(409, 'conflict', err.message, ctx.requestId)
    }
    if (err instanceof TooManyRequestsError) {
      return {
        status: 429,
        headers: { 'retry-after': String(err.retryAfterSeconds) },
        body: { error: { code: 'rate_limited', message: err.message, requestId: ctx.requestId } },
      }
    }
    if (err instanceof UnavailableError) {
      ctx.log.error('identity could not decide', { err })
      return errorReply(503, 'unavailable', 'authentication is temporarily unavailable', ctx.requestId)
    }
    ctx.log.error('unhandled request failure', { err })
    return errorReply(500, 'internal', 'the request could not be completed', ctx.requestId)
  }
}

/* ------------------------------------------------------------------------ authentication */

/**
 * Resolve the caller from their bearer token.
 *
 * The failure mapping is the whole reason this is one function rather than a line in each route:
 * this service's own database being unreachable inside the key lookup must answer 503, never 401,
 * or every client in the estate throws away a perfectly good session over a blip.
 */
async function authenticate(ctx: RequestContext, deps: ServerDeps): Promise<Claims> {
  const header = headerOf(ctx.req, 'authorization')
  const token = header?.startsWith('Bearer ') ? header.slice(7).trim() : null
  if (!token) throw new UnauthenticatedError('no bearer token presented')

  const verified = await verifyToken(deps.sql, token)
  if (!verified.ok) {
    // Logged, never returned. "Signature verification failed" versus "expired" tells an attacker
    // which half of a forged token to fix. `bad_issuer` and `unavailable` are operator faults
    // wearing a 401's clothes, so they are errors rather than warnings.
    const detail = { reason: verified.reason, tokenIssuer: verified.tokenIssuer, err: verified.err }
    if (verified.reason === 'bad_issuer' || verified.reason === 'unavailable') {
      ctx.log.error(`token rejected: ${verified.reason}`, detail)
    } else {
      ctx.log.info(`token rejected: ${verified.reason}`, detail)
    }
    if (verified.reason === 'unavailable') throw new UnavailableError('could not verify the token')
    throw new UnauthenticatedError('invalid token')
  }
  return verified.claims
}

/** A user token, or 401. A service token here is never "close enough". */
async function authenticateUser(ctx: RequestContext, deps: ServerDeps): Promise<UserClaims> {
  const claims = await authenticate(ctx, deps)
  // `typ` is the discriminant and it is checked before anything else. A service token accepted
  // where a user token was expected makes `sub` — a service name — look like a user id, and every
  // lookup after it runs against a user that does not exist.
  if (!isUserClaims(claims)) throw new ForbiddenError('this route requires a user token')
  return claims
}

/** The platform `admin` role. Product permissions are never platform roles — SD-03. */
async function authenticateAdmin(ctx: RequestContext, deps: ServerDeps): Promise<UserClaims> {
  const claims = await authenticateUser(ctx, deps)
  if (!claims.roles.includes('admin')) throw new ForbiddenError('this route requires the admin role')
  return claims
}

/* ------------------------------------------------------------------------ helpers */

function clientContext(req: IncomingMessage): ClientContext {
  return {
    userAgent: headerOf(req, 'user-agent') ?? null,
    acceptLanguage: headerOf(req, 'accept-language') ?? null,
    remoteAddress: clientAddress(req),
  }
}

/**
 * The caller's address.
 *
 * `x-forwarded-for`'s LEFTMOST entry is the client, and every entry in it is attacker-supplied
 * unless a proxy that rewrites the header sits in front. That is why this value is only ever
 * truncated to a prefix and used as a risk signal — never for an authorisation decision, never as a
 * rate-limit key that anything depends on, and never stored whole.
 */
function clientAddress(req: IncomingMessage): string | null {
  const forwarded = headerOf(req, 'x-forwarded-for')
  const first = forwarded?.split(',')[0]?.trim()
  return first && first.length > 0 ? first : (req.socket.remoteAddress ?? null)
}

async function issueFor(
  sql: Db,
  user: UserRow,
  sessionId: string,
  amr: readonly AuthMethod[],
): Promise<{ accessToken: string; expiresIn: number }> {
  const accessToken = await issueAccessToken(sql, {
    userId: user.id,
    handle: user.handle,
    roles: user.roles as Role[],
    sessionId,
    amr,
  })
  return { accessToken, expiresIn: 900 }
}

function requireString(body: Record<string, unknown>, field: string): string {
  const value = body[field]
  if (typeof value !== 'string' || value.trim() === '') {
    throw new BadRequestError(`${field} is required`, [
      { field, code: 'required', message: `${field} is required.` },
    ])
  }
  return value
}

function optionalString(body: Record<string, unknown>, field: string): string | undefined {
  const value = body[field]
  return typeof value === 'string' && value.trim() !== '' ? value : undefined
}

/**
 * An optional requested token lifetime.
 *
 * Validated here so `clampServiceTtl`'s `RangeError` never reaches the error mapper, where it would
 * have to be caught by type and would then turn any unrelated RangeError in this service into a
 * 400. The clamp itself still refuses the same values — this is the HTTP-shaped half of one rule,
 * not a second rule.
 *
 * Absent is not the same as invalid: absent means "no preference" and takes the ceiling, whereas a
 * zero, a fraction or a string is a caller who thinks they are asking for something and is not.
 */
function readTtlSeconds(body: Record<string, unknown>): number | null {
  const value = body['ttlSeconds']
  if (value === undefined || value === null) return null
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new BadRequestError('ttlSeconds must be a positive integer number of seconds')
  }
  return value
}

/* ------------------------------------------------------------------------ routes */

function buildRoutes(): Route[] {
  const define = (
    method: string,
    path: string,
    handler: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>,
  ): Route => ({ method, path, pattern: compile(path), handle: handler })

  return [
    /* ---------------------------------------------------------------- health */

    define('GET', '/livez', async (_ctx, deps) => ({ status: 200, body: deps.lifecycle.livez() })),

    define('GET', '/readyz', async (_ctx, deps) => {
      const report = await deps.lifecycle.readyz()
      return { status: report.ready ? 200 : 503, body: report }
    }),

    define('GET', '/metrics', async (ctx, deps) => {
      try {
        await deps.beforeScrape?.()
      } catch (err) {
        ctx.log.warn('gauge refresh failed; serving the previous values', { err })
      }
      return {
        status: 200,
        text: deps.metrics.render(),
        contentType: 'text/plain; version=0.0.4; charset=utf-8',
      }
    }),

    /**
     * The JWKS. Unauthenticated by definition — it is public keys, and every service in the estate
     * fetches it before it can verify anything.
     *
     * `max-age=300` rather than `no-store`, and it is the one exception in this file. A verifier
     * that re-fetches on every request turns identity into a synchronous dependency of every request
     * in twenty-two services, which SD-01 rejects on availability grounds. Five minutes is far
     * shorter than the twenty-minute publish window, so a key is fetchable long before it signs.
     */
    define('GET', '/.well-known/jwks.json', async (_ctx, deps) => ({
      status: 200,
      body: await getJwks(deps.sql),
      headers: { 'cache-control': 'public, max-age=300' },
    })),

    /* ---------------------------------------------------------------- registration and sign-in */

    define('POST', '/auth/register', async (ctx, deps) => {
      const validated = validateRegistration(await readJson(ctx.req))
      if (!validated.ok) {
        throw new BadRequestError('that registration is not valid', [...validated.errors])
      }

      const done = deps.lifecycle.track()
      try {
        // The request id is threaded through so the registration, session and device events a
        // sign-up produces share one correlation id. The `identity.user.registered` event is
        // emitted inside `registerUser`, in the same transaction as the account — the audit line
        // below is a log and has never been a substitute for it.
        const { user, organisation } = await registerUser(
          deps.sql,
          validated.value,
          ctx.requestId,
        )
        // A fresh account has no factors, so registration completes a session immediately. `amr` is
        // `pwd` and nothing more, which is what lets a later step-up policy tell this session apart
        // from one that presented a second factor.
        const session = await startSession(deps.sql, {
          userId: user.id,
          client: clientContext(ctx.req),
          amr: ['pwd'],
          correlationId: ctx.requestId,
        })
        const { accessToken, expiresIn } = await issueFor(deps.sql, user, session.sessionId, ['pwd'])
        deps.metrics.increment('identity_logins_total', { amr: 'pwd' })
        ctx.log.info('registered', { audit: 'user_registered', userId: user.id })
        return {
          status: 201,
          body: {
            accessToken,
            refreshToken: session.refreshToken,
            expiresIn,
            user: toPublicUser(user),
            organisation,
          },
        }
      } finally {
        done()
      }
    }),

    define('POST', '/auth/login', async (ctx, deps) => {
      const validated = validateLogin(await readJson(ctx.req))
      if (!validated.ok) {
        // One message for every validation failure on this route, and no field list. Saying "that
        // is not an email address" is harmless; saying anything that varies with whether the
        // account exists is not, and keeping the two apart is easier than remembering which is
        // which every time this is edited.
        throw new BadRequestError('an identifier and a password are required')
      }
      const { identifier, identifierKind, password } = validated.value

      // Checked before the account is looked up, and counted for unknown identifiers too, so a
      // lock-out response never reveals whether the account exists.
      const lockedMs = await lockoutRemainingMs(deps.sql, identifier)
      if (lockedMs > 0) {
        deps.metrics.increment('identity_login_failures_total', { reason: 'locked_out' })
        ctx.log.warn('sign-in attempt against a locked-out identifier', { lockedMs })
        throw new TooManyRequestsError(
          'too many failed sign-in attempts; try again later',
          Math.ceil(lockedMs / 1000),
        )
      }

      const done = deps.lifecycle.track()
      try {
        const user = await findUserByIdentifier(deps.sql, identifier, identifierKind)
        const passwordOk = user ? await checkPasswordAgainst(user, password) : false
        if (!user || !passwordOk) {
          const { failures, lockedForMs } = await recordFailedLogin(deps.sql, identifier)
          deps.metrics.increment('identity_login_failures_total', { reason: 'bad_credentials' })
          // A single one of these is a typo; the RATE of them is the only way an ongoing
          // credential-stuffing run is visible at all.
          ctx.log.warn('sign-in failed', { knownAccount: Boolean(user), failures })
          if (lockedForMs > 0) ctx.log.warn('lock-out engaged', { failures, lockedForMs })
          throw new UnauthenticatedError('that email address, handle or password is not right')
        }

        // Status is checked only after the password, so "this account is suspended" is never said
        // to an unproven caller — it would tell them the address exists and is worth attacking.
        const refusal = signInRefusal(user)
        if (refusal) {
          deps.metrics.increment('identity_login_failures_total', { reason: refusal })
          throw new ForbiddenError(`this account is ${refusal}`)
        }

        await clearLoginFailures(deps.sql, identifier)
        // The one moment the plaintext is in hand. See users.ts: this is what makes the work factor
        // upgradable at all.
        await upgradeHashIfStale(deps.sql, user, password, (err) =>
          ctx.log.warn('password rehash failed; the sign-in stands', { err, userId: user.id }),
        )

        if (await hasActiveFactor(deps.sql, user.id)) {
          // The password was right and that is ALL that has been established. No session, no token,
          // nothing to rotate: a challenge that mints nothing until a factor answers.
          const challenge = await createMfaChallenge(deps.sql, user.id)
          deps.metrics.increment('identity_mfa_challenges_total', { outcome: 'issued' })
          return {
            status: 200,
            body: {
              mfaRequired: true,
              challenge,
              factors: (await listFactors(deps.sql, user.id))
                .filter((f) => f.status === 'active')
                .map((f) => ({ id: f.id, kind: f.kind, label: f.label })),
            },
          }
        }

        const session = await startSession(deps.sql, {
          userId: user.id,
          client: clientContext(ctx.req),
          amr: ['pwd'],
          correlationId: ctx.requestId,
        })
        await touchLastSeen(deps.sql, user.id)
        const { accessToken, expiresIn } = await issueFor(deps.sql, user, session.sessionId, ['pwd'])
        deps.metrics.increment('identity_logins_total', { amr: 'pwd' })
        return {
          status: 200,
          body: {
            accessToken,
            refreshToken: session.refreshToken,
            expiresIn,
            user: toPublicUser(user),
            newDevice: session.newDevice,
          },
        }
      } finally {
        done()
      }
    }),

    /** Complete a sign-in by answering the step-up. */
    define('POST', '/auth/mfa', async (ctx, deps) => {
      const body = await readJson(ctx.req)
      const challenge = requireString(body, 'challenge')
      const code = requireString(body, 'code')

      // Spent first, and spent whether or not the code turns out to be right. A challenge that
      // survives a wrong code is an unlimited offline-speed oracle against a six-digit secret.
      const userId = await consumeMfaChallenge(deps.sql, challenge)
      if (!userId) {
        deps.metrics.increment('identity_mfa_challenges_total', { outcome: 'expired' })
        throw new UnauthenticatedError('that sign-in has expired; start again')
      }

      const outcome = await authenticateMfa(deps.sql, { userId, code })
      if (!outcome.ok) {
        deps.metrics.increment('identity_mfa_challenges_total', { outcome: outcome.reason })
        if (outcome.reason === 'replayed') {
          // Not a typo. A code that WAS right for a step already spent is an observed code being
          // presented again, which is what a shoulder-surf or a real-time phishing relay produces.
          ctx.log.warn('a spent TOTP code was presented again', { audit: 'totp_replayed', userId })
        }
        throw new UnauthenticatedError('that code is not right')
      }

      const user = await findUserById(deps.sql, userId)
      if (!user) throw new UnauthenticatedError('that sign-in has expired; start again')

      const amr: AuthMethod[] = ['pwd', outcome.method]
      const session = await startSession(deps.sql, {
        userId,
        client: clientContext(ctx.req),
        amr,
        correlationId: ctx.requestId,
      })
      await touchLastSeen(deps.sql, userId)
      const { accessToken, expiresIn } = await issueFor(deps.sql, user, session.sessionId, amr)
      deps.metrics.increment('identity_logins_total', { amr: outcome.method })
      deps.metrics.increment('identity_mfa_challenges_total', { outcome: 'passed' })
      if (outcome.method === 'recovery_code') {
        // SD-04 tier 2: using a recovery code emits a critical notification. This is the log half;
        // the event half rides on the session, and the remaining count tells the user to regenerate.
        ctx.log.warn('signed in with a recovery code', {
          audit: 'recovery_code_used',
          userId,
          remaining: await remainingRecoveryCodes(deps.sql, userId),
        })
      }
      return {
        status: 200,
        body: {
          accessToken,
          refreshToken: session.refreshToken,
          expiresIn,
          user: toPublicUser(user),
          newDevice: session.newDevice,
        },
      }
    }),

    define('POST', '/auth/refresh', async (ctx, deps) => {
      const body = await readJson(ctx.req)
      const presented = requireString(body, 'refreshToken')

      const rotated = await rotateRefreshToken(deps.sql, presented, ctx.requestId)
      if (rotated.status === 'reuse') {
        deps.metrics.increment('identity_refresh_reuse_total')
        ctx.log.warn('refresh token reuse detected — family and session revoked', {
          audit: 'refresh_reuse',
          userId: rotated.userId,
          sessionId: rotated.sessionId,
        })
      }
      if (rotated.status !== 'ok') throw new UnauthenticatedError('that refresh token is not valid')

      if (rotated.concurrent) {
        // Deliberately info, and deliberately worded as the non-event it is. Logging this as reuse
        // sent whoever read the log hunting a thief who did not exist. It is still worth a line: a
        // sustained rate of it means a client is refreshing more than once per document.
        deps.metrics.increment('identity_refresh_concurrent_total')
        ctx.log.info('refresh re-presented inside the rotation grace window — concurrent, family kept', {
          userId: rotated.userId,
          graceMs: ROTATION_GRACE_MS,
        })
      }

      const user = await findUserById(deps.sql, rotated.userId)
      if (!user || signInRefusal(user)) {
        throw new UnauthenticatedError('that refresh token is not valid')
      }
      // The session's own `amr` is carried forward rather than reset to `pwd`. A session that
      // presented a second factor an hour ago has still presented one, and downgrading it on every
      // refresh would make a step-up policy demand a factor every fifteen minutes.
      const rows = await deps.sql<{ amr: AuthMethod[] }[]>`
        select amr from sessions where id = ${rotated.sessionId}
      `
      const amr = rows[0]?.amr ?? ['pwd']
      const { accessToken, expiresIn } = await issueFor(deps.sql, user, rotated.sessionId, amr)
      return { status: 200, body: { accessToken, refreshToken: rotated.refreshToken, expiresIn } }
    }),

    define('POST', '/auth/logout', async (ctx, deps) => {
      const body = await readJson(ctx.req)
      await revokeSessionByToken(deps.sql, requireString(body, 'refreshToken'), ctx.requestId)
      return { status: 204 }
    }),

    define('GET', '/auth/me', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const user = await findUserById(deps.sql, claims.sub)
      if (!user) throw new NotFoundError('no such user')
      return {
        status: 200,
        body: {
          user: toPublicUser(user),
          session: { id: claims.sid, amr: claims.amr },
          organisations: await listOrganisationsFor(deps.sql, user.id),
        },
      }
    }),

    /* ---------------------------------------------------------------- passwords */

    /**
     * Change a password. Holding a session is not enough — the current password is required.
     *
     * An unattended browser would otherwise be a permanent account takeover, and the same throttle
     * sign-in uses applies here for the same reason: without it, a stolen access token is an
     * unlimited offline-speed oracle for the password behind it.
     */
    define('POST', '/auth/password', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const body = await readJson(ctx.req)
      const currentPassword = requireString(body, 'currentPassword')
      const newPasswordRaw = requireString(body, 'newPassword')

      const user = await findUserById(deps.sql, claims.sub)
      if (!user) throw new NotFoundError('no such user')

      const checked = checkPassword(newPasswordRaw, { handle: user.handle, email: user.email }, 'newPassword')
      if (!checked.ok) throw new BadRequestError('that password is not acceptable', [...checked.errors])

      const lockedMs = await lockoutRemainingMs(deps.sql, user.email)
      if (lockedMs > 0) {
        throw new TooManyRequestsError('too many failed attempts; try again later', Math.ceil(lockedMs / 1000))
      }
      if (!(await checkPasswordAgainst(user, currentPassword))) {
        const { failures, lockedForMs } = await recordFailedLogin(deps.sql, user.email)
        ctx.log.warn('password change: current password wrong', { userId: user.id, failures })
        if (lockedForMs > 0) ctx.log.warn('lock-out engaged', { failures, lockedForMs })
        // NOT `unauthenticated`. This route answers 401 for two unrelated reasons — an expired
        // access token and a wrong current password — and a client that cannot tell them apart
        // either refreshes and retries a password it already knows is wrong, or shows "your session
        // expired" to someone who simply mistyped.
        return errorReply(401, 'bad_password', 'that is not your current password', ctx.requestId)
      }
      // Cleared as soon as the password is proven rather than after the checks below: three typos
      // followed by a rejected "same password" would otherwise leave the counter armed and lock the
      // account on the next genuine attempt.
      await clearLoginFailures(deps.sql, user.email)
      if (currentPassword === newPasswordRaw) {
        throw new BadRequestError('the new password must be different')
      }

      await setPassword(deps.sql, user.id, checked.value)
      // Everything the old password could still reach dies with it: every session, and any reset
      // link that was issued and never used. The caller's own session survives, because the person
      // who just proved they know the password is the one who should stay signed in.
      const revoked = await revokeAllSessions(deps.sql, { userId: user.id, reason: 'password_changed', correlationId: ctx.requestId, keepSessionId: claims.sid })
      await revokePasswordResetTokens(deps.sql, user.id)
      ctx.log.info('password changed', { audit: 'password_change', userId: user.id, revoked })
      return { status: 200, body: { sessionsRevoked: revoked } }
    }),

    /**
     * Ask for a reset link. **Always 202, and always in the same time.**
     *
     * ANSWER BEFORE DOING THE WORK, and read this before undoing it. The lookup below is the last
     * thing on the request path that depends on whether the address exists, and it is one indexed
     * SELECT either way. Everything after it happens only for an address that DOES exist, so
     * awaiting it makes the RESPONSE TIME say what the status code and the body are so carefully
     * written not to. Measured on Nimbus against a relay that accepts and never speaks, an unknown
     * address answered in 10ms and a known one in 6015ms — the full attempt budget. Even a healthy
     * local sink split 4ms from 33ms.
     *
     * `after` runs once the response is on the wire. Nothing in it may throw usefully: there is no
     * request left to fail, so an escaping rejection is an unhandled one.
     */
    define('POST', '/auth/password/forgot', async (ctx, deps) => {
      const body = await readJson(ctx.req)
      const raw = optionalString(body, 'email')
      // A malformed address gets the same 202 as a well-formed unknown one. Answering 400 here
      // would say nothing about whether an account exists — but it makes the route's timing profile
      // depend on the input in a way that is one refactor away from mattering, and the client
      // gains nothing from the distinction.
      const email = raw ? normaliseEmail(raw) : null
      const user = email ? await findUserByIdentifier(deps.sql, email, 'email') : null

      if (!user) {
        ctx.log.warn('password reset requested for an unknown address')
        return { status: 202, body: { status: RESET_REQUEST_STATUS } }
      }
      return {
        status: 202,
        body: { status: RESET_REQUEST_STATUS },
        after: async () => {
          try {
            const { token } = await createPasswordResetToken(deps.sql, user.id, null)
            // The URL is built and handed straight to delivery. It is the only copy of the token in
            // existence and it is not logged, not persisted, and not put in an error message.
            void resetUrlFor(token)
            await deliverPasswordReset(ctx.log, { userId: user.id })
          } catch (err) {
            ctx.log.error('password reset preparation threw', { err, userId: user.id })
          }
        },
      }
    }),

    define('POST', '/auth/password/reset', async (ctx, deps) => {
      const body = await readJson(ctx.req)
      const token = requireString(body, 'token')
      const newPasswordRaw = requireString(body, 'newPassword')

      const userId = await redeemPasswordResetToken(deps.sql, token)
      if (!userId) {
        // Expired, already spent, or never real. All three read the same way to the person holding
        // it, and separating them would say whether a guessed token had ever existed.
        ctx.log.warn('password reset token rejected')
        throw new UnauthenticatedError('that reset link is invalid or has expired')
      }
      const user = await findUserById(deps.sql, userId)
      if (!user) throw new UnauthenticatedError('that reset link is invalid or has expired')

      const checked = checkPassword(newPasswordRaw, { handle: user.handle, email: user.email }, 'newPassword')
      if (!checked.ok) throw new BadRequestError('that password is not acceptable', [...checked.errors])

      await setPassword(deps.sql, user.id, checked.value)
      // SD-04: spending a reset revokes every refresh family. No session is kept — whoever forced
      // the reset must not survive it, and the real owner is about to sign in anyway.
      const revoked = await revokeAllSessions(deps.sql, { userId: user.id, reason: 'password_reset', correlationId: ctx.requestId })
      await revokePasswordResetTokens(deps.sql, user.id)
      // Whoever is resetting almost certainly got here by failing to sign in, so leaving the
      // lock-out in place would hand them a password they cannot use for another fifteen minutes.
      await clearLoginFailures(deps.sql, user.email)
      ctx.log.info('password reset completed', { audit: 'password_reset', userId: user.id, revoked })
      return { status: 204 }
    }),

    /* ---------------------------------------------------------------- the SSO hand-off */

    define('POST', '/auth/handoff', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const body = await readJson(ctx.req)
      const code = await createHandoffCode(deps.sql, claims.sub, requireString(body, 'redirectOrigin'))
      if (!code) throw new ForbiddenError('that origin is not on the hand-off allowlist')
      return { status: 201, body: { code, expiresInSeconds: 60 } }
    }),

    define('POST', '/auth/handoff/redeem', async (ctx, deps) => {
      const body = await readJson(ctx.req)
      const code = requireString(body, 'code')
      // The code is bound to the origin the sign-in redirected to, and a browser always sends
      // `Origin` on a cross-site POST. Requiring it means a code lifted from history is useless to a
      // non-browser client.
      const origin = headerOf(ctx.req, 'origin')
      if (!origin) throw new BadRequestError('an Origin header is required')

      const userId = await redeemHandoffCode(deps.sql, code, origin)
      if (!userId) {
        ctx.log.warn('hand-off code rejected', { origin })
        throw new UnauthenticatedError('that code is invalid or has expired')
      }
      const user = await findUserById(deps.sql, userId)
      if (!user || signInRefusal(user)) {
        throw new UnauthenticatedError('that code is invalid or has expired')
      }
      const session = await startSession(deps.sql, {
        userId,
        client: clientContext(ctx.req),
        amr: ['sso'],
        correlationId: ctx.requestId,
      })
      const { accessToken, expiresIn } = await issueFor(deps.sql, user, session.sessionId, ['sso'])
      deps.metrics.increment('identity_logins_total', { amr: 'sso' })
      return {
        status: 200,
        body: { accessToken, refreshToken: session.refreshToken, expiresIn, user: toPublicUser(user) },
      }
    }),

    /* ---------------------------------------------------------------- sessions */

    define('GET', '/sessions', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      return { status: 200, body: { sessions: await listSessions(deps.sql, claims.sub) } }
    }),

    define('DELETE', '/sessions', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      // Sign out everywhere INCLUDING here. A "sign out everywhere" that spares the button that was
      // pressed is not the operation the user asked for — they pressed it because they believe a
      // session is compromised, and the one they are looking at may be it.
      const revoked = await revokeAllSessions(deps.sql, { userId: claims.sub, reason: 'signed_out_everywhere', correlationId: ctx.requestId })
      ctx.log.info('signed out everywhere', { audit: 'sessions_revoked', userId: claims.sub, revoked })
      return { status: 200, body: { revoked } }
    }),

    define('DELETE', '/sessions/:id', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const id = ctx.params['id'] ?? ''
      if (!isUuid(id)) throw new BadRequestError('that is not a session id')
      await revokeSession(deps.sql, claims.sub, id, 'signed_out', ctx.requestId)
      // 204 whether or not there was one. Signing out of something already signed out is not an
      // error, and a 404 here would say which session ids exist.
      return { status: 204 }
    }),

    /* ---------------------------------------------------------------- MFA */

    define('GET', '/mfa/factors', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      return {
        status: 200,
        body: {
          factors: await listFactors(deps.sql, claims.sub),
          recoveryCodesRemaining: await remainingRecoveryCodes(deps.sql, claims.sub),
        },
      }
    }),

    define('POST', '/mfa/totp', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const user = await findUserById(deps.sql, claims.sub)
      if (!user) throw new NotFoundError('no such user')
      const body = await readJson(ctx.req)
      const enrolment = await enrolTotp(deps.sql, {
        userId: user.id,
        account: user.email,
        label: optionalString(body, 'label') ?? 'Authenticator app',
      })
      // 201 and the secret, exactly once. There is no route that reads it back: the seed is sealed
      // the moment it is written and a "show me my secret again" endpoint would be a way to lift
      // every user's second factor with a stolen access token.
      return { status: 201, body: enrolment }
    }),

    define('POST', '/mfa/totp/:id/activate', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const body = await readJson(ctx.req)
      const outcome = await activateTotp(deps.sql, {
        userId: claims.sub,
        factorId: ctx.params['id'] ?? '',
        code: requireString(body, 'code'),
        correlationId: ctx.requestId,
      })
      if (!outcome.ok) {
        if (outcome.reason === 'not_found') throw new NotFoundError('no pending enrolment')
        throw new BadRequestError('that code is not right; check your device clock and try again')
      }
      ctx.log.info('MFA factor enrolled', {
        audit: 'mfa_enrolled',
        userId: claims.sub,
        factorId: outcome.factor.id,
      })
      return { status: 200, body: { factor: outcome.factor } }
    }),

    define('POST', '/mfa/recovery-codes', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const codes = await generateRecoveryCodes(deps.sql, {
        userId: claims.sub,
        correlationId: ctx.requestId,
      })
      // Shown once. Only their SHA-256 is stored, so this response is the only time they exist.
      return { status: 201, body: codes }
    }),

    define('DELETE', '/mfa/factors/:id', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const body = await readJson(ctx.req)
      const user = await findUserById(deps.sql, claims.sub)
      if (!user) throw new NotFoundError('no such user')

      // Re-authentication is the password, presented now, in this request. A session that was
      // opened an hour ago is not proof that the person removing the last factor is at the keyboard
      // — which is the whole point of the requirement.
      const password = optionalString(body, 'password')
      const reauthenticated = password ? await checkPasswordAgainst(user, password) : false

      const removed = await removeFactor(deps.sql, {
        userId: claims.sub,
        factorId: ctx.params['id'] ?? '',
        reauthenticated,
        correlationId: ctx.requestId,
      })
      ctx.log.warn('MFA factor removed', {
        audit: 'mfa_removed',
        userId: claims.sub,
        factorId: removed.factorId,
        wasLastActive: removed.wasLastActive,
      })
      return { status: 200, body: removed }
    }),

    /**
     * WebAuthn: the schema and the routes exist; the implementation does not.
     *
     * 501 rather than 404, and the difference is deliberate. A 404 says "there is no such thing
     * here" and a client cannot tell it from a typo; 501 says "this is the right address and this
     * build does not do it", which is what a feature-detecting client needs.
     */
    define('POST', '/mfa/webauthn/options', async (ctx, deps) => {
      await authenticateUser(ctx, deps)
      return {
        status: 501,
        body: { error: { code: 'not_implemented', message: WEBAUTHN_NOT_IMPLEMENTED, requestId: ctx.requestId } },
      }
    }),

    define('POST', '/mfa/webauthn', async (ctx, deps) => {
      await authenticateUser(ctx, deps)
      return {
        status: 501,
        body: { error: { code: 'not_implemented', message: WEBAUTHN_NOT_IMPLEMENTED, requestId: ctx.requestId } },
      }
    }),

    /* ---------------------------------------------------------------- organisations */

    define('GET', '/organisations', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      return { status: 200, body: { organisations: await listOrganisationsFor(deps.sql, claims.sub) } }
    }),

    define('GET', '/organisations/:id/memberships', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const id = ctx.params['id'] ?? ''
      const memberships = await listMemberships(deps.sql, id)
      // Membership of the organisation is what grants sight of its membership list. Answering 404
      // rather than 403 for a non-member keeps the existence of an organisation private too.
      if (!memberships.some((m) => m.userId === claims.sub)) throw new NotFoundError('no such organisation')
      return { status: 200, body: { memberships } }
    }),

    define('POST', '/organisations/:id/memberships', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const body = await readJson(ctx.req)
      const userId = requireString(body, 'userId')
      const rawRole = body['role']
      // `null` removes. `undefined` is a caller that forgot the field, and the two must not be the
      // same thing: a typo in a key name would otherwise delete a membership.
      if (rawRole !== null && typeof rawRole !== 'string') {
        throw new BadRequestError('role must be an organisation role, or null to remove the membership')
      }
      const memberships = await changeMembership(deps.sql, {
        organisationId: ctx.params['id'] ?? '',
        actorUserId: claims.sub,
        userId,
        nextRole: rawRole as OrganisationRole | null,
      })
      ctx.log.info('membership changed', {
        audit: 'membership_changed',
        organisationId: ctx.params['id'],
        actor: claims.sub,
        subject: userId,
        role: rawRole,
      })
      return { status: 200, body: { memberships } }
    }),

    /* ---------------------------------------------------------------- service tokens */

    /**
     * SD-05. Admin-only, and every issuance leaves a row naming the operator.
     *
     * The admin role is the gate because an operator is the only principal that should be able to
     * mint a credential for a service. It is not the only gate: `IDENTITY_SERVICE_TOKEN_GRANTS`
     * bounds what any operator can grant to any service, so a compromised admin account cannot hand
     * `custody:sign:treasury` to something that has never held it.
     */
    define('POST', '/service-tokens', async (ctx, deps) => {
      const claims = await authenticateAdmin(ctx, deps)
      const body = await readJson(ctx.req)
      const service = requireString(body, 'service')
      const scopes = body['scopes']
      if (!Array.isArray(scopes) || scopes.some((s) => typeof s !== 'string')) {
        throw new BadRequestError('scopes must be an array of scope strings')
      }

      const issued = await issueServiceTokenFor(deps.sql, {
        service,
        scopes: scopes as string[],
        issuedBy: claims.sub,
        correlationId: ctx.requestId,
      })
      deps.metrics.increment('identity_service_tokens_issued_total', { service })
      ctx.log.info('service token issued', {
        audit: 'service_token_issued',
        service,
        scopes: issued.scopes,
        jti: issued.jti,
        issuedBy: claims.sub,
      })
      // The token itself, and never again. It is not stored, so there is nothing to read back.
      return {
        status: 201,
        body: {
          token: issued.token,
          jti: issued.jti,
          service: issued.service,
          scopes: issued.scopes,
          expiresAt: issued.expiresAt,
          expiresIn: issued.expiresInSeconds,
        },
      }
    }),

    /* ------------------------------------------------------ service credentials (the cliff fix) */

    /**
     * **Exchange a service credential for a short-lived service token.**
     *
     * This is the route whose absence is the ten-minute cliff. Until it existed the only issuer of
     * a service token was an operator holding the `admin` role, so a service could be GIVEN a token
     * at deploy time and could never obtain another; ten minutes later every service-to-service
     * call on the money tier failed. See serviceCredentials.ts for why the answer is a credential
     * rather than a longer TTL.
     *
     * NOT `authenticate()`. The credential is not a JWT and must never be handed to `verifyToken` —
     * it would be rejected as malformed, and more importantly a route that accepted either a token
     * or a credential would let a service token mint its own successor, which is an unexpiring
     * credential assembled out of expiring parts.
     *
     * The service minted for comes from the credential row, never the request body. There is
     * deliberately no `service` field to send.
     */
    define('POST', '/service-tokens/exchange', async (ctx, deps) => {
      const header = headerOf(ctx.req, 'authorization')
      const presented = header?.startsWith('Bearer ') ? header.slice(7).trim() : null
      if (!presented) throw new UnauthenticatedError('no service credential presented')
      // Shape-checked before the database is touched: a caller sending a JWT here has made a
      // category error, and saying so beats a bare 401 that reads as "wrong secret".
      if (!presented.startsWith(CREDENTIAL_PREFIX)) {
        throw new UnauthenticatedError(
          `a service credential is expected here (it begins '${CREDENTIAL_PREFIX}'), not a token`,
        )
      }

      // `readJson` answers `{}` for an empty body, which is the common case: a token provider that
      // wants its whole allowlist for the default lifetime sends nothing at all.
      const body = await readJson(ctx.req)
      const rawScopes = body['scopes']
      if (rawScopes !== undefined) {
        if (!Array.isArray(rawScopes) || rawScopes.some((s) => typeof s !== 'string')) {
          throw new BadRequestError('scopes must be an array of scope strings')
        }
      }

      const issued = await exchangeServiceCredential(deps.sql, {
        secret: presented,
        scopes: rawScopes as string[] | undefined,
        ttlSeconds: readTtlSeconds(body),
        correlationId: ctx.requestId,
      })
      deps.metrics.increment('identity_service_tokens_issued_total', { service: issued.service })
      ctx.log.info('service token issued from a credential', {
        audit: 'service_token_issued',
        service: issued.service,
        scopes: issued.scopes,
        jti: issued.jti,
        expiresIn: issued.expiresInSeconds,
        // The jti and the service, never the credential and never the token. This service has
        // already had one incident where a live credential reached stdout (passwordReset.ts) and it
        // is not having a second; `service_token_issues.issued_by_credential` is where the link to
        // the credential row lives, which is a table rather than a log.
      })
      return {
        status: 201,
        body: {
          token: issued.token,
          jti: issued.jti,
          service: issued.service,
          scopes: issued.scopes,
          expiresAt: issued.expiresAt,
          expiresIn: issued.expiresInSeconds,
        },
      }
    }),

    /**
     * Create a credential. Admin-only, and the secret is in the response exactly once.
     *
     * An operator does this once per service per estate, rather than once per ten minutes, which is
     * the whole point.
     */
    define('POST', '/service-credentials', async (ctx, deps) => {
      const claims = await authenticateAdmin(ctx, deps)
      const body = await readJson(ctx.req)
      const service = requireString(body, 'service')
      const label = optionalString(body, 'label') ?? `${service} credential`

      const created = await createServiceCredential(deps.sql, {
        service,
        label,
        createdBy: claims.sub,
      })
      ctx.log.info('service credential created', {
        audit: 'service_credential_created',
        service: created.service,
        credentialId: created.id,
        createdBy: claims.sub,
      })
      return {
        status: 201,
        body: {
          id: created.id,
          service: created.service,
          label: created.label,
          // Once. Only the SHA-256 is stored, so there is nothing to read back — the same property
          // that stops anyone with database access from minting for a service.
          secret: created.secret,
        },
      }
    }),

    define('GET', '/service-credentials', async (ctx, deps) => {
      await authenticateAdmin(ctx, deps)
      return { status: 200, body: { credentials: await listServiceCredentials(deps.sql) } }
    }),

    /**
     * Revoke. The containment lever a bearer JWT cannot have: a compromised service is offline
     * within one token lifetime rather than one deploy cycle.
     */
    define('POST', '/service-credentials/:id/revoke', async (ctx, deps) => {
      const claims = await authenticateAdmin(ctx, deps)
      const id = ctx.params['id'] ?? ''
      if (!(await revokeServiceCredential(deps.sql, id))) {
        throw new NotFoundError('no such service credential')
      }
      ctx.log.warn('service credential revoked', {
        audit: 'service_credential_revoked',
        credentialId: id,
        revokedBy: claims.sub,
      })
      return { status: 200, body: { id, revoked: true } }
    }),

    /* ---------------------------------------------------------------- deletion */

    define('DELETE', '/users/me', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const body = await readJson(ctx.req)
      const user = await findUserById(deps.sql, claims.sub)
      if (!user) throw new NotFoundError('no such user')

      // The password again, for the same reason the last MFA factor needs it: an unattended browser
      // must not be able to end an account, and this is the one operation with no undo after the
      // grace window.
      const password = optionalString(body, 'password')
      if (!password || !(await checkPasswordAgainst(user, password))) {
        throw new ForbiddenError('deleting an account requires your password')
      }

      const requested = await requestDeletion(deps.sql, {
        userId: user.id,
        graceDays: deps.deletionGraceDays,
        correlationId: ctx.requestId,
        actor: `user:${user.id}`,
      })
      ctx.log.warn('account deletion requested', {
        audit: 'user_deletion_requested',
        userId: user.id,
        tombstoneAt: requested.tombstoneAt,
      })
      return { status: 202, body: requested }
    }),

    /**
     * Cancel a pending deletion.
     *
     * Reached by signing in again — which is possible because `signInRefusal` treats
     * `pending_deletion` as a state you may still authenticate from. That is the whole design: the
     * grace window is only meaningful if the real owner can get back in during it.
     */
    define('POST', '/users/me/deletion/cancel', async (ctx, deps) => {
      const claims = await authenticateUser(ctx, deps)
      const cancelled = await cancelDeletion(deps.sql, claims.sub)
      if (!cancelled) throw new NotPendingDeletionError()
      ctx.log.info('account deletion cancelled', { audit: 'user_deletion_cancelled', userId: claims.sub })
      return { status: 200, body: { status: 'active' } }
    }),

    /* ---------------------------------------------------------------- key rotation */

    define('GET', '/admin/signing-keys', async (ctx, deps) => {
      await authenticateAdmin(ctx, deps)
      return { status: 200, body: { keys: await listSigningKeys(deps.sql) } }
    }),

    define('POST', '/admin/signing-keys', async (ctx, deps) => {
      await authenticateAdmin(ctx, deps)
      const key = await mintSigningKey(deps.sql)
      ctx.log.warn('signing key minted', { audit: 'signing_key_minted', kid: key.kid })
      return { status: 201, body: { key } }
    }),

    define('POST', '/admin/signing-keys/:kid/activate', async (ctx, deps) => {
      await authenticateAdmin(ctx, deps)
      const outcome = await activateSigningKey(deps.sql, ctx.params['kid'] ?? '')
      if (outcome.status === 'not_found') throw new NotFoundError('no such key')
      if (outcome.status === 'is_active') throw new BadRequestError('that key is already active')
      if (outcome.status === 'not_published') throw new BadRequestError('only a published key may be activated')
      if (outcome.status === 'too_soon') {
        // 409 rather than 400: the request is well-formed and will succeed later, which is exactly
        // what a conflict-with-current-state means. The body says when.
        return {
          status: 409,
          body: {
            error: {
              code: 'publish_window',
              message:
                'this key has not been published long enough for every consumer to have fetched it; activating now would 401 the whole estate until their JWKS caches turn over',
              activatableAt: outcome.activatableAt,
              requestId: ctx.requestId,
            },
          },
        }
      }
      ctx.log.warn('signing key activated', { audit: 'signing_key_activated', kid: ctx.params['kid'] })
      return { status: 200, body: { keys: outcome.keys } }
    }),

    define('POST', '/admin/signing-keys/:kid/retire', async (ctx, deps) => {
      await authenticateAdmin(ctx, deps)
      const outcome = await retireSigningKey(deps.sql, ctx.params['kid'] ?? '')
      if (outcome.status === 'not_found') throw new NotFoundError('no such key')
      if (outcome.status === 'is_active') throw new BadRequestError('the active key cannot be retired')
      if (outcome.status !== 'ok') throw new BadRequestError('that key cannot be retired')
      ctx.log.warn('signing key retired', { audit: 'signing_key_retired', kid: ctx.params['kid'] })
      return { status: 200, body: { keys: outcome.keys } }
    }),
  ]
}

/* ------------------------------------------------------------------------ wire */

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    size += buffer.length
    // Capped before buffering, not after: an unbounded body is a memory-exhaustion primitive that
    // any unauthenticated caller can reach.
    if (size > MAX_BODY_BYTES) throw new BadRequestError('request body too large')
    chunks.push(buffer)
  }
  if (size === 0) return {}
  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new BadRequestError('request body must be a JSON object')
    }
    return parsed as Record<string, unknown>
  } catch (err) {
    if (err instanceof BadRequestError) throw err
    throw new BadRequestError('request body is not valid JSON')
  }
}

/**
 * The error shape, identical on every failure and always carrying the request id.
 *
 * The id in the body rather than only in the header is what makes a support conversation work: a
 * user can read back what their browser showed them, and it joins to the log line and the trace.
 */
function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

function send(res: ServerResponse, reply: Reply, requestId: string): void {
  if (res.writableEnded) return
  const payload = reply.text ?? `${JSON.stringify(reply.body ?? {})}\n`
  res.writeHead(reply.status, {
    'content-type': reply.contentType ?? 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'x-request-id': requestId,
    // Nothing this service says is cacheable except the JWKS, which overrides this. An answer about
    // who you are, served from a cache, is an answer about who somebody else was.
    'cache-control': 'no-store',
    // Belt and braces on the same point: a shared cache keyed only on the URL would serve one
    // user's `/auth/me` to the next.
    vary: 'authorization, origin',
    ...reply.headers,
  })
  res.end(payload)
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}

export { isServiceClaims }
