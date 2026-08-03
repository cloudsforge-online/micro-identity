/**
 * Configuration, validated at import.
 *
 * Rule 9 of docs/ecosystem/03 section 2 — "a repo declares the variables it needs; the deploy
 * provides exactly those" — is a property of this file. Every variable the service reads is named
 * here and nowhere else, so the deploy manifest can be derived from it and `env_file: .env` fan-out
 * (which hands every container the whole estate's secrets, SD-12) has nothing to justify it.
 *
 * Two behaviours are copied deliberately from the estate's custody service, which is the only place
 * that gets this right today:
 *
 *   1. **A missing variable names itself.** `undefined` propagating into a connection string
 *      surfaces four layers later as an unreadable driver error.
 *   2. **A known placeholder is refused outright.** A default secret in source is not convenient,
 *      it is catastrophic — and for `IDENTITY_KEY_SECRET` it is the estate's universal forging
 *      credential, because that secret is what wraps the RS256 private half every other service
 *      trusts.
 */

import { hostname } from 'node:os'
import { SCOPE_NAMES, isScope, type Scope } from '@cloudsforge/contracts-auth'

/**
 * The service's own name. A constant rather than a variable: it is a property of the repository,
 * not of the deployment, and making it configurable is how two services end up sharing a migration
 * advisory lock.
 */
export const SERVICE = 'identity'

/** Raised by `loadEnv`. Distinct so a caller can tell configuration from every other failure. */
export class EnvError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvError'
  }
}

const PLACEHOLDERS = new Set([
  'changeme',
  'change-me',
  'placeholder',
  'secret',
  'dev-secret',
  'dev-outbox-signing-secret',
  'replace-with-a-real-secret',
  'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
])

/**
 * Placeholder STEMS, refused wherever they BEGIN a value rather than only when they are the whole
 * of it.
 *
 * ── Why the exact-match set above was not enough ───────────────────────────────────────────────
 *
 * This repository's own `.env.example` shipped
 * `IDENTITY_KEY_SECRET=CHANGE_ME_at_least_32_characters_long`, and that value **booted**: it is 37
 * characters, so it cleared the length floor, and it is not any of the eight strings above, so it
 * cleared the placeholder check. A deployer who copies the example and edits everything except the
 * one line whose whole purpose is to be edited gets a running service whose forging key is a
 * literal in a public-shaped file — and `IDENTITY_KEY_SECRET` is, in `.env.example`'s own words,
 * "the estate's universal forging credential": whoever holds it can mint a token for any user and
 * any service, and every service in the estate accepts it.
 *
 * The refusal it slipped past IS the control. Matching the stem rather than the string is what
 * makes "CHANGE_ME" mean the same thing to this function as it does to the person reading the file,
 * however they padded it out to clear the length check.
 *
 * Compared against the value with separators and case removed, so `CHANGE_ME_…`, `change-me-…` and
 * `changeMe…` are one rule rather than three that can be added to one at a time.
 */
const PLACEHOLDER_STEMS = ['changeme', 'replaceme', 'replacewith', 'yoursecret', 'examplesecret']

const withoutSeparators = (value: string): string => value.toLowerCase().replace(/[^a-z0-9]/g, '')

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

function requiredSecret(source: Source, name: string, minLength = 24): string {
  const value = required(source, name)
  const stripped = withoutSeparators(value)
  if (PLACEHOLDERS.has(value.toLowerCase()) || PLACEHOLDER_STEMS.some((s) => stripped.startsWith(s))) {
    // Names the variable, never the value. The message is read out of a deployment log.
    throw new EnvError(`${name} is set to a known placeholder — generate a real secret`)
  }
  // Length is a proxy for entropy and the only one available here. It is set above the point at
  // which a human-chosen string is plausible, so a memorable password fails this check too.
  if (value.length < minLength) {
    throw new EnvError(`${name} must be at least ${minLength} characters (got ${value.length})`)
  }
  return value
}

function optional(source: Source, name: string, fallback: string): string {
  const value = source[name]?.trim()
  return value && value.length > 0 ? value : fallback
}

function integer(source: Source, name: string, fallback: number, min: number, max: number): number {
  const raw = source[name]?.trim()
  if (!raw) return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new EnvError(`${name} must be an integer between ${min} and ${max} (got ${raw})`)
  }
  return value
}

/**
 * An absolute `scheme://host[:port]` with no path, no query and no fragment.
 *
 * Origins are compared as strings when a hand-off code is redeemed and when a reset link is minted,
 * so a trailing slash on one side and not the other is a mismatch that reads to the user as "sign
 * in bounced me". Normalising here means the comparison never has to be clever.
 */
function origin(name: string, raw: string): string {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new EnvError(`${name} must be an absolute URL (got ${raw})`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new EnvError(`${name} must be http or https (got ${url.protocol})`)
  }
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    throw new EnvError(`${name} must be an origin with no path, query or fragment (got ${raw})`)
  }
  return url.origin
}

/**
 * Which service may be issued which scopes (SD-05).
 *
 * **Fail-closed and explicit.** An operator with the `admin` role mints service tokens, and without
 * this map "admin" would silently mean "may grant `custody:sign:treasury` to anything that asks" —
 * which is the shared-secret problem back again with an audit row attached. A service absent from
 * the map can be issued no token at all.
 *
 * Parsed from JSON rather than a comma soup because it is a map of lists, and because an unknown
 * scope must be a boot failure rather than a token that is quietly narrower than the operator
 * believes. `contracts-auth` owns the closed set; this only ever selects from it.
 */
export function parseServiceGrants(raw: string): Readonly<Record<string, readonly Scope[]>> {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new EnvError('IDENTITY_SERVICE_TOKEN_GRANTS must be a JSON object of service name to scope array')
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new EnvError('IDENTITY_SERVICE_TOKEN_GRANTS must be a JSON object')
  }
  const out: Record<string, readonly Scope[]> = {}
  for (const [service, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!/^[a-z][a-z0-9-]{1,30}$/.test(service)) {
      throw new EnvError(`IDENTITY_SERVICE_TOKEN_GRANTS has an implausible service name: ${service}`)
    }
    if (!Array.isArray(value) || value.some((s) => typeof s !== 'string')) {
      throw new EnvError(`IDENTITY_SERVICE_TOKEN_GRANTS.${service} must be an array of scope strings`)
    }
    for (const scope of value as string[]) {
      if (!isScope(scope)) {
        throw new EnvError(
          `IDENTITY_SERVICE_TOKEN_GRANTS.${service} names an unknown scope: ${scope} (known: ${SCOPE_NAMES.join(', ')})`,
        )
      }
    }
    // De-duplicated so "exactly the scopes requested and no more" cannot be defeated by a map that
    // lists one scope twice and a subset check that counts.
    out[service] = Object.freeze([...new Set(value as Scope[])])
  }
  return Object.freeze(out)
}

export interface Env {
  readonly port: number
  readonly env: string
  readonly version: string
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error'
  /**
   * Rule 1: one database, named by this service's own variable. The CI check greps for any other
   * connection-string variable, so adding a second one here fails the build rather than review.
   */
  readonly databaseUrl: string
  readonly databasePoolMax: number
  /**
   * The `iss` claim this service mints and verifies. Every other service is configured with the
   * same string; a mismatch presents as a universal 401 a long way from its cause, which is why
   * Nimbus's `verifyAccessToken` reports `bad_issuer` separately from a bad signature.
   */
  readonly issuer: string
  /**
   * Wraps the RS256 private half, AES-256-GCM under a scrypt-derived key (see keyEnvelope.ts).
   *
   * The longest secret this service takes, because it is the one whose disclosure is unbounded: it
   * is not a password to something, it is the key to the key every service in the estate trusts.
   */
  readonly keySecret: string
  /**
   * Where password-reset links point. **Never the request `Host` header** (SD-04).
   *
   * Nimbus learned this the hard way: while nothing delivered mail it was a latent bug, and wiring
   * SMTP turned it into unauthenticated account takeover — a forged `Host` had the deployment's own
   * relay mail the victim a genuine reset link pointing at the attacker's origin.
   */
  readonly publicUrl: string
  /**
   * Origins an SSO hand-off code may be redeemed from and redirected to.
   *
   * The allowlist is the whole security of the hand-off: a code is bound to one origin at mint and
   * matched at redemption, so an open redirect cannot turn a legitimate sign-in into a token
   * delivery to somebody else's page.
   */
  readonly handoffOrigins: readonly string[]
  /** HMAC key for outbound event signatures, so a subscriber can prove an event came from us. */
  readonly outboxSigningSecret: string
  readonly instanceId: string
  readonly serviceTokenGrants: Readonly<Record<string, readonly Scope[]>>
  /**
   * How long a `pending_deletion` user waits before being tombstoned.
   *
   * The wait is not politeness. `identity.user.deleted` is published at the request, and every
   * subscriber erases on it; tombstoning the row in the same breath would leave a subscriber that
   * failed and retried with no user to reconcile against. It is also the window in which a deletion
   * driven by a hijacked session can be cancelled by its real owner.
   */
  readonly deletionGraceDays: number
}

const LEVELS = new Set(['debug', 'info', 'warn', 'error'])

/**
 * Pure over its source so the failure paths are testable without mutating the process. The eager
 * export below is what makes the service fail fast.
 */
export function loadEnv(source: Source = process.env, host = ''): Env {
  const logLevel = optional(source, 'LOG_LEVEL', 'info')
  if (!LEVELS.has(logLevel)) {
    throw new EnvError(`LOG_LEVEL must be one of debug, info, warn, error (got ${logLevel})`)
  }

  const handoffOrigins = optional(source, 'IDENTITY_HANDOFF_ORIGINS', '')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
    .map((value) => origin('IDENTITY_HANDOFF_ORIGINS', value))

  return {
    port: integer(source, 'PORT', 4000, 1, 65_535),
    env: optional(source, 'NODE_ENV', 'development'),
    version: optional(source, 'CLOUDSFORGE_TAG', 'dev'),
    logLevel: logLevel as Env['logLevel'],
    databaseUrl: required(source, 'IDENTITY_DATABASE_URL'),
    // A pool larger than the database's own connection budget divided by the replica count is a
    // service that exhausts Postgres for everything else the moment it scales.
    databasePoolMax: integer(source, 'IDENTITY_DATABASE_POOL_MAX', 10, 1, 500),
    issuer: required(source, 'IDENTITY_ISSUER'),
    // 32 rather than the default 24: see the field comment.
    keySecret: requiredSecret(source, 'IDENTITY_KEY_SECRET', 32),
    publicUrl: origin('IDENTITY_PUBLIC_URL', required(source, 'IDENTITY_PUBLIC_URL')),
    handoffOrigins: Object.freeze([...new Set(handoffOrigins)]),
    outboxSigningSecret: requiredSecret(source, 'OUTBOX_SIGNING_SECRET'),
    instanceId: optional(source, 'INSTANCE_ID', host || 'unknown'),
    serviceTokenGrants: parseServiceGrants(optional(source, 'IDENTITY_SERVICE_TOKEN_GRANTS', '{}')),
    deletionGraceDays: integer(source, 'IDENTITY_DELETION_GRACE_DAYS', 7, 0, 365),
  }
}

/**
 * The checks above run at import, before the logger exists, so an uncaught throw reaches the
 * container as a bare V8 stack: not JSON, no level, no service name. The collector drops it and the
 * only symptom an operator gets is a container that exits instantly.
 *
 * So emit one structured fatal line by hand. It is built from a literal rather than routed through
 * the telemetry package: nothing that can itself fail may sit between a configuration error and the
 * report of it. The message is the one `loadEnv` produced, which by construction never contains a
 * value — every branch above names the variable and never quotes a secret.
 */
function fatalConfig(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err)
  process.stderr.write(
    `${JSON.stringify({
      time: new Date().toISOString(),
      level: 'fatal',
      service: SERVICE,
      step: 'env',
      msg: `startup failed at: env — ${message}`,
    })}\n`,
  )
  process.exit(1)
}

export const env: Env = (() => {
  try {
    return loadEnv(process.env, hostname())
  } catch (err) {
    fatalConfig(err)
  }
})()
