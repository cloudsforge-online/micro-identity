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
import { SecretError, assertGeneratedSecret, assertOpaqueSecret } from '@cloudsforge/secrets'
import type { TurnstileConfig } from './turnstile.ts'

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

/**
 * THE `PLACEHOLDERS` SET AND THE `PLACEHOLDER_STEMS` LIST THAT USED TO BE HERE ARE GONE, AND THEIR
 * ABSENCE IS THE FIX.
 *
 * Between them they held thirteen strings and were paired with a 24-character floor (32 for the key
 * secret). Neither could fail for the value that actually reached 44 containers on both networks:
 * micro-org #142's `estate-only-outbox-secret-00000000000000` is 40 characters, does not begin with
 * any stem, and was on nobody's list. A check that cannot fail is worse than no check, because the
 * absence of an alarm gets read as the absence of a problem — and this service holds the key that
 * wraps the RS256 private half every other service trusts.
 *
 * THE STEM LIST WAS ALREADY THE SECOND ATTEMPT, WHICH IS THE ARGUMENT AGAINST THE WHOLE APPROACH.
 * The exact-match set shipped first; `.env.example`'s own `CHANGE_ME_at_least_32_characters_long`
 * booted straight through it, so stems were added to catch a padded `CHANGE_ME`. The next
 * placeholder somebody writes will not begin with a stem either. A deny-list is structurally unable
 * to work, however many times it is extended, because the thing it must refuse is defined only by
 * being something nobody has thought of yet.
 *
 * `@cloudsforge/secrets` asserts the SHAPE of a generated value instead — the property a
 * placeholder cannot have — and it is imported rather than copied so that this service cannot drift
 * from the other sixteen. Everything the stem list was reaching for is still refused, and by a rule
 * that did not have to be told about it: `CHANGE_ME_at_least_32_characters_long` fails the alphabet
 * check on its first underscore, and would fail the marker check even written in base64.
 */

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

/**
 * Re-wrap the shared guard's `SecretError` as this service's `EnvError`.
 *
 * `loadEnv` documents a single error class for every configuration failure, and the boot path
 * catches that one class. The message is preserved verbatim — it already names the variable and the
 * command that fixes it, and it never contains the value.
 */
function asEnvError<T>(run: () => T): T {
  try {
    return run()
  } catch (err) {
    if (err instanceof SecretError) throw new EnvError(err.message)
    throw err
  }
}

/**
 * A secret THIS ESTATE GENERATES, held to the shape a generator produces and a keyboard does not.
 *
 * `assertGeneratedSecret` is the right class for every secret variable identity declares, and that
 * was checked against the running containers rather than inferred from the names. The estate has
 * `*_TOKEN` variables holding `cfsc_` credentials and `*_TOKEN` variables holding JWTs under the
 * same suffix, so a name classifies nothing and pointing everything at the strict rule is how a
 * service dies at boot on a correct value. Measured on 2026-08-05:
 *
 *     IDENTITY_KEY_SECRET_V2   base64, 48 characters
 *     IDENTITY_KEY_SECRET_V3   base64, 48 characters   (hex/64 on the mainnet estate)
 *     OUTBOX_SIGNING_SECRET    one alphabet, 64 characters, 32 bytes
 *
 * All of them are `openssl rand` output written into a gitignored file by an operator following a
 * runbook, so the estate controls the alphabet and the strict rule is the correct one. Neither of
 * the other two classes applies: identity MINTS `cfsc_` credentials rather than holding one, and
 * nothing here arrives from a vendor whose alphabet somebody else chose.
 *
 * `IDENTITY_SERVICE_TOKEN_GRANTS` is deliberately NOT routed through here. It is not a secret at
 * all — it is a JSON map of service name to scope array, and it is validated by
 * `parseServiceGrants`, which asks the only question worth asking of it: are these scopes ones the
 * contracts registry knows. Guarding it with a secret assertion would refuse `{}` at boot for
 * failing an entropy floor, which is a category error with an outage attached.
 *
 * The old `minLength` parameter is gone rather than kept in front: it is a strict subset of the
 * shape check, and running it first answers a 40-character placeholder with "must be at least 24
 * characters" — true, useless, and about the wrong property. Its two different values (24 in
 * general, 32 for the key secret) go with it. That distinction was an attempt to say "this one
 * matters more"; it is expressed properly by both being held to 32 BYTES, which is more than either
 * floor demanded and is the unit an AES key is actually measured in.
 */
function requiredGeneratedSecret(source: Source, name: string): string {
  const value = required(source, name)
  asEnvError(() => assertGeneratedSecret(name, value))
  return value
}

function optional(source: Source, name: string, fallback: string): string {
  const value = source[name]?.trim()
  return value && value.length > 0 ? value : fallback
}

const KEY_SECRET_PREFIX = 'IDENTITY_KEY_SECRET_V'
const LEGACY_KEY_SECRET = 'IDENTITY_KEY_SECRET'

/**
 * The key-encryption keyring: every `IDENTITY_KEY_SECRET_V<n>` present, plus the version that seals.
 *
 * **THE UNSUFFIXED NAME IS ACCEPTED AS V1, AND THAT IS LOAD-BEARING.** Every blob in both live
 * databases was sealed as `v1:` under the value `IDENTITY_KEY_SECRET` held, and `keyEnvelope.ts`
 * derives from the unchanged salt `identity:v1:<purpose>:<id>`. So the same value under the name
 * `IDENTITY_KEY_SECRET_V1` — or left exactly where it is — opens those blobs byte-identically.
 * Without this branch, shipping #188's fix would itself be the destructive rotation it exists to
 * prevent: every existing deployment would boot with an empty keyring and fail to open anything.
 *
 * Empty means unset, matching `optional` above, because a compose interpolation of an unset
 * variable arrives as an empty string rather than as an absent one. That is safe here only because
 * the write version must be present in the map — an empty `_V2` cannot silently downgrade writes
 * back to v1, it fails to boot.
 */
function parseKeySecrets(source: Source): { keySecrets: ReadonlyMap<number, string>; keyVersion: number } {
  const secrets = new Map<number, string>()

  for (const name of Object.keys(source)) {
    if (!name.startsWith(KEY_SECRET_PREFIX)) continue
    const suffix = name.slice(KEY_SECRET_PREFIX.length)
    if (!/^[0-9]{1,3}$/.test(suffix)) continue
    const version = Number(suffix)
    if (version < 1) throw new EnvError(`${name}: envelope versions start at 1`)
    // EMPTY IS UNSET, AND THE CHECK STAYS AHEAD OF THE ASSERTION. Compose interpolates
    // `${IDENTITY_KEY_SECRET_V3:-}` and an unset variable arrives as the empty string; a deployment
    // part-way through a rotation on one network renders an empty `_V3` on the other. Asserting
    // first would turn that render into `exit(1)` on the service every other service authenticates
    // against. It is safe only because the write version must be present in the map — see below.
    if (!(source[name]?.trim())) continue
    // EVERY version present, not just the write version. A retained old secret still opens every
    // blob that has not been re-sealed, so it is not a lesser secret for as long as it is there.
    secrets.set(version, requiredGeneratedSecret(source, name))
  }

  const legacy = source[LEGACY_KEY_SECRET]?.trim()
  if (legacy) {
    const explicit = secrets.get(1)
    if (explicit !== undefined && explicit !== legacy) {
      // Two different values both claiming v1 is unresolvable, and guessing would silently pick the
      // one that fails to open half the blobs. Names the variables, never either value.
      throw new EnvError(
        `${LEGACY_KEY_SECRET} and ${KEY_SECRET_PREFIX}1 are both set and differ — keep ${KEY_SECRET_PREFIX}1 and remove the unsuffixed one`,
      )
    }
    // The unsuffixed name is held to exactly the rule `_V1` is. It is the same key material under
    // an older name, and a compatibility branch that relaxed the guard would be the way every
    // deployment kept the value the guard exists to refuse.
    if (explicit === undefined) secrets.set(1, requiredGeneratedSecret(source, LEGACY_KEY_SECRET))
  }

  if (secrets.size === 0) {
    throw new EnvError(
      `${KEY_SECRET_PREFIX}1 is required — ${SERVICE} refuses to start without a key-encryption key`,
    )
  }

  const highest = Math.max(...secrets.keys())
  const keyVersion = integer(source, 'IDENTITY_KEY_VERSION', highest, 1, 999)
  if (!secrets.has(keyVersion)) {
    throw new EnvError(
      `IDENTITY_KEY_VERSION is ${keyVersion} but ${KEY_SECRET_PREFIX}${keyVersion} is not set — this process would seal blobs it cannot open`,
    )
  }
  return { keySecrets: secrets, keyVersion }
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

/**
 * The registration challenge — all three variables, or none of them (micro-org#361).
 *
 * **THIS IS THE FIRST VENDOR SECRET IDENTITY HOLDS.** The note on `requiredGeneratedSecret` above
 * says "nothing here arrives from a vendor whose alphabet somebody else chose"; that sentence was
 * true when it was written on 2026-08-05 and `TURNSTILE_SECRET` is what stops it being true. It is
 * issued by Cloudflare in Cloudflare's own shape (`0x` followed by a mixed-alphabet tail), so
 * `assertGeneratedSecret` is the wrong class for it and would refuse a correct key at boot —
 * exactly the failure that comment warns against, arriving from the other direction.
 * `assertOpaqueSecret` is the class the shared package documents for "a vendor API key", and it
 * still catches the failures that matter: a placeholder, a marker, something far too short.
 *
 * **OFF IS A SUPPORTED STATE AND MUST STAY ONE.** A developer's machine, CI, and every `micro`
 * network have no Turnstile account. With neither variable set this returns `null`,
 * `GET /auth/challenge` answers `required: false`, hub-web renders no widget and `POST
 * /auth/register` behaves exactly as it did before this feature existed. Making the variables
 * required would break every environment at once, which is the same argument `accountUrl` records.
 *
 * **HALF-CONFIGURED IS NOT A SUPPORTED STATE.** A secret with no site key is a gate no browser can
 * ever pass; a site key with no secret is a widget that is rendered, solved, and then verified
 * against nothing. Both are silent — the first refuses every registration, the second accepts
 * every one — so both fail the boot instead. An operator who wants the feature off removes both
 * lines, which is unambiguous.
 *
 * **AN EMPTY ALLOWLIST WHILE ENABLED FAILS THE BOOT TOO**, and that is not hypothetical: the
 * estate's compose file records `IDENTITY_HANDOFF_ORIGINS` shipping empty and turning
 * `POST /auth/handoff` into a 403 for every caller. `hostnames.includes()` over an empty array is
 * that defect verbatim, so the empty case is refused here where it is loud rather than in the
 * verifier where it is a universal refusal nobody can explain.
 */
function parseTurnstile(source: Source): TurnstileConfig | null {
  const secret = optional(source, 'TURNSTILE_SECRET', '')
  const siteKey = optional(source, 'TURNSTILE_SITE_KEY', '')

  if (!secret && !siteKey) return null
  if (!secret || !siteKey) {
    throw new EnvError(
      'TURNSTILE_SECRET and TURNSTILE_SITE_KEY must be set together — one without the other is a registration gate that either refuses everyone or checks nothing',
    )
  }

  asEnvError(() => assertOpaqueSecret('TURNSTILE_SECRET', secret))

  // The site key is PUBLIC — it is served to browsers by `GET /auth/challenge` and appears in the
  // page source. This compares the two only to catch the paste that swaps them, which is otherwise
  // undetectable: the widget would render under the secret and the secret would be in the bundle.
  // Neither value is named in the message.
  if (secret === siteKey) {
    throw new EnvError('TURNSTILE_SECRET and TURNSTILE_SITE_KEY hold the same value — the secret would be published to every browser')
  }

  const hostnames = optional(source, 'TURNSTILE_HOSTNAMES', '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter((value) => value.length > 0)

  if (hostnames.length === 0) {
    throw new EnvError(
      'TURNSTILE_HOSTNAMES is required when Turnstile is enabled — an empty allowlist refuses every solved challenge',
    )
  }
  for (const host of hostnames) {
    // A HOSTNAME, not an origin: it is compared against `siteverify`'s `hostname` field, which
    // Cloudflare returns bare. A value carrying a scheme, a port or a path would never match
    // anything and would present as "the widget works but registration always fails".
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(host)) {
      throw new EnvError(`TURNSTILE_HOSTNAMES must be bare hostnames with no scheme, port or path (got ${host})`)
    }
  }

  return { secret, siteKey, hostnames: Object.freeze([...new Set(hostnames)]) }
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
   * The network this identity serves — stamped into every token as the `net` claim, or empty and
   * the claim is omitted (micro-org#459 stage 2). Optional with omission BECAUSE the claim's
   * whole rollout story depends on it: tokens without the claim verify everywhere, so an estate
   * that has not set this yet loses nothing, and the enforcement in @cloudsforge/runtime-auth
   * only bites on a mismatch. It becomes meaningful the day both estates trust one identity —
   * a token minted for testnet must not pass at a mainnet service, and this is where that fact
   * enters the token.
   */
  readonly network: string
  /**
   * `CF_NETWORK_SINGLE`: the estate to assume when no `CF-Network` arrives. For `pnpm dev`, which
   * has no gateway. NEVER set in production.
   *
   * NOT a database selector — identity keeps one account set and one database (micro-org#459).
   * It decides the `net` claim's fallback for a credential minted before the combined view.
   */
  readonly singleNetwork: string
  /**
   * The key-encryption keys, BY VERSION — `IDENTITY_KEY_SECRET_V<n>`.
   *
   * Wraps the RS256 private half and every TOTP seed, AES-256-GCM under a scrypt-derived key (see
   * keyEnvelope.ts). It is the secret whose disclosure is unbounded: not a password to something,
   * but the key to the key every service in the estate trusts.
   *
   * It used to carry a longer minimum than everything else — 32 characters against a general 24 —
   * as the way of saying that. It no longer does, and that is not a relaxation: every secret this
   * service reads is now held to 32 BYTES of key material, which is more than either floor asked
   * for and is the unit an AES key is measured in. A rule that is stricter for one variable is a
   * rule somebody has to remember; a rule that is right for all of them is not.
   *
   * A MAP rather than a string, and that is #188's fix. One value meant a rotation destroyed every
   * TOTP seed in the estate — unrecoverably, because the seed exists only in that blob and in the
   * user's authenticator. Holding every version at once is what lets a blob written under the old
   * secret still open while new blobs are written under the new one, which is the only way the
   * drain in `rewrap.ts` can run at all.
   */
  readonly keySecrets: ReadonlyMap<number, string>
  /**
   * The version new blobs are SEALED under. Must be present in `keySecrets`.
   *
   * Defaults to the highest version supplied, so a deployment holding one secret needs no new
   * variable. **Adding `IDENTITY_KEY_SECRET_V<n+1>` therefore promotes the write version on the
   * next restart** — deliberate, because the alternative is a rotation that silently keeps writing
   * under the compromised key, but it does mean the old image must keep V<n+1> in its environment
   * if the deploy is rolled back after any blob has been written under it.
   */
  readonly keyVersion: number
  /**
   * Where password-reset links point. **Never the request `Host` header** (SD-04).
   *
   * Nimbus learned this the hard way: while nothing delivered mail it was a latent bug, and wiring
   * SMTP turned it into unauthenticated account takeover — a forged `Host` had the deployment's own
   * relay mail the victim a genuine reset link pointing at the attacker's origin.
   */
  readonly publicUrl: string
  /**
   * Where the account pages live — Hub's origin, NOT this service's.
   *
   * `publicUrl` above is identity's own address, which is right for identity's own routes and wrong
   * for this one: the email-verification link points at a PAGE (`/account/verify`) that Hub serves,
   * and that page posts the token back here. Building it from `publicUrl` would mail every new user
   * a link to a path this service does not route.
   *
   * **Optional, and it stays optional.** A deployment that has not configured Hub's origin must
   * still be able to register people: the token is minted, the event is emitted, and the payload
   * carries `linkable: false` instead of a URL. Making it required would turn a missing line in a
   * deploy manifest into "nobody can create an account", which is a worse failure than "the mail
   * that goes out has no button in it" — and rule 9's point is that the manifest is derived from
   * this file, so a new required variable breaks every existing environment at once.
   *
   * Never the request `Host` header, for the reason `publicUrl` records above; the argument is if
   * anything stronger here, because this link is what proves control of the mailbox.
   */
  readonly accountUrl: string | null
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
  /**
   * The registration challenge, or `null` when this deployment has no Turnstile account.
   *
   * `null` is not a degraded mode — it is the state every developer machine, every CI run and
   * every `micro` network is in, and in it `POST /auth/register` is byte-for-byte the route it was
   * before micro-org#361. See `parseTurnstile`.
   */
  readonly turnstile: TurnstileConfig | null
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

  // Optional, so it is read through `optional` and validated only when there is something to
  // validate — the same two-step the hand-off allowlist above uses. `origin()` on an empty string
  // would refuse to boot every deployment that has not set it, which is precisely what this
  // variable must not do.
  const accountUrl = optional(source, 'IDENTITY_ACCOUNT_URL', '')

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
    network: optional(source, 'IDENTITY_NETWORK', ''),
    singleNetwork: optional(source, 'CF_NETWORK_SINGLE', ''),
    ...parseKeySecrets(source),
    publicUrl: origin('IDENTITY_PUBLIC_URL', required(source, 'IDENTITY_PUBLIC_URL')),
    accountUrl: accountUrl.length > 0 ? origin('IDENTITY_ACCOUNT_URL', accountUrl) : null,
    handoffOrigins: Object.freeze([...new Set(handoffOrigins)]),
    outboxSigningSecret: requiredGeneratedSecret(source, 'OUTBOX_SIGNING_SECRET'),
    instanceId: optional(source, 'INSTANCE_ID', host || 'unknown'),
    // NOT a secret, and deliberately not guarded as one — it is a map of service name to scope
    // array, 60 characters of service names and scopes on the live estates. `parseServiceGrants`
    // asks the question that matters of it: is every scope one the contracts registry knows.
    serviceTokenGrants: parseServiceGrants(optional(source, 'IDENTITY_SERVICE_TOKEN_GRANTS', '{}')),
    deletionGraceDays: integer(source, 'IDENTITY_DELETION_GRACE_DAYS', 7, 0, 365),
    turnstile: parseTurnstile(source),
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
