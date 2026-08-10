/**
 * The registration challenge: Cloudflare Turnstile, verified here and nowhere else.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * ── WHAT THIS IS FOR, AND WHAT IT IS NOT FOR (micro-org#361) ──────────────────────────────────
 *
 * `POST /auth/register` is the estate's only unauthenticated account-creating route. It is already
 * rate limited at five per address per minute (`LIMITS` in server.ts), and the limiter is a ceiling
 * on how much work ONE address can make ONE replica do — it is not, and cannot be, a defence
 * against a population of addresses. A challenge is.
 *
 * It is worth writing down what this does NOT fix, because micro-org#361 measured it: the thousands
 * of accounts on both networks are `beacon`'s synthetic registrations plus test residue, not bot
 * sign-ups from the open internet. A challenge aimed at strangers will not reduce that number by
 * one. The reason to build it anyway is that the estate has no other control on the route and the
 * cost is one vendor it is already behind.
 *
 * ── THE ONLY VERIFICATION THAT COUNTS IS THIS ONE ─────────────────────────────────────────────
 *
 * The widget in the browser proves nothing. It renders, it produces a token, and a client that
 * skipped it entirely would look identical on the wire. The token is a claim; `siteverify` is what
 * turns it into a fact, and Cloudflare redeems it at that moment — a token is SINGLE USE, so a
 * caller that replays one gets `timeout-or-duplicate` and is refused.
 *
 * ── THREE ASSERTIONS, NOT ONE ─────────────────────────────────────────────────────────────────
 *
 * `success: true` alone is not enough, and this is the part integrations get wrong:
 *
 *   1. `success` — the token was issued by Cloudflare, to this secret's widget, and has not been
 *      spent or expired.
 *   2. `action` — the widget was the one on the SIGN-UP form. Without this, a token harvested from
 *      any other Turnstile widget served under the same sitekey (a contact form, a login page)
 *      is accepted here.
 *   3. `hostname` — the page that solved it was one of ours. Without this, a widget embedded on an
 *      attacker's own page under our sitekey mints tokens this route accepts. The sitekey is
 *      public, so that page costs an attacker nothing to build.
 *
 * ── FAIL CLOSED — A DECISION, TAKEN 2026-08-10, AND THE ISSUE ARGUES THE OTHER WAY ─────────────
 *
 * When Cloudflare cannot be reached, times out, or answers anything this file cannot read, the
 * registration is REFUSED. That is deliberate and it is the minority position:
 *
 *   - micro-org#361 recommends fail-OPEN for registration specifically — "a captcha vendor's
 *     outage should not stop a real person from opening an account, and the existing rate limit
 *     still stands behind it". That reasoning is sound wherever there are real people to lose.
 *   - It is overridden here on one measured fact, and the fact is in the same issue: THIS ESTATE
 *     HAS NO ORGANIC REGISTRATIONS TO LOSE. Every account on both networks is beacon or test
 *     residue, and beacon does not come through this gate at all (it presents a service
 *     principal — see `POST /auth/register`). So the population fail-open protects is, today,
 *     empty, while the population it admits during an outage is exactly the one this exists to
 *     stop. It also matches Cloudflare's own guidance.
 *   - **The day the platform has real users, this is worth revisiting**, and the honest signal for
 *     that is `identity_registration_challenge_total{outcome="upstream_failure"}` rising while genuine
 *     registrations are being turned away. A reader who finds this comment then should read it as
 *     a decision that was made rather than a default that was inherited.
 *
 * Fail-closed is why an outage answers 503 `challenge_unavailable` and not 403: nothing about the
 * caller was wrong, the service could not decide, and that is what 503 means everywhere else in
 * this file's neighbour (see `UnavailableError` in server.ts). A single generic refusal would
 * leave an operator unable to tell "a bot was stopped" from "Cloudflare was unreachable", which is
 * the distinction the whole error and metric shape below exists to preserve.
 *
 * ── NOTHING HERE LOGS THE TOKEN OR THE SECRET ─────────────────────────────────────────────────
 *
 * The secret is read from `TURNSTILE_SECRET` and is only ever written into a request body. The
 * token is a live single-use credential for the few seconds before it is redeemed. Neither appears
 * in a return value, a message, or a log line — the outcomes below carry Cloudflare's own
 * `error-codes`, the returned `action` and the returned `hostname`, and nothing else.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

/** Cloudflare's verification endpoint. The only address this module ever dials. */
export const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'

/**
 * The `action` the sign-up widget is configured with, and the value asserted on the way back.
 *
 * A literal rather than a variable: it is a property of this route, not of the deployment, and a
 * configurable one would be a deployment where the assertion is silently satisfied by whatever the
 * widget happens to send.
 */
export const REGISTER_ACTION = 'signup'

/**
 * The longest token this service will carry to Cloudflare.
 *
 * Turnstile's documented ceiling. Checked here rather than left to `MAX_BODY_BYTES` because the
 * body cap is 64KB and a caller who can make this service post 64KB to a third party on an
 * unauthenticated route has an amplifier; and because a token that is over the vendor's own limit
 * is refusable without a round trip.
 */
export const MAX_TOKEN_CHARS = 2048

/** How long to wait on Cloudflare before giving up. Fail-closed, so this bounds a refusal. */
export const SITEVERIFY_TIMEOUT_MS = 10_000

/** Present only when the deployment configured the whole feature. See `parseTurnstile` in env.ts. */
export interface TurnstileConfig {
  readonly secret: string
  /** PUBLIC. Served to browsers by `GET /auth/challenge` — that is what it is for. */
  readonly siteKey: string
  /** Hostnames a solved widget may have been served from. Never empty; env.ts refuses that. */
  readonly hostnames: readonly string[]
}

/**
 * The four outcomes, and they are the metric's label values.
 *
 * `missing_token` and `rejected` are both the caller's fault and are still separated, because one
 * is "a client that does not implement the challenge" — a stale bundle, a script blocker, a
 * scripted caller — and the other is "a challenge that was attempted and did not hold". A single
 * label would make a broken deploy of hub-web look exactly like an attack.
 */
export type ChallengeOutcome = 'ok' | 'missing_token' | 'rejected' | 'upstream_failure'

export interface ChallengeRefusal {
  readonly outcome: Exclude<ChallengeOutcome, 'ok'>
  /** For the log and the refusal message. Never contains the token or the secret. */
  readonly detail: string
  /** Cloudflare's own codes, when it answered at all. */
  readonly errorCodes?: readonly string[]
}

export type ChallengeResult = { readonly outcome: 'ok' } | ChallengeRefusal

/** Just enough of `fetch` to be injectable. The suite supplies one; the service supplies the real one. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>

/**
 * `bad-request` means WE sent something Cloudflare could not parse, not that the visitor failed.
 *
 * It is classed as an upstream failure rather than a rejection so that a malformed request from
 * this service reads as this service's problem in the metric. The most plausible way to earn it is
 * `remoteip`: the address comes from `x-forwarded-for`, which is attacker-supplied unless a proxy
 * rewrites it, so a caller can put a non-address in it. That can only spoil that caller's OWN
 * registration, and mislabelling it `rejected` would hide a genuine misconfiguration behind a
 * counter that is supposed to mean "a bot was stopped".
 */
const OUR_FAULT_CODES = new Set(['bad-request', 'internal-error'])

/**
 * Read the token out of a registration body.
 *
 * `cf-turnstile-response` is Cloudflare's own field name, and it is kept verbatim rather than
 * camel-cased: it is what the widget puts in a plain HTML form, what every Turnstile integration
 * guide names, and a second spelling on our side would be one more thing for a client to get
 * wrong. It sits beside `email`, `handle` and `password` and is ignored by `validateRegistration`,
 * which reads only the fields it knows about.
 *
 * Exported so the shape rules can be exercised without a network at all.
 */
export function readChallengeToken(body: Record<string, unknown>): ChallengeRefusal | string {
  const raw = body['cf-turnstile-response']
  if (typeof raw !== 'string') {
    return { outcome: 'missing_token', detail: 'no cf-turnstile-response was sent' }
  }
  const token = raw.trim()
  if (token === '') {
    return { outcome: 'missing_token', detail: 'cf-turnstile-response was empty' }
  }
  if (token.length > MAX_TOKEN_CHARS) {
    // The LENGTH, never the value. This branch exists to refuse a caller trying to make this
    // service post something large to a third party, and quoting it would defeat the point.
    return {
      outcome: 'missing_token',
      detail: `cf-turnstile-response is ${token.length} characters; the limit is ${MAX_TOKEN_CHARS}`,
    }
  }
  return token
}

/**
 * Redeem a token at Cloudflare and decide whether it stands.
 *
 * Pure over its inputs apart from the one call it makes, and the call is injected — which is what
 * lets the suite drive a rejection, a wrong `action`, a hostname off the allowlist and an outage
 * without a fake that can only say yes. A verifier whose test double always returns `success: true`
 * proves nothing; micro-org#355 and #356 are that defect twice.
 */
export async function verifyChallengeToken(
  config: TurnstileConfig,
  input: { readonly token: string; readonly remoteIp: string | null },
  fetchImpl: FetchLike,
): Promise<ChallengeResult> {
  const form = new URLSearchParams()
  form.set('secret', config.secret)
  form.set('response', input.token)
  // Optional at Cloudflare, and omitted rather than sent empty when this service has no address
  // for the caller. It is the SAME value the rate limiter keys on (`clientAddress` in server.ts);
  // a second notion of "who is calling" would be a second thing to get wrong.
  if (input.remoteIp) form.set('remoteip', input.remoteIp)

  let response: Response
  try {
    response = await fetchImpl(SITEVERIFY_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
      // A registration that hangs on a third party is a registration nobody completes. Ten seconds
      // is far longer than a healthy siteverify (tens of milliseconds) and far shorter than any
      // client's patience.
      signal: AbortSignal.timeout(SITEVERIFY_TIMEOUT_MS),
    })
  } catch (err) {
    // A timeout, a DNS failure, a TLS failure, a reset. All of them are "could not decide".
    return {
      outcome: 'upstream_failure',
      detail: `siteverify could not be reached: ${err instanceof Error ? err.name : 'unknown error'}`,
    }
  }

  if (!response.ok) {
    return { outcome: 'upstream_failure', detail: `siteverify answered ${response.status}` }
  }

  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    return { outcome: 'upstream_failure', detail: 'siteverify did not answer JSON' }
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    return { outcome: 'upstream_failure', detail: 'siteverify did not answer an object' }
  }

  const answer = payload as Record<string, unknown>
  const errorCodes = Array.isArray(answer['error-codes'])
    ? (answer['error-codes'] as unknown[]).filter((code): code is string => typeof code === 'string')
    : []

  // `=== true`, never `!== false`. A response that lost the field entirely must not read as a pass,
  // and `undefined !== false` is exactly how that happens.
  if (answer['success'] !== true) {
    if (errorCodes.some((code) => OUR_FAULT_CODES.has(code))) {
      return {
        outcome: 'upstream_failure',
        detail: 'siteverify refused this service’s own request',
        errorCodes,
      }
    }
    return { outcome: 'rejected', detail: 'siteverify did not accept the token', errorCodes }
  }

  // Asserted AFTER success, because Cloudflare populates neither field for a token it did not
  // issue — checking them first would compare against absent values and pass or fail for the
  // wrong reason.
  const action = answer['action']
  if (action !== REGISTER_ACTION) {
    return {
      outcome: 'rejected',
      // The action is the widget's own configured label and is not a secret; naming it is what
      // tells an operator that a token from some other form was presented here.
      detail: `the token was solved for action ${JSON.stringify(action)}, not ${REGISTER_ACTION}`,
    }
  }

  const hostname = answer['hostname']
  if (typeof hostname !== 'string' || !config.hostnames.includes(hostname)) {
    return {
      outcome: 'rejected',
      detail: `the token was solved on ${JSON.stringify(hostname)}, which is not in TURNSTILE_HOSTNAMES`,
    }
  }

  return { outcome: 'ok' }
}
