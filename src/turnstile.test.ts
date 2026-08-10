/**
 * The Turnstile verifier, driven by Cloudflare's own documented answers.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE FAKE BELOW CAN SAY NO, AND THAT IS THE WHOLE POINT OF THIS FILE.**
 *
 * The recurring defect in this estate is a check that cannot fail (micro-org#355, #356). A captcha
 * verifier tested against a double that always answers `{"success": true}` is that defect in its
 * purest form: every assertion passes, the suite is green, and deleting the entire verification
 * step changes nothing. So `siteverify` here is a function each test supplies, and the cases are
 * the refusals — a spent token, a token for another form, a widget on somebody else's page, an
 * outage, a body that is not JSON. The one `success: true` case exists to prove the refusals are
 * not just "it always says no".
 *
 * No network. No secret. The fixture below is a generated value that is not Cloudflare's, and the
 * assertions check it is SENT to `siteverify` and never appears anywhere else.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import './testsupport.ts'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import {
  MAX_TOKEN_CHARS,
  REGISTER_ACTION,
  SITEVERIFY_URL,
  readChallengeToken,
  verifyChallengeToken,
  type FetchLike,
  type TurnstileConfig,
} from './turnstile.ts'

const CONFIG: TurnstileConfig = {
  secret: `0x4AAAAAAA${randomBytes(18).toString('base64url')}`,
  siteKey: '0x4AAAAAAEMXmH8jdtxq8FYo',
  hostnames: ['hub.cloudsforge.online'],
}

/** Records what was sent and answers what the test says Cloudflare answers. */
function siteverifyAnswering(payload: unknown, init: { status?: number; text?: string } = {}) {
  const seen: { url: string; body: URLSearchParams; contentType: string }[] = []
  const fetchImpl: FetchLike = async (url, request) => {
    seen.push({
      url,
      body: new URLSearchParams(String(request.body)),
      contentType: (request.headers as Record<string, string>)['content-type'] ?? '',
    })
    if (init.text !== undefined) {
      return new Response(init.text, { status: init.status ?? 200 })
    }
    return new Response(JSON.stringify(payload), {
      status: init.status ?? 200,
      headers: { 'content-type': 'application/json' },
    })
  }
  return { fetchImpl, seen }
}

const PASS = { success: true, action: REGISTER_ACTION, hostname: 'hub.cloudsforge.online' }

/* ---------------------------------------------------------------- what the caller sent */

test('a body with no token, an empty token or a whitespace token is missing_token', () => {
  for (const body of [{}, { 'cf-turnstile-response': '' }, { 'cf-turnstile-response': '   ' }]) {
    const result = readChallengeToken(body)
    assert.notEqual(typeof result, 'string', JSON.stringify(body))
    assert.equal(typeof result === 'string' ? '' : result.outcome, 'missing_token')
  }
})

test('a non-string token is missing_token rather than a crash', () => {
  // A caller can put anything in a JSON body. `{'cf-turnstile-response': {}}` reaching
  // `URLSearchParams.set` would post `[object Object]` to Cloudflare; a number would post digits.
  for (const value of [42, null, {}, [], true]) {
    const result = readChallengeToken({ 'cf-turnstile-response': value })
    assert.equal(typeof result === 'string' ? '' : result.outcome, 'missing_token', String(value))
  }
})

test('an over-long token is refused WITHOUT a round trip, and its value is never quoted', () => {
  // An unauthenticated caller who can make this service post 64KB to a third party has an
  // amplifier. The refusal names the length and never the value.
  const oversized = 'a'.repeat(MAX_TOKEN_CHARS + 1)
  const result = readChallengeToken({ 'cf-turnstile-response': oversized })
  assert.notEqual(typeof result, 'string')
  if (typeof result === 'string') return
  assert.equal(result.outcome, 'missing_token')
  assert.ok(!result.detail.includes(oversized), 'the refusal quoted the token')
  assert.ok(result.detail.includes(String(MAX_TOKEN_CHARS)))

  // Exactly at the limit is accepted: an off-by-one here refuses every real token the day
  // Cloudflare's format grows.
  assert.equal(readChallengeToken({ 'cf-turnstile-response': 'a'.repeat(MAX_TOKEN_CHARS) }), 'a'.repeat(MAX_TOKEN_CHARS))
})

/* ---------------------------------------------------------------- what is sent to Cloudflare */

test('the request to siteverify is form-encoded, carries the secret, and carries remoteip only when known', async () => {
  const { fetchImpl, seen } = siteverifyAnswering(PASS)
  await verifyChallengeToken(CONFIG, { token: 'tok-1', remoteIp: '198.51.100.7' }, fetchImpl)

  assert.equal(seen[0]?.url, SITEVERIFY_URL)
  assert.equal(seen[0]?.contentType, 'application/x-www-form-urlencoded')
  assert.equal(seen[0]?.body?.get('secret'), CONFIG.secret)
  assert.equal(seen[0]?.body?.get('response'), 'tok-1')
  assert.equal(seen[0]?.body?.get('remoteip'), '198.51.100.7')

  // Omitted rather than sent empty. Cloudflare validates the field when it is present, and an
  // empty one earns `bad-request` — which would turn "this service does not know the caller's
  // address" into a refused registration.
  const second = siteverifyAnswering(PASS)
  await verifyChallengeToken(CONFIG, { token: 'tok-2', remoteIp: null }, second.fetchImpl)
  assert.equal(second.seen[0]?.body?.has('remoteip'), false)
})

/* ---------------------------------------------------------------- what Cloudflare answered */

test('a token Cloudflare accepts, for this action, on an allowed hostname, passes', async () => {
  const { fetchImpl } = siteverifyAnswering(PASS)
  assert.deepEqual(await verifyChallengeToken(CONFIG, { token: 'tok', remoteIp: null }, fetchImpl), {
    outcome: 'ok',
  })
})

test('a token Cloudflare rejects is rejected, and its error codes survive to the metric', async () => {
  // `timeout-or-duplicate` is what a REPLAYED token earns — Cloudflare redeems a token at
  // siteverify and it is single-use. This is the case that makes the whole feature worth anything.
  const { fetchImpl } = siteverifyAnswering({
    success: false,
    'error-codes': ['timeout-or-duplicate'],
  })
  const result = await verifyChallengeToken(CONFIG, { token: 'spent', remoteIp: null }, fetchImpl)
  if (result.outcome === 'ok') assert.fail('a spent token was accepted')
  assert.equal(result.outcome, 'rejected')
  assert.deepEqual(result.errorCodes, ['timeout-or-duplicate'])
})

test('a response that merely LOST the success field is not a pass', async () => {
  /*
   * `success !== true`, never `success === false`.
   *
   * Every payload below is an OTHERWISE PERFECT answer — right action, allowed hostname — with
   * `success` some truthy thing that is not the boolean `true`, or absent. That is deliberate and
   * it is the only shape that catches this: the earlier version of this test used bodies with no
   * `action` either, so the action assertion refused them and a `!== true` weakened to `=== false`
   * survived the whole suite. A weakened check has to be starved of every OTHER reason to refuse
   * before it can be seen.
   *
   * The case is not hypothetical. A proxy that rewrites JSON, a gateway error page parsed as an
   * object, and Cloudflare shipping a schema change all produce exactly this: a body that is not a
   * refusal and is not an acceptance either.
   */
  const missing: Record<string, unknown> = { ...PASS }
  delete missing['success']
  for (const payload of [missing, { ...PASS, success: 'true' }, { ...PASS, success: 1 }, { ...PASS, success: {} }]) {
    const { fetchImpl } = siteverifyAnswering(payload)
    const result = await verifyChallengeToken(CONFIG, { token: 'tok', remoteIp: null }, fetchImpl)
    assert.notEqual(result.outcome, 'ok', `${JSON.stringify(payload)} was accepted as a solved challenge`)
  }
})

test('a token solved for ANOTHER action is refused even though Cloudflare accepted it', async () => {
  // The sitekey is public and one account's widgets share it. Without this assertion a token
  // harvested from a contact form or a login widget opens accounts here.
  for (const action of ['login', 'contact', '', undefined, null, 'SIGNUP']) {
    const { fetchImpl } = siteverifyAnswering({ ...PASS, action })
    const result = await verifyChallengeToken(CONFIG, { token: 'tok', remoteIp: null }, fetchImpl)
    assert.equal(result.outcome, 'rejected', `action ${String(action)} was accepted`)
  }
})

test('a token solved on a hostname outside the allowlist is refused', async () => {
  // The attacker's own page, embedding our public sitekey. Cloudflare answers `success: true` for
  // it — correctly, it IS a solved challenge — and the hostname is the only thing that says whose
  // page it was solved on.
  for (const hostname of ['evil.example', 'hub.cloudsforge.online.evil.example', 'cloudsforge.online', '', undefined, 42]) {
    const { fetchImpl } = siteverifyAnswering({ ...PASS, hostname })
    const result = await verifyChallengeToken(CONFIG, { token: 'tok', remoteIp: null }, fetchImpl)
    assert.equal(result.outcome, 'rejected', `hostname ${String(hostname)} was accepted`)
  }
})

test('a hostname on the allowlist but not the first one is accepted', async () => {
  // Guards against an implementation that compares against `hostnames[0]`, which passes every test
  // above with a single-entry allowlist.
  const many: TurnstileConfig = { ...CONFIG, hostnames: ['hub.cloudsforge.online', 'localhost'] }
  const { fetchImpl } = siteverifyAnswering({ ...PASS, hostname: 'localhost' })
  assert.equal((await verifyChallengeToken(many, { token: 'tok', remoteIp: null }, fetchImpl)).outcome, 'ok')
})

/* ---------------------------------------------------------------- when Cloudflare cannot answer */

test('a siteverify outage is upstream_failure, never a pass and never a rejection', async () => {
  // FAIL CLOSED: the caller of this function turns `upstream_failure` into a 503. What must NOT
  // happen is `ok`. The reasoning, and the fact that micro-org#361 argues for fail-open, is
  // written out at the top of turnstile.ts.
  const thrown: FetchLike = async () => {
    throw Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' })
  }
  const result = await verifyChallengeToken(CONFIG, { token: 'tok', remoteIp: null }, thrown)
  if (result.outcome === 'ok') assert.fail('an outage was treated as a solved challenge')
  assert.equal(result.outcome, 'upstream_failure')
  assert.ok(result.detail.includes('TimeoutError'))
})

test('a 5xx, a non-JSON body and a non-object body are all upstream_failure', async () => {
  const cases: { fetchImpl: FetchLike; why: string }[] = [
    { fetchImpl: siteverifyAnswering(null, { status: 502, text: 'bad gateway' }).fetchImpl, why: '502' },
    { fetchImpl: siteverifyAnswering(null, { text: '<html>maintenance</html>' }).fetchImpl, why: 'html' },
    { fetchImpl: siteverifyAnswering(['success']).fetchImpl, why: 'array' },
    { fetchImpl: siteverifyAnswering('true').fetchImpl, why: 'bare string' },
  ]
  for (const { fetchImpl, why } of cases) {
    const result = await verifyChallengeToken(CONFIG, { token: 'tok', remoteIp: null }, fetchImpl)
    assert.equal(result.outcome, 'upstream_failure', why)
  }
})

test('bad-request is OUR fault and is counted as an outage, not as a stopped bot', async () => {
  // Cloudflare answers `bad-request` when the REQUEST was malformed — most plausibly a `remoteip`
  // this service took from an attacker-supplied `x-forwarded-for`. Filing that under `rejected`
  // would hide a misconfiguration of ours behind the counter that is supposed to mean "a bot was
  // stopped", and would make the fail-closed refusal look like the gate working.
  for (const code of ['bad-request', 'internal-error']) {
    const { fetchImpl } = siteverifyAnswering({ success: false, 'error-codes': [code] })
    const result = await verifyChallengeToken(CONFIG, { token: 'tok', remoteIp: null }, fetchImpl)
    assert.equal(result.outcome, 'upstream_failure', code)
  }
  // …while `invalid-input-secret` is a deployment error that still means this caller failed, and
  // `invalid-input-response` is the ordinary bad token. Neither is an outage.
  for (const code of ['invalid-input-response', 'invalid-input-secret', 'missing-input-response']) {
    const { fetchImpl } = siteverifyAnswering({ success: false, 'error-codes': [code] })
    const result = await verifyChallengeToken(CONFIG, { token: 'tok', remoteIp: null }, fetchImpl)
    assert.equal(result.outcome, 'rejected', code)
  }
})

/* ---------------------------------------------------------------- disclosure */

test('no outcome this module produces contains the secret or the token', async () => {
  const token = 'a-token-that-must-not-be-echoed'
  const payloads: unknown[] = [
    { success: false, 'error-codes': ['invalid-input-response'] },
    { ...PASS, action: 'login' },
    { ...PASS, hostname: 'evil.example' },
    { success: false, 'error-codes': ['bad-request'] },
  ]
  for (const payload of payloads) {
    const { fetchImpl } = siteverifyAnswering(payload)
    const result = await verifyChallengeToken(CONFIG, { token, remoteIp: '198.51.100.7' }, fetchImpl)
    const rendered = JSON.stringify(result)
    assert.ok(!rendered.includes(token), `an outcome echoed the token: ${rendered}`)
    assert.ok(!rendered.includes(CONFIG.secret), `an outcome echoed the secret: ${rendered}`)
  }
})
