/**
 * Password reset, against a real database — micro-org #154.
 *
 * A reset flow is the one route on the platform that hands out an account to whoever presents a
 * string, so this file is written as the probes an attacker would run rather than as a description
 * of the happy path. Every test here is a question somebody trying to take an account would ask:
 *
 *   - Does the link work twice?                                    (single use)
 *   - Does it still work tomorrow?                                 (expiry)
 *   - Can I use the link I was sent to reset somebody else?        (binding)
 *   - Does the request tell me whether the address is real?        (enumeration)
 *   - Does the token turn up anywhere I can read it?               (logs, URLs, error bodies, rows)
 *   - Does my stolen session survive the owner resetting?          (session invalidation)
 *   - Does a copy of the link outlive the link?                    (#184, event-bus retention)
 *
 * No test here writes a token literal. Every token is the one the code under test minted, which is
 * also the only way to get one: the table stores nothing but a SHA-256.
 */

import {
  GOOD_PASSWORD,
  enabled,
  freshEmail,
  freshHandle,
  migrateTestDb,
  openDb,
  resetIdentity,
  skip,
} from './testsupport.ts'
import { before, after, beforeEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { normaliseHandle } from '@cloudsforge/contracts-auth'
import type postgres from 'postgres'
import {
  RESET_REQUEST_STATUS,
  buildResetUrl,
  createPasswordResetToken,
  deliverPasswordReset,
  peekPasswordResetToken,
  redeemPasswordResetToken,
  requestPasswordReset,
  resetUrlFor,
  revokePasswordResetTokens,
  type DeliveryLogger,
} from './passwordReset.ts'
import { redactExpiredSecrets } from './outbox.ts'
import { registerUser, type UserRow } from './users.ts'
import type { Db } from './outbox.ts'

let sql: postgres.Sql
let db: Db

before(async () => {
  if (!enabled) return
  sql = openDb(17)
  await migrateTestDb(sql)
  db = sql as unknown as Db
})

after(async () => {
  if (!enabled) return
  await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (enabled) await resetIdentity(sql)
})

async function newUser(): Promise<UserRow> {
  const handle = freshHandle()
  const { user } = await registerUser(db, {
    email: freshEmail(),
    handle,
    handleKey: normaliseHandle(handle),
    password: GOOD_PASSWORD,
  })
  return user
}

const liveTokens = (userId: string): Promise<{ token_hash: string }[]> =>
  sql<{ token_hash: string }[]>`
    select token_hash from password_reset_tokens
     where user_id = ${userId} and used_at is null and expires_at > now()
  `

/** A logger that keeps every line, so a test can search all of them for a value that must not be there. */
interface Line {
  readonly level: 'info' | 'warn'
  readonly message: string
  readonly fields: Record<string, unknown>
}

function recordingLogger(): { readonly lines: Line[]; readonly log: DeliveryLogger } {
  const lines: Line[] = []
  return {
    lines,
    log: {
      info: (message: string, fields?: Record<string, unknown>) =>
        lines.push({ level: 'info', message, fields: fields ?? {} }),
      warn: (message: string, fields?: Record<string, unknown>) =>
        lines.push({ level: 'warn', message, fields: fields ?? {} }),
    },
  }
}

/**
 * Everything the logger was given, as one string.
 *
 * Serialised rather than inspected field by field, because the failure this guards against is a
 * value arriving somewhere nobody thought to look — inside a nested `err`, inside a `parameters`
 * array postgres.js hung off an exception, inside a message built by string concatenation.
 */
const asText = (lines: readonly Line[]): string =>
  lines.map((line) => `${line.level} ${line.message} ${JSON.stringify(line.fields)}`).join('\n')

/** 64 hex characters in a row — the shape of a minted token, wherever it might have landed. */
const TOKEN_SHAPED = /[0-9a-f]{64}/

/* ------------------------------------------------------------------ the shape of the link */

/**
 * **The link points at a PAGE ON HUB, and never at this service.**
 *
 * This is the defect that made the abandoned implementation unshippable. It built the link from
 * `IDENTITY_PUBLIC_URL`, which on both estates is `http://identity:4000` — an address on the
 * internal compose network, over plain HTTP, on a service that routes no `/reset`. Wiring the mail
 * up without fixing it would have sent every person who forgot their password a plaintext link to
 * a host their browser cannot resolve. `IDENTITY_ACCOUNT_URL` is Hub's public origin and the one
 * the verification link already uses, for the reason `env.ts` states on the field itself.
 */
test('the link points at Hub, in the fragment, and never at this service', () => {
  const url = buildResetUrl('https://hub.example', 'a-token-value')!
  assert.equal(url, 'https://hub.example/account/reset#token=a-token-value')

  const parsed = new URL(url)
  // The whole argument at :108 of the module, asserted as the absence it depends on. A token in the
  // query string reaches every access log between the browser and us and rides out again on the
  // `Referer` of the next navigation; Nimbus used `?token=` and wrote the live credential to its
  // own stdout on the request that spent it. A fragment is never transmitted, so a mail scanner's
  // pre-fetch is `GET /account/reset` carrying nothing at all.
  assert.equal(parsed.search, '', 'a token in the query string is a token in every access log')
  assert.equal(parsed.hash, '#token=a-token-value')
  assert.equal(parsed.pathname, '/account/reset')
})

test('the configured origin is used verbatim — a forged Host cannot reach this function', () => {
  // It takes no request at all, which is stronger than taking one and ignoring it: there is nothing
  // here for a future edit to reach for. A `Host`-derived link has the deployment's own relay mail
  // the victim a genuine, correctly branded reset whose button points at the attacker.
  assert.ok(resetUrlFor('a-token-value')!.startsWith('https://hub.test.cloudsforge.local/'))
  assert.ok(!resetUrlFor('a-token-value')!.includes('identity'), 'never this service’s own origin')
})

test('an unconfigured account origin produces NO link rather than a broken one', () => {
  // Not a relative link and not one pointing at identity's own origin, which serves no such page.
  // notify refuses to send a reset with no link, which is honest: the whole body of that mail is
  // the button, and sending it without one is the shape of a phishing message, sent by us.
  assert.equal(buildResetUrl(null, 'a-token-value'), null)
})

test('a token with URL-significant characters survives the round trip', () => {
  assert.equal(
    new URL(buildResetUrl('https://hub.example', 'a b&c#d')!).hash.slice('#token='.length),
    encodeURIComponent('a b&c#d'),
  )
})

/* ------------------------------------------------------------------ single use */

test('a link works ONCE, and the second redemption is refused', { skip }, async () => {
  const user = await newUser()
  const { token } = await createPasswordResetToken(db, user.id, null)

  assert.equal(await redeemPasswordResetToken(db, token), user.id)
  // The second is the whole test. A reset link that works twice is an account takeover held by
  // whoever reads the mailbox next — a backup, a shared inbox, a device left signed in.
  assert.equal(await redeemPasswordResetToken(db, token), null, 'a spent link must be dead')
})

test('two redemptions racing on one link: exactly one wins', { skip }, async () => {
  const user = await newUser()
  const { token } = await createPasswordResetToken(db, user.id, null)

  // The conditional `update ... returning` is what makes this safe. A read-then-write would let
  // both see `used_at is null` and both proceed, which is single-use defeated by two clicks.
  const results = await Promise.all([
    redeemPasswordResetToken(db, token),
    redeemPasswordResetToken(db, token),
  ])
  assert.deepEqual(results.filter((r) => r !== null), [user.id], 'exactly one redemption may win')
})

/**
 * **Looking at a token must not spend it.**
 *
 * The route has to know WHOSE account it is before it can judge the new password — the strength
 * check compares against the handle and the address — and the only way to learn that is from the
 * token. Doing it with the redemption meant a password the policy refused had already destroyed
 * the link that carried it: 400, and the retry the 400 invites answers 401 for ever. Every user who
 * picked a weak password lost their reset and had to ask for another one, which is also the loop
 * that makes an estate mail the same person repeatedly.
 */
test('peeking identifies the account WITHOUT spending the link', { skip }, async () => {
  const user = await newUser()
  const { token } = await createPasswordResetToken(db, user.id, null)

  assert.equal(await peekPasswordResetToken(db, token), user.id)
  assert.equal(await peekPasswordResetToken(db, token), user.id, 'peeking is not a use')
  assert.equal((await liveTokens(user.id)).length, 1, 'the link is still live after two peeks')
  // And the redemption still works exactly once afterwards, so the peek has not weakened the gate.
  assert.equal(await redeemPasswordResetToken(db, token), user.id)
  assert.equal(await redeemPasswordResetToken(db, token), null)
})

test('a peek is refused for a spent or expired link, exactly as a redemption is', { skip }, async () => {
  const user = await newUser()
  const spent = await createPasswordResetToken(db, user.id, null)
  await redeemPasswordResetToken(db, spent.token)
  assert.equal(await peekPasswordResetToken(db, spent.token), null)

  const expiring = await createPasswordResetToken(db, user.id, null)
  await sql`update password_reset_tokens set expires_at = now() - interval '1 second'`
  assert.equal(await peekPasswordResetToken(db, expiring.token), null)
  assert.equal(await peekPasswordResetToken(db, 'never-a-real-token'), null)
})

/* ------------------------------------------------------------------ expiry */

test('an expired link is refused, and says nothing about having existed', { skip }, async () => {
  const user = await newUser()
  const { token } = await createPasswordResetToken(db, user.id, null)
  await sql`update password_reset_tokens set expires_at = now() - interval '1 second'`

  assert.equal(await redeemPasswordResetToken(db, token), null)
  // Indistinguishable from a token that was never real. A different answer for "expired" and "never
  // existed" tells a guesser that a guess was once right, which is the only feedback a 256-bit
  // search needs to become worth running.
  assert.equal(await redeemPasswordResetToken(db, 'never-a-real-token'), null)
})

test('the TTL is thirty minutes — #184’s own remedy, applied from the start', { skip }, async () => {
  const user = await newUser()
  const { expiresAt } = await createPasswordResetToken(db, user.id, null)
  const minutes = (expiresAt.getTime() - Date.now()) / 60_000
  // Long enough to be read out of a mail client and typed into a browser, and 1/48th of the
  // verification token's window. It is what bounds the exposure of the copy that rides the bus.
  assert.ok(minutes > 29 && minutes <= 30, `expected ~30 minutes, got ${minutes}`)
})

/* ------------------------------------------------------------------ binding */

test('a link resets the account it was minted for, and no other', { skip }, async () => {
  const victim = await newUser()
  const attacker = await newUser()
  const { token } = await createPasswordResetToken(db, attacker.id, null)

  // The redemption returns the account the TOKEN is bound to. Nothing in the request says which
  // account is being reset, so there is no field for an attacker to change: the route takes the id
  // from here and never from the body. A reset flow that accepts `{ token, email }` and trusts the
  // second is the classic form of this bug.
  assert.equal(await redeemPasswordResetToken(db, token), attacker.id)
  assert.notEqual(await redeemPasswordResetToken(db, token), victim.id)

  // And the victim's own token set is untouched by any of it.
  assert.equal((await liveTokens(victim.id)).length, 0)
})

/* ------------------------------------------------------------------ one live token per account */

test('minting supersedes: the OLD link stops working the moment a new one is issued', { skip }, async () => {
  const user = await newUser()
  const first = await createPasswordResetToken(db, user.id, null)
  const second = await createPasswordResetToken(db, user.id, null)

  assert.equal((await liveTokens(user.id)).length, 1, 'two live tokens is the state this prevents')
  // The older one is the one most likely to have leaked into a mail client or a chat log.
  assert.equal(await redeemPasswordResetToken(db, first.token), null, 'the superseded link is dead')
  assert.equal(await redeemPasswordResetToken(db, second.token), user.id)
})

test('revoking burns every live token and leaves the spent ones alone', { skip }, async () => {
  const user = await newUser()
  const issued = await createPasswordResetToken(db, user.id, null)

  await revokePasswordResetTokens(db, user.id)
  assert.equal((await liveTokens(user.id)).length, 0)
  assert.equal(await redeemPasswordResetToken(db, issued.token), null)
})

/* ------------------------------------------------------------------ the token is never stored */

test('only the SHA-256 is stored — the raw token is in no column of the row', { skip }, async () => {
  const user = await newUser()
  const { token } = await createPasswordResetToken(db, user.id, null)

  const rows = await sql<{ token_hash: string; row: string }[]>`
    select token_hash, password_reset_tokens::text as row
      from password_reset_tokens where user_id = ${user.id}
  `
  assert.equal(rows.length, 1)
  assert.equal(rows[0]!.token_hash, createHash('sha256').update(token).digest('hex'))
  // The whole row as text, so a column added later that happens to hold the value fails this too.
  assert.ok(!rows[0]!.row.includes(token), 'the raw token must not be recoverable from the database')
})

/* ------------------------------------------------------------------ the token is never logged */

test('a successful delivery logs the user id and NOTHING that resembles a token', { skip }, async () => {
  const user = await newUser()
  const recorder = recordingLogger()

  const outcome = await deliverPasswordReset(db, recorder.log, user, null, 'req-safe')
  assert.equal(outcome.delivered, true)
  assert.equal(outcome.channel, 'notify')

  const text = asText(recorder.lines)
  assert.ok(text.includes(user.id), 'the id is logged, so an operator can join to the row')
  // The address is NOT, which is where this departs from Nimbus: it logged the email at warn on
  // every request, so a log search for an address returned the fact that somebody had asked to
  // reset it — an enumeration oracle in the log store rather than on the wire.
  assert.ok(!text.includes(user.email), 'logging the address makes the log an enumeration oracle')
  assert.ok(!TOKEN_SHAPED.test(text), 'nothing token-shaped may reach a log line')
  assert.ok(!text.includes('/account/reset'), 'the link is not a thing to log either')
})

/**
 * **The failure branch, which is where the leak actually was.**
 *
 * `withOutbox` binds the payload as a query parameter and postgres.js attaches `query` and
 * `parameters` to the errors it throws. `log.warn(msg, { err })` on this path therefore writes the
 * whole event payload — reset link included — to stdout, on exactly the request that minted it.
 * That is the incident the fragment exists to prevent, arriving by the back door.
 */
test('a FAILED delivery logs no token, no payload and no error object', { skip }, async () => {
  const recorder = recordingLogger()
  // An account that does not exist, so the insert violates the foreign key and the transaction
  // throws from inside `withOutbox` with the payload bound to it.
  const ghost = {
    id: '00000000-0000-7000-8000-000000000000',
    handle: 'nobody',
    email: 'nobody@example.invalid',
  }

  const outcome = await deliverPasswordReset(db, recorder.log, ghost, null, 'req-doomed')
  // It reports by return value. The caller has already answered 202 and there is no request left to
  // fail, so an escaping rejection would be an unhandled one.
  assert.equal(outcome.delivered, false)
  assert.equal(outcome.channel, 'none')

  const text = asText(recorder.lines)
  assert.ok(!TOKEN_SHAPED.test(text), 'a caught error must not carry the token out with it')
  assert.ok(!text.includes('resetUrl'), 'nor the payload that held it')
  assert.ok(!text.includes('/account/reset'), 'nor the link built from it')
  for (const line of recorder.lines) {
    assert.ok(!Object.hasOwn(line.fields, 'err'), 'never `{ err }` on this path — see the module header')
    assert.ok(!Object.hasOwn(line.fields, 'parameters'), 'postgres.js hangs the bound payload here')
  }
  // Only scalars the driver sets escape.
  const warned = recorder.lines.find((line) => line.level === 'warn')
  assert.ok(warned, 'the failure is still reported')
  assert.equal(typeof warned.fields['errorCode'], 'string')

  // And nothing was minted, so the user's next click starts over rather than racing a phantom.
  assert.equal((await liveTokens(ghost.id)).length, 0)
})

test('the 202 body is one fixed string, with nothing of the request in it', () => {
  // It varies with the DEPLOYMENT and never with the account, so the body cannot be read as an
  // answer to "does this address exist". It is also the string a UI shows verbatim, so a token or
  // an address appearing here would be rendered into somebody's browser.
  assert.ok(!TOKEN_SHAPED.test(RESET_REQUEST_STATUS))
  assert.ok(!RESET_REQUEST_STATUS.includes('@'))
  assert.match(RESET_REQUEST_STATUS, /If that account exists/)
})

/* ------------------------------------------------------------------ the event */

test('the request leaves as an event, in the SAME transaction as the token row', { skip }, async () => {
  const user = await newUser()
  const { token, expiresAt, linkable } = await requestPasswordReset(db, user, null, 'req-abc')
  assert.equal(linkable, true, 'the suite configures IDENTITY_ACCOUNT_URL')

  const events = await sql<
    { key: string; actor: string; correlation_id: string; payload: Record<string, unknown> }[]
  >`
    select key, actor, correlation_id, payload from outbox
     where topic = 'identity.password.reset_requested'
  `
  assert.equal(events.length, 1)
  const event = events[0]!
  assert.equal(event.key, user.id, 'keyed by the account — ordering is per key, and the later token wins')
  assert.equal(event.actor, `user:${user.id}`)
  assert.equal(event.correlation_id, 'req-abc')

  // Field for field, because notify renders exactly these names and a mismatch is a mail that
  // greets nobody or a button with no link behind it.
  assert.deepEqual(Object.keys(event.payload).sort(), [
    'email',
    'expiresAt',
    'handle',
    'issuedByOperator',
    'linkable',
    'resetUrl',
    'userId',
  ])
  assert.equal(event.payload['userId'], user.id)
  assert.equal(event.payload['handle'], user.handle)
  assert.equal(event.payload['expiresAt'], expiresAt.toISOString())
  assert.equal(event.payload['issuedByOperator'], false)
  assert.equal(event.payload['resetUrl'], buildResetUrl('https://hub.test.cloudsforge.local', token))

  // Same transaction as the row: a committed token nobody was told about is a user waiting for mail
  // that will never come, and a committed event for a token that does not exist is a mail whose
  // link is dead on arrival.
  assert.equal((await liveTokens(user.id)).length, 1)
})

test('an operator-issued reset says THAT one was, never WHICH operator', { skip }, async () => {
  const user = await newUser()
  const operator = await newUser()
  await requestPasswordReset(db, user, operator.id)

  const rows = await sql<{ actor: string; payload: Record<string, unknown> }[]>`
    select actor, payload from outbox where topic = 'identity.password.reset_requested'
  `
  const event = rows[0]!
  assert.equal(event.payload['issuedByOperator'], true)
  // The operator is on the ENVELOPE, where `activity` reads actors, and not in the payload, which
  // is what gets rendered into a mailbox. Naming the staff member who did it is an internal fact.
  assert.equal(event.actor, `operator:${operator.id}`)
  assert.ok(!JSON.stringify(event.payload).includes(operator.id), 'the mail body is not an audit log')
})

test('the operator mint does NOT mail anybody', { skip }, async () => {
  const user = await newUser()
  await createPasswordResetToken(db, user.id, null)

  // `createPasswordResetToken` is the hand-over path: the link is given to the person directly, and
  // an event here would mail a second copy of a live credential to an address that may be exactly
  // the one that has been lost.
  const events = await sql`select 1 from outbox where topic = 'identity.password.reset_requested'`
  assert.equal(events.length, 0)
})

/* ------------------------------------------------------------------ #184: retention on the bus */

/**
 * **The copy on the bus must not outlive the credential.**
 *
 * micro-org #184 is live: a single-use sign-in credential travels on the event bus and is retained
 * in 160 outbox and 148 notify rows, for ever, because nothing ever removes it. The reset token
 * cannot avoid the bus — the table stores only its SHA-256, so identity physically cannot serve the
 * link back to a subscriber that asks for it later, and reference-and-redeem would mean keeping the
 * raw token in the credential table, which is strictly worse than what #184 already describes.
 *
 * What it can do is refuse to RETAIN it. The sweep strips the link out of the outbox row once the
 * token behind it is expired, so the rows that accumulate hold a dead string rather than a live
 * one, and #184's count stops growing on this topic instead of doubling.
 */
test('the sweep strips a spent link out of the outbox row, and leaves a live one alone', { skip }, async () => {
  const user = await newUser()
  const { token } = await requestPasswordReset(db, user, null)

  // Still live: the mail may not have gone out yet, and stripping it here would be a reset nobody
  // can complete.
  assert.equal(await redactExpiredSecrets(db), 0)
  const [before] = await sql<{ payload: Record<string, unknown> }[]>`
    select payload from outbox where topic = 'identity.password.reset_requested'
  `
  assert.ok(String(before!.payload['resetUrl']).includes(token))

  // Now the token is dead. The row is not, and never will be — nothing prunes the outbox — so the
  // only question is whether it goes on holding a credential after the credential stopped meaning
  // anything.
  await sql`
    update outbox set payload = jsonb_set(payload, '{expiresAt}', to_jsonb((now() - interval '1 second')::text))
     where topic = 'identity.password.reset_requested'
  `
  assert.equal(await redactExpiredSecrets(db), 1)

  const [after] = await sql<{ payload: Record<string, unknown>; row: string }[]>`
    select payload, outbox::text as row from outbox
     where topic = 'identity.password.reset_requested'
  `
  assert.ok(!Object.hasOwn(after!.payload, 'resetUrl'), 'the link must not survive the token')
  assert.ok(!after!.row.includes(token), 'nor may it survive anywhere else in the row')
  // `linkable` is corrected rather than left lying, so a replayed event is refused by notify's rule
  // instead of rendering a button with an empty href.
  assert.equal(after!.payload['linkable'], false)
  // Everything an auditor needs is still there: that a reset was asked for, by whom, and when.
  assert.equal(after!.payload['userId'], user.id)

  // Idempotent — the sweep runs every fifteen minutes for the life of the deployment.
  assert.equal(await redactExpiredSecrets(db), 0)
})
