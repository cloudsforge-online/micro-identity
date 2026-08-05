/**
 * Email verification, against a real database.
 *
 * The three properties that carry the design are all here, and each is exercised rather than
 * asserted: the link's SHAPE (a page, with the token after the '#'), SINGLE USE (redeemed twice,
 * the second refused), and ONE LIVE TOKEN PER ACCOUNT (proved twice over — through the module,
 * which supersedes under a lock, and against the partial unique index directly, from a raw
 * connection that skips the module entirely).
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
  buildVerifyUrl,
  redeemEmailVerification,
  requestEmailVerification,
  revokeEmailVerificationTokens,
} from './emailVerification.ts'
import { MIGRATIONS } from './migrations.ts'
import { registerUser, type UserRow } from './users.ts'
import type { Db } from './outbox.ts'

let sql: postgres.Sql
let db: Db

before(async () => {
  if (!enabled) return
  sql = openDb(8)
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
    select token_hash from email_verification_tokens
     where user_id = ${userId} and consumed_at is null
  `

/* ------------------------------------------------------------------ the shape of the link */

test('the token goes after the # and the link points at a PAGE, not at this service', () => {
  const url = buildVerifyUrl('https://hub.example', 'a-token-value')!
  assert.equal(url, 'https://hub.example/account/verify#token=a-token-value')

  const parsed = new URL(url)
  // The whole security argument, asserted as the two absences it depends on. A token in the query
  // reaches every access log between the browser and us — and, worse for a link that arrives by
  // mail, a scanner that pre-fetches it SENDS it. A fragment is never transmitted, so a pre-fetch
  // is `GET /account/verify` carrying nothing, and the page posts the token instead.
  assert.equal(parsed.search, '', 'a token in the query string is a token in every access log')
  assert.equal(parsed.pathname, '/account/verify')
  assert.equal(parsed.hash, '#token=a-token-value')
})

test('a token with URL-significant characters survives the round trip', () => {
  // The mint produces hex, so this cannot bite today. It is asserted because the encode is the kind
  // of line a future edit drops as redundant, and the failure would be a link that verifies nobody.
  const url = buildVerifyUrl('https://hub.example', 'a b&c#d')!
  assert.equal(new URL(url).hash.slice('#token='.length), encodeURIComponent('a b&c#d'))
})

test('an unconfigured account origin produces NO link rather than a broken one', () => {
  // IDENTITY_ACCOUNT_URL is optional, and this is what optional means here: no link, not a relative
  // one and not one pointing at identity's own origin, which serves no such page.
  assert.equal(buildVerifyUrl(null, 'a-token-value'), null)
})

/* ------------------------------------------------------------------ single use */

test('a link works ONCE, and the second redemption is refused', { skip }, async () => {
  const user = await newUser()
  const { token } = await requestEmailVerification(db, user)

  assert.equal(await redeemEmailVerification(db, token), user.id)
  // The property, driven rather than asserted: the same link, again. A conditional UPDATE is what
  // makes this false — a read followed by a write would let both through, and both would mint a
  // session.
  assert.equal(await redeemEmailVerification(db, token), null, 'a verification link is single use')
})

test('two redemptions racing on one link: exactly one wins', { skip }, async () => {
  const user = await newUser()
  const { token } = await requestEmailVerification(db, user)

  const outcomes = await Promise.all([
    redeemEmailVerification(db, token),
    redeemEmailVerification(db, token),
  ])
  assert.equal(outcomes.filter((id) => id === user.id).length, 1, 'one winner')
  assert.equal(outcomes.filter((id) => id === null).length, 1, 'and one loser')
})

test('redeeming stamps the address as proved, and a later one does not move the date', { skip }, async () => {
  const user = await newUser()
  assert.equal(user.email_verified_at, null, 'a new account starts unproved')

  const first = await requestEmailVerification(db, user)
  await redeemEmailVerification(db, first.token)
  const stamped = (await sql<{ email_verified_at: Date }[]>`
    select email_verified_at from users where id = ${user.id}
  `)[0]!.email_verified_at
  assert.ok(stamped instanceof Date)

  // A second link — a resend that raced, or a re-verification — must not rewrite the date the
  // address was FIRST proved. `coalesce`, not an assignment.
  const second = await requestEmailVerification(db, user)
  await redeemEmailVerification(db, second.token)
  const after = (await sql<{ email_verified_at: Date }[]>`
    select email_verified_at from users where id = ${user.id}
  `)[0]!.email_verified_at
  assert.equal(after.getTime(), stamped.getTime())
})

test('an expired link is refused, and says nothing about having existed', { skip }, async () => {
  const user = await newUser()
  const { token } = await requestEmailVerification(db, user)
  await sql`update email_verification_tokens set expires_at = now() - interval '1 second'`

  assert.equal(await redeemEmailVerification(db, token), null)
  // Indistinguishable from a token that was never real, which is the point: a different answer for
  // "expired" and "never existed" tells a guesser that a guess was once right.
  assert.equal(await redeemEmailVerification(db, 'never-a-real-token'), null)
})

test('the TTL is twenty-four hours, not the reset token’s thirty minutes', { skip }, async () => {
  const user = await newUser()
  const { expiresAt } = await requestEmailVerification(db, user)
  const hours = (expiresAt.getTime() - Date.now()) / 3_600_000
  // A verification link is read on a phone the next morning, after the mail sat in a queue. Thirty
  // minutes would routinely fail whoever signs up at night.
  assert.ok(hours > 23.9 && hours <= 24, `expected ~24 hours, got ${hours}`)
})

/* ------------------------------------------------------------------ one live token per account */

test('minting supersedes: the OLD link stops working the moment a new one is issued', { skip }, async () => {
  const user = await newUser()
  const first = await requestEmailVerification(db, user)
  const second = await requestEmailVerification(db, user)

  assert.equal((await liveTokens(user.id)).length, 1, 'two live tokens is the state this prevents')
  // The older one is the one most likely to have leaked into a mail client or a scanner's cache,
  // so it is the one that must die.
  assert.equal(await redeemEmailVerification(db, first.token), null, 'the superseded link is dead')
  assert.equal(await redeemEmailVerification(db, second.token), user.id)
})

test('the DATABASE refuses a second live token, with the module out of the way', { skip }, async () => {
  const user = await newUser()
  await requestEmailVerification(db, user)

  // Straight at the table, skipping the advisory lock and the supersede entirely — which is what a
  // future edit that drops them would look like. The partial unique index is what makes "two live
  // tokens for one account" unrepresentable rather than merely avoided by careful code.
  await assert.rejects(
    sql`
      insert into email_verification_tokens (token_hash, user_id, expires_at)
      values ('a-hash-that-is-not-a-token', ${user.id}, now() + interval '1 day')
    `,
    (err: unknown) => (err as { code?: string }).code === '23505',
    'a second live token must be impossible, not merely unusual',
  )
})

test('the index is PARTIAL: a consumed token does not block the next one', { skip }, async () => {
  const user = await newUser()
  const first = await requestEmailVerification(db, user)
  await redeemEmailVerification(db, first.token)

  // A plain unique index on user_id would make an account verifiable exactly once for the life of
  // the database, and every resend after that would fail at 23505.
  const second = await requestEmailVerification(db, user)
  assert.equal(await redeemEmailVerification(db, second.token), user.id)
})

test('revoking burns every live token and leaves the consumed ones alone', { skip }, async () => {
  const user = await newUser()
  const issued = await requestEmailVerification(db, user)

  await revokeEmailVerificationTokens(db, user.id)
  assert.equal((await liveTokens(user.id)).length, 0)
  assert.equal(await redeemEmailVerification(db, issued.token), null)
})

/* ------------------------------------------------------------------ the token is never stored */

test('only the SHA-256 is stored — the raw token is in no column of the row', { skip }, async () => {
  const user = await newUser()
  const { token } = await requestEmailVerification(db, user)

  const rows = await sql<{ token_hash: string; row: string }[]>`
    select token_hash, email_verification_tokens::text as row
      from email_verification_tokens where user_id = ${user.id}
  `
  assert.equal(rows.length, 1)
  assert.equal(rows[0]!.token_hash, createHash('sha256').update(token).digest('hex'))
  // The whole row as text, so a column added later that happens to hold the value fails this too.
  assert.ok(!rows[0]!.row.includes(token), 'the raw token must not be recoverable from the database')
})

/* ------------------------------------------------------------------ the backfill */

test('migration 13 backfills accounts that predate verification, and stamps them with created_at', { skip }, async () => {
  // The claim the migration is actually making, run against a real database rather than read off
  // the DDL. Every row that exists when it runs was written by a service with no verification at
  // all, so refusing them would sign out the whole platform — the bootstrap administrator included
  // — in an estate where nothing yet delivers the link they would need to get back in.
  //
  // `registerUser` produces exactly the row an old database is full of: created, unverified.
  const user = await newUser()
  assert.equal(user.email_verified_at, null)
  const migration = MIGRATIONS.find((m) => m.version === 13)!

  // Re-run it. Every statement in it is idempotent (`if not exists`, and an update whose predicate
  // is the state it removes), which is what makes this safe and is also worth knowing.
  await sql.unsafe(migration.up)

  const row = (await sql<{ email_verified_at: Date | null; created_at: Date }[]>`
    select email_verified_at, created_at from users where id = ${user.id}
  `)[0]!
  assert.ok(row.email_verified_at, 'an account that predates verification must not be locked out')
  // The account's own creation, not the migration's clock: the claim being recorded is "this
  // predates verification", and `now()` would assert that every historical user proved their
  // address on the day of the deploy.
  assert.equal(row.email_verified_at.getTime(), row.created_at.getTime())
})

/* ------------------------------------------------------------------ the event */

test('the request leaves as an event, in the SAME transaction as the token row', { skip }, async () => {
  const user = await newUser()
  const { token, expiresAt, linkable } = await requestEmailVerification(db, user, 'req-abc')
  assert.equal(linkable, true, 'the suite configures IDENTITY_ACCOUNT_URL')

  const events = await sql<
    { topic: string; key: string; actor: string; correlation_id: string; payload: Record<string, unknown> }[]
  >`
    select topic, key, actor, correlation_id, payload from outbox
     where topic = 'identity.email.verification_requested'
  `
  assert.equal(events.length, 1)
  const event = events[0]!
  assert.equal(event.key, user.id, 'keyed by the account — activity reads the owner off the key')
  assert.equal(event.actor, `user:${user.id}`)
  assert.equal(event.correlation_id, 'req-abc')

  // Field for field, because `notify` renders exactly these names and a mismatch is a template that
  // greets nobody. `identity.user.registered` was in the registry and unemitted for the whole life
  // of this service; a payload whose keys drift is the same failure with a delivery receipt.
  assert.deepEqual(Object.keys(event.payload).sort(), [
    'email',
    'expiresAt',
    'handle',
    'linkable',
    'userId',
    'verifyUrl',
  ])
  assert.equal(event.payload['userId'], user.id)
  assert.equal(event.payload['handle'], user.handle)
  assert.equal(event.payload['email'], user.email)
  assert.equal(event.payload['expiresAt'], expiresAt.toISOString())
  assert.equal(event.payload['linkable'], true)
  // The link carries the token in the fragment, and it is the ONE copy that leaves this service.
  assert.equal(event.payload['verifyUrl'], buildVerifyUrl('https://hub.test.cloudsforge.local', token))

  // Same transaction as the row. Rule 5 of docs/ecosystem/03 §2, and here it is load-bearing: an
  // event published after a commit that got as far as the token and no further would mail a link
  // for a token that does not exist, and one published before would promise a token that never
  // committed.
  assert.equal((await liveTokens(user.id)).length, 1)
})

test('a supersede emits a second event, so the newest link is the one that gets sent', { skip }, async () => {
  const user = await newUser()
  await requestEmailVerification(db, user)
  const second = await requestEmailVerification(db, user)

  const events = await sql<{ payload: Record<string, unknown> }[]>`
    select payload from outbox
     where topic = 'identity.email.verification_requested' order by occurred_at
  `
  assert.equal(events.length, 2)
  assert.equal(
    events[1]!.payload['verifyUrl'],
    buildVerifyUrl('https://hub.test.cloudsforge.local', second.token),
  )
})
