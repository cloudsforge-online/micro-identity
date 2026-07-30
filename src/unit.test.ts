/**
 * Everything that can be decided without a database.
 *
 * `./testsupport.ts` is imported first and its position is load-bearing: it populates the
 * environment that `env.ts` validates at import, and `keyEnvelope.ts` reaches `env.ts`. Moving it
 * below any other import makes this file exit with a configuration error rather than fail a test.
 */

import './testsupport.ts'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normaliseEmail, normaliseHandle, truncateIp } from '@cloudsforge/contracts-auth'
import {
  DEFAULT_PARAMS,
  base32Decode,
  base32Encode,
  otpauthUri,
  stepAt,
  totp,
  verifyTotp,
  type TotpAlgorithm,
} from './totp.ts'
import {
  CURRENT_ALGO,
  CURRENT_PARAMS,
  encodeAlgo,
  hashPassword,
  needsRehash,
  parseAlgo,
  verifyPassword,
} from './passwords.ts'
import { open, seal } from './keyEnvelope.ts'
import { slugFor } from './organisations.ts'
import { fingerprintOf, osFamily, userAgentFamily } from './sessions.ts'
import { isUuid, uuidv7 } from './ids.ts'

/* ------------------------------------------------------------------ TOTP: RFC 6238 Appendix B */

/**
 * The published vectors, verbatim.
 *
 * These are the whole justification for implementing TOTP rather than taking a dependency: the
 * algorithm is pinned by a standard with test data, so "did I get it right" is a question with an
 * answer rather than an opinion. The seeds are ASCII, as the RFC's reference implementation uses
 * them, and the SHA256 and SHA512 seeds are the errata-corrected 32- and 64-byte forms rather than
 * the 20-byte one — a very common way to get a "failing" implementation that is in fact correct.
 */
const SEEDS: Readonly<Record<TotpAlgorithm, Buffer>> = {
  SHA1: Buffer.from('12345678901234567890', 'ascii'),
  SHA256: Buffer.from('12345678901234567890123456789012', 'ascii'),
  SHA512: Buffer.from('1234567890123456789012345678901234567890123456789012345678901234', 'ascii'),
}

const VECTORS: ReadonlyArray<{ time: number; SHA1: string; SHA256: string; SHA512: string }> = [
  { time: 59, SHA1: '94287082', SHA256: '46119246', SHA512: '90693936' },
  { time: 1_111_111_109, SHA1: '07081804', SHA256: '68084774', SHA512: '25091201' },
  { time: 1_111_111_111, SHA1: '14050471', SHA256: '67062674', SHA512: '99943326' },
  { time: 1_234_567_890, SHA1: '89005924', SHA256: '91819424', SHA512: '93441116' },
  { time: 2_000_000_000, SHA1: '69279037', SHA256: '90698825', SHA512: '38618901' },
  // Past 2^32 seconds. This is the one that catches an implementation writing the counter as two
  // 32-bit halves and getting the high word wrong — a bug that is invisible for forty years.
  { time: 20_000_000_000, SHA1: '65353130', SHA256: '77737706', SHA512: '47863826' },
]

test('TOTP matches every RFC 6238 test vector, on all three hashes', () => {
  for (const vector of VECTORS) {
    for (const algorithm of ['SHA1', 'SHA256', 'SHA512'] as const) {
      assert.equal(
        totp(SEEDS[algorithm], vector.time, { stepSeconds: 30, digits: 8, algorithm }),
        vector[algorithm],
        `${algorithm} at t=${vector.time}`,
      )
    }
  }
})

test('the six-digit code this service enrols at is the RFC code truncated, not a different one', () => {
  // Guards against a digits change silently altering the algorithm rather than the presentation.
  for (const vector of VECTORS) {
    assert.equal(totp(SEEDS.SHA1, vector.time, DEFAULT_PARAMS), vector.SHA1.slice(-6))
  }
})

test('verification accepts one step either side and nothing further', () => {
  const now = 1_111_111_111
  const params = DEFAULT_PARAMS
  const previous = totp(SEEDS.SHA1, now - params.stepSeconds, params)
  const current = totp(SEEDS.SHA1, now, params)
  const next = totp(SEEDS.SHA1, now + params.stepSeconds, params)
  const distant = totp(SEEDS.SHA1, now + 5 * params.stepSeconds, params)

  assert.equal(verifyTotp(SEEDS.SHA1, current, now).ok, true)
  assert.equal(verifyTotp(SEEDS.SHA1, previous, now).ok, true, 'a slow phone must still work')
  assert.equal(verifyTotp(SEEDS.SHA1, next, now).ok, true, 'a fast phone must still work')
  assert.equal(verifyTotp(SEEDS.SHA1, distant, now).ok, false, 'the window is one step, not five')
})

test('a code is accepted once, ever — the replay guard refuses its own step again', () => {
  const now = 1_111_111_111
  const code = totp(SEEDS.SHA1, now, DEFAULT_PARAMS)
  const first = verifyTotp(SEEDS.SHA1, code, now)
  assert.equal(first.ok, true)
  assert.ok(first.ok)

  const replay = verifyTotp(SEEDS.SHA1, code, now, { lastUsedStep: first.step })
  assert.equal(replay.ok, false)
  assert.ok(!replay.ok)
  // Distinguished from a wrong code, because it is an attack signal rather than a typo.
  assert.equal(replay.reason, 'replayed')
})

test('a code from a step BEFORE the last used one is also refused', () => {
  // The backwards half of the window is the subtle case: without `matched <= lastUsedStep` an
  // attacker who observed a code could present the PREVIOUS step's code and be accepted.
  const now = 1_111_111_111
  const current = stepAt(now)
  const stale = totp(SEEDS.SHA1, now - DEFAULT_PARAMS.stepSeconds, DEFAULT_PARAMS)
  const result = verifyTotp(SEEDS.SHA1, stale, now, { lastUsedStep: current })
  assert.equal(result.ok, false)
})

test('a malformed code is refused without being compared', () => {
  for (const bad of ['', '12345', '1234567', 'abcdef', '12 34 56 78 90']) {
    const result = verifyTotp(SEEDS.SHA1, bad, 59)
    assert.equal(result.ok, false, bad)
  }
  // Spaces and hyphens inside a well-formed code ARE tolerated: users paste them from apps that add
  // them, and refusing over whitespace is a support ticket with no security benefit.
  assert.equal(verifyTotp(SEEDS.SHA1, '287 082', 59, { params: DEFAULT_PARAMS }).ok, true)
})

test('base32 round-trips, and rejects anything that is not base32', () => {
  for (let length = 1; length <= 40; length += 1) {
    const bytes = Buffer.from(Array.from({ length }, (_v, i) => (i * 37 + 11) & 0xff))
    assert.deepEqual(base32Decode(base32Encode(bytes)), bytes, `length ${length}`)
  }
  assert.equal(base32Decode('0189'), null, '0, 1 and 8 are not in the alphabet')
  assert.equal(base32Decode(''), null)
  // Padding and grouping are tolerated on the way in, which is what a user retyping a key produces.
  assert.deepEqual(base32Decode('MFRGG ZDF===')?.toString(), base32Decode('MFRGGZDF')?.toString())
})

test('the otpauth URI carries the secret, the issuer and the parameters', () => {
  const uri = otpauthUri({
    issuer: 'CloudsForge',
    account: 'sam@example.test',
    secret: SEEDS.SHA1,
  })
  const url = new URL(uri)
  assert.equal(url.protocol, 'otpauth:')
  assert.equal(url.searchParams.get('secret'), base32Encode(SEEDS.SHA1))
  assert.equal(url.searchParams.get('issuer'), 'CloudsForge')
  assert.equal(url.searchParams.get('digits'), '6')
  assert.equal(url.searchParams.get('period'), '30')
  // The account is percent-encoded in the label. A handle may legally contain characters that would
  // otherwise end the path or start the query.
  assert.match(uri, /CloudsForge:sam%40example\.test/)
})

/* ------------------------------------------------------------------ passwords */

test('a password verifies at the parameters its row records, not at the current ones', async () => {
  // The whole point of the hash_algo column. A row hashed at a lower cost must keep verifying after
  // the constant moves, or raising the work factor means a forced reset for every user.
  const weak = { N: 1_024, r: 8, p: 1, keyLen: 64 }
  const stored = await hashPassword('correct horse battery staple', weak)
  assert.equal(stored.algo, encodeAlgo(weak))
  assert.equal(await verifyPassword('correct horse battery staple', stored.hash, stored.algo), true)
  assert.equal(await verifyPassword('wrong', stored.hash, stored.algo), false)

  // And verifying it at the CURRENT parameters fails, which is why the column has to be consulted
  // rather than assumed.
  assert.equal(await verifyPassword('correct horse battery staple', stored.hash, CURRENT_ALGO), false)
})

test('needsRehash finds exactly the rows written at another cost', async () => {
  const current = await hashPassword('a-perfectly-fine-password')
  assert.equal(current.algo, CURRENT_ALGO)
  assert.equal(needsRehash(current.algo), false)
  assert.equal(needsRehash(encodeAlgo({ ...CURRENT_PARAMS, N: 1_024 })), true)
  // Including a HIGHER cost, so a deliberate rollback actually takes effect.
  assert.equal(needsRehash(encodeAlgo({ ...CURRENT_PARAMS, N: 65_536 })), true)
})

test('an unparseable or out-of-range algorithm refuses rather than guessing', async () => {
  const stored = await hashPassword('a-perfectly-fine-password')
  assert.equal(await verifyPassword('a-perfectly-fine-password', stored.hash, 'argon2id$v=19'), false)
  assert.equal(parseAlgo('scrypt$N=99999999,r=8,p=1,keyLen=64'), null, 'N is bounded: it is a DoS knob')
  assert.equal(parseAlgo('scrypt$N=16384,r=8,p=1,keyLen=8'), null, 'a 8-byte key is not a hash')
  assert.equal(await verifyPassword('x', 'not-a-hash', CURRENT_ALGO), false)
  assert.equal(await verifyPassword('x', '', CURRENT_ALGO), false)
})

/* ------------------------------------------------------------------ the envelope */

test('a sealed secret opens, and only under its own purpose and id', () => {
  const blob = seal('totp-seed', 'factor-a', { secret: 'shhh' })
  assert.deepEqual(open('totp-seed', 'factor-a', blob), { secret: 'shhh' })

  // The id is in the salt, so a ciphertext moved between rows by a SQL injection with UPDATE cannot
  // be decrypted as the row it was moved to.
  assert.throws(() => open('totp-seed', 'factor-b', blob))
  // The purpose is in the salt, so a key derived to unwrap a TOTP seed cannot unwrap a signing key.
  assert.throws(() => open('signing-key', 'factor-a', blob))
})

test('a blob that is not in the envelope format says so, rather than failing as a bad secret', () => {
  // The distinction matters at 3am: a GCM authentication error reads like the wrong master secret
  // and sends an operator rotating something that was never the problem.
  assert.throws(() => open('signing-key', 'kid', '{"kty":"RSA"}'), /not in a recognised envelope format/)
  assert.throws(() => open('signing-key', 'kid', 'v9:AAAA'), /envelope version 9/)
})

test('two seals of one value differ, so the ciphertext is not a fingerprint of the plaintext', () => {
  // A deterministic envelope would let anyone with a database read tell which two users share a
  // secret. The IV is random per seal, and this is what asserts it stays that way.
  assert.notEqual(seal('totp-seed', 'x', 'same'), seal('totp-seed', 'x', 'same'))
})

/* ------------------------------------------------------------------ normalisation */

test('one normalisation, applied everywhere — the defect this service exists to close', () => {
  // Nimbus matched verbatim on register and login and lower(email) on forgot-password, so an
  // account created as Sam@example.com could be reset by an address it could not be signed in with.
  for (const spelling of ['Sam@Example.COM', ' sam@example.com ', 'SAM@EXAMPLE.COM']) {
    assert.equal(normaliseEmail(spelling), 'sam@example.com', spelling)
  }
  assert.equal(normaliseHandle(' Alice '), 'alice')
})

test('an IP is reduced to a network and never kept whole', () => {
  assert.equal(truncateIp('203.0.113.42'), '203.0.113.0/24')
  assert.equal(truncateIp('2001:db8:1234:5678::1'), '2001:db8:1234::/48')
  // Node behind a proxy hands back IPv4-mapped addresses; truncating one as IPv6 would keep all
  // thirty-two IPv4 bits inside the /48 — the exact opposite of the intent.
  assert.equal(truncateIp('::ffff:203.0.113.42'), '203.0.113.0/24')
  assert.equal(truncateIp('not-an-address'), null)
})

/* ------------------------------------------------------------------ small things with sharp edges */

test('a user agent is reduced to a family, longest claim first', () => {
  // Every browser lies about being every other one. Matching in the wrong order labels everything
  // "Safari" and makes the device list actively misleading.
  const edge =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36 Edg/120'
  assert.equal(userAgentFamily(edge), 'Edge')
  assert.equal(osFamily(edge), 'Windows')

  const chrome =
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'
  assert.equal(userAgentFamily(chrome), 'Chrome')
  assert.equal(osFamily(chrome), 'macOS')

  // An iPad in desktop mode reports "Macintosh". Listing it as a Mac is exactly the detail that
  // makes a user dismiss a genuine "new device" alert.
  assert.equal(osFamily('Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15'), 'iOS')
  // Unrecognised is null, never a guess.
  assert.equal(userAgentFamily('SomeNewBrowser/1.0'), null)
  assert.equal(userAgentFamily(null), null)
})

test('a device fingerprint is a hash of the headers and nothing else', () => {
  const client = { userAgent: 'Firefox/120', acceptLanguage: 'en-GB', remoteAddress: '203.0.113.1' }
  const same = { ...client, remoteAddress: '198.51.100.9' }
  // The address is deliberately NOT in it: a laptop that moves between home and a train must stay
  // one device, or "sign-in from a new device" fires on every commute and is then ignored.
  assert.equal(fingerprintOf(client), fingerprintOf(same))
  assert.notEqual(fingerprintOf(client), fingerprintOf({ ...client, userAgent: 'Safari/17' }))
  assert.match(fingerprintOf(client), /^[0-9a-f]{64}$/)
})

test('a personal organisation slug is derived from the handle and disambiguated by id', () => {
  assert.equal(slugFor('Alice', '0192abcd-0000-7000-8000-000000000000'), 'alice')
  assert.equal(slugFor('a b!c', '0192abcd-0000-7000-8000-000000000000'), 'a-b-c')
  // Empty after stripping must still produce a slug, or the insert fails on a not-null column.
  assert.equal(slugFor('!!!', '0192abcd-0000-7000-8000-000000000000'), 'user')
  const collided = slugFor('alice', '0192abcd-0000-7000-8000-000000000000', true)
  assert.equal(collided, 'alice-0192abcd')
})

test('uuidv7 sorts in creation order, including inside one millisecond', () => {
  // Registration creates a user, a profile, an organisation and a session in one transaction and
  // one millisecond. Without the sequence counter those ids order randomly.
  const frozen = () => 1_700_000_000_000
  const ids = Array.from({ length: 500 }, () => uuidv7(frozen))
  assert.deepEqual(ids, [...ids].sort(), 'ids generated in one millisecond must still sort')
  assert.equal(new Set(ids).size, ids.length, 'and must be unique')
  for (const id of ids) assert.ok(isUuid(id))
  // Version 7 and the RFC 4122 variant, so anything reading the version nibble agrees.
  assert.equal(ids[0]![14], '7')
  assert.match(ids[0]![19]!, /[89ab]/)
})

test('a clock stepped backwards does not produce ids that sort before existing ones', () => {
  let now = 1_700_000_000_000
  const first = uuidv7(() => now)
  now -= 60_000
  const afterNtpStep = uuidv7(() => now)
  assert.ok(afterNtpStep > first, 'monotonicity must survive a backwards clock')
})
