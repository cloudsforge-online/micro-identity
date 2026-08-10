/**
 * Configuration.
 *
 * `loadEnv` is pure over its source, which is the whole reason the failure paths are testable at
 * all: the eager `env` export calls `process.exit(1)`, and a test suite cannot assert on a process
 * that is gone.
 */

import './testsupport.ts'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { EnvError, loadEnv, parseServiceGrants } from './env.ts'

/**
 * A secret fixture, GENERATED rather than written down.
 *
 * `openssl rand -base64 48` is what the runbook tells an operator to run; this is the same 48
 * bytes, and every call returns a different one. Using it rather than a literal is what stops a
 * placeholder creeping back the next time somebody needs a fixture — which is not hypothetical:
 * every secret literal that used to be in this file was one.
 */
function generated(): string {
  return randomBytes(48).toString('base64')
}

/**
 * The smallest source that boots. Every case below removes or corrupts exactly one thing.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * THE TWO SECRETS HERE WERE `a-real-key-secret-with-enough-entropy-1234` AND
 * `a-real-outbox-signing-secret-1234`, AND THEY NAMED THEMSELVES ACCURATELY IN THE WRONG DIRECTION.
 *
 * Both are hand-typed and hyphenated, which is exactly the shape of micro-org #142's
 * `estate-only-outbox-secret-00000000000000` — 40 characters, past every floor this file enforced,
 * and on nobody's deny-list. Every case below ran against them, so the suite as a whole asserted
 * that a value of that shape is a valid secret for the service that holds the estate's universal
 * forging key. "with-enough-entropy" was a claim, not a measurement; the shape check is the
 * measurement, and it refuses both.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
const COMPLETE: Readonly<Record<string, string>> = {
  IDENTITY_DATABASE_URL: 'postgres://cloudsforge@127.0.0.1:5432/identity',
  IDENTITY_ISSUER: 'https://identity.cloudsforge.local',
  IDENTITY_KEY_SECRET: generated(),
  IDENTITY_PUBLIC_URL: 'https://account.cloudsforge.local',
  OUTBOX_SIGNING_SECRET: generated(),
}

test('a complete source loads, and the defaults are the ones documented', () => {
  const env = loadEnv(COMPLETE, 'host-1')
  assert.equal(env.port, 4000)
  assert.equal(env.databasePoolMax, 10)
  assert.equal(env.instanceId, 'host-1')
  assert.equal(env.deletionGraceDays, 7)
  assert.deepEqual(env.handoffOrigins, [])
  assert.deepEqual(env.serviceTokenGrants, {})
})

test('every required variable names itself when it is missing', () => {
  for (const name of Object.keys(COMPLETE)) {
    const source: Record<string, string> = { ...COMPLETE }
    delete source[name]
    assert.throws(
      () => loadEnv(source),
      (err: unknown) => err instanceof EnvError && err.message.includes(name),
      // `undefined` propagating into a connection string surfaces four layers later as an
      // unreadable driver error, which is the failure this is written to prevent.
      `${name} must name itself`,
    )
  }
})

test('a placeholder is refused outright, for both secrets, whatever it was padded out with', () => {
  // The last two are the exact strings THIS REPOSITORY'S `.env.example` shipped, and both used to
  // boot: 37 and 32 characters, so they cleared the length floor, and neither is one of the eight
  // exact placeholder strings, so they cleared the placeholder check. A deployer who edits every
  // line except the one whose entire purpose is to be edited got a running service whose forging
  // key is a literal in a committed file — and that key mints a token for any user and any service
  // in the estate. Padding a placeholder out to clear a length check must not be how it passes.
  //
  // The last entry is the one the deny-list never had a chance against: it is not `CHANGE_ME`, it
  // does not BEGIN with a stem, and it is 40 characters. It is the value that actually reached 44
  // containers on both networks (micro-org #142), and it is here so that the case this whole change
  // exists for is a case rather than an anecdote.
  const refused = [
    'changeme',
    'CHANGE_ME',
    'change-me-please-this-is-long-enough-ok',
    'CHANGE_ME_at_least_32_characters_long',
    'CHANGE_ME_at_least_24_characters',
    'estate-only-outbox-secret-00000000000000',
  ]
  for (const name of ['IDENTITY_KEY_SECRET', 'OUTBOX_SIGNING_SECRET']) {
    for (const value of refused) {
      assert.throws(
        () => loadEnv({ ...COMPLETE, [name]: value }),
        // WAS `/known placeholder/`, which pinned one branch's exact wording — the branch that only
        // fires for an EXACT match against a list. Three of the six values above are refused by the
        // marker check or the alphabet check and produce different, better messages. Asserting on
        // the class and the variable rather than the sentence lets the guard improve its answer
        // without this file calling that a regression.
        (err: unknown) =>
          err instanceof EnvError && err.message.includes(name) && !err.message.includes(value),
        `${name} accepted the placeholder ${value}`,
      )
    }
  }
})

test('both secrets are held to the SAME rule, and the unit is BYTES rather than keystrokes', () => {
  // ══════════════════════════════════════════════════════════════════════════════════════════════
  // THIS TEST REPLACES `the key secret is held to a longer minimum than everything else`, WHICH WAS
  // DEFENDING THE DEFECT IN TWO SEPARATE WAYS.
  //
  //   1. It asserted `doesNotThrow` on `'x'.repeat(28)` for OUTBOX_SIGNING_SECRET. Twenty-eight
  //      identical characters is not a secret by any measure — it is 21 bytes of key material with
  //      zero entropy — and the suite required that it LOAD. Any fix that refused it failed CI.
  //   2. It pinned the message `/at least 32/`, which is the keystroke floor this work replaces.
  //
  // The asymmetry it was expressing — the key secret matters more than the outbox key — is real,
  // and it is now expressed by both being held to 32 BYTES, which is stricter than either floor was.
  // ══════════════════════════════════════════════════════════════════════════════════════════════
  for (const name of ['IDENTITY_KEY_SECRET', 'OUTBOX_SIGNING_SECRET']) {
    assert.throws(
      () => loadEnv({ ...COMPLETE, [name]: 'x'.repeat(28) }),
      (err: unknown) =>
        err instanceof EnvError &&
        /21 bytes of key material/.test(err.message) &&
        err.message.includes(name),
      name,
    )
    // Long, well-formed and degenerate. Only a measurement of the value itself rejects these: all
    // three are in an accepted alphabet and every one of them clears every length floor.
    for (const degenerate of ['A'.repeat(64), '0'.repeat(64), 'deadbeef'.repeat(8)]) {
      assert.throws(() => loadEnv({ ...COMPLETE, [name]: degenerate }), EnvError, `${name} ${degenerate}`)
    }
    // And the control that stops this becoming a guard somebody disables: what the runbook tells an
    // operator to generate must load, in both encodings, every time.
    for (let i = 0; i < 200; i += 1) {
      assert.doesNotThrow(() => loadEnv({ ...COMPLETE, [name]: randomBytes(48).toString('base64') }))
      assert.doesNotThrow(() => loadEnv({ ...COMPLETE, [name]: randomBytes(32).toString('hex') }))
    }
  }
})

test('THE GUARD HAS NO OFF SWITCH — no environment, no variable, no flag disables it', () => {
  // The failure this replaces was a comment saying "change this in production". Anything that can
  // be turned off is a comment with a longer name, and it would be reached for in exactly the hurry
  // that produced the defect — so the escape hatches somebody would add are asserted absent here
  // rather than merely not written.
  for (const escape of [
    { NODE_ENV: 'development' },
    { NODE_ENV: 'test' },
    { IDENTITY_ALLOW_WEAK_SECRETS: 'true' },
    { IDENTITY_SKIP_SECRET_CHECKS: '1' },
    { CI: 'true' },
  ]) {
    assert.throws(
      () => loadEnv({ ...COMPLETE, ...escape, IDENTITY_KEY_SECRET: 'CHANGE_ME_at_least_32_characters_long' }),
      EnvError,
      JSON.stringify(escape),
    )
  }
})

test('the secret the test suite runs under is not itself a placeholder', () => {
  // A placeholder that boots in the suite is a placeholder that reaches production, because the
  // suite is where anyone would notice.
  assert.doesNotThrow(() =>
    loadEnv({ ...COMPLETE, IDENTITY_KEY_SECRET: process.env['IDENTITY_KEY_SECRET']! }),
  )
})

/* ───────────────────────────────── the key-encryption keyring (#188) ────────────────────────── */

test('the unsuffixed IDENTITY_KEY_SECRET is accepted as v1', () => {
  // LOAD-BEARING, not a courtesy. Every blob in both live databases is stamped `v1:` and was sealed
  // under the value this variable held. If shipping #188's fix required renaming it, the fix would
  // itself be the destructive rotation it exists to prevent.
  const env = loadEnv(COMPLETE)
  assert.deepEqual([...env.keySecrets.keys()], [1])
  assert.equal(env.keyVersion, 1)
})

test('the write version defaults to the highest secret supplied', () => {
  const env = loadEnv({ ...COMPLETE, IDENTITY_KEY_SECRET_V2: generated() })
  assert.deepEqual([...env.keySecrets.keys()].sort((a, b) => a - b), [1, 2])
  // Adding a secret promotes the write version, so a rotation cannot stall half-done with the
  // service still sealing under the compromised key.
  assert.equal(env.keyVersion, 2)
})

test('a write version with no matching secret refuses to boot', () => {
  // Sealing under a version this process cannot open would manufacture unreadable blobs on purpose
  // — the exact damage #188 describes, self-inflicted at boot.
  assert.throws(
    () => loadEnv({ ...COMPLETE, IDENTITY_KEY_VERSION: '2' }),
    /IDENTITY_KEY_VERSION is 2 but IDENTITY_KEY_SECRET_V2 is not set/,
  )
})

test('two different values both claiming v1 refuse to boot rather than guessing', () => {
  // Guessing would silently pick the one that fails to open half the blobs, and the symptom would
  // arrive later, as an authentication failure a long way from its cause.
  // GENERATED, not written: the old literal here was hyphenated, so under the shape rule
  // `parseKeySecrets` would refuse it before it ever reached the conflict check, and this test
  // would pass for the wrong reason.
  assert.throws(
    () => loadEnv({ ...COMPLETE, IDENTITY_KEY_SECRET_V1: generated() }),
    /are both set and differ/,
  )
  // The same value under both names is not a conflict — that is the intermediate state of renaming.
  assert.doesNotThrow(() =>
    loadEnv({ ...COMPLETE, IDENTITY_KEY_SECRET_V1: COMPLETE['IDENTITY_KEY_SECRET']! }),
  )
})

test('EVERY version is held to the full rule, including one retained only for a drain', () => {
  // Not just the write version. A retained old secret still opens every blob that has not been
  // re-sealed, so a placeholder kept "just for the drain" is the whole disclosure for as long as
  // the drain takes — which makes draining off a placeholder work for the image that predates this
  // guard, friction in exactly the right direction.
  //
  // The assertions were `/at least 32/` and `/known placeholder/`. The first pinned the keystroke
  // floor this work replaces; the second pinned the one branch of the guard that a padded
  // placeholder never reaches. Both are now assertions about the variable and the class.
  for (const bad of ['x'.repeat(28), 'CHANGE_ME_at_least_32_characters_long', 'estate-only-key-000000000000000000000000']) {
    assert.throws(
      () => loadEnv({ ...COMPLETE, IDENTITY_KEY_SECRET_V2: bad }),
      (err: unknown) =>
        err instanceof EnvError &&
        err.message.includes('IDENTITY_KEY_SECRET_V2') &&
        !err.message.includes(bad),
      bad,
    )
  }
})

test('an empty versioned secret is treated as unset and cannot silently downgrade writes', () => {
  // A compose interpolation of an unset variable arrives as an empty string, not as an absent one.
  // Treating it as unset is safe only because the write version must be present in the keyring —
  // so an empty _V2 fails to boot rather than quietly sealing new blobs back under v1.
  assert.throws(
    () => loadEnv({ ...COMPLETE, IDENTITY_KEY_SECRET_V2: '', IDENTITY_KEY_VERSION: '2' }),
    /IDENTITY_KEY_VERSION is 2 but IDENTITY_KEY_SECRET_V2 is not set/,
  )
})

test('the public URL must be an origin, because a reset link is built from it', () => {
  // SD-04: the link is built from configuration and never from the request Host header. A value
  // carrying a path or a query would produce a link that is subtly wrong in a way nobody notices
  // until a user cannot recover their account.
  for (const bad of ['not-a-url', 'ftp://account.example', 'https://account.example/portal', 'https://a.example?x=1']) {
    assert.throws(() => loadEnv({ ...COMPLETE, IDENTITY_PUBLIC_URL: bad }), EnvError, bad)
  }
  // A trailing slash is an origin and is normalised, so the comparison never has to be clever.
  assert.equal(loadEnv({ ...COMPLETE, IDENTITY_PUBLIC_URL: 'https://a.example/' }).publicUrl, 'https://a.example')
})

test('the account URL is OPTIONAL, and an estate that has not set it still registers people', () => {
  // It is absent from COMPLETE on purpose: `every required variable names itself when it is
  // missing` above iterates COMPLETE, so a variable that belongs there is one whose absence is a
  // boot failure. This one's absence must not be. Minting a verification token has to keep working
  // in a deployment that has not configured Hub's origin yet — what stops is only the ability to
  // BUILD the link, which the delivery seam reports (emailVerification.ts) rather than throwing on
  // the one route where a throw would mean registration itself starts failing.
  assert.equal(loadEnv(COMPLETE).accountUrl, null)
  assert.equal(loadEnv({ ...COMPLETE, IDENTITY_ACCOUNT_URL: '   ' }).accountUrl, null)
})

test('the account URL must be an origin, because the verification link is built from it', () => {
  // The same rule IDENTITY_PUBLIC_URL is held to, and for a sharper reason: this one is not
  // identity's own origin. The link points at a page Hub serves, and the token rides in the
  // FRAGMENT — so a configured value carrying a path, a query or a fragment of its own would
  // produce a URL whose '#' is not where the code thinks it is.
  for (const bad of ['not-a-url', 'ftp://hub.example', 'https://hub.example/account', 'https://hub.example#x']) {
    assert.throws(() => loadEnv({ ...COMPLETE, IDENTITY_ACCOUNT_URL: bad }), EnvError, bad)
  }
  assert.equal(loadEnv({ ...COMPLETE, IDENTITY_ACCOUNT_URL: 'https://hub.example/' }).accountUrl, 'https://hub.example')
})

test('hand-off origins are parsed, normalised and de-duplicated', () => {
  const env = loadEnv({
    ...COMPLETE,
    IDENTITY_HANDOFF_ORIGINS: 'https://app.example, https://app.example/ ,https://play.example',
  })
  assert.deepEqual(env.handoffOrigins, ['https://app.example', 'https://play.example'])
})

/* ---------------------------------------------------------------- the shipped .env.example */

/**
 * `.env.example`, parsed the way a deployer would read it.
 *
 * Only `KEY=VALUE`; comments and blanks dropped. Deliberately not a dotenv library: the file exists
 * to be read by a person and by `docker compose --env-file`, and a parser cleverer than either of
 * those would accept a file neither of them does.
 */
function readEnvExample(): Record<string, string> {
  const text = readFileSync(new URL('../.env.example', import.meta.url), 'utf8')
  const source: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue
    const eq = trimmed.indexOf('=')
    assert.ok(eq > 0, `.env.example has a line that is neither comment nor assignment: ${trimmed}`)
    source[trimmed.slice(0, eq)] = trimmed.slice(eq + 1)
  }
  return source
}

/** The two values the file ships as placeholders on purpose, and the reals the suite runs under. */
const EXAMPLE_PLACEHOLDERS: Readonly<Record<string, string>> = {
  IDENTITY_KEY_SECRET: COMPLETE['IDENTITY_KEY_SECRET']!,
  OUTBOX_SIGNING_SECRET: COMPLETE['OUTBOX_SIGNING_SECRET']!,
}

test('the shipped .env.example is a configuration that actually loads', () => {
  // The file's own header records why it exists: the first vertical slice had to reconstruct this
  // list by reading `src/env.ts`, and GUESSED ONE VALUE WRONG. A declaration nothing checks is the
  // same failure with an extra step, so this runs the real parser over the real file.
  const source = readEnvExample()

  for (const [name, real] of Object.entries(EXAMPLE_PLACEHOLDERS)) {
    // Belt and braces: the example must never ship a value that would boot. A secret committed here
    // is a secret in every clone of this repository.
    assert.throws(() => loadEnv(source), EnvError, `${name} must not be loadable as shipped`)
    assert.ok(source[name]?.includes('CHANGE_ME'), `${name} must be a CHANGE_ME placeholder`)
    source[name] = real
  }

  const env = loadEnv(source)
  assert.equal(env.port, 4000)
  assert.equal(env.issuer, 'http://localhost:4000')
  assert.equal(env.deletionGraceDays, 7)
  assert.deepEqual(env.serviceTokenGrants, {})
})

test('.env.example declares every variable that is required to boot', () => {
  const source = readEnvExample()
  for (const name of Object.keys(COMPLETE)) {
    assert.ok(name in source, `${name} is required by loadEnv and absent from .env.example`)
  }
})

test('.env.example ships a WORKING hand-off allowlist, not an empty one', () => {
  // The default in code is empty and must stay that way — `a complete source loads` above pins it,
  // because "empty means allow everything" is how an SSO becomes an open redirect. The defect was
  // never the default: it was that the one file a deployer copies shipped the fail-closed value with
  // no indication of what a working one looks like, so nobody could sign in across two surfaces and
  // the symptom was a 403 that reads as "sign in bounced me".
  const source = { ...readEnvExample(), ...EXAMPLE_PLACEHOLDERS }
  const origins = loadEnv(source).handoffOrigins

  assert.ok(origins.length > 0, 'an empty example allowlist refuses every cross-surface sign-in')
  // Hub is where sign-in happens, so an example that omits it documents nothing usable.
  assert.ok(origins.includes('http://localhost:3010'), 'the sign-in surface itself must be listed')
  // Every entry is a normalised origin — no path, no wildcard, no trailing slash. `origin()` would
  // have thrown above on a malformed one; this catches the entry that parses and is still wrong.
  for (const value of origins) {
    assert.equal(new URL(value).origin, value, value)
    assert.ok(!value.includes('*'), `a wildcard would make this allowlist a redirector: ${value}`)
  }
})

test('the scope grant map refuses a scope that is not in the contracts registry', () => {
  // Fail at boot rather than issue a token that is quietly narrower than the operator believes.
  assert.throws(() => parseServiceGrants('{"settlement":["ledger:everything"]}'), /unknown scope/)
  assert.throws(() => parseServiceGrants('{"settlement":["custody:*"]}'), /unknown scope/)
  assert.throws(() => parseServiceGrants('not json'), EnvError)
  assert.throws(() => parseServiceGrants('["settlement"]'), /must be a JSON object/)
  assert.throws(() => parseServiceGrants('{"Settlement Service":["ledger:read"]}'), /implausible service name/)
})

test('the grant map de-duplicates, so a subset check that counts cannot be fooled', () => {
  const grants = parseServiceGrants('{"settlement":["ledger:post","ledger:post","ledger:read"]}')
  assert.deepEqual(grants['settlement'], ['ledger:post', 'ledger:read'])
})

test('a service with no grants is absent rather than empty, so issuance fails closed', () => {
  const grants = parseServiceGrants('{}')
  assert.equal(grants['settlement'], undefined)
})

test('numeric bounds are enforced with the variable named', () => {
  assert.throws(() => loadEnv({ ...COMPLETE, PORT: '0' }), /PORT/)
  assert.throws(() => loadEnv({ ...COMPLETE, PORT: '70000' }), /PORT/)
  assert.throws(() => loadEnv({ ...COMPLETE, IDENTITY_DATABASE_POOL_MAX: '2.5' }), /POOL_MAX/)
  assert.throws(() => loadEnv({ ...COMPLETE, IDENTITY_DELETION_GRACE_DAYS: '-1' }), /GRACE_DAYS/)
  // Zero grace IS allowed: a deployment with no subscribers yet has nothing to wait for, and
  // forbidding it would mean the only way to test the tombstone path is to wait a week.
  assert.equal(loadEnv({ ...COMPLETE, IDENTITY_DELETION_GRACE_DAYS: '0' }).deletionGraceDays, 0)
})

test('LOG_LEVEL is a closed set', () => {
  assert.throws(() => loadEnv({ ...COMPLETE, LOG_LEVEL: 'verbose' }), /LOG_LEVEL/)
  assert.equal(loadEnv({ ...COMPLETE, LOG_LEVEL: 'debug' }).logLevel, 'debug')
})

test('no error message can quote a secret', () => {
  // Every failure path names the VARIABLE. Quoting the value would put the secret in a log line
  // whose whole purpose is to be read by whoever is debugging the deployment — `fatalConfig` writes
  // `err.message` verbatim to stderr and the collector ships it, so an echoed secret would move
  // from one public place to another.
  //
  // It used to check that the message did not contain `sk-this-must-never-appear-in-a-message`, a
  // string that was never passed to `loadEnv`. That assertion could not fail. What it checks now is
  // that the message does not contain THE VALUE THAT WAS REJECTED, which is the property.
  for (const name of ['IDENTITY_KEY_SECRET', 'OUTBOX_SIGNING_SECRET']) {
    for (const value of ['short', 'sk-this-must-never-appear-in-a-message', 'A'.repeat(64)]) {
      try {
        loadEnv({ ...COMPLETE, [name]: value })
        assert.fail(`${name} should have thrown on ${value}`)
      } catch (err) {
        assert.ok(err instanceof EnvError, `${name} ${value}`)
        assert.ok(!err.message.includes(value), `${name} echoed its value`)
        assert.ok(err.message.includes(name), `${name} did not name itself`)
      }
    }
  }
})

/* -------------------------------------------------------------------- the registration challenge */

/**
 * A plausible Turnstile secret. Vendor-shaped, and generated so no literal is left to copy.
 *
 * Cloudflare issues secrets as `0x` followed by a mixed-alphabet tail. `assertOpaqueSecret` is the
 * class that accepts that — `assertGeneratedSecret` would refuse it on the alphabet check, which is
 * the whole reason `parseTurnstile` does not use the strict rule.
 */
function turnstileSecret(): string {
  return `0x4AAAAAAA${randomBytes(18).toString('base64url')}`
}

const SITE_KEY = '0x4AAAAAAEMXmH8jdtxq8FYo'

test('with neither Turnstile variable set the feature is simply absent', () => {
  // The state every developer machine, every CI run and every micro network is in. It must not be
  // an error, and it must not be a half-enabled gate.
  assert.equal(loadEnv(COMPLETE).turnstile, null)
})

test('a Turnstile secret without a site key refuses to boot, and so does the reverse', () => {
  // Both halves are silent failures in production: a secret with no site key refuses every
  // registration (no browser can produce a token), a site key with no secret accepts every one.
  assert.throws(
    () => loadEnv({ ...COMPLETE, TURNSTILE_SECRET: turnstileSecret(), TURNSTILE_HOSTNAMES: 'hub.example.test' }),
    /TURNSTILE_SITE_KEY/,
  )
  assert.throws(
    () => loadEnv({ ...COMPLETE, TURNSTILE_SITE_KEY: SITE_KEY, TURNSTILE_HOSTNAMES: 'hub.example.test' }),
    /TURNSTILE_SECRET/,
  )
})

test('an enabled challenge with an empty hostname allowlist refuses to boot', () => {
  // `IDENTITY_HANDOFF_ORIGINS` shipped empty on the estate and turned `POST /auth/handoff` into a
  // 403 for every caller. `hostnames.includes()` over an empty array is that defect verbatim, so
  // the empty case dies at boot where somebody can see it.
  const half = { ...COMPLETE, TURNSTILE_SECRET: turnstileSecret(), TURNSTILE_SITE_KEY: SITE_KEY }
  assert.throws(() => loadEnv(half), /TURNSTILE_HOSTNAMES/)
  assert.throws(() => loadEnv({ ...half, TURNSTILE_HOSTNAMES: '  ,  ' }), /TURNSTILE_HOSTNAMES/)
})

test('the hostname allowlist takes bare hostnames, lowercased and de-duplicated', () => {
  const source = {
    ...COMPLETE,
    TURNSTILE_SECRET: turnstileSecret(),
    TURNSTILE_SITE_KEY: SITE_KEY,
    TURNSTILE_HOSTNAMES: ' Hub.CloudsForge.online , hub.cloudsforge.online ,localhost ',
  }
  assert.deepEqual(loadEnv(source).turnstile?.hostnames, ['hub.cloudsforge.online', 'localhost'])

  // An origin, a port or a path would never match `siteverify`'s bare `hostname` field, so it would
  // present as "the widget renders and registration always fails" — a boot failure instead.
  for (const bad of ['https://hub.cloudsforge.online', 'hub.cloudsforge.online:443', 'hub.cloudsforge.online/x']) {
    assert.throws(() => loadEnv({ ...source, TURNSTILE_HOSTNAMES: bad }), /TURNSTILE_HOSTNAMES/, bad)
  }
})

test('a placeholder Turnstile secret refuses to boot, and the message never quotes it', () => {
  const base = { ...COMPLETE, TURNSTILE_SITE_KEY: SITE_KEY, TURNSTILE_HOSTNAMES: 'hub.example.test' }
  for (const value of ['changeme', 'x', 'CHANGE_ME_CHANGE_ME_CHANGE']) {
    try {
      loadEnv({ ...base, TURNSTILE_SECRET: value })
      assert.fail(`TURNSTILE_SECRET should have thrown on ${value}`)
    } catch (err) {
      assert.ok(err instanceof EnvError, value)
      assert.ok(!err.message.includes(value), 'the message echoed the rejected secret')
      assert.ok(err.message.includes('TURNSTILE_SECRET'), 'the message did not name the variable')
    }
  }
})

test('the secret and the site key may not be the same value', () => {
  // The paste that swaps them is otherwise undetectable — the widget would render under the secret
  // and the secret would be published to every browser.
  const secret = turnstileSecret()
  assert.throws(
    () =>
      loadEnv({
        ...COMPLETE,
        TURNSTILE_SECRET: secret,
        TURNSTILE_SITE_KEY: secret,
        TURNSTILE_HOSTNAMES: 'hub.example.test',
      }),
    (err: unknown) => err instanceof EnvError && !err.message.includes(secret),
  )
})

test('a complete Turnstile configuration loads', () => {
  const secret = turnstileSecret()
  const turnstile = loadEnv({
    ...COMPLETE,
    TURNSTILE_SECRET: secret,
    TURNSTILE_SITE_KEY: SITE_KEY,
    TURNSTILE_HOSTNAMES: 'hub.cloudsforge.online',
  }).turnstile
  assert.equal(turnstile?.secret, secret)
  assert.equal(turnstile?.siteKey, SITE_KEY)
  assert.deepEqual(turnstile?.hostnames, ['hub.cloudsforge.online'])
})

test('.env.example documents the three Turnstile variables without enabling them', () => {
  // Rule 9 — "a repo declares the variables it needs" — with one wrinkle: this feature is OFF by
  // default, so declaring it as a live assignment would ship an example that refuses to boot. The
  // names must still be findable by somebody deploying it, so they are commented, and this is what
  // stops the comments being deleted as decoration.
  const text = readFileSync(new URL('../.env.example', import.meta.url), 'utf8')
  for (const name of ['TURNSTILE_SECRET', 'TURNSTILE_SITE_KEY', 'TURNSTILE_HOSTNAMES']) {
    assert.ok(text.includes(name), `.env.example does not mention ${name}`)
  }
  // And the file still loads, with the challenge absent — the commented lines must not become
  // assignments by accident.
  const source = readEnvExample()
  source['IDENTITY_KEY_SECRET'] = COMPLETE['IDENTITY_KEY_SECRET']!
  source['OUTBOX_SIGNING_SECRET'] = COMPLETE['OUTBOX_SIGNING_SECRET']!
  assert.equal(loadEnv(source).turnstile, null)
})
