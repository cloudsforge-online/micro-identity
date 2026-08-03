# `micro-identity`

The estate's root of trust. Users, passwords, sessions and devices, MFA, refresh-token families with
reuse detection, organisations and memberships, the SSO hand-off, account deletion, RS256 signing
keys with a published-then-activated rotation, and the JWKS that every other service in the estate
fetches before it can verify anything.

> **It authenticates; it does not authorise a product.** `users.roles` is platform roles only, and
> the schema says why: "the moment a product permission becomes a platform role, every service has
> to understand every product's authorisation model" (`src/migrations.ts:116-119`). Product
> permissions are entitlements (`micro-billing`) or organisation roles (`memberships.role`), never a
> platform role — SD-03, restated at `src/server.ts:544`.

> **It cannot mint its own first admin, and that is deliberate.** See
> [The estate cannot bootstrap itself](#the-estate-cannot-bootstrap-itself) — a service that could
> grant itself the role that mints every other service's credential would be a service whose
> compromise grants the estate.

> **It never sees a full IP address.** `truncateIp` reduces it to a /24 or a /48 before it reaches a
> column, a log line or a response. The prefix carries the whole of the risk signal — "a sign-in
> from a network this account has never used" — and the rest is a personal identifier with no
> retention policy attached (`src/sessions.ts:13-16`, `src/migrations.ts:216-218`).

---

## The credential everything else depends on

`IDENTITY_KEY_SECRET` wraps the RS256 private half in AES-256-GCM under a scrypt-derived key. This
service's own source calls it **"the estate's universal forging credential"**
(`src/env.ts:15-17`), and the field comment is blunter still: "it is not a password to something, it
is the key to the key every service in the estate trusts" (`src/env.ts:169-175`). It is the one
secret required at **32** characters rather than the default 24 (`src/env.ts:236`), and a known
placeholder is refused at boot rather than accepted and forged later (`src/env.ts:57-68`).

Whoever holds it can mint a token for any user and any service, and every service in the estate will
accept it (`.env.example:43-47`).

### Key rotation is three steps, and the wait is the point

`src/keys.ts:19-23` states the lifecycle:

1. `POST /admin/signing-keys` mints a key as **`published`** — in the JWKS immediately, signing
   nothing.
2. **Wait one access-token TTL.** `PUBLISH_BEFORE_ACTIVE_MS` is 20 minutes: 15 for the token TTL
   plus a margin for consumers that cache the JWKS a little longer than they should
   (`src/keys.ts:63`). Activating sooner mints tokens under a `kid` verifiers have not fetched yet,
   and the symptom is **every service 401ing every request until its cache turns over — a
   self-inflicted outage that looks exactly like a key compromise** (`src/keys.ts:56-62`).
3. `POST /admin/signing-keys/:kid/activate` starts it signing; the previous key drops back to
   `published` so the tokens it already minted keep verifying until they expire (`src/keys.ts:214`).

`retired` is the only status that leaves the JWKS, and **nothing deletes a row**: the `kid` of a key
that ever signed is worth keeping so an old token in a log can be attributed
(`src/migrations.ts:155-159`).

---

## Routes

Read out of `src/server.ts`. `authenticate()` resolves the bearer token (`src/server.ts:512`);
`authenticateUser()` additionally refuses a **service** token, because a service token accepted where
a user token was expected makes `sub` — a service name — look like a user id
(`src/server.ts:535-541`); `authenticateAdmin()` additionally requires the `admin` role
(`src/server.ts:545`).

**No route on this service takes an `Idempotency-Key`.** There is no idempotency helper, table or
header path anywhere in the repository — the only occurrence of the word is the outbox relay using
an event id as one when it POSTs to a subscriber (`src/outbox.ts:279-281`). Retry semantics come
from the operations themselves instead: registration is refused by a unique index, refresh rotation
is a conditional `UPDATE … RETURNING`, hand-off redemption is single-use by row lock.

| Method | Path | Who | What it does |
| --- | --- | --- | --- |
| `GET` | `/livez` | **no auth** | liveness (`src/server.ts:618`) |
| `GET` | `/readyz` | **no auth** | 200 ready / 503 not (`src/server.ts:620`) |
| `GET` | `/metrics` | **no auth** | Prometheus text (`src/server.ts:625`) — see Known gaps |
| `GET` | `/.well-known/jwks.json` | **no auth** | public keys. **The one route in the file that is not `no-store`**: `public, max-age=300`, because a verifier re-fetching per request would make identity a synchronous dependency of every request in twenty-two services, which SD-01 rejects on availability grounds (`src/server.ts:647`, reasoning at `:639-646`) |
| `POST` | `/auth/register` | **no auth** | creates the user, a `profiles` row and a **personal organisation** in one transaction, then completes a session immediately with `amr: ['pwd']` (`src/server.ts:655`) |
| `POST` | `/auth/login` | **no auth** | password sign-in; one message for every validation failure so nothing varies with whether the account exists (`src/server.ts:691`, reasoning at `:694-697`) |
| `POST` | `/auth/mfa` | **no auth** (holds a challenge) | completes a sign-in that stopped at a second factor (`src/server.ts:785`) |
| `POST` | `/auth/refresh` | **no auth** (holds a refresh token) | rotates the refresh token; reuse burns the family (`src/server.ts:844`) |
| `POST` | `/auth/logout` | **no auth** (holds a refresh token) | 204; ends the session and its family (`src/server.ts:885`) |
| `GET` | `/auth/me` | user | the user, the current session's `id`/`amr`, and their organisations. **Refuses a service token** (`src/server.ts:891`, refusal at `:540`) |
| `POST` | `/auth/password` | user | change password. **Holding a session is not enough — the current password is required**, or an unattended browser is a permanent account takeover (`src/server.ts:914`, reasoning at `:906-912`) |
| `POST` | `/auth/password/forgot` | **no auth** | always **202**, for a known address, an unknown one and a malformed one alike. The work happens in an `after` hook once the response is on the wire, because the timing difference is the oracle (`src/server.ts:972`) |
| `POST` | `/auth/password/reset` | **no auth** (holds a token) | spends the reset token and sets the password (`src/server.ts:1003`) |
| `POST` | `/auth/handoff` | user | mints a 60-second, single-use, origin-bound SSO code; throttled at 20/minute/address alongside its other half (`src/server.ts:1098`, `:413-432`) |
| `POST` | `/auth/handoff/redeem` | **no auth** (holds a code) | redeems it for tokens **in a response body, never a URL** (`src/server.ts:1115`) |
| `GET` | `/sessions` | user | where this account is signed in (`src/server.ts:1077`) |
| `DELETE` | `/sessions` | user | sign out everywhere (`src/server.ts:1082`) |
| `DELETE` | `/sessions/:id` | user | sign out one session (`src/server.ts:1092`) |
| `GET` | `/mfa/factors` | user | the factor list; never a secret (`src/server.ts:1104`) |
| `POST` | `/mfa/totp` | user | enrol a TOTP factor as `pending` (`src/server.ts:1115`) |
| `POST` | `/mfa/totp/:id/activate` | user | prove a code, move it to `active` (`src/server.ts:1131`) |
| `POST` | `/mfa/recovery-codes` | user | regenerate the set; the old set is revoked in the same statement (`src/server.ts:1152`) |
| `DELETE` | `/mfa/factors/:id` | user | remove a factor; re-authentication with the password is checked and recorded (`src/server.ts:1162`) |
| `POST` | `/mfa/webauthn/options` | user | **501 `not_implemented`** (`src/server.ts:1196`) |
| `POST` | `/mfa/webauthn` | user | **501 `not_implemented`** (`src/server.ts:1204`) |
| `GET` | `/organisations` | user | the caller's organisations (`src/server.ts:1214`) |
| `GET` | `/organisations/:id/memberships` | user | members of one organisation (`src/server.ts:1219`) |
| `POST` | `/organisations/:id/memberships` | user | invite, change or remove a member. Refuses anything that would leave the organisation with no accepted owner (`src/server.ts:1229`) |
| `POST` | `/service-tokens` | **admin** | mints a service token. **The token is returned once and never stored**, so there is nothing to read back (`src/server.ts:1265`, note at `:1288`) |
| `DELETE` | `/users/me` | user | requests deletion; the account moves to `pending_deletion`, which is a state you may still authenticate from (`src/server.ts:1304`, reasoning at `:1336`) |
| `POST` | `/users/me/deletion/cancel` | user | cancels it inside the grace window (`src/server.ts:1339`) |
| `GET` | `/admin/signing-keys` | **admin** | the key list with statuses (`src/server.ts:1349`) |
| `POST` | `/admin/signing-keys` | **admin** | mints a key as `published` (`src/server.ts:1354`) |
| `POST` | `/admin/signing-keys/:kid/activate` | **admin** | starts it signing; refuses a key published for less than 20 minutes (`src/server.ts:1361`) |
| `POST` | `/admin/signing-keys/:kid/retire` | **admin** | removes it from the JWKS (`src/server.ts:1387`) |

### The twelve routes that make no `authenticate()` call

`/livez`, `/readyz`, `/metrics`, `/.well-known/jwks.json`, `/auth/register`, `/auth/login`,
`/auth/mfa`, `/auth/refresh`, `/auth/logout`, `/auth/password/forgot`, `/auth/password/reset`,
`/auth/handoff/redeem`. Each of the last eight carries its own bearer credential in the body — a
refresh token, an MFA challenge, a reset token, a hand-off code — which is why an `Authorization`
header on them is ignored rather than refused. Note that `POST /auth/handoff` (mint) **does**
authenticate; only `/redeem` does not.

**A verifier that could not reach this service's own database answers 503, never 401**
(`src/server.ts:527`, reasoning at `:508-510`). Answering 401 there would have every client in the
estate throw away a perfectly good session over a blip. The *reason* a token was rejected is logged
and never returned: "signature verification failed" versus "expired" tells an attacker which half of
a forged token to fix (`src/server.ts:518-521`).

---

## The estate cannot bootstrap itself

**A fresh deployment cannot issue its first service token, so no service can authenticate to
another.** Recorded at `docs/ecosystem/18-build-status.md` §3.3g, and re-verified against this
source:

* `POST /service-tokens` requires the `admin` role (`src/server.ts:1266`, via `authenticateAdmin` at
  `:545`).
* **No route in this service grants a role.** All twenty-one `POST`, four `DELETE` and zero
  `PUT`/`PATCH` routes were enumerated above; none writes `users.roles`. The only statement in the
  repository that writes that column is `registerUser` (`src/users.ts:104-105`).
* The column defaults to none — `roles text[] not null default '{}'` (`src/migrations.ts:119`).

The only way through is `update users set roles = array['admin']` against the database by hand,
which is what `deploy/scripts/slice-verify.sh` does **and asserts**, so that the day identity grows a
bootstrap the check fails and is deleted.

`micro-admin-api` owns the authorisation half and deliberately did not solve this one: its
`POST /v1/approvals` returns **501**, naming the route identity would need
(`PUT /internal/users/:id/roles` behind a service token holding `identity:admin` — *not*
`authenticateAdmin`, which refuses service tokens at `src/server.ts:540`). A queue that accepts work
it cannot do leaves a row at `approved` for ever, which reads as two operators having authorised
something that never happened.

> **A correction to §3.3g, found while writing this.** That section says `users.roles` defaults to
> `'{}'` and therefore "every user is created with none". The default is right; the conclusion is
> not. `registerUser` inserts `roles = ['player']` explicitly (`src/users.ts:105`), so a freshly
> registered user has one role — just never `admin`. The bootstrap gap is unchanged and the manual
> `UPDATE` is still required; only the stated reason was wrong. **Reported, not edited** — this
> repository's README is the only file this work touches.

---

## Background work

Leased jobs only. There is no `setInterval` doing domain work and CI greps for one. **The lease key
names the contended resource, not the row** (`src/jobs.ts:9-21`).

| Job | Lease key | Cadence | What two replicas do |
| --- | --- | --- | --- |
| `outbox.relay` | `stream` | 1s | one claims the stream; keying on the event id would let two relays deliver one batch to one subscriber twice (`src/jobs.ts:46`) |
| `identity.tombstone` | `global` | 60min | both would select the same batch. The update is conditional on `status = 'pending_deletion'` so the second no-ops, but they would contend on every row lock for nothing (`src/jobs.ts:47`, reasoning at `:16-19`) |
| `identity.sweep` | `global` | 15min | pure deletion, genuinely idempotent; keyed globally only so it runs once rather than N times (`src/jobs.ts:48`) |

The tombstone job runs **hourly rather than by the minute**: its input changes once a day at most per
account and the grace window is measured in days, so running it more often is work with nothing to
find, and less often lets an erasure the user was promised drift past the deadline in the event that
announced it (`src/jobs.ts:40-43`). It tombstones one account at a time with a `heartbeat()` between
them, because each is a transaction touching several tables and a lease expiring mid-run would hand
the rest of the batch to a second replica (`src/jobs.ts:110-122`). The log line it emits carries the
user id and **no address and no handle** — by that point neither exists, and logging what was erased
would defeat the erasure (`src/jobs.ts:116-118`).

The sweep exists because every table already has an opportunistic sweep at its own write path, which
is enough while the service is busy and does nothing at all while it is not: a deployment that stops
being used still stops holding expired hand-off codes, spent challenges and dead reset tokens
(`src/jobs.ts:124-130`).

A dead-lettered recurring job is deliberately **not** re-armed (`src/jobs.ts:65-67`).

---

## The database

Migrations 1–10 in `src/migrations.ts`, run only by `src/migrator.ts`. `index.ts` asserts the version
and refuses to serve below it. `BASELINE_VERSION = 0`: identity is built fresh rather than migrated
in place, because Nimbus's database keeps serving Nimbus until the cutover.

| Constraint | Refuses | Why it is here rather than in a handler |
| --- | --- | --- |
| `users_email_lower_uniq`, a unique index on `lower(email)` (migration **10**) | two accounts differing only by case | **the live defect this service exists partly to fix.** Nimbus matches the address verbatim on register and login but `lower(email)` on forgot-password, so an account created as `Sam@example.com` can be *reset* by someone who typed it lowercase and cannot be *logged into* by them. The migration normalises first and constrains second — creating the index first would fail on exactly the rows the update is there to fix. **A collision makes the migration fail, deliberately**: 23505 rolls the whole thing back and stops the deploy with a diagnosable error, because merging two accounts or picking a winner silently destroys one person's history and no automated rule can be right about which. A migration that stops is recoverable; one that guesses is not (`src/migrations.ts:449`, reasoning at `:424-446`) |
| `sessions_refresh_family_uniq` | a second session on one refresh-token family | **exactly one session per family is the invariant that makes "sign out everywhere" mean anything.** A family that outlives its session is a credential nothing surfaces and nothing can revoke — which is the state the estate is in today, where there are `refresh_tokens` rows and nothing that names them (`src/migrations.ts:227`, reasoning at `:189-193`) |
| `refresh_tokens_hash_uniq` on `token_hash` | a second row for one token | the raw token is never stored, only its SHA-256; that is the property that stops anyone with database access from minting a session (`src/migrations.ts:249`, `:236-238`) |
| `mfa_factors_one_active_per_kind`, a **partial** unique index `where status = 'active' and kind in ('totp','recovery_code')` | a second active TOTP factor or recovery-code set | regenerating codes revokes the old set in the same statement that writes the new one; **the index is what makes that atomic rather than merely intended**. Partial because revoked factors are kept as history and a full unique index would refuse the regeneration it is meant to protect (`src/migrations.ts:292`, reasoning at `:289-291`) |
| `mfa_factors_kind_chk` — `totp`, `webauthn`, `recovery_code`, and **not `sms`** | SMS as a second factor | not an oversight. SIM-swap is the dominant attack against crypto accounts, which makes SMS **weaker than the password it is meant to strengthen**. `contracts-auth`'s `MfaKind` omits it for the same reason, and a kind outside the union is a kind no service can accidentally accept (`src/migrations.ts:283`, reasoning at `:261-265`) |
| `signing_keys_publication_idx`, a partial index `where status <> 'retired'` on `(created_at, kid)` | nondeterministic JWKS ordering | it is not only an access path, it is the order the document is published in. Nondeterministic ordering was a real split-brain defect (SD-14): two replicas bootstrapping an empty database each minted a key, and an unordered select meant a consumer cached one and rejected every token minted by the other (`src/migrations.ts:179`, reasoning at `:175-178`) |
| `signing_keys.private_jwk_enc` **not null** | a plaintext private key | unlike Nimbus, this schema has never had a plaintext column to fall back to (`src/migrations.ts:163-164`) |
| `devices_user_fingerprint_uniq` | a duplicate device row per user | the stored value is a hash, never the raw fingerprint: the raw value is a tracking identifier with no use the hash does not serve (`src/migrations.ts:208`, `:200-201`) |
| `memberships` PK `(organisation_id, user_id)` + `memberships_role_chk` | a duplicate or unnamed role | — |
| **at least one owner per organisation** — *not* a constraint | — | **this one is deliberately not in the schema, and the file says why**: it is a statement about the resulting *set* after a change, and a row-level check cannot see the other rows at the moment it runs. It is enforced in `organisations.ts` under a row lock, using `contracts-auth`'s `wouldOrphanOrganisation` so that "demote the last owner" and "remove the last owner" cannot be caught separately and one of them forgotten (`src/migrations.ts:324-329`) |

Two columns carry reasoning worth repeating:

* **`users.hash_algo`** records the work factor, "so it is upgradable". Nimbus hashes with scrypt at
  library defaults and stores `salt:hash`, which makes the cost it was hashed at unknowable and
  therefore unraisable — there is no way to find the rows that need rehashing on next login
  (`src/migrations.ts:111-114`).
* **`refresh_tokens.rotated_at`** is written *only* by a rotation. `revoked` is set by four different
  things (rotation, sign-out, a password change, a family burn) and cannot tell them apart; this
  column can, which is what lets a re-presentation seconds after a rotation be answered as the
  concurrent refresh it almost always is instead of as theft (`src/migrations.ts:243-247`,
  `src/tokens.ts:200-204`).

### Refresh-token reuse detection

`rotateRefreshToken` returns `ok`, `reuse` or `invalid` (`src/tokens.ts:153-160`). Revoke and replace
happen in **one** transaction, and a narrow grace window absorbs the concurrent-refresh case — two
tabs racing — without which "refresh token reuse detected" fires on ordinary use and the containment
gets switched off (`src/tokens.ts:211-217`, `:295-301`). The grace path additionally requires the
family to still be alive, because without that second condition a burn and a graced sibling
interleaved would let the grace path insert a live token into the family the burn had just ended:
**a burn has to be final, so grace can only ever add to a living family** (`src/tokens.ts:314-318`).
`identity_refresh_reuse_total` and `identity_refresh_concurrent_total` are separate series precisely
so the two are distinguishable on a dashboard (`src/server.ts:155`, `:161`).

---

## Configuration

`.env.example` and `src/env.ts` were cross-checked and **agree**: every variable `loadEnv` reads
appears in the file, and the file names no variable the service does not read. The one thing absent
from `.env.example` is `IDENTITY_TEST_DATABASE_URL`, which is read only by the suite
(`src/testsupport.ts:24`) and is documented under [Running it](#running-it) instead.

`.env.example` itself records why it did not exist until recently (`.env.example:5-21`): identity —
the service every other service authenticates against — shipped without one, and the first vertical
slice had to reconstruct the list by reading `src/env.ts`, guessing one value wrong.

| Variable | Default | If it is wrong or missing |
| --- | --- | --- |
| `PORT` | `4000` | integer 1–65535 or boot fails (`src/env.ts:226`) |
| `NODE_ENV` | `development` | labelling only (`src/env.ts:227`) |
| `LOG_LEVEL` | `info` | outside `debug\|info\|warn\|error` refuses to start (`src/env.ts:215`) |
| `CLOUDSFORGE_TAG` | `dev` | the reported version is wrong (`src/env.ts:228`) |
| `IDENTITY_DATABASE_URL` | — | **required** (`src/env.ts:230`). Rule 1 — CI greps for any second connection-string variable |
| `IDENTITY_DATABASE_POOL_MAX` | `10` | a pool larger than the database's connection budget divided by the replica count exhausts Postgres for everything else the moment identity scales (`src/env.ts:233`, `:231-232`) |
| `IDENTITY_ISSUER` | — | **required**. The `iss` claim minted and verified. A mismatch presents as a **universal 401 a long way from its cause**, which is why `bad_issuer` is reported separately from a bad signature (`src/env.ts:234`, `:163-167`) |
| `IDENTITY_KEY_SECRET` | — | **required, ≥32 chars, placeholders refused.** Wrong → no key can be unwrapped and nothing can be signed. Disclosed → the estate is forgeable (`src/env.ts:236`). A placeholder is matched by **stem, not by exact string**: this file's own `.env.example` shipped `CHANGE_ME_at_least_32_characters_long`, which cleared both the length floor and the exact-match set and **booted** — a committed forging key one un-edited line away from production (`src/env.ts:49-73`) |
| `IDENTITY_PUBLIC_URL` | — | **required**, an origin with no path/query/fragment. Where reset links point, and **never the request `Host` header** (SD-04): Nimbus learned this the hard way — while nothing delivered mail it was latent, and wiring SMTP turned it into unauthenticated account takeover, a forged `Host` having the deployment's own relay mail the victim a genuine reset link pointing at the attacker's origin (`src/env.ts:237`, `:176-182`) |
| `IDENTITY_HANDOFF_ORIGINS` | `` (none) | comma-separated origins allowed to receive a hand-off. **Empty means none**, which is the safe default rather than the convenient one — an empty list makes SSO fail closed, and "empty means allow everything" is how an allowlist becomes an open redirect. **This is the only open-redirect guard in the estate's SSO**: `?return=` is a query parameter on a public page, and `hub-web` deliberately keeps no second list of its own. Every deployment must set it or a user can sign in at Hub and reach no other surface — `.env.example` carries the local `pnpm dev` set and says what goes wrong in both directions. Normalised through `origin()` so a trailing slash on one side is not a mismatch that reads to the user as "sign in bounced me" (`src/env.ts:219-223`, `:85-91`; refusal proved by `an EMPTY allowlist mints nothing at all`, `src/tokens.test.ts`) |
| `OUTBOX_SIGNING_SECRET` | — | **required, ≥24 chars.** Wrong → subscribers cannot verify an event came from us (`src/env.ts:239`) |
| `INSTANCE_ID` | hostname | names this replica in `jobs.locked_by` (`src/env.ts:240`) |
| `IDENTITY_SERVICE_TOKEN_GRANTS` | `{}` | JSON of service → scope array, **fail-closed**: a service absent from the map can be issued **no token at all**. Without it, `admin` would silently mean "may grant `custody:sign:treasury` to anything that asks" — the shared-secret problem back again with an audit row attached. An unknown scope name is a **boot failure that lists every scope it knows**, which is how the first slice discovered it had invented `ledger:write` (`src/env.ts:241`, reasoning at `:108-119`) |
| `IDENTITY_DELETION_GRACE_DAYS` | `7` | integer 0–365. **The wait is not politeness**: `identity.user.deleted` is published at the request and every subscriber erases on it, so tombstoning in the same breath would leave a subscriber that failed and retried with no user to reconcile against. It is also the window in which a deletion driven by a hijacked session can be cancelled by its real owner (`src/env.ts:242`, `:196-203`) |
| `IDENTITY_TEST_DATABASE_URL` | — | tests only; the name must contain `test`. Unset, every database-backed test **skips** (`src/testsupport.ts:24-29`) |

A configuration failure is reported as one hand-built structured `fatal` line to stderr, because the
checks run at import before the logger exists and a bare V8 stack is dropped by the collector
(`src/env.ts:246-268`). Every branch names the variable and never quotes a value.

---

## What it talks to

Identity is the bottom of the estate's dependency graph and calls **no** CloudsForge service. Its
only outbound traffic is the outbox relay POSTing signed envelopes to whatever rows exist in
`event_subscriptions` (`src/outbox.ts:279-281`); a failed delivery records `last_error`, leaves
`delivered_at` null and does not stop the batch.

| Direction | Who | When it is unavailable |
| --- | --- | --- |
| inbound | **every service in the estate**, fetching `/.well-known/jwks.json` and verifying `iss` against `IDENTITY_ISSUER` | consumers cache the JWKS for at least 300s (`src/server.ts:647`), so a short outage is invisible. A long one stops *new* key discovery, not verification of already-cached keys |
| outbound | `event_subscriptions` rows | fail open, per subscriber; the undelivered row is the durable record |
| outbound | **nothing else** | — |

**Password reset has no delivery channel at all.** `deliverPasswordReset` logs
`password_reset_undelivered` at `warn` and returns `{ delivered: false, channel: 'none' }`
(`src/passwordReset.ts:211-227`). This is a supported deployment mode, not a fault — the log carries
the user id and deliberately **not** the address, because Nimbus logged the email on every request
and so a log search for an address returned the fact that somebody had asked to reset it
(`src/passwordReset.ts:217-220`). The token itself is never logged, never persisted and never put in
an error message (`src/server.ts:992-995`). Until `micro-notify` is deployed and identity holds the
`notify:send` scope, an operator issues the link by hand.

---

## Running it

```bash
pnpm install
pnpm typecheck

# Migrations are a one-shot job and are NEVER run by the service process.
IDENTITY_DATABASE_URL=postgres://identity:identity@127.0.0.1:55433/identity pnpm migrate
pnpm start
```

The suite needs a real Postgres whose database name contains `test`; without
`IDENTITY_TEST_DATABASE_URL` every database-backed test **skips** rather than passes.

```bash
docker run -d --rm --name identity-pg \
  -e POSTGRES_USER=identity -e POSTGRES_PASSWORD=identity -e POSTGRES_DB=identity_test \
  -p 55433:5432 postgres:17-alpine

IDENTITY_TEST_DATABASE_URL=postgres://identity:identity@127.0.0.1:55433/identity_test pnpm test
```

**137 `test(` declarations, `node:test` only.** They run against a real database because the
controls that matter here are a partial unique index, a unique index on an expression and a
transactional rotation, and none of them can be proved against a fake. CI is the estate's reusable
`service-ci.yml` and **fails the build if the database-backed suite skipped**
(`.github/workflows/ci.yml`).

---

## Known gaps

* **The bootstrap.** See above. `POST /service-tokens` needs `admin`, nothing grants `admin`, so a
  fresh deployment needs a manual `UPDATE`. Tracked at `docs/ecosystem/18-build-status.md` §3.3g.
* **WebAuthn is two 501s.** The schema and the routes exist; the implementation does not
  (`src/server.ts:1196`, `:1204`). 501 rather than 404 deliberately — a 404 says "no such thing
  here" and a client cannot tell it from a typo (`src/server.ts:1188-1193`).
* **No password-reset delivery.** `deliverPasswordReset` delivers nothing
  (`src/passwordReset.ts:211`). Blocked on `micro-notify` plus the `notify:send` scope.
* **A machine credential has no whoami.** `GET /auth/me` refuses a service token
  (`src/server.ts:540`), so a devplatform API key has no way to ask what it is
  (`docs/ecosystem/18-build-status.md` §3.3d, item 4).
* **`/metrics` is unauthenticated** (`src/server.ts:625`). `micro-beacon` gates its equivalent and
  presents a token from Prometheus; this service does not, so anything that can reach the port can
  read login, failure and reuse counts. Deployment topology is currently the only thing keeping it
  private.
* **No path versioning.** This service serves `/auth/login`, not `/v1/auth/login`. The estate is
  split — `wallet`, `market`, `mint` and `worlds` serve `/v1/…`, `identity`, `ledger`, `foresight`,
  `pricing` and `activity` do not — and the public API is specified as URL-versioned with no gateway
  rewrite defined (`docs/ecosystem/18-build-status.md` §3.3d, item 3).
* **No email verification flow.** `users.email_verified_at` exists (`src/migrations.ts:107`) and no
  route sets it.
* **§3.3g's stated reason is wrong** (the conclusion is not). Recorded above; reported rather than
  edited, because this task's remit is this repository's README.
