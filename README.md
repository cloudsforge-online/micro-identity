# `micro-identity`

[![ci](https://github.com/cloudsforge-online/micro-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudsforge-online/micro-identity/actions/workflows/ci.yml) [![TypeScript](https://img.shields.io/badge/TypeScript-strict%20ESM-3178C6?logo=typescript&logoColor=white)](./tsconfig.base.json) [![node](https://img.shields.io/badge/node-%3E%3D22-5FA04E?logo=nodedotjs&logoColor=white)](./package.json) [![tests](https://img.shields.io/badge/tests-real%20Postgres-4169E1?logo=postgresql&logoColor=white)](./.github/workflows/ci.yml) [![licence](https://img.shields.io/badge/licence-MIT-blue)](./LICENSE)

The estate's root of trust. Users, passwords, sessions and devices, MFA, refresh-token families with
reuse detection, organisations and memberships, the SSO hand-off, account deletion, RS256 signing
keys with a published-then-activated rotation, and the JWKS that every other service in the estate
fetches before it can verify anything.

Design authority: [`ecosystem/03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md)

> **It authenticates; it does not authorise a product.** `users.roles` is platform roles only, and
> the schema says why: "the moment a product permission becomes a platform role, every service has
> to understand every product's authorisation model" (`src/migrations.ts`). Product
> permissions are entitlements (`micro-billing`) or organisation roles (`memberships.role`), never a
> platform role — SD-03, restated at `src/server.ts`.

> **It cannot mint its own first admin, and that is deliberate.** See
> [The first administrator](#the-first-administrator) — a service that could grant itself the role
> that mints every other service's credential would be a service whose compromise grants the estate.
> What it *can* now do is refuse a second one: the schema permits exactly one **unapproved**
> administrator per database, for ever, and every administrator after the first carries an approval
> id out of `micro-admin-api`'s four-eyes queue.

> **It never sees a full IP address.** `truncateIp` reduces it to a /24 or a /48 before it reaches a
> column, a log line or a response. The prefix carries the whole of the risk signal — "a sign-in
> from a network this account has never used" — and the rest is a personal identifier with no
> retention policy attached (`src/sessions.ts`, `src/migrations.ts`).

---

## The credential everything else depends on

`IDENTITY_KEY_SECRET` wraps the RS256 private half in AES-256-GCM under a scrypt-derived key. This
service's own source calls it **"the estate's universal forging credential"**
(`src/env.ts`), and the field comment is blunter still: "it is not a password to something, it
is the key to the key every service in the estate trusts" (`src/env.ts`). It is the one
secret required at **32** characters rather than the default 24 (`src/env.ts`), and a known
placeholder is refused at boot rather than accepted and forged later (`src/env.ts`).

Whoever holds it can mint a token for any user and any service, and every service in the estate will
accept it (`.env.example:43-47`).

### Key rotation is three steps, and the wait is the point

`src/keys.ts` states the lifecycle:

1. `POST /admin/signing-keys` mints a key as **`published`** — in the JWKS immediately, signing
   nothing.
2. **Wait one access-token TTL.** `PUBLISH_BEFORE_ACTIVE_MS` is 20 minutes: 15 for the token TTL
   plus a margin for consumers that cache the JWKS a little longer than they should
   (`src/keys.ts`). Activating sooner mints tokens under a `kid` verifiers have not fetched yet,
   and the symptom is **every service 401ing every request until its cache turns over — a
   self-inflicted outage that looks exactly like a key compromise** (`src/keys.ts`).
3. `POST /admin/signing-keys/:kid/activate` starts it signing; the previous key drops back to
   `published` so the tokens it already minted keep verifying until they expire (`src/keys.ts`).

`retired` is the only status that leaves the JWKS, and **nothing deletes a row**: the `kid` of a key
that ever signed is worth keeping so an old token in a log can be attributed
(`src/migrations.ts`).

---

## Routes

Read out of `src/server.ts`, and the table below is the whole of `buildRoutes()` rather than a
selection from it. `grep -c "define('" src/server.ts` is how that claim is checked, and it is
written as a command rather than as a number on purpose: the count in this file was wrong for as
long as the machine-credential routes were missing from the table, and a number typed here goes
stale the next time a route lands whereas a command does not.

`authenticate()` resolves the bearer token (`src/server.ts`);
`authenticateUser()` additionally refuses a **service** token, because a service token accepted where
a user token was expected makes `sub` — a service name — look like a user id
(`src/server.ts`); `authenticateAdmin()` additionally requires the `admin` role
(`src/server.ts`).

**No route on this service takes an `Idempotency-Key`.** There is no idempotency helper, table or
header path anywhere in the repository — the only occurrence of the word is the outbox relay using
an event id as one when it POSTs to a subscriber (`src/outbox.ts`). Retry semantics come
from the operations themselves instead: registration is refused by a unique index, refresh rotation
is a conditional `UPDATE … RETURNING`, hand-off redemption is single-use by row lock.

| Method | Path | Who | What it does |
| --- | --- | --- | --- |
| `GET` | `/livez` | **no auth** | liveness (`src/server.ts`) |
| `GET` | `/readyz` | **no auth** | 200 ready / 503 not (`src/server.ts`) |
| `GET` | `/metrics` | **no auth** | Prometheus text (`src/server.ts`) — see Known gaps |
| `GET` | `/.well-known/jwks.json` | **no auth** | public keys. **The one route in the file that is not `no-store`**: `public, max-age=300`, because a verifier re-fetching per request would make identity a synchronous dependency of every request in twenty-two services, which SD-01 rejects on availability grounds (`src/server.ts`, reasoning) |
| `POST` | `/auth/register` | **no auth** | creates the user, a `profiles` row and a **personal organisation** in one transaction, mints a verification token and answers **202 — no session, no tokens** (`src/server.ts`). It used to complete a session on the spot, which is how an address nobody had proved control of signed in: `{ verificationRequired: true, email, status }` is what it answers now |
| `POST` | `/auth/email/verify` | **no auth** (holds a token) | spends the verification link, stamps `users.email_verified_at` and mints the account's **first** session, `amr: ['pwd']` (`src/server.ts`). **POST, and there is deliberately no GET that consumes a token**: the link in the mail is a page on Hub with the token in the URL *fragment*, so a mail scanner's pre-fetch is `GET /account/verify` carrying nothing (`src/emailVerification.ts`) |
| `POST` | `/auth/email/verify/resend` | **no auth** | always **202**, with one fixed string for an account that needs a link, one that does not, one that does not exist and a malformed identifier alike — and the work happens in an `after` hook, because the timing is the oracle (`src/server.ts`) |
| `POST` | `/auth/login` | **no auth** | password sign-in; one message for every validation failure so nothing varies with whether the account exists (`src/server.ts`, reasoning). An unverified account is refused **after** the password verifies, `403 email_unverified` — its own code, because the client can act on it by offering a resend (`src/server.ts`) |
| `POST` | `/auth/mfa` | **no auth** (holds a challenge) | completes a sign-in that stopped at a second factor (`src/server.ts`) |
| `POST` | `/auth/refresh` | **no auth** (holds a refresh token) | rotates the refresh token; reuse burns the family (`src/server.ts`) |
| `POST` | `/auth/logout` | **no auth** (holds a refresh token) | 204; ends the session and its family (`src/server.ts`) |
| `GET` | `/auth/me` | user | the user, the current session's `id`/`amr`, and their organisations. **Refuses a service token** (`src/server.ts`, refusal) |
| `POST` | `/auth/password` | user | change password. **Holding a session is not enough — the current password is required**, or an unattended browser is a permanent account takeover (`src/server.ts`, reasoning) |
| `POST` | `/auth/password/forgot` | **no auth** | always **202**, for a known address, an unknown one and a malformed one alike. The work happens in an `after` hook once the response is on the wire, because the timing difference is the oracle (`src/server.ts`) |
| `POST` | `/auth/password/reset` | **no auth** (holds a token) | spends the reset token and sets the password (`src/server.ts`) |
| `POST` | `/auth/handoff` | user | mints a 60-second, single-use, origin-bound SSO code; throttled at 20/minute/address alongside its other half (`src/server.ts`) |
| `POST` | `/auth/handoff/redeem` | **no auth** (holds a code) | redeems it for tokens **in a response body, never a URL** (`src/server.ts`) |
| `GET` | `/sessions` | user | where this account is signed in (`src/server.ts`) |
| `DELETE` | `/sessions` | user | sign out everywhere (`src/server.ts`) |
| `DELETE` | `/sessions/:id` | user | sign out one session (`src/server.ts`) |
| `GET` | `/mfa/factors` | user | the factor list; never a secret (`src/server.ts`) |
| `POST` | `/mfa/totp` | user | enrol a TOTP factor as `pending` (`src/server.ts`) |
| `POST` | `/mfa/totp/:id/activate` | user | prove a code, move it to `active` (`src/server.ts`) |
| `POST` | `/mfa/recovery-codes` | user | regenerate the set; the old set is revoked in the same statement (`src/server.ts`) |
| `DELETE` | `/mfa/factors/:id` | user | remove a factor; re-authentication with the password is checked and recorded (`src/server.ts`) |
| `POST` | `/mfa/webauthn/options` | user | **501 `not_implemented`** (`src/server.ts`) |
| `POST` | `/mfa/webauthn` | user | **501 `not_implemented`** (`src/server.ts`) |
| `GET` | `/organisations` | user | the caller's organisations (`src/server.ts`) |
| `GET` | `/organisations/:id/memberships` | user | members of one organisation (`src/server.ts`) |
| `POST` | `/organisations/:id/memberships` | user | invite, change or remove a member. Refuses anything that would leave the organisation with no accepted owner (`src/server.ts`) |
| `POST` | `/service-tokens` | **admin** | mints a service token. **The token is returned once and never stored**, so there is nothing to read back (`src/server.ts`, note) |
| `POST` | `/service-tokens/exchange` | **a service credential** — the `cfsc_…` secret in the `Authorization` header, never a token | trades the long-lived credential a container holds at rest for a fresh ten-minute service token. **This is the route that ends the ten-minute cliff.** `POST /service-tokens` above needs an operator, so before this existed a service could be *given* a token at deploy time and could never obtain a second one; ten minutes later every service-to-service call on the money tier failed with an expired credential, and no per-service suite could see it because a suite mints a token and uses it seconds later (`src/serviceCredentials.ts`). **It makes no `authenticate()` call and must not**: a `cfsc_…` string is not a JWT, and a route that accepted either would let a service token mint its own successor — an unexpiring credential assembled out of expiring parts (`src/server.ts`, reasoning). The prefix is checked before the database is touched, so a caller presenting a JWT here gets a 401 that *says* a credential was expected rather than one that reads as "wrong secret". **The service minted for is read off the credential row and never off the request — there is deliberately no `service` field to send**, because a caller that could name its own service would only have to hold any credential in the estate to mint for `settlement` (`src/serviceCredentials.ts`, reasoning). An empty body is the common case and yields the service's whole `IDENTITY_SERVICE_TOKEN_GRANTS` allowlist, which is what a provider wants at boot when it cannot yet know which of its call sites will be reached; `scopes` narrows and identity never widens, and anything outside the allowlist is **403 `scope_not_granted`**. `ttlSeconds` may only ever *shorten* — a caller asking for a day is clamped to 600s (`clampServiceTtl`, `src/tokens.ts`), because "just make the TTL longer" is the repair this was built instead of. An unrecognised credential and a revoked one are answered **identically, 401 `unauthenticated`**: telling a caller "that one exists but is revoked" confirms a valid secret to whoever stole it. Exchanging neither consumes nor rotates the credential, and that is the requirement rather than an omission — N replicas boot from the same credential and each needs its own token in its own process memory, so reuse detection here would read the second replica's start-up as a replay and burn the credential of a service that was doing nothing but starting (`src/serviceCredentials.ts`, reasoning) |
| `POST` | `/service-credentials` | **admin** (a *user* token holding the role; `authenticateAdmin` refuses a service token outright) | mints the long-lived `cfsc_…` credential a service holds at rest — once per service per estate rather than once per ten minutes, which is the whole point. **The secret is in the response exactly once**: only its SHA-256 is stored, the same property that stops anyone with database access from minting for a service, and the reason re-provisioning is replace-and-revoke rather than "reuse the existing one" (`deploy/scripts/estate-bootstrap.sh` §5b does exactly that). Fail-closed on a service with no `IDENTITY_SERVICE_TOKEN_GRANTS` entry, because a credential that could never mint a single token would leave an operator holding a secret that silently does nothing. That refusal is **400 `unknown_service`**, and the message names the service that was not recognised. It was a bare `Error` until 2026-08-09, which had no arm in the mapper and so surfaced as **500 `internal`** with a generic message — a mistyped service name read as identity being faulty, and the two lead to opposite next actions. **It is deliberately not the 403 `scope_not_granted` that `POST /service-tokens` gives for the same missing entry**: that route is asked to mint a token which *acts as* a service and refuses an authorisation, this one is asked to create a credential *for* a service that does not exist, and `deploy/scripts/estate-verify.sh:396` asserts the 403 against the live estate (`src/serviceCredentials.ts`, `UnconfiguredServiceError`) |
| `GET` | `/service-credentials` | **admin** | every credential with its service, label, creator, `createdAt`, `lastUsedAt` and `revokedAt`. **Never a secret, and there is none to return** — only the digest was ever stored. `lastUsedAt` is the operator-visible answer to "which services never adopted the token provider": a credential unused since a deploy is either a service that is down or one still sitting on the cliff, and both should be visible without reading logs (`src/serviceCredentials.ts`). `estate-bootstrap.sh` reads this list to find the previous run's credentials by label and revoke them before it mints the next set |
| `POST` | `/service-credentials/:id/revoke` | **admin** | the containment lever a bearer JWT cannot have: a compromised service is offline within one token lifetime rather than one deploy cycle. Idempotent, and the **first** revocation's timestamp is the one kept, because re-revoking must not rewrite when containment actually began — the first thing an incident asks (`src/serviceCredentials.ts`, reasoning). **Tokens already minted under the credential stay valid until they expire**, which is the ten minutes doing its job and the reason that ceiling is worth defending. An id that names nothing is **404**, not a silent 200 |
| `PUT` | `/internal/users/:id/roles` | **service token holding `identity:admin`** | sets a user's platform roles, writing a `platform_role_grants` row with `source = 'approval'` and the caller's `approvalId` in the same transaction. Refuses an operator's own token: a human who could promote directly would be one pair of eyes. See [The first administrator](#the-first-administrator) |
| `GET` | `/internal/users/:id/role-grants` | **service token holding `identity:admin`** | the promotion trail for one user — who, when, on whose approval, and why |
| `DELETE` | `/users/me` | user | requests deletion; the account moves to `pending_deletion`, which is a state you may still authenticate from (`src/server.ts`, reasoning) |
| `POST` | `/users/me/deletion/cancel` | user | cancels it inside the grace window (`src/server.ts`) |
| `GET` | `/admin/signing-keys` | **admin** | the key list with statuses (`src/server.ts`) |
| `POST` | `/admin/signing-keys` | **admin** | mints a key as `published` (`src/server.ts`) |
| `POST` | `/admin/signing-keys/:kid/activate` | **admin** | starts it signing; refuses a key published for less than 20 minutes (`src/server.ts`) |
| `POST` | `/admin/signing-keys/:kid/retire` | **admin** | removes it from the JWKS (`src/server.ts`) |

### The routes that make no `authenticate()` call

`/livez`, `/readyz`, `/metrics`, `/.well-known/jwks.json`, `/auth/register`, `/auth/login`,
`/auth/email/verify`, `/auth/email/verify/resend`, `/auth/mfa`, `/auth/refresh`, `/auth/logout`,
`/auth/password/forgot`, `/auth/password/reset`, `/auth/handoff/redeem`. Each of the last ten
carries its own bearer credential in the body — a refresh token, an MFA challenge, a reset token, a
verification token, a hand-off code — which is why an `Authorization` header on them is ignored
rather than refused. (`/auth/email/verify/resend` carries none: it takes an identifier and answers
the same 202 whatever it is given.) Note that `POST /auth/handoff` (mint) **does**
authenticate; only `/redeem` does not.

**And one that is easy to miss, because it is the only route in the file that reads the
`Authorization` header itself: `POST /service-tokens/exchange`.** What it expects there is a service
credential rather than a token, so `authenticate()` is not merely unnecessary but wrong —
`verifyToken` would reject a `cfsc_…` string as malformed, and a route that accepted a token *or* a
credential would let a service token mint its own successor. It is an authenticated route by any
useful definition; it simply does not authenticate against the JWKS. This heading used to say
"fourteen", and the exchange landing is what made that false — hence no number in it now.

**A verifier that could not reach this service's own database answers 503, never 401**
(`src/server.ts`, reasoning). Answering 401 there would have every client in the
estate throw away a perfectly good session over a blip. The *reason* a token was rejected is logged
and never returned: "signature verification failed" versus "expired" tells an attacker which half of
a forged token to fix (`src/server.ts`).

---

## The first administrator

**A fresh deployment has no operator, and nothing in this service can create one.** That has not
changed and must not: `POST /service-tokens` requires the `admin` role (via `authenticateAdmin`), no
route grants a role to a user who has none, and the column defaults to none
(`roles text[] not null default '{}'`, `src/migrations.ts`). A service that could promote its own
first operator is a service whose compromise grants the estate, and `micro-admin-api`'s approval
queue cannot authorise the first grant either, because approving one needs an operator who already
holds the role. So the first grant is a runbook step, run by a human against this database.

**What changed is the shape of that step, not its place.** Until migration 12 it was one statement —

```sql
update users set roles = array['admin'] where email = '<the operator>';
```

— and it was *repeatable* (nothing made the second run differ from the first, so it was not a
bootstrap but a permanent superuser lever), *unaudited* (the most consequential write in the estate
was the only one with no actor, reason or time), and *unproven* (nothing went red if this service or
`micro-admin-api` grew a route that did the same thing).

Migration 12 puts three controls in the schema, where a bug, a migration or an operator holding a
psql connection cannot route around them — the threat model for a privilege escalation here has to
include a database connection, because the bootstrap is itself a database step:

| control | what it refuses |
| --- | --- |
| `platform_role_grants_one_bootstrap`, a **partial unique index** on `source = 'bootstrap'` | a second bootstrap grant, ever, in any transaction, from any client including psql — SQLSTATE 23505. It caps **unapproved** administrators at one rather than administrators at one, because four-eyes approval needs two operators |
| `users_roles_need_a_grant`, a **deferred constraint trigger** on `users` | a row that *gains* a privileged role without a `platform_role_grants` row for that user and role written **in the same transaction** — 23514, raised at `COMMIT`, so no ordering inside the transaction escapes it. Same-transaction and not merely "a grant exists": otherwise a demoted administrator is re-promotable for ever on the row that authorised the first promotion |
| `platform_role_grants_immutable`, a **before update or delete trigger** | any `UPDATE` or `DELETE` on a grant row. Without it the one-shot index is re-armable by `delete from platform_role_grants where source = 'bootstrap'` |

Losing a role never needs a grant. A control that could block a revocation would be a liability
during an incident rather than a safeguard.

The bootstrap step, in its correct shape — **one transaction**, so that a re-run fails at the index
before the update is attempted and rolls back:

```sql
begin;
insert into platform_role_grants (user_id, role, source, actor, reason)
select id, 'admin', 'bootstrap', 'estate-bootstrap.sh',
       'first operator of this environment; no approval queue can exist before one'
  from users where email = lower(btrim('<the operator>'));
update users set roles = array['player','admin']
 where email = lower(btrim('<the operator>'));
commit;
```

`deploy/scripts/estate-bootstrap.sh` still runs the bare `UPDATE`, which migration 12 now
refuses; `micro-deploy` owns that script and has been told what it must become, including that the
procedure should assert its own re-run fails.

**Every administrator after the first** comes through `PUT /internal/users/:id/roles`, the route
`micro-admin-api` specified and answers **501** without. It is gated on a **service** token holding
`identity:admin` — not `authenticateAdmin`, which refuses a service token outright and would make
the route unreachable from the queue, and not an operator's own token, because a human who could
promote directly would be a single pair of eyes on the estate's most consequential write. The
handler writes the grant row and the `users.roles` update in one transaction; it does not have to be
trusted to, because the deferred trigger refuses the update otherwise.

The honest limit: the database owner can `alter table … disable trigger` or drop an index, and
nothing in a schema survives its own superuser. What this buys is that each of those is a
deliberate, loud, separate act that leaves DDL behind, rather than an `UPDATE` that looks like every
other `UPDATE`.

> **A correction to §3.3g, found while writing this.** That section says `users.roles` defaults to
> `'{}'` and therefore "every user is created with none". The default is right; the conclusion is
> not. `registerUser` inserts `roles = ['player']` explicitly (`src/users.ts`), so a freshly
> registered user has one role — just never `admin`.

---

## Background work

Leased jobs only. There is no `setInterval` doing domain work and CI greps for one. **The lease key
names the contended resource, not the row** (`src/jobs.ts`).

| Job | Lease key | Cadence | What two replicas do |
| --- | --- | --- | --- |
| `outbox.relay` | `stream` | 1s | one claims the stream; keying on the event id would let two relays deliver one batch to one subscriber twice (`src/jobs.ts`) |
| `identity.tombstone` | `global` | 60min | both would select the same batch. The update is conditional on `status = 'pending_deletion'` so the second no-ops, but they would contend on every row lock for nothing (`src/jobs.ts`, reasoning) |
| `identity.sweep` | `global` | 15min | pure deletion, genuinely idempotent; keyed globally only so it runs once rather than N times (`src/jobs.ts`) |

The tombstone job runs **hourly rather than by the minute**: its input changes once a day at most per
account and the grace window is measured in days, so running it more often is work with nothing to
find, and less often lets an erasure the user was promised drift past the deadline in the event that
announced it (`src/jobs.ts`). It tombstones one account at a time with a `heartbeat()` between
them, because each is a transaction touching several tables and a lease expiring mid-run would hand
the rest of the batch to a second replica (`src/jobs.ts`). The log line it emits carries the
user id and **no address and no handle** — by that point neither exists, and logging what was erased
would defeat the erasure (`src/jobs.ts`).

The sweep exists because every table already has an opportunistic sweep at its own write path, which
is enough while the service is busy and does nothing at all while it is not: a deployment that stops
being used still stops holding expired hand-off codes, spent challenges and dead reset tokens
(`src/jobs.ts`).

A dead-lettered recurring job is deliberately **not** re-armed (`src/jobs.ts`).

---

## The database

Migrations 1–13 in `src/migrations.ts`, run only by `src/migrator.ts`. `index.ts` asserts the version
and refuses to serve below it. `BASELINE_VERSION = 0`: identity is built fresh rather than migrated
in place, because Nimbus's database keeps serving Nimbus until the cutover.

| Constraint | Refuses | Why it is here rather than in a handler |
| --- | --- | --- |
| `users_email_lower_uniq`, a unique index on `lower(email)` (migration **10**) | two accounts differing only by case | **the live defect this service exists partly to fix.** Nimbus matches the address verbatim on register and login but `lower(email)` on forgot-password, so an account created as `Sam@example.com` can be *reset* by someone who typed it lowercase and cannot be *logged into* by them. The migration normalises first and constrains second — creating the index first would fail on exactly the rows the update is there to fix. **A collision makes the migration fail, deliberately**: 23505 rolls the whole thing back and stops the deploy with a diagnosable error, because merging two accounts or picking a winner silently destroys one person's history and no automated rule can be right about which. A migration that stops is recoverable; one that guesses is not (`src/migrations.ts`, reasoning) |
| `sessions_refresh_family_uniq` | a second session on one refresh-token family | **exactly one session per family is the invariant that makes "sign out everywhere" mean anything.** A family that outlives its session is a credential nothing surfaces and nothing can revoke — which is the state the estate is in today, where there are `refresh_tokens` rows and nothing that names them (`src/migrations.ts`, reasoning) |
| `refresh_tokens_hash_uniq` on `token_hash` | a second row for one token | the raw token is never stored, only its SHA-256; that is the property that stops anyone with database access from minting a session (`src/migrations.ts`) |
| `mfa_factors_one_active_per_kind`, a **partial** unique index `where status = 'active' and kind in ('totp','recovery_code')` | a second active TOTP factor or recovery-code set | regenerating codes revokes the old set in the same statement that writes the new one; **the index is what makes that atomic rather than merely intended**. Partial because revoked factors are kept as history and a full unique index would refuse the regeneration it is meant to protect (`src/migrations.ts`, reasoning) |
| `mfa_factors_kind_chk` — `totp`, `webauthn`, `recovery_code`, and **not `sms`** | SMS as a second factor | not an oversight. SIM-swap is the dominant attack against crypto accounts, which makes SMS **weaker than the password it is meant to strengthen**. `contracts-auth`'s `MfaKind` omits it for the same reason, and a kind outside the union is a kind no service can accidentally accept (`src/migrations.ts`, reasoning) |
| `signing_keys_publication_idx`, a partial index `where status <> 'retired'` on `(created_at, kid)` | nondeterministic JWKS ordering | it is not only an access path, it is the order the document is published in. Nondeterministic ordering was a real split-brain defect (SD-14): two replicas bootstrapping an empty database each minted a key, and an unordered select meant a consumer cached one and rejected every token minted by the other (`src/migrations.ts`, reasoning) |
| `platform_role_grants_one_bootstrap`, a **partial** unique index `where source = 'bootstrap'` (migration **12**) | a second bootstrap grant, ever, from any client including psql | **the estate gets exactly one administrator that answers to nothing.** Partial and not a plain unique on `source`, because capping *approved* grants at one would make a second administrator impossible and four-eyes approval needs two operators (`src/migrations.ts`, migration 12) |
| `users_roles_need_a_grant`, a **deferred constraint trigger** on `users` (migration **12**) | a row that gains a privileged role with no grant row written in the same transaction | a CHECK cannot reference another table and cannot see the old row. Deferred so the grant and the promotion may be written in either order, which also means a bare `update users set roles = array['admin']` from psql fails at `COMMIT` rather than being caught by a handler the attacker is already past |
| `platform_role_grants_immutable`, a before-`UPDATE`-or-`DELETE` trigger (migration **12**) | any edit or deletion of a grant row | without it the one-shot index above is re-armable by one `DELETE`, and a promotion is un-recordable after the fact |
| `email_verification_tokens_one_live`, a **partial** unique index on `(user_id) where consumed_at is null` (migration **13**) | a second live verification token for one account | two live links means the older one — the one most likely to have leaked into a mail client, a chat log or a scanner's cache — still verifies. `emailVerification.ts` supersedes under `pg_advisory_xact_lock` so the race cannot happen; **this index is what makes the state unrepresentable if a future edit drops the lock**. Partial, because a plain unique on `user_id` would make an account verifiable exactly once for the life of the database and every resend would fail at 23505 (`src/migrations.ts`, reasoning) |
| migration 13's backfill — `email_verified_at = created_at` for every existing row | locking out the whole platform on deploy | every account that exists when it runs was created by a service with no verification at all, so none was ever offered a link. Refusing them instead would sign out every user *and the bootstrap administrator*, in an estate where nothing yet consumes `identity.email.verification_requested` — so there would be no way back in. `created_at` and not `now()`: the claim is "this account predates verification" (`src/migrations.ts`) |
| `signing_keys.private_jwk_enc` **not null** | a plaintext private key | unlike Nimbus, this schema has never had a plaintext column to fall back to (`src/migrations.ts`) |
| `devices_user_fingerprint_uniq` | a duplicate device row per user | the stored value is a hash, never the raw fingerprint: the raw value is a tracking identifier with no use the hash does not serve (`src/migrations.ts`) |
| `memberships` PK `(organisation_id, user_id)` + `memberships_role_chk` | a duplicate or unnamed role | — |
| **at least one owner per organisation** — *not* a constraint | — | **this one is deliberately not in the schema, and the file says why**: it is a statement about the resulting *set* after a change, and a row-level check cannot see the other rows at the moment it runs. It is enforced in `organisations.ts` under a row lock, using `contracts-auth`'s `wouldOrphanOrganisation` so that "demote the last owner" and "remove the last owner" cannot be caught separately and one of them forgotten (`src/migrations.ts`) |

Two columns carry reasoning worth repeating:

* **`users.hash_algo`** records the work factor, "so it is upgradable". Nimbus hashes with scrypt at
  library defaults and stores `salt:hash`, which makes the cost it was hashed at unknowable and
  therefore unraisable — there is no way to find the rows that need rehashing on next login
  (`src/migrations.ts`).
* **`refresh_tokens.rotated_at`** is written *only* by a rotation. `revoked` is set by four different
  things (rotation, sign-out, a password change, a family burn) and cannot tell them apart; this
  column can, which is what lets a re-presentation seconds after a rotation be answered as the
  concurrent refresh it almost always is instead of as theft (`src/migrations.ts`,
  `src/tokens.ts`).

### Refresh-token reuse detection

`rotateRefreshToken` returns `ok`, `reuse` or `invalid` (`src/tokens.ts`). Revoke and replace
happen in **one** transaction, and a narrow grace window absorbs the concurrent-refresh case — two
tabs racing — without which "refresh token reuse detected" fires on ordinary use and the containment
gets switched off (`src/tokens.ts`). The grace path additionally requires the
family to still be alive, because without that second condition a burn and a graced sibling
interleaved would let the grace path insert a live token into the family the burn had just ended:
**a burn has to be final, so grace can only ever add to a living family** (`src/tokens.ts`).
`identity_refresh_reuse_total` and `identity_refresh_concurrent_total` are separate series precisely
so the two are distinguishable on a dashboard (`src/server.ts`).

---

## Configuration

`.env.example` and `src/env.ts` were cross-checked and **agree**: every variable `loadEnv` reads
appears in the file, and the file names no variable the service does not read. The one thing absent
from `.env.example` is `IDENTITY_TEST_DATABASE_URL`, which is read only by the suite
(`src/testsupport.ts`) and is documented under [Running it](#running-it) instead.

`.env.example` itself records why it did not exist until recently (`.env.example:5-21`): identity —
the service every other service authenticates against — shipped without one, and the first vertical
slice had to reconstruct the list by reading `src/env.ts`, guessing one value wrong.

| Variable | Default | If it is wrong or missing |
| --- | --- | --- |
| `PORT` | `4000` | integer 1–65535 or boot fails (`src/env.ts`) |
| `NODE_ENV` | `development` | labelling only (`src/env.ts`) |
| `LOG_LEVEL` | `info` | outside `debug\|info\|warn\|error` refuses to start (`src/env.ts`) |
| `CLOUDSFORGE_TAG` | `dev` | the reported version is wrong (`src/env.ts`) |
| `IDENTITY_DATABASE_URL` | — | **required** (`src/env.ts`). Rule 1 — CI greps for any second connection-string variable |
| `IDENTITY_DATABASE_POOL_MAX` | `10` | a pool larger than the database's connection budget divided by the replica count exhausts Postgres for everything else the moment identity scales (`src/env.ts`) |
| `IDENTITY_ISSUER` | — | **required**. The `iss` claim minted and verified. A mismatch presents as a **universal 401 a long way from its cause**, which is why `bad_issuer` is reported separately from a bad signature (`src/env.ts`) |
| `IDENTITY_KEY_SECRET` | — | **required, ≥32 chars, placeholders refused.** Wrong → no key can be unwrapped and nothing can be signed. Disclosed → the estate is forgeable (`src/env.ts`). A placeholder is matched by **stem, not by exact string**: this file's own `.env.example` shipped `CHANGE_ME_at_least_32_characters_long`, which cleared both the length floor and the exact-match set and **booted** — a committed forging key one un-edited line away from production (`src/env.ts`) |
| `IDENTITY_PUBLIC_URL` | — | **required**, an origin with no path/query/fragment. Where reset links point, and **never the request `Host` header** (SD-04): Nimbus learned this the hard way — while nothing delivered mail it was latent, and wiring SMTP turned it into unauthenticated account takeover, a forged `Host` having the deployment's own relay mail the victim a genuine reset link pointing at the attacker's origin (`src/env.ts`) |
| `IDENTITY_ACCOUNT_URL` | `` (none) | **optional**, an origin with no path/query/fragment. Where an email-verification link points — **Hub's origin, not this service's**: the link opens `<origin>/account/verify#token=…`, a page Hub serves, which posts the token back to `POST /auth/email/verify`. Unset is a supported mode and deliberately so: the token is still minted and the event still emitted, carrying `linkable: false` instead of a `verifyUrl`, because making it required would turn a missing line in a deploy manifest into "nobody can create an account". What it costs while unset is the button in the mail (`src/env.ts`; the seam reports it at `src/emailVerification.ts`) |
| `IDENTITY_HANDOFF_ORIGINS` | `` (none) | comma-separated origins allowed to receive a hand-off. **Empty means none**, which is the safe default rather than the convenient one — an empty list makes SSO fail closed, and "empty means allow everything" is how an allowlist becomes an open redirect. **This is the only open-redirect guard in the estate's SSO**: `?return=` is a query parameter on a public page, and `hub-web` deliberately keeps no second list of its own. Every deployment must set it or a user can sign in at Hub and reach no other surface — `.env.example` carries the local `pnpm dev` set and says what goes wrong in both directions. Normalised through `origin()` so a trailing slash on one side is not a mismatch that reads to the user as "sign in bounced me" (`src/env.ts`; refusal proved by `an EMPTY allowlist mints nothing at all`, `src/tokens.test.ts`) |
| `OUTBOX_SIGNING_SECRET` | — | **required, ≥24 chars.** Wrong → subscribers cannot verify an event came from us (`src/env.ts`) |
| `INSTANCE_ID` | hostname | names this replica in `jobs.locked_by` (`src/env.ts`) |
| `IDENTITY_SERVICE_TOKEN_GRANTS` | `{}` | JSON of service → scope array, **fail-closed**: a service absent from the map can be issued **no token at all**. Without it, `admin` would silently mean "may grant `custody:sign:treasury` to anything that asks" — the shared-secret problem back again with an audit row attached. An unknown scope name is a **boot failure that lists every scope it knows**, which is how the first slice discovered it had invented `ledger:write` (`src/env.ts`, reasoning) |
| `IDENTITY_DELETION_GRACE_DAYS` | `7` | integer 0–365. **The wait is not politeness**: `identity.user.deleted` is published at the request and every subscriber erases on it, so tombstoning in the same breath would leave a subscriber that failed and retried with no user to reconcile against. It is also the window in which a deletion driven by a hijacked session can be cancelled by its real owner (`src/env.ts`) |
| `IDENTITY_TEST_DATABASE_URL` | — | tests only; the name must contain `test`. Unset, every database-backed test **skips** (`src/testsupport.ts`) |

A configuration failure is reported as one hand-built structured `fatal` line to stderr, because the
checks run at import before the logger exists and a bare V8 stack is dropped by the collector
(`src/env.ts`). Every branch names the variable and never quotes a value.

---

## What it talks to

Identity is the bottom of the estate's dependency graph and calls **no** CloudsForge service. Its
only outbound traffic is the outbox relay POSTing signed envelopes to whatever rows exist in
`event_subscriptions` (`src/outbox.ts`); a failed delivery records `last_error`, leaves
`delivered_at` null and does not stop the batch.

| Direction | Who | When it is unavailable |
| --- | --- | --- |
| inbound | **every service in the estate**, fetching `/.well-known/jwks.json` and verifying `iss` against `IDENTITY_ISSUER` | consumers cache the JWKS for at least 300s (`src/server.ts`), so a short outage is invisible. A long one stops *new* key discovery, not verification of already-cached keys |
| outbound | `event_subscriptions` rows | fail open, per subscriber; the undelivered row is the durable record |
| outbound | **nothing else** | — |

**Password reset has no delivery channel at all.** `deliverPasswordReset` logs
`password_reset_undelivered` at `warn` and returns `{ delivered: false, channel: 'none' }`
(`src/passwordReset.ts`). This is a supported deployment mode, not a fault — the log carries
the user id and deliberately **not** the address, because Nimbus logged the email on every request
and so a log search for an address returned the fact that somebody had asked to reset it
(`src/passwordReset.ts`). The token itself is never logged, never persisted and never put in
an error message (`src/server.ts`). Until `micro-notify` is deployed and identity holds the
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

* **The bootstrap is still a manual step, and stays one.** A fresh deployment needs one transaction
  run against this database by a human — see [The first administrator](#the-first-administrator).
  What is no longer a gap is that it was repeatable, unaudited and unproven; migration 12 makes it
  one-shot, trailed and tested. `micro-deploy` still runs the old bare `UPDATE`, which now fails.
  Tracked at `docs/ecosystem/18-build-status.md` §3.3g.
* **WebAuthn is two 501s.** The schema and the routes exist; the implementation does not
  (`src/server.ts`). 501 rather than 404 deliberately — a 404 says "no such thing
  here" and a client cannot tell it from a typo (`src/server.ts`).
* **No password-reset delivery.** `deliverPasswordReset` delivers nothing
  (`src/passwordReset.ts`). Blocked on `micro-notify` plus the `notify:send` scope.
* **A machine credential has no whoami.** `GET /auth/me` refuses a service token
  (`src/server.ts`), so a devplatform API key has no way to ask what it is
  (`docs/ecosystem/18-build-status.md` §3.3d, item 4).
* **`/metrics` is unauthenticated** (`src/server.ts`). `micro-beacon` gates its equivalent and
  presents a token from Prometheus; this service does not, so anything that can reach the port can
  read login, failure and reuse counts. Deployment topology is currently the only thing keeping it
  private.
* **No path versioning.** This service serves `/auth/login`, not `/v1/auth/login`. The estate is
  split — `wallet`, `market`, `mint` and `worlds` serve `/v1/…`, `identity`, `ledger`, `foresight`,
  `pricing` and `activity` do not — and the public API is specified as URL-versioned with no gateway
  rewrite defined (`docs/ecosystem/18-build-status.md` §3.3d, item 3).
* **Nothing sends the verification email yet.** The flow exists end to end inside this service —
  the token, the routes, the refusal at sign-in — and the fact leaves as
  `identity.email.verification_requested` (`src/emailVerification.ts`) because identity does not
  speak SMTP and `notify` owns every outbound channel. Until `notify` subscribes to that topic, a
  new account is created, refused at sign-in and has no way to receive its link. **A deployment must
  set `IDENTITY_ACCOUNT_URL` before it turns this on**, or the event carries `linkable: false` and
  there is no URL to render. The same gap the password-reset bullet above describes, on the same
  blocker.
* **§3.3g's stated reason is wrong** (the conclusion is not). Recorded above; reported rather than
  edited, because this task's remit is this repository's README.

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, assets
generated with **FLUX 2 Pro**, under human direction and review.
