/**
 * The versioned schema.
 *
 * Rule 7 of docs/ecosystem/03 section 2: versioned files, run by a one-shot job under an advisory
 * lock, expand/contract only. Nothing here is executed by `index.ts` — `src/migrator.ts` is the
 * only caller, and the service asserts the version rather than reaching it.
 *
 * **Expand/contract is not advice.** A rolling deploy always runs two versions of this service
 * against one schema, so every change is four releases: add a column, deploy code that writes both,
 * backfill, deploy code that reads the new one, then drop the old one.
 *
 * **A released migration is immutable.** `@cloudsforge/db` checksums each one and refuses a run
 * where the text changed after it was applied. The fix for a wrong migration is always a new one.
 *
 * What is deliberately NOT here, carried over from Nimbus's `signing_keys` table: a plaintext
 * `private_jwk` column. Nimbus keeps one only so a boot pass can empty it, and its own comment says
 * the column exists to be dropped once every deployment has run that build. A database created by
 * this service has never held the key in the clear, so the column has nothing to migrate and its
 * presence would only be somewhere for a future bug to write.
 */

import { JOBS_SCHEMA_SQL } from '@cloudsforge/jobs'
import type { Migration } from '@cloudsforge/db'

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: 'jobs',
    // Taken verbatim from the runtime package so the table the claim query assumes and the table
    // that exists cannot drift. Copying the DDL by hand is how a service ends up with a jobs table
    // missing the (kind, key) unique constraint, which silently turns every recurring enqueue into
    // a duplicate run.
    up: JOBS_SCHEMA_SQL,
  },
  {
    version: 2,
    name: 'outbox',
    up: `
      create table if not exists outbox (
        id             uuid        primary key default gen_random_uuid(),
        topic          text        not null,
        key            text        not null,
        occurred_at    timestamptz not null default now(),
        producer       text        not null,
        version        integer     not null default 1,
        actor          text,
        correlation_id text,
        payload        jsonb       not null default '{}'::jsonb,
        published_at   timestamptz
      );

      -- The relay's access path. Partial on the unpublished set, so the index stays the size of the
      -- backlog rather than the size of history.
      create index if not exists outbox_unpublished_idx
        on outbox (occurred_at)
        where published_at is null;

      create table if not exists event_subscriptions (
        id         uuid        primary key default gen_random_uuid(),
        topic      text        not null,
        url        text        not null,
        active     boolean     not null default true,
        created_at timestamptz not null default now(),
        constraint event_subscriptions_topic_url_uniq unique (topic, url)
      );

      -- Delivery is tracked per (event, subscription) rather than per event. With one flag on the
      -- outbox row, one failing subscriber either blocks every other subscriber or causes the event
      -- to be redelivered to all of them on each retry.
      create table if not exists outbox_deliveries (
        event_id        uuid        not null references outbox (id) on delete cascade,
        subscription_id uuid        not null references event_subscriptions (id) on delete cascade,
        delivered_at    timestamptz,
        attempts        integer     not null default 0,
        last_error      text,
        primary key (event_id, subscription_id)
      );

      -- Delivery is at-least-once, so the consumer is what makes it effectively-once. The primary
      -- key is the dedupe: a redelivered event conflicts and the handler is never re-run.
      create table if not exists inbox (
        topic       text        not null,
        event_id    uuid        not null,
        received_at timestamptz not null default now(),
        primary key (topic, event_id)
      );
    `,
  },
  {
    version: 3,
    name: 'users',
    // 04-domain-model section 1.1 and 1.2. Two tables rather than one because the profile is read
    // by every product and written rarely, and because a profile read must never have to select a
    // password hash to get a display name.
    //
    // `handle_key` is the lower-cased handle and carries the uniqueness; `handle` keeps the casing
    // the user chose. Without the split, `Alice` and `alice` are two accounts and the second exists
    // only to be mistaken for the first.
    //
    // `email` is NOT unique here. The uniqueness lands in migration 10 as an index on
    // `lower(email)`, together with the normalisation of existing rows — see that migration for why
    // it is separate.
    up: `
      create table if not exists users (
        id                  uuid        primary key,
        email               text        not null,
        email_verified_at   timestamptz,
        handle              text        not null,
        handle_key          text        not null,
        password_hash       text        not null,
        -- The work factor, recorded so it is upgradable. Nimbus hashes with scrypt at library
        -- defaults and stores 'salt:hash', which means the cost it was hashed at is unknowable and
        -- therefore unraisable: there is no way to find the rows that need rehashing on next login.
        hash_algo           text        not null,
        status              text        not null default 'active',
        -- Platform roles only. Product permissions are entitlements (billing) or organisation
        -- roles; the moment a product permission becomes a platform role, every service has to
        -- understand every product's authorisation model.
        roles               text[]      not null default '{}',
        created_at          timestamptz not null default now(),
        last_seen_at        timestamptz,
        -- When deletion was requested. The grace window between the event being published and the
        -- row being tombstoned is measured from here.
        pending_deletion_at timestamptz,
        deleted_at          timestamptz,
        constraint users_handle_key_uniq unique (handle_key),
        constraint users_status_chk check (
          status in ('active', 'suspended', 'locked', 'pending_deletion', 'deleted')
        )
      );

      create table if not exists profiles (
        user_id          uuid        primary key references users (id) on delete cascade,
        display_name     text,
        avatar_asset_urn text,
        bio              text,
        links            jsonb       not null default '[]'::jsonb,
        country          text,
        locale           text,
        timezone         text,
        visibility       text        not null default 'public',
        updated_at       timestamptz not null default now(),
        constraint profiles_visibility_chk check (visibility in ('public', 'members', 'private'))
      );
    `,
  },
  {
    version: 4,
    name: 'signing_keys',
    // The RS256 signing key and its rotation state machine (SD-01), carried forward from Nimbus's
    // keys.ts unchanged in behaviour.
    //
    // `published` is the state that makes rotation safe in both directions. A key must be in the
    // JWKS before it signs anything, or the tokens it mints are rejected by every service whose
    // cache has not refreshed; and it must STAY in the JWKS after it stops signing, until the last
    // access token it minted has expired. Both of those are the same state — in the document, not
    // signing — so there is one name for it. `retired` is the only state that leaves the document,
    // and nothing deletes a row: the kid of a key that ever signed is worth keeping so an old token
    // in a log can be attributed.
    up: `
      create table if not exists signing_keys (
        kid               text        primary key,
        -- AES-256-GCM under a scrypt-derived key. NOT NULL, unlike Nimbus, because this schema has
        -- never had a plaintext column to fall back to.
        private_jwk_enc   text        not null,
        public_jwk        jsonb       not null,
        status            text        not null default 'active',
        created_at        timestamptz not null default now(),
        -- When it entered its current state. Activation refuses a key that has not been published
        -- for a whole access-token TTL, and this is the clock it reads.
        status_changed_at timestamptz not null default now(),
        constraint signing_keys_status_chk check (status in ('active', 'published', 'retired'))
      );

      -- The JWKS query's access path, and it is also the order the document is published in.
      -- Nondeterministic ordering here was a split-brain defect (SD-14): two replicas bootstrapping
      -- an empty database each minted a key, and an unordered select meant a consumer cached one
      -- and rejected every token minted by the other.
      create index if not exists signing_keys_publication_idx
        on signing_keys (created_at, kid)
        where status <> 'retired';
    `,
  },
  {
    version: 5,
    name: 'sessions_and_devices',
    // 04-domain-model section 1.4. Neither exists in the estate today: there are `refresh_tokens`
    // rows and nothing that names or surfaces them, so "sign out everywhere" and "where am I signed
    // in" are both unanswerable.
    //
    // The invariant is carried by `sessions_refresh_family_uniq`: exactly one session per
    // refresh-token family. A family that outlives its session is a credential nothing surfaces and
    // nothing can revoke.
    up: `
      create table if not exists devices (
        id                uuid        primary key,
        user_id           uuid        not null references users (id) on delete cascade,
        -- A hash, never the raw fingerprint. The raw value is a tracking identifier and we have no
        -- use for it that the hash does not serve.
        fingerprint_hash  text        not null,
        -- Family only — "Firefox", "iOS". A full user-agent string is a fingerprint by itself.
        user_agent_family text,
        os_family         text,
        first_seen_at     timestamptz not null default now(),
        last_seen_at      timestamptz not null default now(),
        trusted_at        timestamptz,
        label             text,
        constraint devices_user_fingerprint_uniq unique (user_id, fingerprint_hash)
      );

      create table if not exists sessions (
        id                uuid        primary key,
        user_id           uuid        not null references users (id) on delete cascade,
        device_id         uuid        references devices (id) on delete set null,
        refresh_family_id uuid        not null,
        -- Truncated to a /24 or a /48 by contracts-auth's truncateIp. **Never a full address**, in
        -- this column, in a log line, or in a response: a full address is personal data with no
        -- retention story attached, and the prefix carries the whole of the risk signal.
        ip_prefix         text,
        -- How the subject proved who they were, so a step-up can be demanded later.
        amr               text[]      not null default '{}',
        status            text        not null default 'active',
        created_at        timestamptz not null default now(),
        last_active_at    timestamptz not null default now(),
        revoked_at        timestamptz,
        revoke_reason     text,
        constraint sessions_refresh_family_uniq unique (refresh_family_id),
        constraint sessions_status_chk check (status in ('active', 'expired', 'revoked', 'superseded'))
      );

      create index if not exists sessions_user_idx on sessions (user_id, created_at desc);

      create table if not exists refresh_tokens (
        id         uuid        primary key,
        user_id    uuid        not null references users (id) on delete cascade,
        session_id uuid        not null references sessions (id) on delete cascade,
        -- SHA-256 hex of the opaque token; the raw token is never stored, which is the property
        -- that stops anyone with database access from minting a session.
        token_hash text        not null,
        family_id  uuid        not null,
        expires_at timestamptz not null,
        revoked    boolean     not null default false,
        -- When this row was spent BY A ROTATION, and only by a rotation. The revoked flag is set by four
        -- different things (rotation, sign-out, a password change, a family burn) and cannot tell
        -- them apart; this column can, which is what lets a re-presentation seconds after a
        -- rotation be answered as the concurrent refresh it almost always is instead of as theft.
        rotated_at timestamptz,
        created_at timestamptz not null default now(),
        constraint refresh_tokens_hash_uniq unique (token_hash)
      );

      create index if not exists refresh_tokens_family_idx on refresh_tokens (family_id);
      create index if not exists refresh_tokens_user_idx on refresh_tokens (user_id);
    `,
  },
  {
    version: 6,
    name: 'mfa',
    // 04-domain-model section 1.3 and SD-02.
    //
    // `sms` is absent from the check constraint on purpose and it is not an oversight: SIM-swap is
    // the dominant attack against crypto accounts, which makes SMS a weaker factor than the
    // password it is meant to strengthen. contracts-auth's `MfaKind` omits it for the same reason,
    // and a kind that is not in the union is a kind no service can accidentally accept.
    //
    // A recovery-code SET is one factor row; the individual codes are rows in
    // `mfa_recovery_codes`. Modelling it the other way — a factor per code — would make "remove the
    // last factor" fire on spending the ninth of ten codes.
    up: `
      create table if not exists mfa_factors (
        id           uuid        primary key,
        user_id      uuid        not null references users (id) on delete cascade,
        kind         text        not null,
        -- User-supplied. Never the secret, never a partial secret.
        label        text        not null,
        -- The TOTP seed, in the same AES-256-GCM envelope the signing key uses. A shared secret in
        -- the clear is a second factor an attacker with a database read can compute.
        secret_enc   text,
        status       text        not null default 'pending',
        last_used_at timestamptz,
        activated_at timestamptz,
        created_at   timestamptz not null default now(),
        constraint mfa_factors_kind_chk check (kind in ('totp', 'webauthn', 'recovery_code')),
        constraint mfa_factors_status_chk check (status in ('pending', 'active', 'revoked'))
      );

      create index if not exists mfa_factors_user_idx on mfa_factors (user_id, status);

      -- At most one active recovery-code set and one active TOTP factor per user. Regenerating
      -- codes revokes the old set in the same statement that writes the new one, so this index is
      -- what makes that atomic rather than merely intended.
      create unique index if not exists mfa_factors_one_active_per_kind
        on mfa_factors (user_id, kind)
        where status = 'active' and kind in ('totp', 'recovery_code');

      create table if not exists mfa_recovery_codes (
        factor_id uuid        not null references mfa_factors (id) on delete cascade,
        -- SHA-256 of the code. A recovery code is 20 random base32 characters — about 100 bits —
        -- so it is not guessable and does not need a slow hash. A password does; this does not.
        code_hash text        not null,
        used_at   timestamptz,
        primary key (factor_id, code_hash)
      );

      -- The step-up between "your password was right" and "you are signed in". Holding it is not
      -- holding a session: it mints nothing until a factor answers.
      create table if not exists mfa_challenges (
        challenge_hash text        not null primary key,
        user_id        uuid        not null references users (id) on delete cascade,
        expires_at     timestamptz not null,
        consumed_at    timestamptz,
        created_at     timestamptz not null default now()
      );

      create index if not exists mfa_challenges_user_idx on mfa_challenges (user_id);
    `,
  },
  {
    version: 7,
    name: 'organisations',
    // 04-domain-model section 1.5. Every user gets a `personal` organisation at registration, so
    // there is never a code path that handles "this subject has no organisation".
    //
    // The at-least-one-owner invariant is NOT expressible as a table constraint — it is a statement
    // about the resulting set after a change, and a row-level check cannot see the other rows at
    // the moment it runs. It is enforced in organisations.ts under a row lock on the organisation,
    // using contracts-auth's `wouldOrphanOrganisation` so that "demote the last owner" and "remove
    // the last owner" cannot be caught separately and one of them forgotten.
    up: `
      create table if not exists organisations (
        id         uuid        primary key,
        slug       text        not null,
        name       text        not null,
        kind       text        not null,
        status     text        not null default 'active',
        created_at timestamptz not null default now(),
        constraint organisations_slug_uniq unique (slug),
        constraint organisations_kind_chk check (kind in ('personal', 'team', 'project')),
        constraint organisations_status_chk check (status in ('active', 'suspended', 'closed'))
      );

      create table if not exists memberships (
        organisation_id uuid        not null references organisations (id) on delete cascade,
        user_id         uuid        not null references users (id) on delete cascade,
        role            text        not null,
        invited_by      uuid        references users (id) on delete set null,
        -- Null while the invitation is outstanding. An unaccepted owner is not yet an owner, which
        -- is why the orphan check counts accepted owners only.
        accepted_at     timestamptz,
        created_at      timestamptz not null default now(),
        primary key (organisation_id, user_id),
        constraint memberships_role_chk check (role in ('owner', 'admin', 'member', 'billing', 'read'))
      );

      create index if not exists memberships_user_idx on memberships (user_id);
    `,
  },
  {
    version: 8,
    name: 'recovery_and_handoff',
    // Three single-use, hashed-at-rest credentials, all three carried forward from Nimbus.
    up: `
      -- Per-account throttling. The route rate limit caps one IP; this is what an attacker rotating
      -- IPs still runs into. Rows exist for unknown emails too, so a lock-out response cannot be
      -- used to probe which accounts are real.
      create table if not exists login_attempts (
        email        text        primary key,
        failures     integer     not null default 0,
        locked_until timestamptz,
        updated_at   timestamptz not null default now()
      );

      create table if not exists password_reset_tokens (
        -- Only the hash. Not even an operator with database access can recover an issued link.
        token_hash text        primary key,
        user_id    uuid        not null references users (id) on delete cascade,
        -- Null for a user's own "I forgot" request; an operator's id when it was issued for them.
        issued_by  uuid        references users (id) on delete set null,
        expires_at timestamptz not null,
        used_at    timestamptz,
        created_at timestamptz not null default now()
      );

      create index if not exists password_reset_tokens_user_idx on password_reset_tokens (user_id);

      -- The SSO hand-off. The code carries no tokens — those are minted only when it is redeemed —
      -- so the value that travels through the browser is worthless after 60 seconds or one use.
      create table if not exists auth_exchange_codes (
        code_hash       text        primary key,
        user_id         uuid        not null references users (id) on delete cascade,
        -- Bound at mint and matched at redemption, so a code leaked from browser history is useless
        -- anywhere but the origin it was made for.
        redirect_origin text        not null,
        expires_at      timestamptz not null,
        redeemed        boolean     not null default false,
        created_at      timestamptz not null default now()
      );
    `,
  },
  {
    version: 9,
    name: 'service_tokens',
    // SD-05. Not a credential table — a service token is a signed RS256 JWT and is not stored — but
    // an issuance ledger, because "which service was granted what, by which operator, and when" is
    // the question the two shared bearer secrets could never answer. The token itself is
    // unrecoverable from here; only its `jti`, which is what an incident correlates on.
    up: `
      create table if not exists service_token_issues (
        jti          uuid        primary key,
        service      text        not null,
        scopes       text[]      not null,
        issued_by    uuid        references users (id) on delete set null,
        issued_at    timestamptz not null default now(),
        expires_at   timestamptz not null,
        correlation_id text
      );

      create index if not exists service_token_issues_service_idx
        on service_token_issues (service, issued_at desc);
    `,
  },
  {
    version: 10,
    name: 'email_normalisation',
    // **The live defect this service exists partly to fix.**
    //
    // Nimbus matches the address verbatim on register and login but `lower(email)` on
    // forgot-password, so an account created as `Sam@example.com` can be reset by someone who typed
    // it in lowercase and cannot be logged into by them. Nimbus's own comment says the real repair
    // is to normalise on write and migrate the rows, and that it was not done because it needs a
    // decision about two accounts differing only by case. This is that decision.
    //
    // Normalise first, then constrain. The order matters: creating the index first would fail on
    // exactly the rows the update is there to fix.
    //
    // **Two accounts differing only by case make this migration FAIL, deliberately.** The unique
    // index raises 23505 and the whole migration rolls back, which stops the deploy with a
    // diagnosable error. The alternative — merging them, or picking a winner — silently destroys
    // one person's account and its history, and there is no automated rule that can be right about
    // which one. A migration that stops is recoverable; a migration that guesses is not. The
    // operator resolves the collision by hand and runs it again.
    //
    // On a database this service created there is nothing to normalise: every write already goes
    // through contracts-auth's `normaliseEmail`. The update is here for the estate migration, and
    // it is idempotent.
    up: `
      update users set email = lower(btrim(email)) where email <> lower(btrim(email));

      create unique index if not exists users_email_lower_uniq on users (lower(email));
    `,
  },
  {
    version: 11,
    name: 'service_credentials',
    // **The missing half of SD-05, and the fix for the ten-minute cliff.**
    //
    // SD-05 gave every service a scoped ten-minute token and retired the two omnipotent shared
    // secrets. What it never gave them was a way to obtain the SECOND token. `POST /service-tokens`
    // requires the `admin` role, so the only issuer is a human operator; the estate's answer was to
    // mint twenty-one tokens at deploy time into environment variables and hand them to containers
    // that read them once at boot. Ten minutes later every service-to-service call on the money tier
    // fails, and no per-service suite can see it because each one mints a fresh token as it starts.
    //
    // A credential row is what a service holds AT REST so that it can mint for itself, for ever,
    // without an operator and without a token that outlives its purpose. **This is emphatically not
    // the return of `PAY_SERVICE_TOKEN`.** That was one bearer string, shared by three containers,
    // granting read/debit/credit/liquidate over every user's money, with no identity, no scope, no
    // expiry and no audit trail. A row here has all four: it names exactly one service, it can mint
    // only within that service's `IDENTITY_SERVICE_TOKEN_GRANTS` allowlist, every token it mints
    // still dies in ten minutes, and every exchange leaves a `service_token_issues` row pointing
    // back at it. Holding one authorises nothing at the money tier directly — it buys a scoped,
    // short-lived token and nothing else.
    //
    // **And unlike a JWT it is revocable.** `revoked_at` takes a compromised service offline within
    // one token lifetime. That is a containment lever the estate does not have today: a leaked
    // service token cannot be recalled at all, only waited out.
    //
    // SHA-256 AND NOT SCRYPT, which is the opposite of `users.password_hash` and deliberately so.
    // The secret is 32 bytes from `randomBytes` — there is no dictionary to attack and no human
    // memory to be weak — so the slow salted hash buys nothing, while an unsalted digest is what
    // makes the row FINDABLE by the secret the caller presents. `refresh_tokens.token_hash` is the
    // same decision for the same reason, and this follows it rather than inventing a second shape.
    up: `
      create table if not exists service_credentials (
        id           uuid        primary key,
        service      text        not null,
        secret_hash  text        not null unique,
        label        text        not null,
        created_by   uuid        references users (id) on delete set null,
        created_at   timestamptz not null default now(),
        last_used_at timestamptz,
        revoked_at   timestamptz
      );

      -- Partial: the lookup that matters is "the live credentials for this service", and a revoked
      -- row is never a candidate for one.
      create index if not exists service_credentials_live_idx
        on service_credentials (service) where revoked_at is null;

      -- Which credential minted this token. Null for the admin path, which keeps issued_by.
      -- "Which service was granted what, by whom, and when" is the question SD-05 exists to answer,
      -- and once a machine can mint, "by whom" has a second possible shape that must be recorded or
      -- the ledger quietly stops being able to answer it.
      alter table service_token_issues
        add column if not exists issued_by_credential uuid
          references service_credentials (id) on delete set null;
    `,
  },
  {
    version: 12,
    name: 'platform_role_grants',
    // **THE FIRST ADMINISTRATOR, AND EVERY ONE AFTER.**
    //
    // A fresh environment has no operator, and the estate's only way to make one is
    // `deploy/scripts/estate-bootstrap.sh` running, by hand, against this database:
    //
    //     update users set roles = array['admin'] where email = '<the operator>';
    //
    // WHERE that runs is right and stays right. `admin-api/src/actions.ts` argues it at length: a
    // service that can mint its own first administrator is a service whose compromise grants the
    // estate, and admin-api's own four-eyes queue cannot authorise the first grant because
    // approving one needs an operator who already holds the role. So admin-api answers 501 to
    // `identity.role.grant` rather than growing an unauthenticated route that mints an operator,
    // and `admin-api/src/bootstrap.test.ts` pins that it cannot silently become one.
    //
    // WHAT that statement IS was wrong, in three ways that have nothing to do with where it runs:
    //
    //   - **Repeatable.** Nothing made the second run differ from the first, so it was not a
    //     bootstrap but a permanent superuser lever available for ever to anyone who reaches the
    //     database. "We only run it once" is a convention, not a control.
    //   - **Unaudited.** Migration 3 gives `users.roles` a default and nothing else, so the most
    //     consequential write in the estate was the only one with no trail: no actor, no reason,
    //     no time, no authorising decision.
    //   - **Unproven.** Nothing went red if identity, or admin-api, grew a route that did the same.
    //
    // ## Why this is in the schema and not in a handler
    //
    // The threat model explicitly includes someone holding a psql connection — that is the whole
    // reason the bootstrap is a database step in the first place. A privilege-escalation guard that
    // lives in a request handler is worth very little against that, because the handler is the
    // layer the attacker is assumed to be past. `micro-worlds` landed its comparable control as a
    // BEFORE UPDATE trigger because a CHECK cannot see the old row; admin-api's treasury caps use a
    // constraint trigger because a CHECK cannot reference another table. Both apply here, so both
    // shapes are used.
    //
    // ## The three controls, and exactly what each refuses
    //
    //   1. `platform_role_grants_one_bootstrap` — a partial unique index on `source = 'bootstrap'`.
    //      **One bootstrap grant per database, for ever.** The second insert raises 23505, in any
    //      transaction, from any client, including a psql prompt. Capping ADMINISTRATORS at one
    //      would be wrong: four-eyes approval needs two operators, and an estate that can only ever
    //      have one has no second pair of eyes. Capping UNAPPROVED administrators at one is the
    //      invariant that was actually wanted, and it is what this index expresses.
    //
    //   2. `users_roles_need_a_grant` — a DEFERRED constraint trigger on `users`. A row that GAINS
    //      a privileged role is refused at COMMIT unless a `platform_role_grants` row for that user
    //      and that role was written **in the same transaction**. So the bare update above now
    //      fails, and the only way to succeed is to write the audit record with the promotion.
    //
    //      Same-transaction rather than merely "some grant row exists", and the difference is a
    //      real hole rather than pedantry: with the weaker rule, an administrator who is demoted
    //      can be re-promoted for ever afterwards on the strength of the row that authorised the
    //      first promotion — one approval, unlimited grants. `granted_at` defaults to
    //      `transaction_timestamp()` and the trigger compares against `transaction_timestamp()`,
    //      which is one value for the whole transaction and a different one in the next.
    //
    //      Deferred so the grant and the promotion may be written in either order. It fires only
    //      on roles the row did not already hold, so REMOVING a role never needs a grant — a
    //      control that could block a revocation would be a liability during an incident, not a
    //      safeguard.
    //
    //   3. `platform_role_grants_immutable` — the grant table is append-only. Without it the
    //      one-shot index is re-armable: `delete from platform_role_grants where source =
    //      'bootstrap'` and the whole property is gone. It also means a promotion cannot be
    //      un-recorded after the fact.
    //
    // **The honest limit.** The database owner can `alter table ... disable trigger` or drop an
    // index; nothing in a schema survives its own superuser. What this buys is that every one of
    // those is a deliberate, loud, separate act that leaves DDL behind, rather than an UPDATE that
    // looks like every other UPDATE. That is the same floor every constraint in this estate has.
    //
    // ## The bootstrap, in its correct shape
    //
    // The runbook step becomes ONE transaction — `micro-deploy` owns the script:
    //
    //     begin;
    //     insert into platform_role_grants (user_id, role, source, actor, reason)
    //     select id, 'admin', 'bootstrap', 'estate-bootstrap.sh',
    //            'first operator of this environment; no approval queue can exist before one'
    //       from users where email = lower(btrim('<the operator>'));
    //     update users set roles = array['player','admin']
    //      where email = lower(btrim('<the operator>'));
    //     commit;
    //
    // Run it twice and the second run fails at 23505 on the insert, before the update is even
    // attempted, and the transaction rolls back. That is the procedure's own assertion.
    //
    // ## What an already-bootstrapped environment does
    //
    // Nothing, deliberately. The trigger fires on roles a row GAINS, so existing administrators are
    // undisturbed and no backfill is attempted — a backfill would have to invent an actor and a
    // reason, and if such an environment had two administrators a backfill claiming both were
    // bootstrapped would fail this migration at the index. What changes for an existing environment
    // is only that no NEW administrator can appear without a row.
    up: `
      create table if not exists platform_role_grants (
        id          uuid        primary key default gen_random_uuid(),
        -- No ON DELETE action. A grant is the audit record of a promotion, and a cascade would let
        -- deleting the user erase the record of it. Nothing in this service deletes a user row —
        -- deletion.ts tombstones in place, precisely so rows keyed on a user id survive erasure.
        user_id     uuid        not null references users (id),
        role        text        not null,
        -- 'bootstrap' is the one grant that answers to nothing, because nothing exists yet to
        -- answer to. 'approval' is every one after it, and carries two operators' signatures out of
        -- admin-api's queue in the form of the approval id.
        source      text        not null,
        approval_id uuid,
        actor       text        not null,
        reason      text        not null,
        granted_at  timestamptz not null default transaction_timestamp(),
        constraint platform_role_grants_source_known
          check (source in ('bootstrap', 'approval')),
        -- An equality, not two implications: 'approval' without an id is an unauthorised grant
        -- wearing the authorised source, and 'bootstrap' WITH one is a claim that the first
        -- administrator was approved by a queue that could not have existed.
        constraint platform_role_grants_approval_pairing
          check ((source = 'approval') = (approval_id is not null)),
        -- The privileged set, and it is the same list the trigger below carries. 'player' is not
        -- here: it is the default every account gets at registration, and requiring a grant row for
        -- it would mean a grant per user and a bootstrap collision on the second registration.
        constraint platform_role_grants_role_known check (role in ('admin')),
        constraint platform_role_grants_actor_present check (btrim(actor) <> ''),
        constraint platform_role_grants_reason_present check (btrim(reason) <> '')
      );

      -- ONE bootstrap grant per database, for ever. The second insert raises 23505 from any client.
      create unique index if not exists platform_role_grants_one_bootstrap
        on platform_role_grants (source) where source = 'bootstrap';

      create index if not exists platform_role_grants_user_idx
        on platform_role_grants (user_id, granted_at desc);

      -- Append-only. Without this the one-shot index above is re-armable by a DELETE.
      create or replace function platform_role_grants_append_only() returns trigger
      language plpgsql as $fn$
      begin
        raise exception
          using errcode = 'check_violation',
                message = 'platform_role_grants is append-only: ' || tg_op || ' is refused',
                hint = 'withdraw a role by removing it from users.roles; the grant row is the record that it was ever held';
      end;
      $fn$;

      drop trigger if exists platform_role_grants_immutable on platform_role_grants;
      create trigger platform_role_grants_immutable
        before update or delete on platform_role_grants
        for each row execute function platform_role_grants_append_only();

      -- No privileged role without a grant row written in the SAME transaction.
      create or replace function users_roles_need_a_grant() returns trigger
      language plpgsql as $fn$
      declare
        privileged constant text[] := array['admin'];
        gained      text[];
        gained_role text;
      begin
        -- Roles the row did not already hold. Losing a role is always permitted: a guard that could
        -- block a revocation is a liability in an incident rather than a safeguard.
        select array(
          select r
            from unnest(coalesce(new.roles, '{}'::text[])) as t(r)
           where r = any (privileged)
             and (tg_op = 'INSERT' or not (r = any (coalesce(old.roles, '{}'::text[]))))
        ) into gained;

        foreach gained_role in array gained loop
          if not exists (
            select 1
              from platform_role_grants g
             where g.user_id = new.id
               and g.role = gained_role
               -- transaction_timestamp() is constant for the life of a transaction and is what
               -- granted_at defaults to, so this is exactly "written by whoever is promoting".
               -- A grant from an earlier transaction authorises nothing, which is what stops one
               -- approval from being spent twice.
               and g.granted_at = transaction_timestamp()
          ) then
            raise exception
              using errcode = 'check_violation',
                    message = 'user ' || new.id || ' gained the platform role ' || gained_role ||
                              ' with no platform_role_grants row written in the same transaction',
                    hint = 'insert the grant row and update users.roles in ONE transaction: source ''bootstrap'' once per database, or ''approval'' carrying an approval id';
          end if;
        end loop;
        return null;
      end;
      $fn$;

      drop trigger if exists users_roles_need_a_grant on users;
      -- DEFERRABLE INITIALLY DEFERRED: the grant and the promotion may be written in either order,
      -- and a bare 'update users set roles = ...' therefore fails at COMMIT rather than at the
      -- statement — which is the same answer, from the layer that an attacker with a connection
      -- cannot step around.
      create constraint trigger users_roles_need_a_grant
        after insert or update of roles on users
        deferrable initially deferred
        for each row execute function users_roles_need_a_grant();
    `,
  },
  {
    version: 13,
    name: 'email_verification',
    // The column `users.email_verified_at` has existed since migration 3 and NOTHING EVER WROTE IT.
    // `toPublicUser` surfaced it as `emailVerifiedAt` (users.ts:56), every account read `null`, and
    // `signInRefusal` (users.ts:222) never looked at it — so registration minted a session on the
    // spot and an address nobody had proved control of signed in for ever. Verified against the live
    // estate before this migration was written: a registration against
    // https://nimbus.cloudsforge.online/auth/register was followed by a 200 from `POST /auth/login`
    // carrying `emailVerifiedAt: null`.
    //
    // ## The token table
    //
    // The same shape as `password_reset_tokens` (migration 8) and for the same three reasons: only
    // the hash is stored, so not even an operator with database access can recover an issued link;
    // the primary key is that hash, so redemption is one indexed equality against a value that says
    // nothing about how much of a guess was right; and single use is a conditional UPDATE rather
    // than a read followed by a write.
    //
    // It differs in one deliberate way — `email_verification_tokens_one_live`. See below.
    //
    // ## The backfill, and why it is not a softening of the policy
    //
    // Every row that exists when this runs was created by a service that had no verification at all,
    // so no live address on the platform has ever been offered a link and none can be retro-actively
    // proved. Constraining them instead of backfilling would sign out every existing account
    // including the bootstrap administrator (migration 12), and would do it in an estate where the
    // consumer of `identity.email.verification_requested` is not deployed yet — so the accounts
    // locked out would have no way whatsoever to get back in. `created_at`, not `now()`: the claim
    // being recorded is "this account predates verification", and stamping it with the migration's
    // own clock would assert that every historical user proved their address the day of the deploy.
    //
    // Normalise, THEN constrain — the same order migration 10 uses for `lower(email)`, for the same
    // reason. The refusal in `signInRefusal` is the constraint here and it is in code rather than in
    // DDL, so the ordering is between this migration and the deploy of the code that reads it; a
    // rolling deploy therefore backfills before any replica refuses anyone.
    up: `
      create table if not exists email_verification_tokens (
        -- Only the hash, exactly as password_reset_tokens does it.
        token_hash  text        primary key,
        user_id     uuid        not null references users (id) on delete cascade,
        expires_at  timestamptz not null,
        -- Stamped by the redemption UPDATE, and by a supersession. Null means live.
        consumed_at timestamptz,
        created_at  timestamptz not null default now()
      );

      -- ONE LIVE TOKEN PER ACCOUNT, AND IT IS AN INDEX RATHER THAN A CHECK IN CODE.
      --
      -- "Two live verification tokens for one account" is the state a resend race produces, and the
      -- older of the two is the one most likely to have leaked into a mail client, a chat log or a
      -- scanner's cache. emailVerification.ts supersedes under an advisory lock so the race cannot
      -- happen — and this index means that even if a future edit drops the lock, the
      -- second insert raises 23505 instead of quietly creating the state. The wrong state has no
      -- representation rather than being merely checked for.
      --
      -- PARTIAL, and that is not a detail: a plain unique index on user_id would make an account
      -- verifiable exactly once for the lifetime of the database, so every resend, every
      -- supersession and every re-verification after an address change would fail at 23505.
      create unique index if not exists email_verification_tokens_one_live
        on email_verification_tokens (user_id) where consumed_at is null;

      -- Consumed rows are outside the partial index above, and erasure (deletion.ts) deletes by
      -- user_id across all of them.
      create index if not exists email_verification_tokens_user_idx
        on email_verification_tokens (user_id);

      update users
         set email_verified_at = created_at
       where email_verified_at is null and status <> 'deleted';
    `,
  },
  {
    version: 14,
    name: 'service_credentials_network',
    // **Which estate a credential mints for — the combined view's first live defect.**
    //
    // Under micro-org#459 this identity mints for BOTH estates: the 19 testnet services exchange
    // their credentials here. Migration 11 predates that world, so the only network anywhere in the
    // mint path was `IDENTITY_NETWORK` — this deployment's own — and every token said `net=mainnet`
    // regardless of who exchanged. Observed live within hours of the flip, both ways at once:
    // testnet custody refusing testnet settlement ("token minted for network mainnet, this
    // deployment is testnet", a remint loop every ~2 minutes), while the same token would have
    // VERIFIED at the mainnet ledger — the crossing the `net` claim was built to refuse.
    //
    // The row is the right home because the row already answers the analogous question for the
    // service name: `exchangeServiceCredential` reads `service` from the row, never the request,
    // so a caller cannot name its own service — and it must not be able to name its own estate
    // either, or the claim is advisory. Same column shape as the claim: free text naming an estate,
    // because estates are names here ('mainnet', 'testnet'), not an enum the schema should freeze.
    //
    // NULL means "this identity's own network" (the fallback in tokens.ts), which is what every
    // credential minted before the combined view meant implicitly — so existing mainnet rows need
    // no backfill and behave exactly as before. The 19 testnet-labelled rows provisioned for the
    // flip are set right here rather than by a hand UPDATE on the host: the defect was live when
    // this migration was written, and a deploy that ships the code without the data would keep the
    // remint loop running until an operator remembered.
    up: `
      alter table service_credentials
        add column if not exists network text;

      -- The flip's provisioning (micro-org#459, 2026-08-14) labelled every testnet-estate
      -- credential 'testnet' precisely so they would be findable as a set. This is that promise
      -- being kept. Scoped to the label AND to rows still unset, so a future credential whose
      -- label happens to collide is not silently re-pointed.
      update service_credentials
         set network = 'testnet'
       where label = 'testnet' and network is null;
    `,
  },
]

/**
 * The version this build of the service requires. `index.ts` asserts it at boot and refuses to
 * serve below it, which is what stops a replica of the new code answering requests against the old
 * schema when a deploy runs ahead of its migrator.
 */
export const SCHEMA_VERSION: number = MIGRATIONS.reduce((max, m) => Math.max(max, m.version), 0)

/**
 * How an existing hand-built schema is adopted.
 *
 * Zero for a new service, which makes this a no-op. Identity is built fresh rather than migrated in
 * place — Nimbus's database keeps serving Nimbus until the cutover — so it stays zero.
 */
export const BASELINE_VERSION = 0
