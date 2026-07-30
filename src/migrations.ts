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
