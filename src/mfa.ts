/**
 * Multi-factor authentication — SD-02 and 04-domain-model section 1.3.
 *
 * **There is no MFA anywhere in the estate today.** No TOTP, no WebAuthn, no recovery codes, on a
 * platform that custodies private keys for five chains — and, per SD-08 and SD-11, no MFA on the
 * administrator accounts that can reach the custody surface either.
 *
 * What is here:
 *
 *   * **TOTP**, RFC 6238, implemented on `node:crypto` in totp.ts with no dependency, seed sealed
 *     in the same AES-256-GCM envelope as the signing key.
 *   * **Recovery codes**, single-use, shown once, regenerable. A set is ONE factor row and the
 *     individual codes hang off it; the other modelling — a factor per code — would make "you are
 *     removing your last factor" fire when the ninth of ten codes is spent.
 *   * **WebAuthn**, defined in the schema and in the routes, answering **501**. That is a deliberate
 *     choice over three alternatives: leaving it out of the schema (which makes adding it a
 *     migration during a security release), leaving it out of the routes (which makes a client
 *     unable to feature-detect), or stubbing it as something that always succeeds (which would be a
 *     factor that is not a factor, and is the only genuinely dangerous option). A 501 with a clear
 *     message is the honest answer and it is testable.
 *
 * **SMS is absent and that is a decision, not an omission.** SIM-swap is the dominant attack against
 * crypto accounts, so SMS is a weaker factor than the password it is meant to strengthen.
 * `contracts-auth`'s `MfaKind` omits it, the check constraint omits it, and a kind that is in
 * neither is a kind no code path can accidentally accept.
 *
 * **Removing the last active factor requires re-authentication and emits a critical event.** The
 * classification comes from `contracts-auth`'s `classifyFactorRemoval`, which returns a union rather
 * than a boolean precisely so the branch that would silently drop a user to password-only does not
 * type-check unless it is written.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { classifyFactorRemoval, type MfaFactor, type MfaKind } from '@cloudsforge/contracts-auth'
import { env } from './env.ts'
import { uuidv7 } from './ids.ts'
import { open, seal } from './keyEnvelope.ts'
import { DEFAULT_PARAMS, base32Encode, otpauthUri, stepAt, verifyTotp } from './totp.ts'
import { withOutbox, type Db, type Tx } from './outbox.ts'

/**
 * The message the WebAuthn routes answer with.
 *
 * Exported so the routes and the test assert the same string. A 501 whose body says only "not
 * implemented" is a support ticket; one that names what is missing and what to use instead is not.
 */
export const WEBAUTHN_NOT_IMPLEMENTED =
  'WebAuthn is not implemented on this build. The schema and the routes exist so that clients can ' +
  'feature-detect and so that enabling it is not a migration during a security release. Enrol a ' +
  'TOTP factor instead; WebAuthn is the phishing-resistant factor and will be recommended first ' +
  'when it ships.'

/** How many recovery codes a set holds. */
const RECOVERY_CODE_COUNT = 10

/**
 * How long a login step-up challenge lives.
 *
 * Five minutes. It has to survive fetching a phone from another room, and it is a credential in its
 * own right for as long as it lives — holding one means the password is already known to whoever
 * holds it.
 */
const CHALLENGE_TTL_MS = 5 * 60_000

export class FactorNotFoundError extends Error {
  constructor() {
    super('no such factor')
    this.name = 'FactorNotFoundError'
  }
}

/** Removing this factor would leave the account with none, and re-authentication was not supplied. */
export class ReauthenticationRequiredError extends Error {
  constructor() {
    super('removing your last active factor requires re-authentication')
    this.name = 'ReauthenticationRequiredError'
  }
}

interface FactorRow {
  readonly id: string
  readonly user_id: string
  readonly kind: MfaKind
  readonly label: string
  readonly secret_enc: string | null
  readonly status: MfaFactor['status']
  readonly last_used_at: Date | null
  readonly created_at: Date
}

const toFactor = (row: FactorRow): MfaFactor => ({
  id: row.id,
  userId: row.user_id,
  kind: row.kind,
  label: row.label,
  status: row.status,
  lastUsedAt: row.last_used_at?.toISOString() ?? null,
  createdAt: row.created_at.toISOString(),
})

/** Every factor, without a secret. The select names its columns so a secret cannot leak by `*`. */
export async function listFactors(sql: Db | Tx, userId: string): Promise<MfaFactor[]> {
  const rows = await sql<FactorRow[]>`
    select id, user_id, kind, label, null as secret_enc, status, last_used_at, created_at
      from mfa_factors where user_id = ${userId} order by created_at
  `
  return rows.map(toFactor)
}

export async function hasActiveFactor(sql: Db, userId: string): Promise<boolean> {
  const rows = await sql<{ id: string }[]>`
    select id from mfa_factors where user_id = ${userId} and status = 'active' limit 1
  `
  return rows.length > 0
}

/* ------------------------------------------------------------------------ TOTP */

export interface TotpEnrolment {
  readonly factorId: string
  /** Base32, for a user typing it in by hand. This is the only moment it leaves the service. */
  readonly secret: string
  /** For a QR code. Carries the same secret. */
  readonly otpauthUri: string
}

/**
 * Begin a TOTP enrolment. The factor is `pending` and authenticates nothing until it is activated.
 *
 * **Pending, not active, and the two-step shape is the point.** Enrolling in one step would let a
 * user store a secret their authenticator never received — a mistyped or half-scanned code — and
 * discover it at the moment they are locked out. Requiring a working code to activate proves the
 * loop closes before anything depends on it.
 *
 * Twenty bytes of entropy, which is the RFC 4226 recommended seed length and what every
 * authenticator app expects.
 */
export async function enrolTotp(
  sql: Db,
  input: { userId: string; account: string; label: string },
): Promise<TotpEnrolment> {
  const factorId = uuidv7()
  const secret = randomBytes(20)

  // Any earlier pending TOTP enrolment is dropped rather than accumulated. A user who scans, fails,
  // and scans again should not leave a trail of half-enrolments, and the partial unique index only
  // constrains ACTIVE rows so nothing else would remove them.
  await sql`
    delete from mfa_factors where user_id = ${input.userId} and kind = 'totp' and status = 'pending'
  `
  await sql`
    insert into mfa_factors (id, user_id, kind, label, secret_enc, status)
    values (
      ${factorId},
      ${input.userId},
      'totp',
      ${input.label},
      ${seal('totp-seed', factorId, secret.toString('base64'))},
      'pending'
    )
  `
  return {
    factorId,
    secret: base32Encode(secret),
    otpauthUri: otpauthUri({ issuer: env.issuer, account: input.account, secret }),
  }
}

function secretOf(row: FactorRow): Buffer {
  return Buffer.from(open<string>('totp-seed', row.id, row.secret_enc!), 'base64')
}

export type TotpActivation =
  | { readonly ok: true; readonly factor: MfaFactor }
  | { readonly ok: false; readonly reason: 'not_found' | 'bad_code' }

/**
 * Activate a pending TOTP factor by proving a code from it.
 *
 * `last_used_at` is stamped with the matched step's own time rather than with `now()`. The
 * difference matters: the replay guard compares steps, and a code accepted inside the backwards
 * window would otherwise record a step LATER than the one it used, silently rejecting the next
 * legitimate code.
 */
export async function activateTotp(
  sql: Db,
  input: { userId: string; factorId: string; code: string; correlationId: string },
): Promise<TotpActivation> {
  const rows = await sql<FactorRow[]>`
    select id, user_id, kind, label, secret_enc, status, last_used_at, created_at
      from mfa_factors
     where id = ${input.factorId} and user_id = ${input.userId} and kind = 'totp' and status = 'pending'
  `
  const row = rows[0]
  if (!row || !row.secret_enc) return { ok: false, reason: 'not_found' }

  const verification = verifyTotp(secretOf(row), input.code, Math.floor(Date.now() / 1000))
  if (!verification.ok) return { ok: false, reason: 'bad_code' }

  const usedAt = new Date(verification.step * DEFAULT_PARAMS.stepSeconds * 1000)
  const factor = await withOutbox(sql, 'identity', async (tx, emit) => {
    // Any previously active TOTP factor is revoked in the same statement that promotes this one:
    // the partial unique index permits exactly one, and doing it in two statements would fail the
    // second half of a re-enrolment with a constraint violation the user cannot act on.
    await tx`
      update mfa_factors set status = 'revoked'
       where user_id = ${input.userId} and kind = 'totp' and status = 'active'
    `
    const updated = await tx<FactorRow[]>`
      update mfa_factors
         set status = 'active', activated_at = now(), last_used_at = ${usedAt}
       where id = ${input.factorId}
      returning id, user_id, kind, label, null as secret_enc, status, last_used_at, created_at
    `
    emitMfaChanged(emit, {
      userId: input.userId,
      change: 'enrolled',
      kind: 'totp',
      factorId: input.factorId,
      critical: false,
      correlationId: input.correlationId,
    })
    return toFactor(updated[0]!)
  })
  return { ok: true, factor }
}

/* ------------------------------------------------------------------------ recovery codes */

export interface RecoveryCodes {
  readonly factorId: string
  /** Shown once. Only their SHA-256 is stored, so this is the only time they exist. */
  readonly codes: readonly string[]
}

/**
 * A code: twenty base32 characters, grouped for transcription.
 *
 * About a hundred bits, which is why `mfa_recovery_codes` stores a plain SHA-256 rather than a slow
 * hash. A password needs scrypt because it is guessable; this is not, and putting it behind a slow
 * hash would only make the recovery path slow for the person already having the worst day.
 */
function recoveryCode(): string {
  const raw = base32Encode(randomBytes(13)).slice(0, 20)
  return `${raw.slice(0, 5)}-${raw.slice(5, 10)}-${raw.slice(10, 15)}-${raw.slice(15, 20)}`
}

const hashRecoveryCode = (code: string): string =>
  createHash('sha256').update(code.replace(/[\s-]/g, '').toUpperCase()).digest('hex')

/**
 * Generate a fresh set, replacing any existing one.
 *
 * **Regenerating revokes the old set in the same transaction.** Leaving both live would mean a set
 * printed a year ago and lost in a drawer still opens the account, which is the opposite of what
 * the user believed they were doing by regenerating.
 */
export async function generateRecoveryCodes(
  sql: Db,
  input: { userId: string; correlationId: string },
): Promise<RecoveryCodes> {
  const factorId = uuidv7()
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, recoveryCode)

  await withOutbox(sql, 'identity', async (tx, emit) => {
    await tx`
      update mfa_factors set status = 'revoked'
       where user_id = ${input.userId} and kind = 'recovery_code' and status = 'active'
    `
    await tx`
      insert into mfa_factors (id, user_id, kind, label, status, activated_at)
      values (${factorId}, ${input.userId}, 'recovery_code', 'Recovery codes', 'active', now())
    `
    for (const code of codes) {
      await tx`
        insert into mfa_recovery_codes (factor_id, code_hash) values (${factorId}, ${hashRecoveryCode(code)})
      `
    }
    emitMfaChanged(emit, {
      userId: input.userId,
      change: 'recovery_codes_regenerated',
      kind: 'recovery_code',
      factorId,
      // SD-04 tier 2: the USE of a recovery code emits a critical notification, and so does minting
      // a new set — an attacker who has the password and regenerates the codes has just locked the
      // real owner out of their own recovery path, and this is the only signal of it.
      critical: true,
      correlationId: input.correlationId,
    })
  })
  return { factorId, codes }
}

/** How many of the current set are still unspent. Shown so a user knows when to regenerate. */
export async function remainingRecoveryCodes(sql: Db, userId: string): Promise<number> {
  const rows = await sql<{ n: number }[]>`
    select count(*)::int as n
      from mfa_recovery_codes c
      join mfa_factors f on f.id = c.factor_id
     where f.user_id = ${userId} and f.kind = 'recovery_code' and f.status = 'active'
       and c.used_at is null
  `
  return rows[0]?.n ?? 0
}

/* ------------------------------------------------------------------------ authentication */

export type MfaOutcome =
  | { readonly ok: true; readonly method: 'totp' | 'recovery_code'; readonly factorId: string }
  | { readonly ok: false; readonly reason: 'no_factor' | 'bad_code' | 'replayed' }

/**
 * Answer a challenge with a TOTP code or a recovery code.
 *
 * TOTP is tried first because it is what almost every attempt is; a recovery code is only reached
 * when the digits did not match, which costs one indexed lookup on the unhappy path and keeps the
 * happy path to one.
 *
 * **A spent recovery code is spent by a conditional `UPDATE ... RETURNING`.** Select-then-update
 * would let two concurrent presentations of one code both succeed, which for a single-use
 * credential is the whole property gone.
 */
export async function authenticateMfa(
  sql: Db,
  input: { userId: string; code: string },
): Promise<MfaOutcome> {
  const rows = await sql<FactorRow[]>`
    select id, user_id, kind, label, secret_enc, status, last_used_at, created_at
      from mfa_factors where user_id = ${input.userId} and status = 'active'
  `
  if (rows.length === 0) return { ok: false, reason: 'no_factor' }

  const totpRow = rows.find((row) => row.kind === 'totp' && row.secret_enc)
  if (totpRow) {
    const lastStep = totpRow.last_used_at
      ? stepAt(Math.floor(totpRow.last_used_at.getTime() / 1000))
      : undefined
    const verification = verifyTotp(secretOf(totpRow), input.code, Math.floor(Date.now() / 1000), {
      ...(lastStep !== undefined ? { lastUsedStep: lastStep } : {}),
    })
    if (verification.ok) {
      await sql`
        update mfa_factors
           set last_used_at = ${new Date(verification.step * DEFAULT_PARAMS.stepSeconds * 1000)}
         where id = ${totpRow.id}
      `
      return { ok: true, method: 'totp', factorId: totpRow.id }
    }
    // Reported distinctly so the route can log it. A code that WAS right for a step already spent
    // is not a typo — it is an observed code being presented a second time, which is the signal a
    // shoulder-surf or a real-time phishing relay produces.
    if (verification.reason === 'replayed') return { ok: false, reason: 'replayed' }
  }

  const recoveryRow = rows.find((row) => row.kind === 'recovery_code')
  if (recoveryRow) {
    const spent = await sql<{ code_hash: string }[]>`
      update mfa_recovery_codes set used_at = now()
       where factor_id = ${recoveryRow.id}
         and code_hash = ${hashRecoveryCode(input.code)}
         and used_at is null
      returning code_hash
    `
    if (spent.length > 0) return { ok: true, method: 'recovery_code', factorId: recoveryRow.id }
  }

  return { ok: false, reason: 'bad_code' }
}

/* ------------------------------------------------------------------------ the login challenge */

const hashChallenge = (challenge: string): string =>
  createHash('sha256').update(challenge).digest('hex')

/**
 * Mint the token that stands between "your password was right" and "you are signed in".
 *
 * It is stored hashed and it mints nothing on its own. Holding it proves the password is known,
 * which is why it expires in minutes rather than hours: it is a partial credential, and treating it
 * as a harmless bookkeeping id is how a step-up becomes a formality.
 */
export async function createMfaChallenge(sql: Db, userId: string): Promise<string> {
  await sql`delete from mfa_challenges where expires_at < now()`
  const challenge = randomBytes(32).toString('hex')
  await sql`
    insert into mfa_challenges (challenge_hash, user_id, expires_at)
    values (${hashChallenge(challenge)}, ${userId}, ${new Date(Date.now() + CHALLENGE_TTL_MS)})
  `
  return challenge
}

/** Spend a challenge exactly once, returning whose it was. Conditional update, for the usual reason. */
export async function consumeMfaChallenge(sql: Db, challenge: string): Promise<string | null> {
  const rows = await sql<{ user_id: string }[]>`
    update mfa_challenges set consumed_at = now()
     where challenge_hash = ${hashChallenge(challenge)} and consumed_at is null and expires_at > now()
    returning user_id
  `
  return rows[0]?.user_id ?? null
}

/* ------------------------------------------------------------------------ removal */

export interface RemoveFactorInput {
  readonly userId: string
  readonly factorId: string
  /**
   * Proof that the person removing the factor is at the keyboard.
   *
   * Required only for the last active factor, and supplied by the caller having verified the
   * password. A boolean rather than the password itself: this module has no business handling
   * plaintext credentials, and the verification belongs next to the hash parameters in users.ts.
   */
  readonly reauthenticated: boolean
  readonly correlationId: string
}

export interface FactorRemoved {
  readonly factorId: string
  readonly wasLastActive: boolean
  readonly remainingActive: number
}

/**
 * Revoke a factor, refusing the last one without re-authentication.
 *
 * The whole decision is `classifyFactorRemoval` from contracts-auth, called on the set rather than
 * on the row, and taken under a lock on the user: two concurrent removals each see two active
 * factors, each concludes one will remain, and the account ends with none. That is the same
 * read-then-write race the last-owner rule has, and it has the same answer.
 *
 * Revoked rather than deleted. A user asking "what happened to my account" deserves an answer, and
 * a factor row that is gone cannot give one.
 */
export async function removeFactor(sql: Db, input: RemoveFactorInput): Promise<FactorRemoved> {
  return withOutbox(sql, 'identity', async (tx, emit) => {
    await tx`select pg_advisory_xact_lock(hashtext(${input.userId})::bigint)`

    const factors = await listFactors(tx, input.userId)
    const classified = classifyFactorRemoval(factors, input.factorId)
    if (classified.kind === 'not_found') throw new FactorNotFoundError()
    // Already revoked is not an error: the second click of a double-click, or a retry of a request
    // whose response was lost, must not be a failure the user has to interpret.
    if (classified.kind === 'already_revoked') {
      return {
        factorId: input.factorId,
        wasLastActive: false,
        remainingActive: factors.filter((f) => f.status === 'active').length,
      }
    }

    const lastActive = classified.kind === 'last_active'
    // The union carries `requires: ['reauthentication', 'notification']`, and both obligations are
    // discharged here: this refusal, and the critical event below.
    if (lastActive && !input.reauthenticated) throw new ReauthenticationRequiredError()

    await tx`update mfa_factors set status = 'revoked' where id = ${input.factorId}`
    const target = factors.find((f) => f.id === input.factorId)!

    emitMfaChanged(emit, {
      userId: input.userId,
      change: lastActive ? 'last_factor_removed' : 'removed',
      kind: target.kind,
      factorId: input.factorId,
      // 10.3: a critical security notification ignores preferences and always sends. Dropping to
      // password-only is exactly the change a user must be told about even if they have muted
      // everything, because the person who did it may not be them.
      critical: lastActive,
      correlationId: input.correlationId,
    })

    return {
      factorId: input.factorId,
      wasLastActive: lastActive,
      remainingActive: classified.kind === 'ordinary' ? classified.remainingActive : 0,
    }
  })
}

function emitMfaChanged(
  emit: Parameters<Parameters<typeof withOutbox>[2]>[1],
  input: {
    userId: string
    change: 'enrolled' | 'removed' | 'last_factor_removed' | 'recovery_codes_regenerated'
    kind: MfaKind
    factorId: string
    critical: boolean
    correlationId: string
  },
): void {
  emit({
    topic: 'identity.mfa.changed',
    // Keyed on the user, not the factor: ordering is per (topic, key), and "enrolled then removed"
    // for one account must not be reorderable into "removed then enrolled" by a consumer.
    key: input.userId,
    payload: {
      userId: input.userId,
      change: input.change,
      kind: input.kind,
      factorId: input.factorId,
      critical: input.critical,
    },
    actor: `user:${input.userId}`,
    correlationId: input.correlationId,
  })
}

/**
 * Constant-time string compare, for the one comparison here that is not already timing-safe.
 *
 * Exported because the test asserts it, and present because the recovery-code path compares a hash
 * inside Postgres where the comparison is not ours to control — this is used where a code is
 * checked in process.
 */
export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}
