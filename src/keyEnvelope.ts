/**
 * The envelope secrets are stored in: AES-256-GCM under a scrypt-derived key.
 *
 * Carried forward from Nimbus's `keyEnvelope.ts` unchanged in shape, and widened by one purpose.
 *
 * WHY THERE IS ONE. Nimbus's `signing_keys.private_jwk` held the RS256 private key as readable
 * JSONB, in a database eight services share a role on. That key is the estate's universal forging
 * credential: every service verifies `iss` plus `aud: cloudsforge` and nothing else, so a
 * self-minted `{sub, roles:['admin']}` is accepted everywhere.
 *
 * WHAT IT ACTUALLY BUYS, stated as narrowly as it should be. An attacker who can run code in this
 * container has the environment, and the environment has this secret; an attacker with
 * write-capable SQL can insert their own admin user and needs no key at all. What encryption at
 * rest closes is the READ-ONLY vector: a stolen dump, a SELECT-only injection, a copied backup.
 * Those turn a database read into silent, unrevocable, offline-usable impersonation across every
 * product, and they are exactly the vectors an env-held secret defeats, because the secret is not
 * in the artefact.
 *
 * WHAT IS NEW HERE: the TOTP seed goes in the same envelope, under a different purpose. A second
 * factor whose shared secret sits in the clear is a second factor that a database read computes,
 * which would make MFA a control that defeats only the attacker who did not get that far.
 *
 * THE PURPOSE IS IN THE SALT, and that is what keeps the two uses apart. A blob is bound to
 * `identity:v<n>:<purpose>:<id>`, so a key derived to unwrap a TOTP seed cannot unwrap a signing key
 * even if the ciphertexts were swapped in the database — which a SQL injection with UPDATE could
 * otherwise do to make one user's factor decrypt as another's.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE DEFECT THIS FILE NOW FIXES (#188): THE VERSION SELECTED A SALT, NOT A SECRET.**
 *
 * The previous revision of this file carried a `v<n>:` prefix, folded the version into the scrypt
 * salt, and said in its own words that derived keys "do not survive a rotation of the secret
 * itself" — by design. That is precisely the defect custody's `crypto.ts` records as SDR-03: a
 * version marker that selects a SALT while every version derives from the SAME env secret is not a
 * rotation mechanism. Changing `IDENTITY_KEY_SECRET` made every blob undecryptable, in every
 * version, at once — a GCM authentication failure, not a soft error. Concretely that is:
 *
 *   - every `signing_keys.private_jwk_enc`, so identity can sign nothing until it bootstraps a
 *     fresh key, and every live session verifies only until the old `kid` leaves JWKS; and
 *   - every `mfa_factors.secret_enc`, and THAT one is not recoverable. A TOTP seed exists in that
 *     blob and in the user's authenticator app, nowhere else. Rotating the secret naively does not
 *     invalidate a factor, it destroys it.
 *
 * So the version now selects a SECRET, from a keyring, exactly as custody's does:
 *
 *   `IDENTITY_KEY_SECRET_V1`, `IDENTITY_KEY_SECRET_V2`, … with `IDENTITY_KEY_VERSION` naming the
 *   one that SEALS. Every version any stored blob might carry is held at once, and `open` picks
 *   the secret by the stamp the blob itself carries.
 *
 * ROTATION, END TO END — and the third step is the one that is always skipped:
 *
 *   1. Add `IDENTITY_KEY_SECRET_V<n+1>`. Leave V<n> in place. Nothing changes yet.
 *   2. Set `IDENTITY_KEY_VERSION=<n+1>` and restart. New blobs seal under it immediately; every
 *      existing blob still opens under V<n>, because the blob names its own version.
 *   3. **DRAIN.** Run `pnpm rewrap` until `remainingCount` is zero. Without this step the old
 *      secret is load-bearing for ever and has been supplemented, not rotated — and removing it
 *      later orphans every blob that never got rewritten. That has already happened once in this
 *      estate and left 509 blobs readable only because an old secret survived in git history.
 *   4. Only when nothing remains below <n+1>, remove `IDENTITY_KEY_SECRET_V<n>`.
 *
 * The salt string is UNCHANGED — `identity:v<n>:<purpose>:<id>` — so a v1 blob written before this
 * file existed opens byte-identically under `IDENTITY_KEY_SECRET_V1` holding the value that
 * `IDENTITY_KEY_SECRET` used to hold. That is what makes this a deploy rather than a data
 * migration, and `loadEnv` accepts the unsuffixed name as v1 for exactly that reason.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'
import { env } from './env.ts'

/** `v<n>:<base64>`. ':' is not in the base64 alphabet, so this cannot be ambiguous. */
const VERSIONED = /^v([0-9]{1,3}):([A-Za-z0-9+/]+={0,2})$/

const IV_BYTES = 12
const TAG_BYTES = 16
const KEY_BYTES = 32

/**
 * What a blob is for. Part of the salt, so a derived key never unwraps the wrong kind of secret.
 *
 * A union rather than a string: adding a third kind of wrapped secret should be a deliberate edit
 * here, where this comment is, rather than a new literal at a call site.
 */
export type EnvelopePurpose = 'signing-key' | 'totp-seed'

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvelopeError'
  }
}

/**
 * The version stamped on a stored blob, without decrypting it.
 *
 * This is what the rewrap pass selects on, and it is why an interrupted rewrap is resumable: the
 * blob's own stamp is authoritative, so a row can always be re-examined without consulting
 * anything that might disagree with it.
 */
export function versionOf(blob: string): number {
  const match = VERSIONED.exec(blob.trim())
  if (!match) throw new EnvelopeError('blob carries no envelope version')
  return Number(match[1])
}

/**
 * The key-encryption keys this process holds, by version.
 *
 * A class rather than a module-level `env` read, for one reason that is not tidiness: a rotation
 * test has to hold two keyrings at once — the old one that wrote the blob and the new one that must
 * still read it — and a module-level secret cannot be two values in one process. Every negative
 * control in `unit.test.ts` depends on being able to build a keyring that is deliberately wrong.
 */
export class Keyring {
  readonly #secrets: ReadonlyMap<number, string>
  readonly #writeVersion: number

  constructor(secrets: ReadonlyMap<number, string>, writeVersion: number) {
    if (secrets.size === 0) throw new EnvelopeError('a keyring needs at least one secret')
    if (!secrets.has(writeVersion)) {
      throw new EnvelopeError(`no key secret for the write version v${writeVersion}`)
    }
    this.#secrets = new Map(secrets)
    this.#writeVersion = writeVersion
  }

  /** The version new blobs are sealed under. */
  get writeVersion(): number {
    return this.#writeVersion
  }

  /** Every version this process can OPEN, ascending. Counts and numbers only — never the values. */
  get versions(): readonly number[] {
    return [...this.#secrets.keys()].sort((a, b) => a - b)
  }

  /**
   * Per-secret data key: scrypt(secret_v<n>, `identity:v<n>:<purpose>:<id>`) -> 32 bytes.
   *
   * Cost is scrypt's default (N=16384, r=8, p=1). That is low for a password and appropriate here
   * for a different reason: the input is a 32-character high-entropy env secret, not something a
   * human chose, so the derivation is not defending against a guessing attack on its input. What it
   * is doing is domain separation and key stretching to 32 bytes, and raising the cost would only
   * make every signature and every TOTP check slower.
   *
   * The parameters are FROZEN for every released version. Editing them does not re-encrypt
   * anything; it makes every blob at that version undecryptable, which is the exact failure this
   * file exists to remove. A cost change is a new version number and a drain, like any other.
   */
  #deriveKey(version: number, purpose: EnvelopePurpose, id: string): Buffer {
    const secret = this.#secrets.get(version)
    if (secret === undefined) {
      // Names the version and never the secret. An operator reading this in a deployment log is
      // being told they removed a key secret before the drain finished — step 4 before step 3.
      throw new EnvelopeError(
        `no key secret for envelope version v${version}; this process holds v${this.versions.join(', v')}`,
      )
    }
    return scryptSync(secret, `identity:v${version}:${purpose}:${id}`, KEY_BYTES)
  }

  /** AES-256-GCM a JSON-serialisable secret under the write version. */
  seal(purpose: EnvelopePurpose, id: string, value: unknown): string {
    return this.sealAs(this.#writeVersion, purpose, id, value)
  }

  /**
   * Seal under a NAMED version. The rewrap pass is the only caller that needs this — everything
   * else goes through `seal`, so that "what do we write today" has exactly one answer.
   */
  sealAs(version: number, purpose: EnvelopePurpose, id: string, value: unknown): string {
    const key = this.#deriveKey(version, purpose, id)
    const iv = randomBytes(IV_BYTES)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const ct = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return `v${version}:${Buffer.concat([iv, tag, ct]).toString('base64')}`
  }

  open<T>(purpose: EnvelopePurpose, id: string, blob: string): T {
    const match = VERSIONED.exec(blob.trim())
    if (!match) {
      // Not a shape this ever wrote. Say that, rather than letting it fail as a GCM authentication
      // error — which reads like the wrong secret and sends an operator rotating something that was
      // never the problem.
      throw new EnvelopeError(`${purpose} ${id} is not in a recognised envelope format`)
    }
    const version = Number(match[1])
    const buf = Buffer.from(match[2]!, 'base64')
    const iv = buf.subarray(0, IV_BYTES)
    const tag = buf.subarray(IV_BYTES, IV_BYTES + TAG_BYTES)
    const ct = buf.subarray(IV_BYTES + TAG_BYTES)
    const decipher = createDecipheriv('aes-256-gcm', this.#deriveKey(version, purpose, id), iv)
    decipher.setAuthTag(tag)
    return JSON.parse(Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8')) as T
  }
}

/**
 * The keyring built from the environment.
 *
 * Lazy, so that importing this module does not require a valid environment — the unit tests build
 * their own keyrings and must not be forced to fabricate one in `process.env` to do it.
 */
let processKeyring: Keyring | null = null

export function keyring(): Keyring {
  processKeyring ??= new Keyring(env.keySecrets, env.keyVersion)
  return processKeyring
}

/**
 * Test seam. Installs the keyring the module-level `seal`/`open` use, or `null` to fall back to the
 * environment.
 *
 * It exists so that a rotation test can drive the REAL authentication path — `authenticateMfa`
 * reaching `open` through `secretOf` — across a rotation, rather than asserting against a
 * hand-rolled copy of the envelope. `env.ts` validates once at import and a test cannot take a
 * variable back afterwards, so without this seam the only provable rotation would be one that
 * bypasses the code under test, which is exactly the shape of blindness this tracker is full of.
 */
export function installKeyring(ring: Keyring | null): void {
  processKeyring = ring
}

/** AES-256-GCM a JSON-serialisable secret. Returns `v<n>:base64(iv||tag||ct)`. */
export function seal(purpose: EnvelopePurpose, id: string, value: unknown): string {
  return keyring().seal(purpose, id, value)
}

export function open<T>(purpose: EnvelopePurpose, id: string, blob: string): T {
  return keyring().open<T>(purpose, id, blob)
}
