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
 * `identity:v1:<purpose>:<id>`, so a key derived to unwrap a TOTP seed cannot unwrap a signing key
 * even if the ciphertexts were swapped in the database — which a SQL injection with UPDATE could
 * otherwise do to make one user's factor decrypt as another's.
 *
 * WHY THE SAME SHAPE AS THE ESTATE'S CUSTODY VAULT (scrypt from an env secret, AES-256-GCM,
 * `v<n>:` + base64(iv||tag||ct)): two envelope formats in one estate is one format nobody can read
 * in an incident. The version prefix is what makes the secret rotatable later — SD-06 records that
 * custody's master secret is unrotatable today precisely because it has no v2 branch, and this one
 * is written so that adding one is a new `deriveKey` case and not a migration of every blob.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'
import { env } from './env.ts'

const CURRENT_VERSION = 1

/** `v<n>:<base64>`. ':' is not in the base64 alphabet, so this cannot be ambiguous. */
const VERSIONED = /^v([0-9]{1,3}):([A-Za-z0-9+/]+={0,2})$/

/**
 * What a blob is for. Part of the salt, so a derived key never unwraps the wrong kind of secret.
 *
 * A union rather than a string: adding a third kind of wrapped secret should be a deliberate edit
 * here, where this comment is, rather than a new literal at a call site.
 */
export type EnvelopePurpose = 'signing-key' | 'totp-seed'

/**
 * Per-secret data key: scrypt(IDENTITY_KEY_SECRET, salt) -> 32 bytes.
 *
 * The version is in the salt as well as the prefix, so a derived key does not survive a rotation of
 * the secret itself.
 *
 * Cost is scrypt's default (N=16384, r=8, p=1). That is low for a password and appropriate here for
 * a different reason: the input is a 32-character high-entropy env secret, not something a human
 * chose, so the derivation is not defending against a guessing attack on its input. What it is
 * doing is domain separation and key stretching to 32 bytes, and raising the cost would only make
 * every signature and every TOTP check slower.
 */
function deriveKey(version: number, purpose: EnvelopePurpose, id: string): Buffer {
  return scryptSync(env.keySecret, `identity:v${version}:${purpose}:${id}`, 32)
}

/** AES-256-GCM a JSON-serialisable secret. Returns `v<n>:base64(iv||tag||ct)`. */
export function seal(purpose: EnvelopePurpose, id: string, value: unknown): string {
  const key = deriveKey(CURRENT_VERSION, purpose, id)
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `v${CURRENT_VERSION}:${Buffer.concat([iv, tag, ct]).toString('base64')}`
}

export function open<T>(purpose: EnvelopePurpose, id: string, blob: string): T {
  const match = VERSIONED.exec(blob.trim())
  if (!match) {
    // Not a shape this ever wrote. Say that, rather than letting it fail as a GCM authentication
    // error — which reads like the wrong secret and sends an operator rotating something that was
    // never the problem.
    throw new Error(`${purpose} ${id} is not in a recognised envelope format`)
  }
  const version = Number(match[1])
  if (version > CURRENT_VERSION) {
    throw new Error(
      `${purpose} ${id} is envelope version ${version}; this build reads up to v${CURRENT_VERSION}`,
    )
  }
  const buf = Buffer.from(match[2]!, 'base64')
  const iv = buf.subarray(0, 12)
  const tag = buf.subarray(12, 28)
  const ct = buf.subarray(28)
  const decipher = createDecipheriv('aes-256-gcm', deriveKey(version, purpose, id), iv)
  decipher.setAuthTag(tag)
  return JSON.parse(Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8')) as T
}
