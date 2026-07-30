/**
 * Password hashing: scrypt, with the work factor recorded so it can be raised.
 *
 * Carried forward from Nimbus's `passwords.ts` — scrypt, a 16-byte random salt, `salt:hash` hex, a
 * constant-time compare — with one addition that 04-domain-model section 1.1 asks for by name.
 *
 * **THE DEFECT BEING FIXED IS THAT NIMBUS CANNOT RAISE ITS WORK FACTOR.** It calls `scrypt` at the
 * library's defaults and stores two hex strings. Nothing in the row says what cost produced them,
 * so raising the cost has no safe rollout: the new code cannot tell an old hash from a new one, and
 * therefore cannot verify old hashes at old parameters, and therefore cannot rehash on next login.
 * The only migration available is a forced reset for every user on the platform. Recording the
 * parameters costs one column and makes the upgrade a normal operation — verify at whatever the row
 * says, and rehash at the current cost the moment the plaintext is in hand, which is the one moment
 * it ever is.
 *
 * `hash_algo` is not decorative. `verifyPassword` reads its parameters FROM IT rather than from a
 * constant, which is what makes the old rows verifiable after the constant moves. A column that
 * merely records what everything is assumed to be would be a comment with a table around it.
 */

import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from 'node:crypto'
import { promisify } from 'node:util'

/**
 * `promisify` picks the first overload, which is the one without options — so the cost parameters
 * would be silently dropped and every hash would be at library defaults, which is the exact defect
 * this file exists to fix. The signature is restated so the compiler enforces it.
 */
const scryptAsync = promisify(scrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
) => Promise<Buffer>

const SALT_LEN = 16

export interface ScryptParams {
  readonly N: number
  readonly r: number
  readonly p: number
  readonly keyLen: number
}

/**
 * What this build hashes at.
 *
 * N=16384 is Node's default and Nimbus's effective setting, kept so that a user whose row was
 * written by Nimbus and copied across verifies without a reset. Raising it is now a one-line change
 * here plus nothing else: every existing row keeps verifying under its own recorded parameters and
 * is silently rehashed the next time its owner signs in.
 *
 * `maxmem` has to be raised alongside N by hand — Node's default ceiling is 32 MiB and scrypt needs
 * roughly `128 * N * r`, which N=16384 sits just inside and N=32768 does not. Getting that wrong
 * presents as every login throwing, so it is derived rather than remembered.
 */
export const CURRENT_PARAMS: ScryptParams = { N: 16_384, r: 8, p: 1, keyLen: 64 }

/** `scrypt$N=16384,r=8,p=1,keyLen=64`. Self-describing, parseable, and stable to sort on. */
export function encodeAlgo(params: ScryptParams): string {
  return `scrypt$N=${params.N},r=${params.r},p=${params.p},keyLen=${params.keyLen}`
}

export const CURRENT_ALGO = encodeAlgo(CURRENT_PARAMS)

/**
 * Parse a recorded algorithm back into parameters.
 *
 * Returns null rather than throwing, and the caller treats null as "this credential cannot be
 * verified" — which is a failed sign-in, not a 500. A row carrying an algorithm this build does not
 * understand is a row written by a NEWER build during a rolling deploy, and the correct behaviour
 * for the older replica is to refuse the sign-in and let the user's retry land on a newer one. The
 * alternative, guessing at current parameters, would produce a wrong answer confidently.
 */
export function parseAlgo(algo: string): ScryptParams | null {
  const match = /^scrypt\$N=(\d+),r=(\d+),p=(\d+),keyLen=(\d+)$/.exec(algo.trim())
  if (!match) return null
  const params = {
    N: Number(match[1]),
    r: Number(match[2]),
    p: Number(match[3]),
    keyLen: Number(match[4]),
  }
  // Bounded so a tampered row cannot turn one sign-in into an out-of-memory kill of the process.
  // N is memory-hard by design, which makes it a denial-of-service primitive if it is attacker-set.
  if (params.N < 1_024 || params.N > 1_048_576) return null
  if (params.r < 1 || params.r > 64) return null
  if (params.p < 1 || params.p > 16) return null
  if (params.keyLen < 32 || params.keyLen > 128) return null
  return params
}

/** scrypt needs about `128 * N * r` bytes; Node's default ceiling is 32 MiB and is not enough above N=16384. */
function maxmemFor(params: ScryptParams): number {
  return Math.max(32 * 1024 * 1024, 256 * params.N * params.r)
}

export interface StoredPassword {
  /** `<salt hex>:<derived hex>`. The same shape Nimbus writes, so its rows are readable here. */
  readonly hash: string
  /** Goes in `users.hash_algo`. */
  readonly algo: string
}

/** Hash a password at the current work factor. */
export async function hashPassword(
  password: string,
  params: ScryptParams = CURRENT_PARAMS,
): Promise<StoredPassword> {
  const salt = randomBytes(SALT_LEN)
  const derived = await scryptAsync(password, salt, params.keyLen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: maxmemFor(params),
  })
  return { hash: `${salt.toString('hex')}:${derived.toString('hex')}`, algo: encodeAlgo(params) }
}

/**
 * Constant-time verify against a stored hash, at the parameters the row records.
 *
 * `timingSafeEqual` on the derived bytes rather than a string compare: a byte-at-a-time comparison
 * of a hash is a byte-at-a-time oracle for it.
 */
export async function verifyPassword(password: string, stored: string, algo: string): Promise<boolean> {
  const params = parseAlgo(algo)
  if (!params) return false
  const [saltHex, hashHex] = stored.split(':')
  if (!saltHex || !hashHex) return false

  let salt: Buffer
  let expected: Buffer
  try {
    salt = Buffer.from(saltHex, 'hex')
    expected = Buffer.from(hashHex, 'hex')
  } catch {
    return false
  }
  if (salt.length === 0 || expected.length === 0) return false

  // Derived to the length the STORED hash is, not to the parameter's, so a row whose keyLen and
  // hash disagree fails the compare rather than throwing out of timingSafeEqual.
  const derived = await scryptAsync(password, salt, expected.length, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: maxmemFor(params),
  })
  if (derived.length !== expected.length) return false
  return timingSafeEqual(derived, expected)
}

/**
 * Should this credential be rehashed?
 *
 * True when the row was written at anything other than the current cost — including a HIGHER one,
 * because a deliberate rollback of the work factor must actually take effect rather than leaving
 * the expensive rows expensive for ever. The caller rehashes only when it already holds the
 * plaintext, which is the sign-in it has just accepted and nowhere else.
 */
export function needsRehash(algo: string): boolean {
  return algo.trim() !== CURRENT_ALGO
}
