/**
 * TOTP — RFC 6238, over RFC 4226 HOTP, implemented on `node:crypto`.
 *
 * **No dependency, deliberately.** The whole algorithm is an HMAC, a truncation and a modulo, and
 * it is pinned by published test vectors that `totp.test.ts` asserts against. A second-factor
 * implementation pulled from the registry is a supply-chain dependency sitting directly on the
 * authentication path, in a repository whose install policy already makes a week-old package
 * unusable (see `pnpm-workspace.yaml`). Sixty lines that the RFC's own vectors verify is the
 * smaller risk.
 *
 * SD-02 records what this factor is and is not worth: TOTP resists credential stuffing and password
 * reuse, and does not resist a convincing phishing proxy. WebAuthn is the phishing-resistant factor
 * and is the one the UI recommends first (see mfa.ts, which defines its schema and answers 501
 * rather than pretending).
 */

import { createHmac, timingSafeEqual } from 'node:crypto'

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512'

export interface TotpParams {
  /** Seconds per step. 30 is the RFC default and what every authenticator app assumes. */
  readonly stepSeconds: number
  readonly digits: number
  readonly algorithm: TotpAlgorithm
}

/**
 * What this service enrols at.
 *
 * SHA1 and six digits, which is not a security choice so much as an interoperability one: the
 * `otpauth://` URI carries an algorithm parameter and a substantial number of authenticator apps
 * ignore it, silently computing SHA1 anyway. Enrolling at SHA256 would therefore produce a factor
 * that works on some phones and not others, and the failure would look to the user like their code
 * being wrong. SHA1's weakness is collision resistance; HMAC-SHA1 does not depend on it.
 */
export const DEFAULT_PARAMS: TotpParams = { stepSeconds: 30, digits: 6, algorithm: 'SHA1' }

const HMAC_NAME: Readonly<Record<TotpAlgorithm, string>> = {
  SHA1: 'sha1',
  SHA256: 'sha256',
  SHA512: 'sha512',
}

/** Which step a moment falls in. T0 is the epoch, as the RFC's own vectors assume. */
export function stepAt(unixSeconds: number, stepSeconds: number = DEFAULT_PARAMS.stepSeconds): number {
  return Math.floor(unixSeconds / stepSeconds)
}

/**
 * HOTP (RFC 4226 section 5.3) for one counter value.
 *
 * The counter is written as a 64-bit big-endian integer. It is built from a BigInt rather than two
 * 32-bit halves because the high word is not hypothetical: RFC 6238's own last test vector is at
 * t=20000000000, which is step 666666666 — still inside 32 bits, but the arithmetic that gets there
 * via floating point is not exact for every input, and a code that is right for forty years and
 * wrong afterwards is the worst kind of bug to leave.
 */
export function hotp(secret: Buffer, counter: number, params: TotpParams = DEFAULT_PARAMS): string {
  const message = Buffer.alloc(8)
  message.writeBigUInt64BE(BigInt(counter))

  const digest = createHmac(HMAC_NAME[params.algorithm], secret).update(message).digest()

  // Dynamic truncation: the low nibble of the last byte picks the offset, and the high bit of the
  // selected word is masked off so the result is a positive 31-bit integer on every platform.
  const offset = digest[digest.length - 1]! & 0x0f
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff)

  return String(binary % 10 ** params.digits).padStart(params.digits, '0')
}

/** The code for a moment. */
export function totp(
  secret: Buffer,
  unixSeconds: number,
  params: TotpParams = DEFAULT_PARAMS,
): string {
  return hotp(secret, stepAt(unixSeconds, params.stepSeconds), params)
}

export interface VerifyOptions {
  readonly params?: TotpParams
  /**
   * How many steps either side of now are accepted.
   *
   * One, which is thirty seconds late and thirty seconds early. It exists for clock drift between a
   * phone and this server and for the user who starts typing at second 29, and every step of window
   * is a step of extra guessing surface — three accepted codes rather than one is three times the
   * chance a blind guess lands. The throttle, not the window, is what makes six digits survivable.
   */
  readonly window?: number
  /**
   * The step this factor last authenticated with, if any.
   *
   * **This is the replay guard and it is not optional in practice.** A TOTP code is valid for its
   * whole step, so an attacker who observes one — over the user's shoulder, or from a phishing page
   * relaying in real time — can present the same digits again a few seconds later and be accepted.
   * Refusing any step at or below the last one that succeeded reduces that window to zero: one code
   * authenticates exactly once, ever.
   */
  readonly lastUsedStep?: number
}

export type TotpVerification =
  | { readonly ok: true; readonly step: number }
  /** Distinguished from a wrong code so the caller can log it: a replay is an attack signal. */
  | { readonly ok: false; readonly reason: 'mismatch' | 'replayed' | 'malformed' }

/**
 * Verify a presented code.
 *
 * The comparison is `timingSafeEqual` over the digits. That is close to superstition for a six-digit
 * value an attacker can already enumerate offline — but the cost is nothing, and the habit is what
 * stops the next comparison, of something that does matter, being written with `===`.
 */
export function verifyTotp(
  secret: Buffer,
  presented: string,
  unixSeconds: number,
  options: VerifyOptions = {},
): TotpVerification {
  const params = options.params ?? DEFAULT_PARAMS
  const window = options.window ?? 1
  const cleaned = presented.replace(/[\s-]/g, '')
  if (!new RegExp(`^\\d{${params.digits}}$`).test(cleaned)) return { ok: false, reason: 'malformed' }

  const current = stepAt(unixSeconds, params.stepSeconds)
  let matched: number | null = null
  // Every candidate is computed even after a match, so the time this takes does not depend on WHICH
  // step matched — which would otherwise leak the drift between the attacker's clock and ours.
  for (let offset = -window; offset <= window; offset += 1) {
    const step = current + offset
    if (step < 0) continue
    const expected = Buffer.from(hotp(secret, step, params))
    const actual = Buffer.from(cleaned)
    if (expected.length === actual.length && timingSafeEqual(expected, actual)) matched = step
  }

  if (matched === null) return { ok: false, reason: 'mismatch' }
  if (options.lastUsedStep !== undefined && matched <= options.lastUsedStep) {
    return { ok: false, reason: 'replayed' }
  }
  return { ok: true, step: matched }
}

/* ------------------------------------------------------------------------ base32 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/**
 * RFC 4648 base32, unpadded.
 *
 * Unpadded because that is what every authenticator app expects in an `otpauth://` secret, and a
 * trailing `=` is a character a user retyping the key by hand will drop anyway.
 */
export function base32Encode(bytes: Buffer): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31]
  return out
}

/** Returns null for anything that is not base32, so a typo is a 400 and not a decode of garbage. */
export function base32Decode(text: string): Buffer | null {
  // Padding and spacing are tolerated on the way in: apps and users both add them, and refusing a
  // secret over a space the user did not type is a support ticket with no security benefit.
  const cleaned = text.replace(/[\s=-]/g, '').toUpperCase()
  if (cleaned.length === 0) return null
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const char of cleaned) {
    const index = ALPHABET.indexOf(char)
    if (index < 0) return null
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

/**
 * The `otpauth://` URI an authenticator app scans.
 *
 * The label carries the issuer as well as the account so a phone with two CloudsForge accounts on
 * it shows which is which, and `issuer` is repeated as a parameter because the two are read by
 * different apps. Everything is percent-encoded: a handle may legally contain characters that would
 * otherwise end the query.
 */
export function otpauthUri(options: {
  readonly issuer: string
  readonly account: string
  readonly secret: Buffer
  readonly params?: TotpParams
}): string {
  const params = options.params ?? DEFAULT_PARAMS
  const label = `${encodeURIComponent(options.issuer)}:${encodeURIComponent(options.account)}`
  const query = new URLSearchParams({
    secret: base32Encode(options.secret),
    issuer: options.issuer,
    algorithm: params.algorithm,
    digits: String(params.digits),
    period: String(params.stepSeconds),
  })
  return `otpauth://totp/${label}?${query.toString()}`
}
