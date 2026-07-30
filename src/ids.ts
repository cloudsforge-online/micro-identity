/**
 * UUIDv7.
 *
 * 04-domain-model section 0: "All ids are UUIDv7 (time-ordered, so they index well and sort
 * chronologically)". Identity's tables are not the estate's highest-insert-rate — that is the
 * ledger's journal — but two of the properties matter here specifically:
 *
 *   * **A session list is `order by id`.** "Where am I signed in, most recent first" is the whole
 *     point of surfacing sessions at all, and with a v4 key it needs `created_at` plus a tie-break
 *     to be a total order. With v7 the key *is* the order.
 *   * **They index well.** `refresh_tokens` is written on every rotation and never updated in
 *     place, so a random primary key means its index write set is the whole index, for ever.
 *
 * Postgres' `gen_random_uuid()` is v4, which is why ids are generated here and passed in rather
 * than defaulted in the DDL. The `outbox`, `inbox` and `jobs` tables keep their v4 defaults: they
 * come verbatim from the runtime packages, and diverging from the shared DDL to gain an ordering
 * nothing reads would be a drift with no benefit.
 */

import { randomBytes } from 'node:crypto'

let lastMillis = -1
let sequence = 0

/**
 * A UUIDv7: 48 bits of Unix milliseconds, 4 bits of version, 12 bits of sequence, 2 bits of
 * variant, 62 bits of randomness.
 *
 * The 12-bit sequence counter is what makes ids generated inside one millisecond still sort in
 * creation order — which registration needs, because a user, their profile, their personal
 * organisation and their first session are all created inside one transaction and one millisecond.
 */
export function uuidv7(now: () => number = Date.now): string {
  const millis = now()

  if (millis === lastMillis) {
    sequence += 1
    // 12 bits. Exhausting it inside one millisecond would mean 4096 ids in that millisecond;
    // rolling into the next millisecond keeps the ordering guarantee instead of silently wrapping
    // the counter back behind ids already issued.
    if (sequence > 0xfff) {
      lastMillis = millis + 1
      sequence = 0
    }
  } else {
    // Never go backwards, even if the wall clock does. A clock stepped back by NTP must not produce
    // ids that sort before rows already written.
    lastMillis = millis > lastMillis ? millis : lastMillis + 1
    sequence = 0
  }

  const timestamp = lastMillis
  const bytes = randomBytes(16)

  bytes[0] = Math.floor(timestamp / 2 ** 40) & 0xff
  bytes[1] = Math.floor(timestamp / 2 ** 32) & 0xff
  bytes[2] = Math.floor(timestamp / 2 ** 24) & 0xff
  bytes[3] = Math.floor(timestamp / 2 ** 16) & 0xff
  bytes[4] = Math.floor(timestamp / 2 ** 8) & 0xff
  bytes[5] = timestamp & 0xff

  // Version 7 in the high nibble of byte 6, sequence in the remaining 12 bits.
  bytes[6] = 0x70 | ((sequence >> 8) & 0x0f)
  bytes[7] = sequence & 0xff

  // RFC 4122 variant: the two high bits of byte 8 are '10'.
  bytes[8] = 0x80 | (bytes[8]! & 0x3f)

  const hex = bytes.toString('hex')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Is this a UUID at all?
 *
 * Checked before a value reaches a query. Postgres rejects a malformed uuid with a 22P02 that
 * surfaces as a 500, and a caller that sent a typo deserves a 400 that says so.
 */
export function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value)
}
