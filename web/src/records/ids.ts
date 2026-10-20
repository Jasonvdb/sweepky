// Record ids, ported from sweepky-core's `ids.rs`: the `<id>` in
// `bounties/<id>.json` and `sweeps/<id>.json`.
//
// An id is a `pubky-timestamp`: microseconds since 1970 as a 64-bit number,
// whose 8 bytes (big-endian) are written as 13 characters of upper-case
// Crockford base32, the format pubky-app-specs uses.

/**
 * A record id in its canonical 13-character form, from `parseRecordId` or
 * `recordIdFromMicros`.
 *
 * The alphabet below is in ASCII order and every id has the same length, so
 * comparing two ids as strings (`<`, `>`, or a plain `sort()`) is comparing
 * their timestamps. That is why a homeserver's byte-order listing is
 * chronological.
 */
export type RecordId = string & { readonly __brand: 'RecordId' }

/** Crockford's base32 alphabet, upper case only, in value order. */
const CROCKFORD_UPPER = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/**
 * A canonical id: 13 characters of upper-case Crockford base32, the last one
 * with an even value.
 *
 * Only upper case, and no `I`, `L`, `O` or `U`: Crockford decoders often read
 * lower case, `I` and `L` as `1` and `O` as `0`, which would let several
 * strings name one record. And 13 characters carry 65 bits for a 64-bit
 * number, so the last character's lowest bit is padding that decoding
 * ignores (`...E` and `...F` decode alike). Only the even one is the form an
 * encoder writes.
 */
const CANONICAL_ID = /^[0-9A-HJKMNP-TV-Z]{12}[02468ACEGJMPRTWY]$/

const U64_LIMIT = 1n << 64n

/** The id `text` is, or `null` when it is not exactly a canonical id. */
export function parseRecordId(text: string): RecordId | null {
  return CANONICAL_ID.test(text) ? (text as RecordId) : null
}

/**
 * The timestamp `id` encodes, in microseconds since 1970.
 *
 * A `bigint`, because a 64-bit number does not fit a JavaScript `number`
 * exactly: integers above 2^53 lose their low bits.
 */
export function recordIdMicros(id: RecordId): bigint {
  // Each character is five bits, the first the highest. The 65 bits read
  // this way are the number shifted left by one, with the padding bit last.
  let bits = 0n
  for (const char of id) {
    bits = (bits << 5n) | BigInt(CROCKFORD_UPPER.indexOf(char))
  }
  return bits >> 1n
}

/**
 * The id of the timestamp `micros`, which must fit in 64 unsigned bits.
 * Throws a `RangeError` otherwise: a caller's mistake, never a stranger's
 * input, because ids from records go through `parseRecordId`.
 */
export function recordIdFromMicros(micros: bigint): RecordId {
  if (micros < 0n || micros >= U64_LIMIT) {
    throw new RangeError('a record id holds a timestamp of 0 to 2^64 - 1 microseconds')
  }
  // The reverse of `recordIdMicros`: append the zero padding bit, then write
  // five bits a character, the highest first.
  const bits = micros << 1n
  let id = ''
  for (let shift = 60n; shift >= 0n; shift -= 5n) {
    id += CROCKFORD_UPPER.charAt(Number((bits >> shift) & 31n))
  }
  return id as RecordId
}
