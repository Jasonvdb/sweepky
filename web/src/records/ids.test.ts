import { describe, expect, it } from 'vitest'
import { parseRecordId, recordIdFromMicros, recordIdMicros, type RecordId } from './ids.ts'

/** A bounty id from fixtures/trust-labels.json. */
const FIXTURE_ID = '0035G87EK4XFE'

/** A known id, checked against Python's own base32 encoder with the alphabet swapped. */
const FIXTURE_MICROS = 1_785_748_325_481_207n

function id(text: string): RecordId {
  const parsed = parseRecordId(text)
  if (parsed === null) throw new Error(`test id ${text} does not parse`)
  return parsed
}

describe('parseRecordId', () => {
  it('reads a fixture id and decodes its timestamp', () => {
    expect(parseRecordId(FIXTURE_ID)).toBe(FIXTURE_ID)
    expect(recordIdMicros(id(FIXTURE_ID))).toBe(FIXTURE_MICROS)
  })

  it.each([
    ['lower case', '0035g87ek4xfe'],
    ['an I', '0035G87EK4IFE'],
    ['an L', '0035G87EK4LFE'],
    ['an O', '0035G87EK4OFE'],
    ['a U', '0035G87EK4UFE'],
    ['12 characters', '0035G87EK4XF'],
    ['14 characters', '0035G87EK4XFE0'],
    ['the empty string', ''],
    // E is 01110 and F is 01111: the one padding bit must be zero.
    ['a non-canonical last character', '0035G87EK4XFF'],
    ['a trailing newline', '0035G87EK4XF\n'],
  ])('refuses %s', (_case, value) => {
    expect(parseRecordId(value)).toBeNull()
  })
})

describe('record id order', () => {
  it('sorts ids as strings in the order of their timestamps', () => {
    const october2025 = 1_760_529_600_000_000n
    const ascending = [0n, 7n, 1n << 40n, october2025, october2025 + 2n, 2n ** 64n - 1n]
    const ids = ascending.map(recordIdFromMicros)
    // The default sort compares strings by UTF-16 code unit, which for these
    // ASCII ids is the byte order a homeserver lists them in.
    expect([...ids].reverse().sort()).toEqual(ids)
  })
})

describe('recordIdFromMicros', () => {
  it('writes the canonical id, which parses back to the same timestamp', () => {
    expect(recordIdFromMicros(1_760_529_600_000_000n)).toBe('00342C9XDJR00')
    expect(recordIdFromMicros(0n)).toBe('0000000000000')
    expect(recordIdFromMicros(2n ** 64n - 1n)).toBe('ZZZZZZZZZZZZY')
    for (const micros of [0n, 1n, FIXTURE_MICROS, 2n ** 64n - 1n]) {
      const text = recordIdFromMicros(micros)
      expect(recordIdMicros(id(text))).toBe(micros)
    }
  })

  it('refuses a timestamp outside 64 unsigned bits', () => {
    expect(() => recordIdFromMicros(-1n)).toThrow(RangeError)
    expect(() => recordIdFromMicros(2n ** 64n)).toThrow(RangeError)
  })
})
