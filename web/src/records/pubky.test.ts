import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parsePubky } from './pubky.ts'

/** The local testnet homeserver's key (pubky-testnet 0.16.2), as in core's tests. */
const TESTNET = '8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo'

/** The testnet key with the character at `index` replaced by `char`. */
function testnetWith(index: number, char: string): string {
  return TESTNET.slice(0, index) + char + TESTNET.slice(index + 1)
}

function readFixture(name: string): unknown {
  return JSON.parse(readFileSync(new URL(`../../../fixtures/${name}`, import.meta.url), 'utf8'))
}

describe('parsePubky', () => {
  it('reads the raw and the pubky-prefixed form as one key', () => {
    const raw = parsePubky(TESTNET)
    const prefixed = parsePubky(`pubky${TESTNET}`)
    expect(raw).toBe(TESTNET)
    expect(prefixed).toBe(raw)
  })

  it('strips the prefix only when exactly 52 characters follow it', () => {
    // A raw key may itself begin with the letters "pubky".
    const raw = `pubky${'y'.repeat(47)}`
    expect(parsePubky(raw)).toBe(raw)
    expect(parsePubky(`pubky${raw}`)).toBe(raw)
    expect(parsePubky(`pubky${TESTNET.slice(0, 51)}`)).toBeNull()
  })

  it.each([
    ['upper case', TESTNET.toUpperCase()],
    ['an upper-case prefix', `PUBKY${TESTNET}`],
    ['51 characters', TESTNET.slice(0, 51)],
    ['53 characters', `${TESTNET}y`],
    ['the empty string', ''],
    ['a 0, outside z-base32', testnetWith(10, '0')],
    ['a 2, outside z-base32', testnetWith(10, '2')],
    ['an l, outside z-base32', testnetWith(10, 'l')],
    ['a v, outside z-base32', testnetWith(10, 'v')],
    ['a non-ASCII character', testnetWith(10, '\u00e9')],
    // 'o' is 10000 and 't' is 10001: the four padding bits must be zero.
    ['a non-canonical last character', testnetWith(51, 't')],
    ['surrounding whitespace', ` ${TESTNET}`],
  ])('refuses %s', (_case, value) => {
    expect(parsePubky(value)).toBeNull()
  })

  it('reads every pubky in the shared fixtures', () => {
    const labels = readFixture('trust-labels.json') as {
      roster: { admin: string; members: { pubky: string }[] }
      bounties: { owner: string; credits: string[] }[]
      expected: Record<string, unknown>
    }
    const discovered = readFixture('discovered.json') as {
      sweeps: string[]
      cursors: Record<string, string>
    }
    const pubkys = [
      labels.roster.admin,
      ...labels.roster.members.map((member) => member.pubky),
      ...labels.bounties.flatMap((bounty) => [bounty.owner, ...bounty.credits]),
      ...Object.keys(labels.expected),
      ...discovered.sweeps.map((url) => url.split('/')[2] ?? ''),
      ...Object.keys(discovered.cursors),
    ]
    expect(pubkys).toHaveLength(38)
    for (const pubky of pubkys) {
      expect(parsePubky(pubky), pubky).toBe(pubky)
    }
  })
})
