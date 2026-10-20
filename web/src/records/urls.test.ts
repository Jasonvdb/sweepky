import { describe, expect, it } from 'vitest'
import { MAX_PATH_LEN } from './limits.ts'
import { formatSweepkyPath, parseSweepkyPath } from './paths.ts'
import {
  formatPubkyUrl,
  parseBountyRef,
  parseListingLine,
  parsePubkyUrl,
  parseSweepRef,
} from './urls.ts'

/** The local testnet homeserver's key (pubky-testnet 0.16.2), as in core's tests. */
const TESTNET = '8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo'
/** S1 from fixtures/trust-labels.json, a second key. */
const OTHER = 'a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy'
/** A bounty id from fixtures/trust-labels.json. */
const ID = '0035G87EK4XFE'

const SWEEP_PATH = `/pub/sweepky/sweeps/${ID}.json`
const SWEEP_URL = `pubky://${TESTNET}${SWEEP_PATH}`

describe('the three spellings of a sweep URL', () => {
  it.each([
    ['pubky://<z32>', SWEEP_URL],
    ['pubky://pubky<z32>', `pubky://pubky${TESTNET}${SWEEP_PATH}`],
    ['the listing form', `https://_pubky.${TESTNET}/storage/${TESTNET}${SWEEP_PATH}`],
  ])('%s names the same owner, kind and id', (_form, line) => {
    const url = parseListingLine(line)
    expect(url).toEqual({ user: TESTNET, path: SWEEP_PATH })
    expect(parseSweepkyPath(url?.path ?? '')).toEqual({ kind: 'sweepRecord', id: ID })
  })

  it('reads both pubky:// spellings as one sweep ref, written back raw', () => {
    const raw = parseSweepRef(SWEEP_URL)
    expect(raw).toEqual({ sweeper: TESTNET, id: ID })
    expect(parseSweepRef(`pubky://pubky${TESTNET}${SWEEP_PATH}`)).toEqual(raw)
    const url = parsePubkyUrl(`pubky://pubky${TESTNET}${SWEEP_PATH}`)
    expect(url && formatPubkyUrl(url)).toBe(SWEEP_URL)
  })
})

describe('parseSweepkyPath', () => {
  it.each([
    [`/pub/sweepky/bounties/${ID}.json`, { kind: 'bounty', id: ID }],
    [`/pub/sweepky/bounties/${ID}.discovered.json`, { kind: 'discovered', id: ID }],
    [`/pub/sweepky/sweeps/${ID}.json`, { kind: 'sweepRecord', id: ID }],
    [`/pub/sweepky/sweeps/${ID}.age`, { kind: 'sweepPackage', id: ID }],
    ['/pub/sweepky/circle.json', { kind: 'circle' }],
    ['/pub/sweepky/keys/laptop-1.json', { kind: 'key', deviceId: 'laptop-1' }],
  ])('classifies %s, and writes it back the same', (path, expected) => {
    const parsed = parseSweepkyPath(path)
    expect(parsed).toEqual(expected)
    expect(parsed && formatSweepkyPath(parsed)).toBe(path)
  })

  it.each([
    `/pub/sweepky/bounties/../sweeps/${ID}.json`,
    `/pub/sweepky/bounties/x/${ID}.json`,
    `/pub/sweepky/bounties/${ID}.json/`,
    `/pub/sweepky//bounties/${ID}.json`,
    `/pub/sweepky/bounties/${ID}.age`,
    `/pub/sweepky/sweeps/${ID}.discovered.json`,
    `/pub/sweepky/bounties/${ID.toLowerCase()}.json`,
    '/pub/sweepky/keys/-laptop.json',
    '/pub/sweepky/bounties/',
    `/pub/other.app/bounties/${ID}.json`,
  ])('is not one of ours: %s', (path) => {
    expect(parseSweepkyPath(path)).toBeNull()
  })

  it('keeps the bounty and sweep refs to their own record kind', () => {
    const discovered = `pubky://${TESTNET}/pub/sweepky/bounties/${ID}.discovered.json`
    const pkg = `pubky://${TESTNET}/pub/sweepky/sweeps/${ID}.age`
    expect(parseBountyRef(`pubky://${TESTNET}/pub/sweepky/bounties/${ID}.json`)).toEqual({
      owner: TESTNET,
      id: ID,
    })
    expect(parseBountyRef(discovered)).toBeNull()
    expect(parseBountyRef(SWEEP_URL)).toBeNull()
    expect(parseSweepRef(pkg)).toBeNull()
    expect(parsePubkyUrl(pkg)).not.toBeNull()
  })
})

describe('refused lines', () => {
  it.each([
    [
      'an https line whose host and storage owner differ',
      `https://_pubky.${OTHER}/storage/${TESTNET}${SWEEP_PATH}`,
    ],
    [
      'an https line with a prefixed owner',
      `https://_pubky.pubky${TESTNET}/storage/pubky${TESTNET}${SWEEP_PATH}`,
    ],
    ['an https line without the storage prefix', `https://_pubky.${TESTNET}${SWEEP_PATH}`],
    ['a query', `${SWEEP_URL}?x=1`],
    ['an empty query', `${SWEEP_URL}?`],
    ['a fragment', `${SWEEP_URL}#x`],
    ['a space', `pubky://${TESTNET}/pub/sweepky/sweeps/${ID} .json`],
    ['a trailing newline', `${SWEEP_URL}\n`],
    ['a no-break space', `pubky://${TESTNET}/pub/other.app/a\u00a0b`],
    ['a NUL', `${SWEEP_URL}\u0000`],
    ['a terminal escape', `pubky://${TESTNET}/pub/other.app/\u001b[31mred`],
    ['a C1 control', `pubky://${TESTNET}/pub/other.app/a\u0085b`],
    ['a right-to-left override', `pubky://${TESTNET}/pub/other.app/a\u202eb`],
    ['a left-to-right isolate', `pubky://${TESTNET}/pub/other.app/a\u2066b`],
    ['another scheme', `http://${TESTNET}${SWEEP_PATH}`],
    ['an upper-case scheme', `PUBKY://${TESTNET}${SWEEP_PATH}`],
    ['a host that is not a pubky', `pubky://example.com${SWEEP_PATH}`],
    ['a port', `pubky://${TESTNET}:6286${SWEEP_PATH}`],
    ['no path', `pubky://${TESTNET}`],
  ])('refuses %s', (_case, line) => {
    expect(parseListingLine(line)).toBeNull()
  })

  it('takes a path of up to 1024 bytes, counted in UTF-8', () => {
    const longest = `/${'x'.repeat(MAX_PATH_LEN - 1)}`
    expect(parsePubkyUrl(`pubky://${TESTNET}${longest}`)?.path).toBe(longest)
    expect(parsePubkyUrl(`pubky://${TESTNET}/${'x'.repeat(MAX_PATH_LEN)}`)).toBeNull()
    // 512 characters, but 1024 bytes, plus the leading '/'.
    const wide = `pubky://${TESTNET}/${'\u00e9'.repeat(512)}`
    expect(parsePubkyUrl(wide)).toBeNull()
    const transport = `https://_pubky.${TESTNET}/storage/${TESTNET}`
    expect(parseListingLine(`${transport}/${'x'.repeat(MAX_PATH_LEN)}`)).toBeNull()
  })
})
