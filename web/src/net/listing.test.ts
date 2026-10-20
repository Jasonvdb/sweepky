import { describe, expect, it } from 'vitest'
import { recordIdFromMicros, type RecordId } from '../records/ids.ts'
import { MAX_LISTING_LINE_BYTES, maxPageBytes, utf8Length } from '../records/limits.ts'
import { BOUNTIES_DIR, SWEEPS_DIR, type SweepkyPath } from '../records/paths.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import {
  DEFAULT_LIST_LIMITS,
  listDirNewestFirst,
  REFUSAL_TEXT,
  type ListingRefusal,
  type ListLimits,
} from './listing.ts'
import type { ListedDir, ListingAnswer, ListOptions, Transport } from './transport.ts'

/** A, the roster's admin in fixtures/trust-labels.json: the owner whose directory is listed. */
const OWNER = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
/** S1 in fixtures/trust-labels.json: someone else. */
const STRANGER = pubky('a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy')

/** Limits small enough to cross in a test, remote.rs's `SMALL`: 4 a page, 6 in all, 3 pages. */
const SMALL: ListLimits = { pageSize: 4, maxEntries: 6, maxPages: 3 }
/** Two entries a page, so a short directory still runs over several pages. */
const TWO_A_PAGE: ListLimits = { pageSize: 2, maxEntries: 100, maxPages: 10 }

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`test key ${text} is not a key`)
  return key
}

/** The record id of timestamp `n`: a larger `n` is a newer record. */
function id(n: number): RecordId {
  return recordIdFromMicros(BigInt(n))
}

/** A listing line for `owner`'s file at `path`, as a 0.16.2 homeserver writes one. */
function line(path: string, owner: Pubky = OWNER): string {
  return `pubky://${owner}${path}`
}

const bountyLine = (n: number) => line(`${BOUNTIES_DIR}${id(n)}.json`)
const discoveredLine = (n: number) => line(`${BOUNTIES_DIR}${id(n)}.discovered.json`)
const sweepLine = (n: number) => line(`${SWEEPS_DIR}${id(n)}.json`)
const packageLine = (n: number) => line(`${SWEEPS_DIR}${id(n)}.age`)

const bounty = (n: number): SweepkyPath => ({ kind: 'bounty', id: id(n) })
const discovered = (n: number): SweepkyPath => ({ kind: 'discovered', id: id(n) })
const sweepRecord = (n: number): SweepkyPath => ({ kind: 'sweepRecord', id: id(n) })

/** Bounties `from` down to `to`, newest first, as listing lines. */
function bountyLines(from: number, to: number): string[] {
  const lines: string[] = []
  for (let n = from; n >= to; n -= 1) lines.push(bountyLine(n))
  return lines
}

const encoder = new TextEncoder()

/** A 2xx page of `lines`, joined with `\n`; a line given as bytes goes in as it is. */
function page(...lines: (string | Uint8Array)[]): ListingAnswer {
  const bytes: number[] = []
  lines.forEach((text, index) => {
    if (index > 0) bytes.push(0x0a)
    bytes.push(...(typeof text === 'string' ? encoder.encode(text) : text))
  })
  return { kind: 'body', body: new Uint8Array(bytes) }
}

/** A 2xx page whose body is `text` exactly. */
function rawPage(text: string): ListingAnswer {
  return { kind: 'body', body: encoder.encode(text) }
}

/** A 404: the directory is empty. */
const NOT_FOUND: ListingAnswer = { kind: 'empty' }

interface ListCall {
  readonly owner: Pubky
  readonly dir: ListedDir
  readonly options: ListOptions
}

/**
 * A transport that answers each listing request with the next of `answers`,
 * then 404 for every request after them, and records what it was asked.
 */
function fakeTransport(answers: readonly ListingAnswer[]) {
  const calls: ListCall[] = []
  const transport: Transport = {
    async list(owner, dir, options) {
      calls.push({ owner, dir, options })
      return answers[calls.length - 1] ?? NOT_FOUND
    },
    getRecord() {
      throw new Error('the pager reads no record')
    },
    lookupHomeserver() {
      throw new Error('the pager resolves no homeserver')
    },
  }
  return { transport, calls }
}

interface ListSetup {
  readonly dir?: ListedDir
  readonly newestSeen?: RecordId | null
  readonly limits?: ListLimits
}

/** OWNER's `dir` (bounties/ unless said) listed from `answers`, within SMALL unless said. */
async function list(
  answers: readonly ListingAnswer[],
  { dir = BOUNTIES_DIR, newestSeen = null, limits = SMALL }: ListSetup = {},
) {
  const { transport, calls } = fakeTransport(answers)
  const result = await listDirNewestFirst(transport, OWNER, dir, newestSeen, limits)
  return { result, calls }
}

function listed(entries: SweepkyPath[], skipped = 0) {
  return { kind: 'listed', listing: { entries, skipped } }
}

function refused(reason: ListingRefusal) {
  return { kind: 'refused', reason, message: REFUSAL_TEXT[reason] }
}

describe('paging', () => {
  it('asks for the first page newest first, with the limit and no cursor', async () => {
    const { transport, calls } = fakeTransport([page(sweepLine(9))])
    await listDirNewestFirst(transport, OWNER, SWEEPS_DIR, null)
    expect(calls).toEqual([
      {
        owner: OWNER,
        dir: SWEEPS_DIR,
        options: { limit: 100, reverse: true, cache: 'no-cache' },
      },
    ])
    expect(calls[0]?.options.cursor).toBeUndefined()
  })

  it('pages on from the last entry of the owner in the directory, ours or not', async () => {
    const full = page(
      bountyLine(9),
      line(`${BOUNTIES_DIR}notes.txt`),
      line(`${BOUNTIES_DIR}${id(8)}.json`, STRANGER),
      line(`${SWEEPS_DIR}${id(7)}.json`),
    )
    const { result, calls } = await list([full, page(bountyLine(6))])
    expect(calls).toHaveLength(2)
    expect(calls[1]?.options).toEqual({
      limit: 4,
      reverse: true,
      cursor: { user: OWNER, path: `${BOUNTIES_DIR}notes.txt` },
      cache: 'no-cache',
    })
    expect(result).toEqual(listed([bounty(9), bounty(6)], 3))
  })

  it('ends at a page shorter than the limit', async () => {
    const { result, calls } = await list([page(...bountyLines(9, 7)), page(bountyLine(6))])
    expect(result).toEqual(listed([bounty(9), bounty(8), bounty(7)]))
    expect(calls).toHaveLength(1)
  })

  it('ends at an empty page', async () => {
    const { result, calls } = await list([page(...bountyLines(9, 6)), rawPage('')])
    expect(result).toEqual(listed([bounty(9), bounty(8), bounty(7), bounty(6)]))
    expect(calls).toHaveLength(2)
  })

  it('reads the whole directory when nothing was seen, up to the 404 after it', async () => {
    const pages = [page(bountyLine(5), discoveredLine(5)), page(bountyLine(4), bountyLine(3))]
    const { result, calls } = await list(pages, { limits: TWO_A_PAGE })
    expect(result).toEqual(listed([bounty(5), discovered(5), bounty(4), bounty(3)]))
    expect(calls).toHaveLength(3)
  })
})

describe('the watermark', () => {
  // Newest first, as a homeserver lists with `reverse=true`: a bounty's
  // record sorts after its `.discovered.json`, so it comes first.
  it.each([
    ['at', [page(bountyLine(5), discoveredLine(5)), page(bountyLine(4), bountyLine(3))]],
    ['below', [page(bountyLine(5), discoveredLine(5)), page(bountyLine(4), bountyLine(2))]],
  ])(
    'stops at the first record %s the newest id seen, keeps nothing from it on, asks for no more',
    async (_where, pages) => {
      const more = page(bountyLine(1))
      const { result, calls } = await list([...pages, more], {
        newestSeen: id(3),
        limits: TWO_A_PAGE,
      })
      expect(result).toEqual(listed([bounty(5), discovered(5), bounty(4)]))
      // The second page is full, and still the last one asked for.
      expect(calls).toHaveLength(2)
      expect(calls[1]?.options.cursor).toEqual({
        user: OWNER,
        path: `${BOUNTIES_DIR}${id(5)}.discovered.json`,
      })
    },
  )

  it('keeps nothing and asks for nothing more when the first line is the stop', async () => {
    const { result, calls } = await list([page(...bountyLines(5, 2)), page(bountyLine(1))], {
      newestSeen: id(5),
    })
    expect(result).toEqual(listed([]))
    expect(calls).toHaveLength(1)
  })

  it.each([
    [
      '.discovered.json',
      BOUNTIES_DIR,
      [bountyLine(5), discoveredLine(3), bountyLine(3)],
      bounty(5),
    ],
    ['.age', SWEEPS_DIR, [sweepLine(5), packageLine(3), sweepLine(3)], sweepRecord(5)],
  ] as const)('stops at a %s file too, which is not kept', async (_kind, dir, lines, newest) => {
    const { result } = await list([page(...lines)], { dir, newestSeen: id(3) })
    expect(result).toEqual(listed([newest]))
  })

  it('counts nothing as skipped after the stop', async () => {
    const after = line(`${BOUNTIES_DIR}${id(2)}.json`, STRANGER)
    const { result } = await list([page(bountyLine(3), after)], { newestSeen: id(3) })
    expect(result).toEqual(listed([]))
  })

  // A stop on the first line must not let the rest of the page break the
  // protocol unseen.
  it.each([
    ['over-long', 'lineTooLong', [line(`${BOUNTIES_DIR}${'a'.repeat(MAX_LISTING_LINE_BYTES)}`)]],
    ['not UTF-8', 'notUtf8', [new Uint8Array([0x70, 0xff])]],
    ['not a URL', 'notAResource', ['hello']],
    ['past the page limit', 'pageOverLimit', bountyLines(9, 6)],
  ] as const)('still refuses a later line that is %s', async (_what, reason, later) => {
    const { result } = await list([page(bountyLine(10), ...later)], { newestSeen: id(10) })
    expect(result).toEqual(refused(reason))
  })
})

describe('entries skipped and counted, never fatal', () => {
  it("skips another owner's entries, comparing parsed keys rather than spellings", async () => {
    const { result } = await list([
      page(
        line(`${BOUNTIES_DIR}${id(9)}.json`, STRANGER),
        // The owner's key with the SDK's `pubky` prefix is still the owner's.
        `pubky://pubky${OWNER}${BOUNTIES_DIR}${id(8)}.json`,
        line(`${BOUNTIES_DIR}${id(7)}.json`),
      ),
    ])
    expect(result).toEqual(listed([bounty(8), bounty(7)], 1))
  })

  it('skips entries outside the directory and the directory itself, none a cursor', async () => {
    const { result, calls } = await list([
      page(
        bountyLine(9),
        line(`${SWEEPS_DIR}${id(8)}.json`),
        line('/pub/sweepky/bounties'),
        line(BOUNTIES_DIR),
      ),
    ])
    expect(result).toEqual(listed([bounty(9)], 3))
    expect(calls[1]?.options.cursor).toEqual({ user: OWNER, path: `${BOUNTIES_DIR}${id(9)}.json` })
  })

  it('skips names the Sweepky path parser does not accept', async () => {
    const { result } = await list([
      page(
        line(`${BOUNTIES_DIR}notes.txt`),
        line(`${BOUNTIES_DIR}${id(9).toLowerCase()}.json`),
        line(`${BOUNTIES_DIR}sub/${id(9)}.json`),
        line(`${BOUNTIES_DIR}${id(9)}.age`),
      ),
      page(bountyLine(8)),
    ])
    expect(result).toEqual(listed([bounty(8)], 4))
  })
})

describe('a listing refused whole', () => {
  it('refuses a page over pageSize x 4098 bytes, blank lines and all', async () => {
    const cap = maxPageBytes(SMALL.pageSize)
    expect(cap).toBe(4 * 4098)
    expect((await list([rawPage('\n'.repeat(cap + 1))])).result).toEqual(refused('pageTooLarge'))
    expect((await list([rawPage('\n'.repeat(cap))])).result).toEqual(listed([]))
  })

  it('refuses a page the transport found over its cap', async () => {
    const { result } = await list([page(...bountyLines(9, 6)), { kind: 'tooLarge' }])
    expect(result).toEqual(refused('pageTooLarge'))
  })

  it('refuses a line over 4096 bytes, measured in bytes before it is decoded', async () => {
    const entry = bountyLine(9)
    const room = MAX_LISTING_LINE_BYTES - utf8Length(entry)
    // Trailing white space is trimmed off after the line is measured.
    const longest = `${entry}${' '.repeat(room)}`
    expect((await list([page(longest)])).result).toEqual(listed([bounty(9)]))
    expect((await list([page(`${longest} `)])).result).toEqual(refused('lineTooLong'))

    // U+3000, an ideographic space, is one UTF-16 unit but three UTF-8
    // bytes: a string length would let this line through.
    const wide = `${entry}${'　'.repeat(Math.ceil((room + 1) / 3))}`
    expect(wide.length).toBeLessThan(MAX_LISTING_LINE_BYTES)
    expect((await list([page(wide)])).result).toEqual(refused('lineTooLong'))
  })

  it.each([
    ['a byte that is never UTF-8', [0xff]],
    ['a truncated sequence', [0xc3]],
    ['an encoded surrogate', [0xed, 0xa0, 0x80]],
    ['an overlong slash', [0xc0, 0xaf]],
  ])('refuses a line with %s, never decoding it lossily', async (_what, bad) => {
    const start = encoder.encode(line(`${BOUNTIES_DIR}${id(9)}`))
    const notUtf8 = new Uint8Array([...start, ...bad, ...encoder.encode('.json')])
    expect((await list([page(notUtf8)])).result).toEqual(refused('notUtf8'))
  })

  it.each([
    ['plain text', 'hello'],
    ['a host that is not a key', `pubky://not-a-key${BOUNTIES_DIR}${id(9)}.json`],
    ['another scheme', `ftp://${OWNER}${BOUNTIES_DIR}${id(9)}.json`],
    ['plain http', `http://_pubky.${OWNER}/storage/${OWNER}${BOUNTIES_DIR}${id(9)}.json`],
    ['an https URL of another host', `https://example.com${BOUNTIES_DIR}${id(9)}.json`],
    ['a lone \\r, which ends no line', `${bountyLine(9)}\r${bountyLine(8)}`],
    // The SDK's resource paths refuse these segments, so the CLI does too.
    ['a .. segment', line(`${BOUNTIES_DIR}../sweeps/${id(9)}.json`)],
    ['a . segment', line(`${BOUNTIES_DIR}./${id(9)}.json`)],
    ['an empty segment', line(`/pub/sweepky//bounties/${id(9)}.json`)],
  ])('refuses a line that is not a resource URL: %s', async (_what, text) => {
    expect((await list([page(text)])).result).toEqual(refused('notAResource'))
  })

  it('refuses a page with more entries than were asked for', async () => {
    const { result } = await list([page(...bountyLines(9, 5))])
    expect(result).toEqual(refused('pageOverLimit'))
  })

  it('refuses a listing with more entries in all than it reads', async () => {
    const { result } = await list([page(...bountyLines(9, 6)), page(...bountyLines(5, 2))])
    expect(result).toEqual(refused('tooManyEntries'))
  })

  it('refuses a listing that runs to more pages than it reads, even an empty one', async () => {
    const pages = [page(bountyLine(9)), page(bountyLine(8)), page(bountyLine(7)), rawPage('')]
    const oneAPage: ListLimits = { pageSize: 1, maxEntries: 100, maxPages: 3 }
    const { result, calls } = await list(pages, { limits: oneAPage })
    expect(result).toEqual(refused('tooManyPages'))
    expect(calls).toHaveLength(4)
  })

  it.each([
    ["another owner's entries", (n: number) => line(`${BOUNTIES_DIR}${id(n)}.json`, STRANGER)],
    ['entries outside the directory', (n: number) => sweepLine(n)],
  ])('refuses a full page of %s: there is no cursor to go on from', async (_what, entry) => {
    const { result, calls } = await list([page(entry(9), entry(8), entry(7), entry(6))])
    expect(result).toEqual(refused('noCursor'))
    expect(calls).toHaveLength(1)
  })

  it('refuses a page in fixed text, never the line that broke the rule', async () => {
    const hostile = `pubky://${OWNER}/\u001b[31mpwned`
    const { result } = await list([page(hostile)])
    expect(result).toEqual(refused('notAResource'))
    expect(JSON.stringify(result)).not.toContain('pwned')
  })
})

describe('lines', () => {
  it('splits at \\n, drops one \\r and trims each line', async () => {
    const body = `\n${bountyLine(9)}\r\n\n   \n\t${bountyLine(8)} \n`
    expect((await list([rawPage(body)])).result).toEqual(listed([bounty(9), bounty(8)]))
  })

  it('drops only one \\r before the line is measured', async () => {
    const entry = bountyLine(9)
    const longest = `${entry}${' '.repeat(MAX_LISTING_LINE_BYTES - utf8Length(entry))}`
    expect((await list([rawPage(`${longest}\r\n`)])).result).toEqual(listed([bounty(9)]))
    expect((await list([rawPage(`${longest}\r\r\n`)])).result).toEqual(refused('lineTooLong'))
  })

  // Rust's `trim` takes Unicode White_Space, which holds U+0085 (NEL) and
  // not U+FEFF (a byte-order mark). JavaScript's own `trim` is the other
  // way round.
  it('trims Unicode white space as Rust does: a NEL goes, a byte-order mark stays', async () => {
    expect((await list([page(`${bountyLine(9)}\u0085`)])).result).toEqual(listed([bounty(9)]))
    expect((await list([page(`﻿${bountyLine(9)}`)])).result).toEqual(refused('notAResource'))
  })

  it('skips blank lines without counting them against the page', async () => {
    const body = `\n\r\n${bountyLine(9)}\n  \n\n${bountyLine(8)}\n\n`
    const { result, calls } = await list([rawPage(body)], { limits: TWO_A_PAGE })
    expect(result).toEqual(listed([bounty(9), bounty(8)]))
    // Two entries fill a page of two, so the next page is asked for.
    expect(calls).toHaveLength(2)
  })

  it('reads a 404 as an empty listing', async () => {
    const { result, calls } = await list([NOT_FOUND])
    expect(result).toEqual(listed([]))
    expect(calls).toHaveLength(1)
  })

  it('reads a 404 after a full page as the end of the listing', async () => {
    const { result, calls } = await list([page(...bountyLines(9, 6)), NOT_FOUND])
    expect(result).toEqual(listed([bounty(9), bounty(8), bounty(7), bounty(6)]))
    expect(calls).toHaveLength(2)
  })

  it('reads lines in both the pubky:// and the https:// form', async () => {
    const https = `https://_pubky.${OWNER}/storage/${OWNER}${BOUNTIES_DIR}${id(8)}.json`
    const { result } = await list([page(bountyLine(9), https)])
    expect(result).toEqual(listed([bounty(9), bounty(8)]))
  })
})

describe('failures', () => {
  it.each([
    { kind: 'notBrowserReachable' },
    { kind: 'failed', message: 'the homeserver answered HTTP 500' },
  ] as const)('fails the whole listing when a page is $kind, keeping nothing', async (failure) => {
    const { result } = await list([page(...bountyLines(9, 6)), failure])
    expect(result).toEqual(failure)
  })
})

describe("the CLI's limits", () => {
  it("defaults to ListLimits::DEFAULT: 100 a page, at most 1000 entries in 11 pages", () => {
    expect(DEFAULT_LIST_LIMITS).toEqual({ pageSize: 100, maxEntries: 1000, maxPages: 11 })
  })

  it('reads 1000 entries in ten full pages and an empty eleventh, refusing one more', async () => {
    const fullPages = Array.from({ length: 11 }, (_, index) =>
      page(...bountyLines(1100 - 100 * index, 1001 - 100 * index)),
    )
    const tenPages = await list([...fullPages.slice(0, 10), rawPage('')], {
      limits: DEFAULT_LIST_LIMITS,
    })
    const thousand = Array.from({ length: 1000 }, (_, index) => bounty(1100 - index))
    expect(tenPages.result).toEqual(listed(thousand))
    expect(tenPages.calls).toHaveLength(11)

    const elevenPages = await list(fullPages, { limits: DEFAULT_LIST_LIMITS })
    expect(elevenPages.result).toEqual(refused('tooManyEntries'))
  })
})
