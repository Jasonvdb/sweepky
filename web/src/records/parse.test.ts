import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { recordIdFromMicros } from './ids.ts'
import { MAX_CREDITS, MAX_RECORD_BYTES, MAX_STATUS_BYTES, MAX_TARGETS } from './limits.ts'
import {
  asKnownBountyStatus,
  asKnownSweepStatus,
  asKnownTargetKind,
  parseBounty,
  parseCircle,
  parseDiscovered,
  parseSweep,
  recordTimeMs,
  type Parsed,
} from './parse.ts'

/** A, the roster's admin in fixtures/trust-labels.json, as a bounty's owner. */
const OWNER = 'ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo'
/** S1 from the same fixture, a sweeper outside the roster. */
const SWEEPER = 'a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy'
/** A bounty id from the same fixture. */
const ID = '0035G87EK4XFE'

const encoder = new TextEncoder()

function bytesOf(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value))
}

function readFixture(name: string): Uint8Array {
  // A Node `Buffer` is a `Uint8Array`, so the parsers take it as it is.
  return readFileSync(new URL(`../../../fixtures/${name}`, import.meta.url))
}

function readFixtureJson(name: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(readFixture(name))) as Record<string, unknown>
}

/** The roster in fixtures/trust-labels.json, a circle record of its own. */
function roster(): Record<string, unknown> {
  return readFixtureJson('trust-labels.json').roster as Record<string, unknown>
}

/** fixtures/discovered.json, as a value to change. */
function discovered(): Record<string, unknown> {
  return readFixtureJson('discovered.json')
}

/** A bounty record in 01's shape, with `fields` set over it. */
function bounty(fields: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    title: 'Auth and session handling',
    focus: 'security',
    brief: 'Look at `src/auth/`.',
    playbook: { suggested: 'cloudflare/security-audit@c1c8a8c', required: false },
    targets: [{ id: 't1', kind: 'repo', repo: 'github.com/org/name', rev: 'a'.repeat(40) }],
    open: true,
    reward: null,
    status: 'open',
    credits: [],
    createdAt: '2026-10-16T09:41:07Z',
    doneAt: null,
    ...fields,
  }
}

/** A sweep record in 01's shape, with `fields` set over it. */
function sweep(fields: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    bounty: `pubky://${OWNER}/pub/sweepky/bounties/${ID}.json`,
    targets: ['t1'],
    playbook: 'cloudflare/security-audit@c1c8a8c',
    status: 'running',
    startedAt: '2026-10-16T09:41:07Z',
    ...fields,
  }
}

/** `count` targets with the ids `t0`, `t1`, ... */
function targets(count: number): Record<string, unknown>[] {
  return Array.from({ length: count }, (_, i) => ({ id: `t${i}`, kind: 'commit' }))
}

function recordOf<T>(parsed: Parsed<T>): T {
  if (!parsed.ok) throw new Error(`refused: ${parsed.error.message}`)
  return parsed.record
}

/** What refused the record, as a plain object `toEqual` can compare. */
function refusal(parsed: Parsed<unknown>): { kind: string; field: string } {
  if (parsed.ok) throw new Error('the record was accepted')
  return { kind: parsed.error.kind, field: parsed.error.field }
}

describe('the fixtures', () => {
  it('reads fixtures/discovered.json: two sweeps and two cursors', () => {
    const record = recordOf(parseDiscovered(readFixture('discovered.json')))
    expect(record.sweeps).toEqual([
      { sweeper: SWEEPER, id: '0035SQ1Y8CJ7T' },
      { sweeper: 'qwujy4epafpmfei7bxn8fccfm1shzqp516sbenxi7qr6gua4n77o', id: '0035TS37CP92Y' },
    ])
    expect(record.cursors).toEqual(
      new Map([
        ['1nepshaq7wqc3ddb7361kz1mf6yum4k6qgtpyuy8zt1n5pzpue9o', '583029'],
        ['iod35orpq5tx7ntebmra8k98m5bua41dq7ys9g5rgosyf8aq9m6o', '1207'],
      ]),
    )
  })

  it('reads the trust-labels roster as a circle', () => {
    const circle = recordOf(parseCircle(bytesOf(roster())))
    expect(circle.name).toBe('Trust-label fixture circle')
    expect(circle.admin).toBe(OWNER)
    expect(circle.members).toEqual([
      { pubky: OWNER, label: 'A' },
      { pubky: 'btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy', label: 'B' },
      { pubky: '5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco', label: 'D' },
    ])
  })
})

describe('the body', () => {
  it('refuses a body over 1 MiB, counted in bytes, before decoding it', () => {
    // Padded with two-byte characters to exactly the cap: far fewer
    // characters than bytes.
    const room = MAX_RECORD_BYTES - bytesOf({ ...roster(), name: '' }).length
    const name = '\u00e9'.repeat(Math.floor(room / 2)) + 'x'.repeat(room % 2)
    expect(bytesOf({ ...roster(), name })).toHaveLength(MAX_RECORD_BYTES)
    expect(parseCircle(bytesOf({ ...roster(), name })).ok).toBe(true)
    expect(refusal(parseCircle(bytesOf({ ...roster(), name: `${name}x` })))).toEqual({
      kind: 'tooLarge',
      field: 'record',
    })
    // Not UTF-8 either, but the size is what refuses it.
    expect(refusal(parseCircle(new Uint8Array(MAX_RECORD_BYTES + 1).fill(0xff)))).toEqual({
      kind: 'tooLarge',
      field: 'record',
    })
  })

  it('refuses a body that is not UTF-8 rather than decoding it lossily', () => {
    const [before, after] = JSON.stringify({ ...roster(), name: 'SPLIT' }).split('SPLIT')
    const body = new Uint8Array([...encoder.encode(before), 0xff, ...encoder.encode(after)])
    expect(refusal(parseCircle(body))).toEqual({ kind: 'notUtf8', field: 'record' })
    // A byte-order mark is not JSON whitespace, so it is kept and refused.
    const marked = new Uint8Array([0xef, 0xbb, 0xbf, ...bytesOf(roster())])
    expect(refusal(parseCircle(marked))).toEqual({ kind: 'notJson', field: 'record' })
  })

  const parsers = [
    ['circle', parseCircle, roster],
    ['bounty', parseBounty, bounty],
    ['sweep', parseSweep, sweep],
    ['discovered', parseDiscovered, discovered],
  ] as const

  it.each(parsers)('reads a %s record of schemaVersion 1', (_, parse, make) => {
    expect(parse(bytesOf({ ...make(), schemaVersion: 1 })).ok).toBe(true)
  })

  it.each(parsers)(
    'refuses a %s record of schemaVersion 2, whatever its shape',
    (_, parse, make) => {
      expect(refusal(parse(bytesOf({ ...make(), schemaVersion: 2 })))).toEqual({
        kind: 'unsupportedVersion',
        field: 'schemaVersion',
      })
      expect(refusal(parse(bytesOf({ schemaVersion: 2 })))).toEqual({
        kind: 'unsupportedVersion',
        field: 'schemaVersion',
      })
    },
  )
})

describe('open strings and free text', () => {
  it('keeps a status and a target kind this build does not know', () => {
    const crate = { id: 't1', kind: 'crate', name: 'x' }
    const parsed = recordOf(parseBounty(bytesOf(bounty({ status: 'archived', targets: [crate] }))))
    expect(parsed.status).toBe('archived')
    expect(asKnownBountyStatus(parsed.status)).toBeNull()
    expect(parsed.targets[0]?.kind).toBe('crate')
    expect(parsed.targets[0]?.fields).toEqual(new Map([['name', 'x']]))
    expect(asKnownTargetKind('crate')).toBeNull()

    const swept = recordOf(parseSweep(bytesOf(sweep({ status: 'paused' }))))
    expect(swept.status).toBe('paused')
    expect(asKnownSweepStatus(swept.status)).toBeNull()
  })

  it('names the statuses and kinds it knows', () => {
    expect(asKnownBountyStatus('done')).toBe('done')
    expect(asKnownSweepStatus('aborted')).toBe('aborted')
    expect(asKnownTargetKind('pr')).toBe('pr')
    // Exact and case-sensitive, as core's `as_known`.
    expect(asKnownSweepStatus('Done')).toBeNull()
  })

  it('keeps free text verbatim, control and bidi characters included', () => {
    const title = 'a\u202eb\u001b[31m'
    expect(recordOf(parseBounty(bytesOf(bounty({ title })))).title).toBe(title)
  })
})

describe('the poll caps', () => {
  // 16 two-byte characters are 32 bytes; one more ASCII character is 17
  // characters in 33 bytes.
  const longest = '\u00e9'.repeat(MAX_STATUS_BYTES / 2)

  it('skips a bounty whose status is over 32 bytes', () => {
    expect(parseBounty(bytesOf(bounty({ status: longest }))).ok).toBe(true)
    expect(refusal(parseBounty(bytesOf(bounty({ status: `${longest}x` }))))).toEqual({
      kind: 'invalid',
      field: 'status',
    })
  })

  it('skips a bounty with more than 128 credits', () => {
    const credits = (count: number) => Array.from({ length: count }, () => SWEEPER)
    expect(parseBounty(bytesOf(bounty({ credits: credits(MAX_CREDITS) }))).ok).toBe(true)
    expect(refusal(parseBounty(bytesOf(bounty({ credits: credits(MAX_CREDITS + 1) }))))).toEqual({
      kind: 'invalid',
      field: 'credits',
    })
  })

  it('skips a sweep with more than 32 targets or a status over 32 bytes', () => {
    const ids = (count: number) => targets(count).map((target) => target.id)
    expect(parseSweep(bytesOf(sweep({ targets: ids(MAX_TARGETS), status: longest }))).ok).toBe(true)
    expect(refusal(parseSweep(bytesOf(sweep({ targets: ids(MAX_TARGETS + 1) }))))).toEqual({
      kind: 'invalid',
      field: 'targets',
    })
    expect(refusal(parseSweep(bytesOf(sweep({ status: `${longest}x` }))))).toEqual({
      kind: 'invalid',
      field: 'status',
    })
  })

  it('leaves a bounty with more than 32 targets alone: the cap is on sweeps', () => {
    expect(parseBounty(bytesOf(bounty({ targets: targets(MAX_TARGETS + 1) }))).ok).toBe(true)
  })
})

describe('the bounty rules core applies', () => {
  it('refuses a bounty whose targets share an id, compared case-sensitively', () => {
    const shared = [
      { id: 't1', kind: 'commit' },
      { id: 't1', kind: 'repo' },
    ]
    expect(refusal(parseBounty(bytesOf(bounty({ targets: shared }))))).toEqual({
      kind: 'invalid',
      field: 'targets',
    })
    const cased = [
      { id: 't1', kind: 'commit' },
      { id: 'T1', kind: 'repo' },
    ]
    expect(parseBounty(bytesOf(bounty({ targets: cased }))).ok).toBe(true)
  })

  it.each([
    ['a word', 'nobody'],
    ['an upper-case key', SWEEPER.toUpperCase()],
    ['a number', 7],
  ])('refuses a bounty with a credit that is %s', (_case, credit) => {
    expect(refusal(parseBounty(bytesOf(bounty({ credits: [SWEEPER, credit] }))))).toEqual({
      kind: 'invalid',
      field: 'credits',
    })
  })

  it('reads the credits in either pubky spelling, written raw', () => {
    const body = bytesOf(bounty({ status: 'done', credits: [`pubky${SWEEPER}`] }))
    expect(recordOf(parseBounty(body)).credits).toEqual([SWEEPER])
  })
})

describe('recordTimeMs', () => {
  const id = recordIdFromMicros(1_785_748_325_481_207n)
  const idMs = 1_785_748_325_481

  it('reads the RFC 3339 UTC form Sweepky writes', () => {
    expect(recordTimeMs('2026-10-16T09:41:07Z', id)).toBe(Date.UTC(2026, 9, 16, 9, 41, 7))
  })

  it.each([
    '2026-10-16T09:41:07.5Z',
    '2026-10-16T09:41:07+00:00',
    '2026-10-16 09:41:07Z',
    '2026-02-30T00:00:00Z',
    '1760607667',
    'yesterday',
  ])('falls back to the id for %j', (time) => {
    expect(recordTimeMs(time, id)).toBe(idMs)
  })
})
