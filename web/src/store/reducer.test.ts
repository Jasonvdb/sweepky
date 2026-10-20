import { describe, expect, it } from 'vitest'
import { REFUSAL_TEXT, type ListingResult } from '../net/listing.ts'
import type { HomeserverLookup, ListedDir, RecordAnswer } from '../net/transport.ts'
import { recordIdFromMicros, type RecordId } from '../records/ids.ts'
import { SWEEPS_DIR, type SweepkyPath } from '../records/paths.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import type { BoardAction } from './actions.ts'
import { boardReducer } from './reducer.ts'
import {
  bountyKey,
  initialBoardState,
  MAX_MEMBERS,
  memberState,
  rosterKeys,
  sweepKey,
  type BoardState,
} from './state.ts'

/**
 * The identities of 06's end-to-end test, with keys from
 * fixtures/trust-labels.json (A, B and S1 there): A is the circle's admin
 * and owns the open bounty X, B is a member who sweeps it, C is a stranger
 * who sweeps it too.
 */
const A = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
const B = pubky('btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy')
const C = pubky('a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy')
/** D in the same file, standing in for a homeserver's key. */
const HOMESERVER = pubky('5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco')

/** When the poller got an answer: two polls, 30 s apart. */
const T0 = Date.UTC(2026, 9, 20, 12, 0, 0)
const T1 = T0 + 30_000

const X: BountyRef = { owner: A, id: id(1) }
/** C's sweep of X. */
const S: SweepRef = { sweeper: C, id: id(7) }
/** B's sweep of X. */
const BS: SweepRef = { sweeper: B, id: id(5) }

const FINISHED_AT = '2026-10-20T11:52:00Z'
const DONE_AT = '2026-10-20T12:30:00Z'

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`test key ${text} is not a key`)
  return key
}

/** The record id of timestamp `n`: a larger `n` is a newer record. */
function id(n: number): RecordId {
  return recordIdFromMicros(BigInt(n))
}

/** The z-base32 alphabet, in value order. */
const Z32 = 'ybndrfg8ejkmcpqxot1uwisza345h769'

/**
 * Key number `n`: `n` in z-base32 digits, padded with `y` (zero) and ended
 * with a canonical `y`.
 */
function syntheticKey(n: number): Pubky {
  const digits = [...n.toString(32)].map((digit) => Z32.charAt(parseInt(digit, 32))).join('')
  return pubky(`${digits.padStart(51, 'y')}y`)
}

const encoder = new TextEncoder()

/** A 2xx answer whose body is `value` as JSON. */
function body(value: unknown): RecordAnswer {
  return { kind: 'body', body: encoder.encode(JSON.stringify(value)) }
}

const ABSENT: RecordAnswer = { kind: 'absent' }
const FAILED: RecordAnswer = { kind: 'failed', message: 'the homeserver answered 503' }
const TOO_LARGE: RecordAnswer = { kind: 'tooLarge' }
const NOT_JSON: RecordAnswer = { kind: 'body', body: encoder.encode('{"schemaVersion": 1,') }

function circleJson(members: readonly Pubky[], admin: Pubky = A): Record<string, unknown> {
  const listed = members.map((key) => ({ pubky: key }))
  return { schemaVersion: 1, name: 'Test circle', admin, members: listed }
}

/** An open bounty in 01's shape, with `fields` set over it. */
function bountyJson(fields: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    title: 'Auth and session handling',
    focus: 'security',
    brief: 'Look at `src/auth/`.',
    playbook: { suggested: null, required: false },
    targets: [{ id: 't1', kind: 'repo', repo: 'github.com/org/name', rev: 'a'.repeat(40) }],
    open: true,
    status: 'open',
    credits: [],
    createdAt: '2026-10-20T10:00:00Z',
    doneAt: null,
    ...fields,
  }
}

/** `ref`'s URL, its owner spelt `prefix` + raw z-base32. */
function bountyUrl(ref: BountyRef, prefix = ''): string {
  return `pubky://${prefix}${ref.owner}/pub/sweepky/bounties/${ref.id}.json`
}

/** A `running` sweep of the bounty at `bounty`, with `fields` set over it. */
function sweepJson(bounty: string, fields: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    bounty,
    targets: ['t1'],
    playbook: 'cloudflare/security-audit@c1c8a8c',
    status: 'running',
    startedAt: '2026-10-20T11:00:00Z',
    ...fields,
  }
}

/** A discovered-sweeps file listing `sweeps`. The board ignores its cursors. */
function discoveredJson(sweeps: readonly SweepRef[]): Record<string, unknown> {
  return {
    schemaVersion: 1,
    sweeps: sweeps.map((ref) => `pubky://${ref.sweeper}/pub/sweepky/sweeps/${ref.id}.json`),
    cursors: { [HOMESERVER]: '42' },
  }
}

function circleRead(answer: RecordAnswer, at = T0, admin: Pubky = A): BoardAction {
  return { type: 'circleRead', admin, answer, at }
}

function bountyRead(ref: BountyRef, answer: RecordAnswer, at = T0): BoardAction {
  return { type: 'bountyRead', ref, answer, at }
}

function sweepRead(ref: SweepRef, answer: RecordAnswer, at = T0): BoardAction {
  return { type: 'sweepRead', ref, answer, at }
}

function discoveredRead(bounty: BountyRef, answer: RecordAnswer, at = T0): BoardAction {
  return { type: 'discoveredRead', bounty, answer, at }
}

function lookedUp(member: Pubky, lookup: HomeserverLookup, at = T0): BoardAction {
  return { type: 'homeserverLookedUp', member, lookup, at }
}

function listingRead(member: Pubky, dir: ListedDir, result: ListingResult, at = T0): BoardAction {
  return { type: 'listingRead', member, dir, result, at }
}

function sweepRecord(n: number): SweepkyPath {
  return { kind: 'sweepRecord', id: id(n) }
}

function listed(...entries: SweepkyPath[]): ListingResult {
  return { kind: 'listed', listing: { entries, skipped: 0 } }
}

const FOUND: HomeserverLookup = { kind: 'found', homeserver: HOMESERVER }
const REFUSED: ListingResult = { kind: 'refused', reason: 'notUtf8', message: REFUSAL_TEXT.notUtf8 }

function fold(state: BoardState, ...actions: BoardAction[]): BoardState {
  return actions.reduce(boardReducer, state)
}

/** A's circle with `members`, read once. */
function circleOf(members: readonly Pubky[]): BoardState {
  return fold(initialBoardState(A), circleRead(body(circleJson(members))))
}

/** The circle {A, B}, A's open bounty X, and X's discovered file listing `sweeps`. */
function xListing(...sweeps: SweepRef[]): BoardState {
  return fold(
    circleOf([B]),
    bountyRead(X, body(bountyJson())),
    discoveredRead(X, body(discoveredJson(sweeps))),
  )
}

/** `xListing(S)` with C's sweep S of X read: attached to X. */
function withStrangersSweep(): BoardState {
  return fold(xListing(S), sweepRead(S, body(sweepJson(bountyUrl(X)))))
}

function bountyOf(state: BoardState, ref: BountyRef) {
  return state.bounties.get(bountyKey(ref))
}

function sweepOf(state: BoardState, ref: SweepRef) {
  return state.sweeps.get(sweepKey(ref))
}

describe('sweeps', () => {
  it('replaces a running sweep with its done re-read, finishedAt included', () => {
    // Done-when: a `running` → `done` sweep transition within one poll.
    const running = fold(circleOf([B]), sweepRead(BS, body(sweepJson(bountyUrl(X)))))
    expect(sweepOf(running, BS)?.record).toMatchObject({ status: 'running', finishedAt: null })
    const done = sweepJson(bountyUrl(X), { status: 'done', finishedAt: FINISHED_AT })
    const state = boardReducer(running, sweepRead(BS, body(done), T1))
    expect(sweepOf(state, BS)?.record).toMatchObject({ status: 'done', finishedAt: FINISHED_AT })
  })

  it.each([
    ['aborted', 'running'],
    ['aborted', 'done'],
    ['done', 'running'],
  ])('keeps a %s sweep as it is when a later read says %s', (final, later) => {
    // `submit` never moves a sweep on from `done` or `aborted` (P2b).
    const first = sweepJson(bountyUrl(X), { status: final, finishedAt: FINISHED_AT })
    const before = fold(circleOf([B]), sweepRead(BS, body(first)))
    const reread = sweepJson(bountyUrl(X), { status: later })
    const state = boardReducer(before, sweepRead(BS, body(reread)))
    expect(sweepOf(state, BS)).toBe(sweepOf(before, BS))
  })

  it('removes a sweep on a 404 re-read', () => {
    const before = fold(circleOf([B]), sweepRead(BS, body(sweepJson(bountyUrl(X)))))
    expect(sweepOf(boardReducer(before, sweepRead(BS, ABSENT)), BS)).toBeUndefined()
  })

  it.each([
    ['is not JSON', NOT_JSON],
    ['is a newer schemaVersion', body(sweepJson(bountyUrl(X), { schemaVersion: 2 }))],
    ['is over the record cap', TOO_LARGE],
  ])('keeps the last good sweep when a re-read %s', (_, answer) => {
    const before = fold(circleOf([B]), sweepRead(BS, body(sweepJson(bountyUrl(X)))))
    expect(sweepOf(boardReducer(before, sweepRead(BS, answer)), BS)).toBe(sweepOf(before, BS))
  })
})

describe("strangers' sweeps", () => {
  it.each([
    ['raw', ''],
    ['pubky-prefixed', 'pubky'],
  ])(
    "attaches a stranger's sweep an open bounty's discovered file lists, owner spelt %s",
    (_, prefix) => {
      // Done-when: a stranger's sweep appearing after the owner's `pull`
      // has published it to discovered.json. The bounty URL is compared by
      // key, so either spelling of A names X.
      const read = sweepRead(S, body(sweepJson(bountyUrl(X, prefix))))
      const state = boardReducer(xListing(S), read)
      expect(sweepOf(state, S)?.record.bounty).toEqual(X)
      expect(bountyOf(state, X)?.discovered).toEqual({
        sweeps: new Map([[sweepKey(S), S]]),
        readAt: T0,
      })
    },
  )

  it.each([
    ['another bounty of the same owner', { owner: A, id: id(2) }],
    ['the same id under another owner', { owner: B, id: id(1) }],
  ])("drops a listed stranger's sweep whose bounty URL names %s", (_, other: BountyRef) => {
    const before = xListing(S)
    expect(boardReducer(before, sweepRead(S, body(sweepJson(bountyUrl(other)))))).toBe(before)
  })

  it("detaches a stranger's sweep that a later discovered list no longer names", () => {
    const emptyList = discoveredRead(X, body(discoveredJson([])), T1)
    const state = boardReducer(withStrangersSweep(), emptyList)
    expect(sweepOf(state, S)).toBeUndefined()
    expect(bountyOf(state, X)?.discovered).toEqual({ sweeps: new Map(), readAt: T1 })
  })

  it.each([
    ['fails', FAILED, T0],
    ['no longer parses', NOT_JSON, T1],
    ['is over the record cap', TOO_LARGE, T1],
  ])('keeps the last good discovered list when a read %s', (_, answer, readAt) => {
    // A failed request is no answer, so the list keeps its time too; a body
    // that cannot be read is an answer, just not a list.
    const state = boardReducer(withStrangersSweep(), discoveredRead(X, answer, T1))
    expect(sweepOf(state, S)).toBeDefined()
    expect(bountyOf(state, X)?.discovered).toEqual({
      sweeps: new Map([[sweepKey(S), S]]),
      readAt,
    })
  })

  it("keeps an open bounty's strangers' sweeps when a re-read finds it done", () => {
    // Done-when: the bounty flipping to done with its credits and C's badge
    // becoming `known 1`. `pull` writes discovered.json for open bounties
    // only, so after `done` the last list read is the one to keep.
    const done = bountyJson({ status: 'done', doneAt: DONE_AT, credits: [B, C] })
    const state = boardReducer(withStrangersSweep(), bountyRead(X, body(done), T1))
    expect(bountyOf(state, X)?.record).toMatchObject({ status: 'done', credits: [B, C] })
    expect(bountyOf(state, X)?.discovered?.sweeps.has(sweepKey(S))).toBe(true)
    expect(sweepOf(state, S)).toBeDefined()
  })
})

describe('bounties', () => {
  it('updates status, doneAt and credits when a bounty is re-read as done', () => {
    const done = bountyJson({ status: 'done', doneAt: DONE_AT, credits: [B, C] })
    const open = bountyRead(X, body(bountyJson()))
    const state = fold(circleOf([B]), open, bountyRead(X, body(done), T1))
    expect(bountyOf(state, X)?.record).toMatchObject({
      status: 'done',
      doneAt: DONE_AT,
      credits: [B, C],
    })
  })

  it("removes a bounty on a 404 re-read, and the strangers' sweeps its list attached", () => {
    const state = boardReducer(withStrangersSweep(), bountyRead(X, ABSENT, T1))
    expect(bountyOf(state, X)).toBeUndefined()
    expect(sweepOf(state, S)).toBeUndefined()
  })

  it.each([
    ['is not JSON', NOT_JSON],
    ['is a newer schemaVersion', body(bountyJson({ schemaVersion: 2 }))],
    ['is over the record cap', TOO_LARGE],
  ])('keeps the last good bounty when a re-read %s', (_, answer) => {
    const before = fold(circleOf([B]), bountyRead(X, body(bountyJson())))
    expect(bountyOf(boardReducer(before, bountyRead(X, answer, T1)), X)).toBe(bountyOf(before, X))
  })

  it('keeps a target of a kind this build does not know, for a placeholder', () => {
    const crate = { id: 't2', kind: 'crate', name: 'sweepky-core', version: '0.1.0' }
    const repo = { id: 't1', kind: 'repo', rev: 'b'.repeat(40) }
    const record = bountyJson({ targets: [repo, crate] })
    const targets = bountyOf(fold(circleOf([]), bountyRead(X, body(record))), X)?.record.targets
    expect(targets?.map((target) => target.kind)).toEqual(['repo', 'crate'])
    expect(targets?.[1]?.fields.get('name')).toBe('sweepky-core')
  })

  it('ignores records from keys outside the roster and the discovered sweepers', () => {
    const before = xListing()
    const actions = [
      bountyRead({ owner: C, id: id(3) }, body(bountyJson())),
      sweepRead(S, body(sweepJson(bountyUrl(X)))),
      lookedUp(C, FOUND),
      listingRead(C, SWEEPS_DIR, listed(sweepRecord(7))),
    ]
    for (const action of actions) expect(boardReducer(before, action)).toBe(before)
  })
})

describe('circle', () => {
  it.each([
    ['names another admin', body(circleJson([B], C))],
    ['is gone', ABSENT],
  ])('counts the admin alone when circle.json %s', (_, answer) => {
    // As `pull` counts its owner alone (P2c): the side of less trust.
    const state = boardReducer(circleOf([B]), circleRead(answer, T1))
    expect(rosterKeys(state)).toEqual([A])
  })

  it.each([
    ['fails', FAILED],
    ['no longer parses', NOT_JSON],
  ])('keeps the last good circle when a re-read %s', (_, answer) => {
    const before = circleOf([B])
    expect(boardReducer(before, circleRead(answer, T1)).circle).toBe(before.circle)
  })

  it('keeps each member once and the first MAX_MEMBERS keys, the admin first', () => {
    // The CLI polls the same keys (pull/roster.rs, `bounded`), so a key it
    // cuts is outside the circle on the board too.
    const more = Array.from({ length: MAX_MEMBERS }, (_, n) => syntheticKey(n + 1))
    const keys = rosterKeys(circleOf([A, B, B, ...more]))
    expect(keys).toEqual([A, B, ...more.slice(0, MAX_MEMBERS - 2)])
  })

  it('drops what a key that leaves the roster had: its member state, bounties and sweeps', () => {
    const bBounty: BountyRef = { owner: B, id: id(3) }
    const before = fold(
      circleOf([B]),
      lookedUp(B, FOUND),
      bountyRead(bBounty, body(bountyJson())),
      sweepRead(BS, body(sweepJson(bountyUrl(X)))),
    )
    const state = boardReducer(before, circleRead(body(circleJson([])), T1))
    expect(state.members.has(B)).toBe(false)
    expect(bountyOf(state, bBounty)).toBeUndefined()
    expect(sweepOf(state, BS)).toBeUndefined()
  })
})

describe('homeservers', () => {
  it.each([
    ['found', FOUND, { kind: 'found', homeserver: HOMESERVER, resolvedAt: T1 }],
    [
      'no record',
      { kind: 'unreachable', reason: 'noRecord' },
      { kind: 'noRecord', resolvedAt: T1 },
    ],
    [
      'a failed lookup',
      { kind: 'unreachable', reason: 'lookupFailed' },
      { kind: 'lookupFailed', resolvedAt: T1 },
    ],
  ] as const)("keeps a roster key's lookup and when it was made: %s", (_, lookup, resolution) => {
    const state = boardReducer(circleOf([B]), lookedUp(B, lookup, T1))
    expect(memberState(state, B).resolution).toEqual(resolution)
  })

  it('marks a roster key not browser-reachable when a read says so, keeping its homeserver', () => {
    const unreachable: RecordAnswer = { kind: 'notBrowserReachable' }
    const state = fold(circleOf([B]), lookedUp(B, FOUND), sweepRead(BS, unreachable, T1))
    expect(memberState(state, B).resolution).toEqual({
      kind: 'notBrowserReachable',
      homeserver: HOMESERVER,
      resolvedAt: T1,
    })
  })

  it.each([
    ['a sweep read failed', B, sweepRead(BS, FAILED, T1)],
    ['a listing failed', B, listingRead(B, SWEEPS_DIR, { kind: 'failed', message: 'failed' }, T1)],
    ['a listing was refused', B, listingRead(B, SWEEPS_DIR, REFUSED, T1)],
    ['circle.json failed', A, circleRead(FAILED, T1)],
    ['discovered.json failed', A, discoveredRead(X, FAILED, T1)],
  ])('notes when a read of a roster key last failed: %s', (_, key, action) => {
    // The poller looks a key up again after a failed read (04).
    const state = fold(xListing(), lookedUp(key, FOUND), action)
    expect(memberState(state, key)).toMatchObject({
      resolution: { kind: 'found', resolvedAt: T0 },
      readFailedAt: T1,
    })
  })
})

describe('listings', () => {
  it('passes the watermark over each listed record once read, never over one unread', () => {
    // As `pull` moves it (P2c): what a failure leaves unread stays above the
    // watermark, so the next listing names it again.
    const listing = listed(
      sweepRecord(3),
      { kind: 'sweepPackage', id: id(3) },
      sweepRecord(2),
      sweepRecord(1),
    )
    const running = body(sweepJson(bountyUrl(X)))
    const first = fold(circleOf([B]), listingRead(B, SWEEPS_DIR, listing))
    expect(memberState(first, B).listings[SWEEPS_DIR]).toEqual({
      watermark: null,
      listed: [id(1), id(2), id(3)].map((n) => ({ id: n, settled: false })),
    })

    const failed = fold(
      first,
      sweepRead({ sweeper: B, id: id(1) }, running),
      sweepRead({ sweeper: B, id: id(3) }, running),
      sweepRead({ sweeper: B, id: id(2) }, FAILED),
      // The next poll lists down to the watermark again: 3 stays read.
      listingRead(B, SWEEPS_DIR, listed(sweepRecord(3), sweepRecord(2)), T1),
    )
    expect(memberState(failed, B).listings[SWEEPS_DIR]).toEqual({
      watermark: id(1),
      listed: [
        { id: id(2), settled: false },
        { id: id(3), settled: true },
      ],
    })

    // 2 no longer parses: skipped for good, so the watermark passes it and 3.
    const settled = boardReducer(failed, sweepRead({ sweeper: B, id: id(2) }, NOT_JSON, T1))
    expect(memberState(settled, B).listings[SWEEPS_DIR]).toEqual({ watermark: id(3), listed: [] })
  })

  it("keeps where each roster key's turn through its done bounties stopped", () => {
    const action: BoardAction = {
      type: 'rereadTurnTaken',
      member: B,
      kind: 'doneBounties',
      lastRead: id(4),
    }
    expect(memberState(boardReducer(circleOf([B]), action), B).rereadAfter).toEqual({
      openBounties: null,
      runningSweeps: null,
      doneBounties: id(4),
    })
  })
})
