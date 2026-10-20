import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parseRecordId, recordIdFromMicros, type RecordId } from '../records/ids.ts'
import type { Bounty, Sweep } from '../records/parse.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import {
  boardStatus,
  bountyTimeline,
  circleMembers,
  creditedSweepers,
  floorPlan,
  LEFT_AFTER_MS,
  RECENTLY_DONE_LIMIT,
  recentlyDone,
  sweepBadge,
  sweepsInProgress,
  sweepsToday,
  TICKER_LIMIT,
  tickerEvents,
} from './selectors.ts'
import {
  bountyKey,
  initialBoardState,
  memberState,
  sweepKey,
  type BoardState,
  type BountyEntry,
  type Resolution,
  type SweepEntry,
} from './state.ts'

/**
 * Keys from fixtures/trust-labels.json: A is the circle's admin and owns the
 * open bounty X, B is a member who sweeps it, C is a stranger who sweeps it
 * too (06's end-to-end test). D and S2 are the file's names.
 */
const A = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
const B = pubky('btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy')
const C = pubky('a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy')
const D = pubky('5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco')
const S2 = pubky('kmjs3ec6imcijf5wknsbfrh1bk4ariso7en8tteestniygu159xo')
const S3 = pubky('qwujy4epafpmfei7bxn8fccfm1shzqp516sbenxi7qr6gua4n77o')
const THREE_RUS = pubky('3rus98p3q6naiqxckzo676jeewj1whf6ai8911mxacshks18eq3y')

/** The board's fixed clock: noon on 2026-10-20, local time. */
const NOW = new Date(2026, 9, 20, 12, 0, 0).getTime()
const HOUR = 60 * 60 * 1000

const X: BountyRef = { owner: A, id: id(1) }
const BS: SweepRef = { sweeper: B, id: id(5) }
const CS: SweepRef = { sweeper: C, id: id(7) }

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`test key ${text} is not a key`)
  return key
}

/** The record id of timestamp `n` microseconds: a larger `n` is a newer record. */
function id(n: number): RecordId {
  return recordIdFromMicros(BigInt(n))
}

/** `ms` in the one time form Sweepky writes, `2026-10-20T10:00:00Z`. */
function time(ms: number): string {
  return new Date(ms).toISOString().replace('.000Z', 'Z')
}

/** A bounty of `ref`'s owner, open unless `fields` say otherwise. */
function bounty(ref: BountyRef, fields: Partial<Bounty> = {}): BountyEntry {
  const record: Bounty = {
    title: 'Auth and session handling',
    focus: 'security',
    brief: 'Look at `src/auth/`.',
    playbook: { suggested: null, required: false },
    targets: [],
    open: true,
    status: 'open',
    credits: [],
    createdAt: time(NOW - 10 * HOUR),
    doneAt: null,
    ...fields,
  }
  return { ref, record, discovered: null }
}

/** `of`'s bounty done at `doneAt`, crediting `credits`. */
function done(of: BountyEntry, credits: readonly Pubky[], doneAt = time(NOW - HOUR)): BountyEntry {
  return { ...of, record: { ...of.record, status: 'done', credits, doneAt } }
}

/** A sweep of `of`, `running` and started an hour ago unless `fields` say otherwise. */
function sweep(ref: SweepRef, of: BountyRef, fields: Partial<Sweep> = {}): SweepEntry {
  const record: Sweep = {
    bounty: of,
    targets: ['t1'],
    playbook: 'cloudflare/security-audit@c1c8a8c',
    status: 'running',
    startedAt: time(NOW - HOUR),
    finishedAt: null,
    sha256: null,
    ...fields,
  }
  return { ref, record }
}

interface Board {
  readonly admin?: Pubky | null
  readonly members?: readonly Pubky[]
  readonly bounties?: readonly BountyEntry[]
  readonly sweeps?: readonly SweepEntry[]
  readonly resolutions?: ReadonlyArray<readonly [Pubky, Resolution]>
}

function listed(key: Pubky) {
  return { pubky: key, label: null }
}

/** A board whose circle of `admin` (A by default) lists `members`, holding these records. */
function board({ admin = A, members = [], bounties = [], sweeps = [], resolutions = [] }: Board) {
  const state = initialBoardState(admin)
  return {
    ...state,
    circle: admin === null ? null : { name: 'Test circle', admin, members: members.map(listed) },
    bounties: new Map(bounties.map((entry) => [bountyKey(entry.ref), entry])),
    sweeps: new Map(sweeps.map((entry) => [sweepKey(entry.ref), entry])),
    members: new Map(
      resolutions.map(([key, resolution]) => [key, { ...memberState(state, key), resolution }]),
    ),
  } satisfies BoardState
}

describe('trust badges', () => {
  it("badges a member's sweep circle, a stranger's unknown, then known 1 once done", () => {
    // 06's end-to-end test, the derivation half: C's sweep appears with the
    // `unknown` badge, and A marking X done with credits for B and C makes
    // C `known` with one bounty from one owner.
    const sweeps = [sweep(BS, X), sweep(CS, X)]
    const before = board({ members: [B], bounties: [bounty(X)], sweeps })
    expect(sweepBadge(before, BS).label).toBe('circle')
    expect(sweepBadge(before, CS)).toEqual({ label: 'unknown', bounties: 0, owners: 0 })

    const after = board({ members: [B], bounties: [done(bounty(X), [B, C])], sweeps })
    expect(sweepBadge(after, BS).label).toBe('circle')
    expect(sweepBadge(after, CS)).toEqual({ label: 'known', bounties: 1, owners: 1 })
  })

  it('changes no badge for a self-credit or a credit on an open bounty', () => {
    // 01: the trust label ignores a credit naming the bounty's owner, and
    // only a done bounty's credits count.
    const plain = board({ members: [B, D] })
    const credited = board({
      members: [B, D],
      bounties: [
        done(bounty({ owner: D, id: id(2) }), [D]),
        bounty({ owner: A, id: id(3) }, { credits: [S3] }),
      ],
    })
    for (const sweeper of [D, S3]) {
      const ref: SweepRef = { sweeper, id: id(9) }
      expect(sweepBadge(credited, ref)).toEqual(sweepBadge(plain, ref))
    }
  })

  it('badges a sweep against the admin alone before circle.json has an answer', () => {
    const state = { ...board({ bounties: [done(bounty(X), [C])] }), circle: null }
    expect(sweepBadge(state, { sweeper: A, id: id(9) }).label).toBe('circle')
    expect(sweepBadge(state, CS)).toEqual({ label: 'known', bounties: 1, owners: 1 })
  })
})

/** fixtures/trust-labels.json, read as a board would hold it. */
interface Fixture {
  readonly roster: { readonly members: readonly { readonly pubky: string }[] }
  readonly bounties: readonly {
    readonly id: string
    readonly owner: string
    readonly status: string
    readonly credits: readonly string[]
  }[]
  readonly expected: Readonly<Record<string, { bounties: number; owners: number }>>
}

const FIXTURE = JSON.parse(
  readFileSync(new URL('../../../fixtures/trust-labels.json', import.meta.url), 'utf8'),
) as Fixture

/**
 * The fixture's roster and every bounty in it. The reducer keeps only the
 * roster's bounties, so the outsider's is left out, as the board would.
 */
function fixtureBoard(): BoardState {
  const members = FIXTURE.roster.members.map((member) => pubky(member.pubky))
  const bounties = FIXTURE.bounties
    .map((entry) => {
      const recordId = parseRecordId(entry.id)
      if (recordId === null) throw new Error(`fixture id ${entry.id} is not an id`)
      return bounty(
        { owner: pubky(entry.owner), id: recordId },
        { status: entry.status, credits: entry.credits.map(pubky) },
      )
    })
    .filter((entry) => members.includes(entry.ref.owner))
  return board({ members: members.filter((key) => key !== A), bounties })
}

function fixtureBounty(state: BoardState, recordId: string): BountyEntry {
  const entry = [...state.bounties.values()].find((held) => held.ref.id === recordId)
  if (entry === undefined) throw new Error(`fixture bounty ${recordId} is not held`)
  return entry
}

describe('creditedSweepers', () => {
  it("drops the bounty's owner and lists each sweeper once", () => {
    const state = fixtureBoard()
    // D credits D and S2: only S2 shows.
    expect(creditedSweepers(fixtureBounty(state, '0035JREYBXX7T'))).toEqual([S2])
    // C, then 3rus... twice: 3rus... shows once.
    expect(creditedSweepers(fixtureBounty(state, '0035G87EK4XFE'))).toEqual([C, THREE_RUS])
  })

  it('lists nobody for a bounty that is not done, whatever its credits say', () => {
    expect(creditedSweepers(bounty(X, { credits: [S3] }))).toEqual([])
  })
})

describe('circleMembers', () => {
  it("gives each member the credits received that trustLabels counts, the admin first", () => {
    const listed = circleMembers(fixtureBoard())
    expect(listed.map((member) => member.pubky)).toEqual([A, B, D])
    for (const member of listed) {
      const expected = FIXTURE.expected[member.pubky]
      expect(member.trust.bounties, member.pubky).toBe(expected?.bounties)
      expect(member.trust.owners, member.pubky).toBe(expected?.owners)
    }
  })

  it('says how far each member can be reached', () => {
    const at = NOW - HOUR
    const state = board({
      members: [B, C, D, S2],
      resolutions: [
        [A, { kind: 'found', homeserver: S3, resolvedAt: at }],
        [B, { kind: 'lookupFailed', resolvedAt: at }],
        [C, { kind: 'noRecord', resolvedAt: at }],
        [D, { kind: 'notBrowserReachable', homeserver: S3, resolvedAt: at }],
      ],
    })
    const reach = circleMembers(state).map((member) => [member.reachability, member.homeserver])
    expect(reach).toEqual([
      ['reachable', S3],
      ['unreachable', null],
      ['unreachable', null],
      ['notBrowserReachable', S3],
      // S2 has not been looked up yet.
      ['resolving', null],
    ])
  })
})

describe('boardStatus', () => {
  it('is no-circle when no circle is selected', () => {
    expect(boardStatus(board({ admin: null }))).toBe('no-circle')
  })

  it.each(['lookupFailed', 'noRecord'] as const)(
    "is admin-unreachable when the admin's lookup is %s",
    (kind) => {
      const state = board({ resolutions: [[A, { kind, resolvedAt: NOW }]] })
      expect(boardStatus(state)).toBe('admin-unreachable')
    },
  )

  it("is admin-unreachable when the admin's homeserver is not browser-reachable", () => {
    const state = board({
      resolutions: [[A, { kind: 'notBrowserReachable', homeserver: S3, resolvedAt: NOW }]],
    })
    expect(boardStatus(state)).toBe('admin-unreachable')
  })

  it('is ok otherwise', () => {
    expect(boardStatus(board({}))).toBe('ok')
    const found = board({ resolutions: [[A, { kind: 'found', homeserver: S3, resolvedAt: NOW }]] })
    expect(boardStatus(found)).toBe('ok')
  })
})

describe('floorPlan', () => {
  it('has no rooms without bounties', () => {
    expect(floorPlan(board({ members: [B] }), NOW)).toEqual([])
  })

  it('draws an open bounty as a lit room with its detectors', () => {
    const fresh = sweep(BS, X, { startedAt: time(NOW - LEFT_AFTER_MS + 60_000) })
    const old = sweep(CS, X, { startedAt: time(NOW - LEFT_AFTER_MS) })
    const state = board({ members: [B], bounties: [bounty(X)], sweeps: [fresh, old] })
    const [room, ...rest] = floorPlan(state, NOW)
    expect(rest).toEqual([])
    expect(room).toMatchObject({ ref: X, status: 'open', open: true, swept: false, credited: [] })
    // 04: pulsing while `running` and younger than 6 h; older fades to "left".
    const detectors = room?.detectors.map((detector) => [detector.ref, detector.signal])
    expect(detectors).toEqual([
      [CS, 'left'],
      [BS, 'pulsing'],
    ])
    // The stranger's detector carries the hollow `unknown` badge.
    expect(room?.detectors[0]?.trust.label).toBe('unknown')
  })

  it('strikes an aborted sweep and marks a room swept by a done one', () => {
    const aborted = sweep(BS, X, { status: 'aborted', finishedAt: time(NOW - 1000) })
    const finished = sweep(CS, X, { status: 'done', finishedAt: time(NOW - 1000) })
    const struck = floorPlan(board({ members: [B], bounties: [bounty(X)], sweeps: [aborted] }), NOW)
    expect(struck[0]?.swept).toBe(false)
    expect(struck[0]?.detectors[0]?.signal).toBe('aborted')

    const swept = floorPlan(board({ bounties: [bounty(X)], sweeps: [aborted, finished] }), NOW)
    expect(swept[0]?.swept).toBe(true)
    expect(swept[0]?.detectors.map((detector) => detector.signal)).toEqual(['aborted', 'done'])
  })

  it("darkens a done bounty's room and puts its credited sweepers on the door", () => {
    const rooms = floorPlan(board({ members: [B], bounties: [done(bounty(X), [A, B, C, C])] }), NOW)
    expect(rooms[0]).toMatchObject({ status: 'done', credited: [B, C] })
  })

  it('lists rooms newest first and skips a sweep whose bounty is not held', () => {
    const older = bounty({ owner: B, id: id(1) })
    const newer = bounty({ owner: A, id: id(2) })
    const elsewhere = sweep(BS, { owner: D, id: id(3) })
    const state = board({ members: [B], bounties: [older, newer], sweeps: [elsewhere] })
    const rooms = floorPlan(state, NOW)
    expect(rooms.map((room) => room.ref)).toEqual([newer.ref, older.ref])
    expect(rooms.flatMap((room) => room.detectors)).toEqual([])
  })

  it('gives the same rooms back for the same state and clock', () => {
    // zustand renders again on a selector answer that is not `===` the last.
    const state = board({ bounties: [bounty(X)], sweeps: [sweep(BS, X)] })
    expect(floorPlan(state, NOW)).toBe(floorPlan(state, NOW))
    const unread = { ...state, circle: null }
    expect(circleMembers(unread)).toBe(circleMembers(unread))
  })
})

describe('sweeps in progress and the sweeper timeline', () => {
  const first = sweep(BS, X, { startedAt: time(NOW - 3 * HOUR) })
  const second = sweep(CS, X, { startedAt: time(NOW - HOUR) })
  const finished = sweep({ sweeper: B, id: id(9) }, X, {
    status: 'done',
    startedAt: time(NOW - 2 * HOUR),
    finishedAt: time(NOW - HOUR),
  })
  const state = board({ members: [B], bounties: [bounty(X)], sweeps: [first, second, finished] })

  it('lists running sweeps newest first', () => {
    expect(sweepsInProgress(state, NOW).map((view) => view.ref)).toEqual([CS, BS])
  })

  it("orders a bounty's sweeps by startedAt, with status and finishedAt", () => {
    const timeline = bountyTimeline(state, X, NOW).map((view) => [
      view.ref,
      view.status,
      view.finishedAtMs,
    ])
    expect(timeline).toEqual([
      [BS, 'running', null],
      [finished.ref, 'done', NOW - HOUR],
      [CS, 'running', null],
    ])
  })
})

describe('sweepsToday', () => {
  it('counts the sweeps started since local midnight', () => {
    const midnight = new Date(2026, 9, 20, 0, 0, 0).getTime()
    const sweeps = [
      sweep(BS, X, { startedAt: time(midnight - 30_000) }),
      sweep(CS, X, { startedAt: time(midnight) }),
      sweep({ sweeper: B, id: id(9) }, X, { status: 'done', startedAt: time(NOW - HOUR) }),
    ]
    expect(sweepsToday(board({ members: [B], sweeps }), NOW)).toBe(2)
  })
})

describe('recentlyDone', () => {
  it('lists done bounties by doneAt, newest first, falling back to the id time', () => {
    const early = done(bounty({ owner: A, id: id(2) }), [B], time(NOW - 3 * HOUR))
    const late = done(bounty({ owner: A, id: id(3) }), [C], time(NOW - HOUR))
    // No doneAt: placed at its id's time, 1970, so last.
    const closed = done(bounty({ owner: B, id: id(4) }), [C])
    const undated = { ...closed, record: { ...closed.record, doneAt: null } }
    const state = board({ members: [B], bounties: [early, undated, late, bounty(X)] })
    const listed = recentlyDone(state).map((view) => [view.ref, view.credited])
    expect(listed).toEqual([
      [late.ref, [C]],
      [early.ref, [B]],
      [undated.ref, [C]],
    ])
  })

  it(`returns at most ${RECENTLY_DONE_LIMIT}`, () => {
    const bounties = Array.from({ length: RECENTLY_DONE_LIMIT + 1 }, (_, n) =>
      done(bounty({ owner: A, id: id(n + 1) }), [], time(NOW - (n + 1) * 60_000)),
    )
    const listed = recentlyDone(board({ bounties }))
    expect(listed).toHaveLength(RECENTLY_DONE_LIMIT)
    expect(listed[0]?.ref).toEqual(bounties[0]?.ref)
  })
})

describe('tickerEvents', () => {
  it('has no events on an empty board', () => {
    expect(tickerEvents(board({ members: [B] }))).toEqual([])
  })

  it("comes newest first from the records' own times", () => {
    const posted = bounty(X, { createdAt: time(NOW - 5 * HOUR) })
    const closed = done(posted, [C], time(NOW - HOUR))
    const finished = sweep(CS, X, {
      status: 'done',
      startedAt: time(NOW - 4 * HOUR),
      finishedAt: time(NOW - 3 * HOUR),
    })
    const struck = sweep(BS, X, {
      status: 'aborted',
      startedAt: time(NOW - 2.5 * HOUR),
      finishedAt: time(NOW - 2 * HOUR),
    })
    const state = board({ members: [B], bounties: [closed], sweeps: [finished, struck] })
    const events = tickerEvents(state)
    expect(events.map((event) => [event.kind, event.at])).toEqual([
      ['bountyDone', NOW - HOUR],
      ['sweepAborted', NOW - 2 * HOUR],
      ['sweepStarted', NOW - 2.5 * HOUR],
      ['sweepDone', NOW - 3 * HOUR],
      ['sweepStarted', NOW - 4 * HOUR],
      ['bountyPosted', NOW - 5 * HOUR],
    ])
  })

  it(`keeps at most the newest ${TICKER_LIMIT}`, () => {
    const sweeps = Array.from({ length: TICKER_LIMIT + 1 }, (_, n) =>
      sweep({ sweeper: B, id: id(n + 2) }, X, { startedAt: time(NOW - (n + 1) * 60_000) }),
    )
    const events = tickerEvents(board({ members: [B], sweeps }))
    expect(events).toHaveLength(TICKER_LIMIT)
    expect(events[0]?.at).toBe(NOW - 60_000)
  })
})
