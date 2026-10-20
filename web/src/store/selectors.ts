// The board's derived views: what each page draws, computed from the state
// the reducer keeps (state.ts) and nothing else, so a closed tab misses
// nothing and nothing is faked (04, "Live-ness").
//
// Every selector is a pure function of the state and, where age matters, of
// `now` in milliseconds since 1970. The clock is an argument, never read
// here, so the same state and clock always draw the same board. Pass a `now`
// that changes when the view should age (a ticking clock in the store), not
// `Date.now()` on every render, or the memo below never hits.
//
// Memoised: zustand renders a component again when its selector returns a
// value that is not `===` the last one, so a selector that built a new array
// on every call would render on every store change. Each selector keeps its
// last inputs and answer, and the reducer replaces only the parts of the
// state that changed, so an unchanged part gives back the same answer.
//
// Trust: a badge (`circle`, `known N`, `unknown`) is a label from the
// roster and the credits on done bounties (trust/trust.ts). `known N` is not
// trust; only the circle's content is (P2c).

import { recordIdMicros, type RecordId } from '../records/ids.ts'
import {
  asKnownBountyStatus,
  asKnownSweepStatus,
  recordTimeMs,
  type Circle,
  type KnownBountyStatus,
  type KnownSweepStatus,
} from '../records/parse.ts'
import type { Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import {
  creditedSweepers as creditsWithoutOwner,
  trustLabels,
  type Trust,
  type TrustTable,
} from '../trust/trust.ts'
import {
  bountyKey,
  memberState,
  type BoardState,
  type BountyEntry,
  type MemberState,
  type RecordKey,
  type Resolution,
  type SweepEntry,
} from './state.ts'

/** How long a `running` sweep pulses before it fades to "left": 6 h (04). */
export const LEFT_AFTER_MS = 6 * 60 * 60 * 1000

/** The most done bounties "recently done" lists. */
export const RECENTLY_DONE_LIMIT = 10

/** The most events the ticker holds. */
export const TICKER_LIMIT = 20

// Trust

/** The trust table for the board's roster and every bounty it holds. */
export function trustTable(state: BoardState): TrustTable {
  return trustTableOf(state.admin, state.circle, state.bounties)
}

const trustTableOf = lastResult(
  (
    admin: Pubky | null,
    circle: Circle | null,
    bounties: ReadonlyMap<RecordKey, BountyEntry>,
  ): TrustTable => {
    const roster = rosterOf(admin, circle)
    if (roster === null) return { get: () => UNKNOWN }
    // One entry per held record: the map is keyed by owner and id, so no
    // bounty counts twice.
    const credited = [...bounties.values()].map(({ ref, record }) => ({
      owner: ref.owner,
      status: record.status,
      credits: record.credits,
    }))
    return trustLabels(roster, credited)
  },
)

const UNKNOWN: Trust = { label: 'unknown', bounties: 0, owners: 0 }

/**
 * The roster in effect as a `Circle`, as `rosterKeys` reads it: before
 * circle.json has an answer, the admin alone. `null` with no circle selected.
 */
function rosterOf(admin: Pubky | null, circle: Circle | null): Circle | null {
  if (admin === null) return null
  return circle ?? { name: '', admin, members: [] }
}

/** The badge on `ref`'s sweep: its sweeper's trust. */
export function sweepBadge(state: BoardState, ref: SweepRef): Trust {
  return trustTable(state).get(ref.sweeper)
}

/**
 * The sweepers a done bounty credits, each once, never its owner (01: the
 * board ignores any credit naming the bounty's owner), in the order its
 * credits first name them. None for a bounty that is not exactly `done`,
 * whose credits count for nothing yet. The one source for a dark room's
 * marks and the bounty page's credited list.
 */
export function creditedSweepers({ ref, record }: BountyEntry): readonly Pubky[] {
  if (asKnownBountyStatus(record.status) !== 'done') return []
  const { status, credits } = record
  return [...creditsWithoutOwner({ owner: ref.owner, status, credits })]
}

// Sweeps

/**
 * What a sweep's detector shows: `pulsing` while `running` and younger than
 * LEFT_AFTER_MS, `left` once older, `done` (the room is swept), `aborted`
 * (struck, no pulse), or `unrecognised` for a status this build does not
 * know.
 */
export type SweepSignal = 'pulsing' | 'left' | 'done' | 'aborted' | 'unrecognised'

/** One sweep as the views draw it: a detector, a timeline row, an in-progress line. */
export interface SweepView {
  readonly ref: SweepRef
  /** The bounty its record names. */
  readonly bounty: BountyRef
  readonly status: KnownSweepStatus | null
  readonly signal: SweepSignal
  readonly trust: Trust
  readonly startedAtMs: number
  readonly finishedAtMs: number | null
}

/** Every held sweep as a view, oldest first. */
function sweepViews(state: BoardState, now: number): readonly SweepView[] {
  return sweepViewsOf(trustTable(state), state.sweeps, now)
}

const sweepViewsOf = lastResult(
  (table: TrustTable, sweeps: ReadonlyMap<RecordKey, SweepEntry>, now: number) =>
    [...sweeps.values()].map((entry) => sweepView(entry, table, now)).sort(byStart),
)

function sweepView({ ref, record }: SweepEntry, table: TrustTable, now: number): SweepView {
  const status = asKnownSweepStatus(record.status)
  const startedAtMs = recordTimeMs(record.startedAt, ref.id)
  return {
    ref,
    bounty: record.bounty,
    status,
    signal: signalOf(status, now - startedAtMs),
    trust: table.get(ref.sweeper),
    startedAtMs,
    finishedAtMs: record.finishedAt === null ? null : recordTimeMs(record.finishedAt, ref.id),
  }
}

function signalOf(status: KnownSweepStatus | null, ageMs: number): SweepSignal {
  switch (status) {
    case 'running':
      return ageMs < LEFT_AFTER_MS ? 'pulsing' : 'left'
    case 'done':
    case 'aborted':
      return status
    case null:
      return 'unrecognised'
  }
}

/** Oldest start first; equal starts by id, then by sweeper, so the order is total. */
function byStart(a: SweepView, b: SweepView): number {
  return (
    a.startedAtMs - b.startedAtMs ||
    compareText(a.ref.id, b.ref.id) ||
    compareText(a.ref.sweeper, b.ref.sweeper)
  )
}

/** Running sweeps, newest first; those past LEFT_AFTER_MS included, as `left`. */
export function sweepsInProgress(state: BoardState, now: number): readonly SweepView[] {
  return inProgressOf(sweepViews(state, now))
}

const inProgressOf = lastResult((views: readonly SweepView[]) =>
  views.filter((view) => view.status === 'running').reverse(),
)

/** `bounty`'s sweeps, oldest start first: the bounty page's sweeper timeline. */
export function bountyTimeline(
  state: BoardState,
  bounty: BountyRef,
  now: number,
): readonly SweepView[] {
  // Keyed by the bounty's key, a string, so a caller's fresh `BountyRef`
  // object for the same bounty still hits the memo.
  return timelineOf(sweepViews(state, now), bountyKey(bounty))
}

const timelineOf = lastResult((views: readonly SweepView[], key: RecordKey) =>
  views.filter((view) => bountyKey(view.bounty) === key),
)

/** How many sweeps started between local midnight and `now`. */
export function sweepsToday(state: BoardState, now: number): number {
  const midnight = new Date(now)
  midnight.setHours(0, 0, 0, 0)
  const from = midnight.getTime()
  const startedToday = sweepViews(state, now).filter(
    (view) => view.startedAtMs >= from && view.startedAtMs <= now,
  )
  return startedToday.length
}

// Bounties

/** One bounty as the floor plan draws it. */
export interface Room {
  readonly ref: BountyRef
  readonly title: string
  /** `open` is lit, `done` is dark; `null` is a status this build does not know. */
  readonly status: KnownBountyStatus | null
  /** The `open` marker: strangers may sweep it. */
  readonly open: boolean
  /** Whether any of its sweeps is done. */
  readonly swept: boolean
  /** Its sweeps, oldest start first. */
  readonly detectors: readonly SweepView[]
  /** The marks on a dark room's door: `creditedSweepers`. */
  readonly credited: readonly Pubky[]
}

/**
 * Every held bounty as a room, newest first. No bounties, no rooms: the
 * empty state draws no sample room.
 */
export function floorPlan(state: BoardState, now: number): readonly Room[] {
  return floorPlanOf(state.bounties, sweepViews(state, now))
}

const floorPlanOf = lastResult(
  (bounties: ReadonlyMap<RecordKey, BountyEntry>, views: readonly SweepView[]): readonly Room[] => {
    const byBounty = new Map<RecordKey, SweepView[]>()
    for (const view of views) {
      const key = bountyKey(view.bounty)
      const held = byBounty.get(key)
      if (held === undefined) byBounty.set(key, [view])
      else held.push(view)
    }
    const entries = [...bounties.values()].sort((a, b) => byNewestId(a.ref, b.ref))
    return entries.map((entry) => {
      const detectors = byBounty.get(bountyKey(entry.ref)) ?? []
      return {
        ref: entry.ref,
        title: entry.record.title,
        status: asKnownBountyStatus(entry.record.status),
        open: entry.record.open,
        swept: detectors.some((view) => view.status === 'done'),
        detectors,
        credited: creditedSweepers(entry),
      }
    })
  },
)

/** One done bounty in "recently done". */
export interface DoneBounty {
  readonly ref: BountyRef
  readonly title: string
  /** Its `doneAt`, or its id's time when it has none. */
  readonly doneAtMs: number
  readonly credited: readonly Pubky[]
}

/** The done bounties, latest done first, at most RECENTLY_DONE_LIMIT. */
export function recentlyDone(state: BoardState): readonly DoneBounty[] {
  return recentlyDoneOf(state.bounties)
}

const recentlyDoneOf = lastResult((bounties: ReadonlyMap<RecordKey, BountyEntry>) =>
  [...bounties.values()]
    .filter((entry) => asKnownBountyStatus(entry.record.status) === 'done')
    .map((entry) => ({
      ref: entry.ref,
      title: entry.record.title,
      doneAtMs: doneAtMs(entry),
      credited: creditedSweepers(entry),
    }))
    .sort((a, b) => b.doneAtMs - a.doneAtMs || byNewestId(a.ref, b.ref))
    .slice(0, RECENTLY_DONE_LIMIT),
)

function doneAtMs({ ref, record }: BountyEntry): number {
  return record.doneAt === null ? idTimeMs(ref.id) : recordTimeMs(record.doneAt, ref.id)
}

/** Newest id first; one id from two owners by owner key, so the order is total. */
function byNewestId(a: BountyRef, b: BountyRef): number {
  return compareText(b.id, a.id) || compareText(a.owner, b.owner)
}

// The ticker

export type TickerKind =
  | 'bountyPosted'
  | 'bountyDone'
  | 'sweepStarted'
  | 'sweepDone'
  | 'sweepAborted'

/** Something a record says happened, at the time the record gives. */
export interface TickerEvent {
  /** Unique among the events, for a React list key. */
  readonly key: string
  readonly kind: TickerKind
  readonly at: number
  readonly bounty: BountyRef
  /** The sweep, for a sweep's event. */
  readonly sweep: SweepRef | null
}

/**
 * The newest TICKER_LIMIT events, newest first, each read from a held
 * record's own time fields. A record without the field (a done sweep with no
 * `finishedAt`) gives no event for it: the ticker shows only what a record
 * says, never a time it guessed.
 */
export function tickerEvents(state: BoardState): readonly TickerEvent[] {
  return tickerEventsOf(state.bounties, state.sweeps)
}

const tickerEventsOf = lastResult(
  (bounties: ReadonlyMap<RecordKey, BountyEntry>, sweeps: ReadonlyMap<RecordKey, SweepEntry>) => {
    const events: TickerEvent[] = []
    for (const [key, { ref, record }] of bounties) {
      const at = recordTimeMs(record.createdAt, ref.id)
      events.push({ key: `${key}:posted`, kind: 'bountyPosted', at, bounty: ref, sweep: null })
      if (asKnownBountyStatus(record.status) === 'done' && record.doneAt !== null) {
        events.push({
          key: `${key}:done`,
          kind: 'bountyDone',
          at: recordTimeMs(record.doneAt, ref.id),
          bounty: ref,
          sweep: null,
        })
      }
    }
    for (const [key, { ref, record }] of sweeps) {
      const { bounty } = record
      const at = recordTimeMs(record.startedAt, ref.id)
      events.push({ key: `${key}:started`, kind: 'sweepStarted', at, bounty, sweep: ref })
      const status = asKnownSweepStatus(record.status)
      if ((status === 'done' || status === 'aborted') && record.finishedAt !== null) {
        const kind = status === 'done' ? 'sweepDone' : 'sweepAborted'
        const finishedAt = recordTimeMs(record.finishedAt, ref.id)
        events.push({ key: `${key}:finished`, kind, at: finishedAt, bounty, sweep: ref })
      }
    }
    events.sort((a, b) => b.at - a.at || compareText(a.key, b.key))
    return events.slice(0, TICKER_LIMIT)
  },
)

// The circle

/**
 * How far the board can reach a member's storage. `resolving` before the
 * first lookup; `unreachable` with no pkarr record or a failed lookup;
 * `notBrowserReachable` when its homeserver has no ICANN HTTPS endpoint,
 * which a browser needs and the CLI does not (04, "Live-ness").
 */
export type Reachability = 'resolving' | 'reachable' | 'notBrowserReachable' | 'unreachable'

/** One roster key on the Circle page. */
export interface MemberView {
  readonly pubky: Pubky
  readonly isAdmin: boolean
  /** The label circle.json gives it; `null` for the admin, whose entry the roster drops. */
  readonly label: string | null
  readonly homeserver: Pubky | null
  readonly reachability: Reachability
  /** Its badge, and the credits received behind it. */
  readonly trust: Trust
  /**
   * Its last activity: the newest time any of its held records gives, in
   * milliseconds since 1970, or `null` when the board holds none of them.
   */
  readonly lastActivityMs: number | null
}

/** The roster, the admin first, as the Circle page lists it. */
export function circleMembers(state: BoardState): readonly MemberView[] {
  return circleMembersOf(
    state.admin,
    state.circle,
    state.members,
    trustTable(state),
    lastActivityOf(state.bounties, state.sweeps),
  )
}

const circleMembersOf = lastResult(
  (
    admin: Pubky | null,
    circle: Circle | null,
    members: ReadonlyMap<Pubky, MemberState>,
    table: TrustTable,
    lastActivity: ReadonlyMap<Pubky, number>,
  ): readonly MemberView[] => {
    // Inside the memo: `rosterOf` builds a new circle while circle.json has
    // no answer, which would never be `===` the last one.
    const roster = rosterOf(admin, circle)
    if (roster === null) return []
    const adminEntry = { pubky: roster.admin, label: null }
    return [adminEntry, ...roster.members].map(({ pubky, label }) => {
      const resolution = members.get(pubky)?.resolution ?? null
      return {
        pubky,
        isAdmin: pubky === roster.admin,
        label,
        homeserver: homeserverOf(resolution),
        reachability: reachabilityOf(resolution),
        trust: table.get(pubky),
        lastActivityMs: lastActivity.get(pubky) ?? null,
      }
    })
  },
)

/**
 * Each writer's newest record time: a bounty's `doneAt` or `createdAt`, a
 * sweep's `finishedAt` or `startedAt`, whichever is latest. Strangers'
 * sweeps get an entry too, which the Circle page never asks for.
 */
const lastActivityOf = lastResult(
  (
    bounties: ReadonlyMap<RecordKey, BountyEntry>,
    sweeps: ReadonlyMap<RecordKey, SweepEntry>,
  ): ReadonlyMap<Pubky, number> => {
    const newest = new Map<Pubky, number>()
    const note = (writer: Pubky, ms: number) => {
      newest.set(writer, Math.max(ms, newest.get(writer) ?? -Infinity))
    }
    for (const { ref, record } of bounties.values()) {
      note(ref.owner, recordTimeMs(record.createdAt, ref.id))
      if (record.doneAt !== null) note(ref.owner, recordTimeMs(record.doneAt, ref.id))
    }
    for (const { ref, record } of sweeps.values()) {
      note(ref.sweeper, recordTimeMs(record.startedAt, ref.id))
      if (record.finishedAt !== null) note(ref.sweeper, recordTimeMs(record.finishedAt, ref.id))
    }
    return newest
  },
)

/** The homeserver a member's last lookup found, if any. */
function homeserverOf(resolution: Resolution | null): Pubky | null {
  switch (resolution?.kind) {
    case 'found':
    case 'notBrowserReachable':
      return resolution.homeserver
    default:
      return null
  }
}

function reachabilityOf(resolution: Resolution | null): Reachability {
  switch (resolution?.kind) {
    case undefined:
      return 'resolving'
    case 'found':
      return 'reachable'
    case 'notBrowserReachable':
      return 'notBrowserReachable'
    case 'noRecord':
    case 'lookupFailed':
      return 'unreachable'
  }
}

/**
 * What the board as a whole can show: `no-circle` when none is selected,
 * `admin-unreachable` when the admin's lookup failed, found no record, or
 * found a homeserver with no ICANN HTTPS endpoint (in each case the browser
 * cannot read circle.json, so the roster cannot be read), else `ok`.
 */
export type BoardStatus = 'no-circle' | 'admin-unreachable' | 'ok'

export function boardStatus(state: BoardState): BoardStatus {
  if (state.admin === null) return 'no-circle'
  const resolution = memberState(state, state.admin).resolution
  switch (reachabilityOf(resolution)) {
    case 'unreachable':
    case 'notBrowserReachable':
      return 'admin-unreachable'
    case 'resolving':
    case 'reachable':
      return 'ok'
  }
}

// Helpers

/** The time `id` encodes, in milliseconds since 1970. */
function idTimeMs(id: RecordId): number {
  return Number(recordIdMicros(id) / 1000n)
}

/**
 * Code-unit order, `-1`, `0` or `1`. Ids and z-base32 keys are ASCII, so
 * this is their byte order, which for ids is time order (ids.ts).
 */
function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

/**
 * `compute`, remembering its last arguments and answer: a call whose
 * arguments are each `Object.is` the last call's gives back the last
 * answer, the same object. One slot is enough for a store with one state.
 */
function lastResult<Args extends readonly unknown[], Result>(
  compute: (...args: Args) => Result,
): (...args: Args) => Result {
  let last: { readonly args: Args; readonly result: Result } | null = null
  return (...args) => {
    const held = last
    if (held !== null && args.every((arg, index) => Object.is(arg, held.args[index]))) {
      return held.result
    }
    const result = compute(...args)
    last = { args, result }
    return result
  }
}
