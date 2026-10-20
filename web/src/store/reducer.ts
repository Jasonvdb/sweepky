// The board's reducer: folds each answer the poller had (actions.ts) into
// the board's state (state.ts). Pure: no I/O, no clock, so the same answers
// in the same order always give the same state, and tests need no network
// and no timer. An action that changes nothing gives back the state it was
// given, the same object, so no view renders again for it.
//
// The rules, and why:
//
// - **Only the roster's records, and the strangers' sweeps its owners
//   published.** A bounty is kept when its owner is in the roster. A sweep
//   is kept when its sweeper is, or when it is a stranger's sweep that the
//   bounty its own record names lists in that bounty's discovered file:
//   `pull` publishes there the strangers' sweeps it accepted for that bounty
//   (01). Compared by owner key and id, so a list cannot attach a sweep made
//   for another bounty. Anything else is ignored, and a new roster or a new
//   list drops what no longer qualifies.
// - **A done bounty keeps its strangers' sweeps.** A bounty's discovered
//   list stays with it across re-reads, whatever its status: `pull` writes
//   discovered.json for open bounties only and nothing deletes it, and 04
//   says a closed tab misses nothing, as every view comes from current
//   records. So the moment a bounty is done changes neither its sweeps nor
//   their sweepers' badges.
// - **A 404 removes; an unreadable answer keeps the last good one.** A record
//   that is gone is gone. One over its cap or that no longer parses keeps
//   what was read before: a newer Sweepky's record may parse once this build
//   is updated (P2c, "Faults skip"). A failed request changes no record; it
//   is noted on the key whose storage it read.
// - **A sweep's `done` or `aborted` is final.** `submit` never moves a sweep
//   on from either (P2b), and the poller stops reading it, so a later answer
//   that says otherwise is not taken.
// - **The watermark passes only what has settled.** A directory's watermark
//   moves past a listed record once its read has an answer (read, gone or
//   skipped for good) and never past one still unread, so what a failure or
//   a per-poll cap leaves unread is listed again next poll, as in `pull`.

import type { Listing } from '../net/listing.ts'
import type { ListedDir, RecordAnswer } from '../net/transport.ts'
import type { RecordId } from '../records/ids.ts'
import {
  asKnownSweepStatus,
  parseBounty,
  parseCircle,
  parseDiscovered,
  parseSweep,
  type Circle,
  type CircleMember,
  type Parsed,
  type Sweep,
} from '../records/parse.ts'
import { BOUNTIES_DIR, SWEEPS_DIR, type SweepkyPath } from '../records/paths.ts'
import type { Pubky } from '../records/pubky.ts'
import type { SweepRef } from '../records/urls.ts'
import type {
  BoardAction,
  BountyRead,
  CircleRead,
  DiscoveredRead,
  HomeserverLookedUp,
  ListingRead,
  RereadTurnTaken,
  SweepRead,
} from './actions.ts'
import {
  bountyKey,
  MAX_MEMBERS,
  memberState,
  rosterKeys,
  sweepKey,
  type BoardState,
  type BountyEntry,
  type DiscoveredList,
  type ListedRecord,
  type ListingProgress,
  type MemberState,
  type RecordKey,
  type SweepEntry,
} from './state.ts'

/** The state after `action`: `state` itself, the same object, when the action changes nothing. */
export function boardReducer(state: BoardState, action: BoardAction): BoardState {
  // No `default`: TypeScript checks every action has its case, so a new one
  // does not compile until someone decides what it does.
  switch (action.type) {
    case 'circleRead':
      return circleRead(state, action)
    case 'homeserverLookedUp':
      return homeserverLookedUp(state, action)
    case 'listingRead':
      return listingRead(state, action)
    case 'bountyRead':
      return bountyRead(state, action)
    case 'sweepRead':
      return sweepRead(state, action)
    case 'discoveredRead':
      return discoveredRead(state, action)
    case 'rereadTurnTaken':
      return rereadTurnTaken(state, action)
  }
}

/**
 * What a record read gave, whatever the transport's answer was. `unreadable`
 * is a body over its cap or one the parser refused: the record's fault, not
 * the homeserver's, so the key's reads are not in doubt.
 */
type Outcome<T> =
  | { readonly kind: 'record'; readonly record: T }
  | { readonly kind: 'absent' }
  | { readonly kind: 'unreadable' }
  | { readonly kind: 'failed'; readonly failure: ReadFailure }

/** A request that gave no answer about the record: no browser endpoint, or a failure. */
type ReadFailure = { readonly kind: 'notBrowserReachable' } | { readonly kind: 'failed' }

function outcomeOf<T>(answer: RecordAnswer, parse: (bytes: Uint8Array) => Parsed<T>): Outcome<T> {
  switch (answer.kind) {
    case 'body': {
      const parsed = parse(answer.body)
      return parsed.ok ? { kind: 'record', record: parsed.record } : { kind: 'unreadable' }
    }
    case 'absent':
      return { kind: 'absent' }
    case 'tooLarge':
      return { kind: 'unreadable' }
    case 'notBrowserReachable':
    case 'failed':
      return { kind: 'failed', failure: answer }
  }
}

function circleRead(state: BoardState, { admin, answer, at }: CircleRead): BoardState {
  if (admin !== state.admin) return state
  const outcome = outcomeOf(answer, parseCircle)
  switch (outcome.kind) {
    case 'record':
      // A roster counts only in its admin's own storage: anyone can put any
      // file in theirs.
      return withCircle(
        state,
        outcome.record.admin === admin ? bounded(outcome.record) : alone(admin),
      )
    case 'absent':
      return withCircle(state, alone(admin))
    case 'unreadable':
      // A first answer that cannot be read leaves the admin alone, as in
      // `pull`; a re-read keeps the last good circle, as for every record.
      return state.circle === null ? withCircle(state, alone(admin)) : state
    case 'failed':
      return noteReadFailure(state, admin, outcome.failure, at)
  }
}

/** The roster of `admin` alone: no circle, or none that counts. */
function alone(admin: Pubky): Circle {
  return { name: '', admin, members: [] }
}

/**
 * `circle` with each member once, none the admin, and at most MAX_MEMBERS
 * keys with the admin: `bounded` in pull/roster.rs. A `Pubky` has one
 * spelling per key, so the set compares keys.
 */
function bounded(circle: Circle): Circle {
  const seen = new Set<Pubky>([circle.admin])
  const members: CircleMember[] = []
  for (const member of circle.members) {
    if (seen.has(member.pubky)) continue
    if (seen.size >= MAX_MEMBERS) break
    seen.add(member.pubky)
    members.push(member)
  }
  return { ...circle, members }
}

function withCircle(state: BoardState, circle: Circle): BoardState {
  return pruned({ ...state, circle })
}

function homeserverLookedUp(
  state: BoardState,
  { member, lookup, at }: HomeserverLookedUp,
): BoardState {
  return updateMember(state, member, (kept) => ({
    ...kept,
    resolution:
      lookup.kind === 'found'
        ? { kind: 'found', homeserver: lookup.homeserver, resolvedAt: at }
        : { kind: lookup.reason, resolvedAt: at },
  }))
}

function listingRead(state: BoardState, { member, dir, result, at }: ListingRead): BoardState {
  switch (result.kind) {
    case 'listed':
      return updateProgress(state, member, dir, (progress) =>
        withListing(progress, result.listing, dir),
      )
    case 'refused':
      // A listing that breaks the protocol puts the key's homeserver in
      // doubt, as `pull` reads it (P2c): it is looked up again.
      return noteReadFailure(state, member, { kind: 'failed' }, at)
    case 'notBrowserReachable':
    case 'failed':
      return noteReadFailure(state, member, result, at)
  }
}

/**
 * `progress` waiting for the records `listing` names above its watermark,
 * oldest first, each once. One the last listing saw settled stays settled.
 */
function withListing(
  progress: ListingProgress,
  listing: Listing,
  dir: ListedDir,
): ListingProgress {
  const settledBefore = new Set(
    progress.listed.filter((record) => record.settled).map((record) => record.id),
  )
  const ids = new Set<RecordId>()
  for (const path of listing.entries) {
    const id = recordIdIn(path, dir)
    // Ids compare as strings in timestamp order (records/ids.ts).
    if (id !== null && (progress.watermark === null || id > progress.watermark)) ids.add(id)
  }
  // `sort` compares strings by UTF-16 unit; ids are ASCII, so that is
  // timestamp order too.
  const listed = [...ids].sort().map((id) => ({ id, settled: settledBefore.has(id) }))
  return passSettled(progress.watermark, listed)
}

/**
 * The id of the record `path` is in `dir`, or `null` for any other file,
 * such as an open bounty's `.discovered.json` or a sweep's `.age`: only a
 * record is read, so only a record holds the watermark back.
 */
function recordIdIn(path: SweepkyPath, dir: ListedDir): RecordId | null {
  if (dir === BOUNTIES_DIR) return path.kind === 'bounty' ? path.id : null
  return path.kind === 'sweepRecord' ? path.id : null
}

/** `progress` with `id`'s read settled. */
function withSettled(progress: ListingProgress, id: RecordId): ListingProgress {
  if (!progress.listed.some((record) => record.id === id && !record.settled)) return progress
  const listed = progress.listed.map((record) =>
    record.id === id ? { id, settled: true } : record,
  )
  return passSettled(progress.watermark, listed)
}

/**
 * The watermark moved past the settled records at the front of `listed`, and
 * the records after them, from the first unread one on.
 */
function passSettled(
  watermark: RecordId | null,
  listed: readonly ListedRecord[],
): ListingProgress {
  const firstUnread = listed.findIndex((record) => !record.settled)
  const passed = firstUnread === -1 ? listed.length : firstUnread
  return { watermark: listed[passed - 1]?.id ?? watermark, listed: listed.slice(passed) }
}

function bountyRead(state: BoardState, { ref, answer, at }: BountyRead): BoardState {
  if (!isInRoster(state, ref.owner)) return state
  const key = bountyKey(ref)
  const outcome = outcomeOf(answer, parseBounty)
  switch (outcome.kind) {
    case 'record': {
      // The discovered list stays with the bounty whatever its new status:
      // the module comment says why.
      const discovered = state.bounties.get(key)?.discovered ?? null
      const bounties = withEntry(state.bounties, key, { ref, record: outcome.record, discovered })
      return settle({ ...state, bounties }, ref.owner, BOUNTIES_DIR, ref.id)
    }
    case 'absent':
      // `pruned` drops the strangers' sweeps its list attached.
      return settle(pruned(withoutBounty(state, key)), ref.owner, BOUNTIES_DIR, ref.id)
    case 'unreadable':
      return settle(state, ref.owner, BOUNTIES_DIR, ref.id)
    case 'failed':
      return noteReadFailure(state, ref.owner, outcome.failure, at)
  }
}

function sweepRead(state: BoardState, { ref, answer, at }: SweepRead): BoardState {
  const key = sweepKey(ref)
  const isMember = isInRoster(state, ref.sweeper)
  if (!isMember && !isListedByAnyBounty(state.bounties, key)) return state
  const outcome = outcomeOf(answer, parseSweep)
  switch (outcome.kind) {
    case 'record': {
      const held = state.sweeps.get(key)
      if (held !== undefined && isFinal(held.record)) {
        return settle(state, ref.sweeper, SWEEPS_DIR, ref.id)
      }
      const entry: SweepEntry = { ref, record: outcome.record }
      const next =
        isMember || isListedByItsBounty(state.bounties, entry)
          ? { ...state, sweeps: withEntry(state.sweeps, key, entry) }
          : withoutSweep(state, key)
      return settle(next, ref.sweeper, SWEEPS_DIR, ref.id)
    }
    case 'absent':
      return settle(withoutSweep(state, key), ref.sweeper, SWEEPS_DIR, ref.id)
    case 'unreadable':
      return settle(state, ref.sweeper, SWEEPS_DIR, ref.id)
    case 'failed':
      return noteReadFailure(state, ref.sweeper, outcome.failure, at)
  }
}

/** Whether `sweep` is `done` or `aborted`, the statuses a sweep never leaves. */
function isFinal(sweep: Sweep): boolean {
  const status = asKnownSweepStatus(sweep.status)
  return status === 'done' || status === 'aborted'
}

function discoveredRead(state: BoardState, { bounty, answer, at }: DiscoveredRead): BoardState {
  const held = state.bounties.get(bountyKey(bounty))
  if (held === undefined) return state
  const outcome = outcomeOf(answer, parseDiscovered)
  switch (outcome.kind) {
    case 'record': {
      // A `Map` keeps the file's order and holds a sweep listed twice once.
      // The cursors are the CLI's business: the board reads no feed.
      const sweeps = new Map(outcome.record.sweeps.map((sweep) => [sweepKey(sweep), sweep]))
      return withDiscovered(state, held, { sweeps, readAt: at })
    }
    case 'absent':
      // No file, so nothing discovered.
      return withDiscovered(state, held, { sweeps: new Map(), readAt: at })
    case 'unreadable': {
      const sweeps = held.discovered?.sweeps ?? new Map<RecordKey, SweepRef>()
      return withDiscovered(state, held, { sweeps, readAt: at })
    }
    case 'failed':
      return noteReadFailure(state, bounty.owner, outcome.failure, at)
  }
}

/**
 * `state` with `held`'s discovered list replaced, and the strangers' sweeps
 * it no longer names dropped.
 */
function withDiscovered(
  state: BoardState,
  held: BountyEntry,
  discovered: DiscoveredList,
): BoardState {
  const bounties = withEntry(state.bounties, bountyKey(held.ref), { ...held, discovered })
  return pruned({ ...state, bounties })
}

function rereadTurnTaken(
  state: BoardState,
  { member, kind, lastRead }: RereadTurnTaken,
): BoardState {
  // `[kind]` is a computed key: the property named by `kind`'s value.
  return updateMember(state, member, (kept) => ({
    ...kept,
    rereadAfter: { ...kept.rereadAfter, [kind]: lastRead },
  }))
}

/**
 * `state` with a failed read of `key`'s storage noted: the key is not
 * browser-reachable, or its read failed at `at`. Nothing for a key outside
 * the roster, such as a stranger whose sweep could not be read.
 */
function noteReadFailure(
  state: BoardState,
  key: Pubky,
  failure: ReadFailure,
  at: number,
): BoardState {
  return updateMember(state, key, (member) => {
    if (failure.kind === 'failed') return { ...member, readFailedAt: at }
    const previous = member.resolution
    const homeserver =
      previous?.kind === 'found' || previous?.kind === 'notBrowserReachable'
        ? previous.homeserver
        : null
    return { ...member, resolution: { kind: 'notBrowserReachable', homeserver, resolvedAt: at } }
  })
}

/** `state` with `id` of `key`'s `dir` settled, if its last listing is waiting for it. */
function settle(state: BoardState, key: Pubky, dir: ListedDir, id: RecordId): BoardState {
  // Only a key that has been listed has a listing waiting, so this asks
  // `members` directly and makes no entry for a stranger.
  if (!state.members.has(key)) return state
  return updateProgress(state, key, dir, (progress) => withSettled(progress, id))
}

function updateProgress(
  state: BoardState,
  key: Pubky,
  dir: ListedDir,
  change: (progress: ListingProgress) => ListingProgress,
): BoardState {
  return updateMember(state, key, (member) => {
    const progress = change(member.listings[dir])
    if (progress === member.listings[dir]) return member
    return { ...member, listings: { ...member.listings, [dir]: progress } }
  })
}

/**
 * `state` with `change` made to what it keeps of `key`. Nothing for a key
 * outside the roster: `members` holds roster keys alone.
 */
function updateMember(
  state: BoardState,
  key: Pubky,
  change: (member: MemberState) => MemberState,
): BoardState {
  if (!isInRoster(state, key)) return state
  const before = memberState(state, key)
  const after = change(before)
  return after === before ? state : { ...state, members: withEntry(state.members, key, after) }
}

/**
 * `state` without what its roster and its discovered lists no longer cover:
 * the member state and bounties of keys outside the roster, and each sweep
 * `isKept` refuses. `state` itself when nothing goes.
 */
function pruned(state: BoardState): BoardState {
  const roster = new Set(rosterKeys(state))
  const members = filtered(state.members, (_, key) => roster.has(key))
  const bounties = filtered(state.bounties, (entry) => roster.has(entry.ref.owner))
  // Against the bounties that stay, so a stranger's sweep whose bounty just
  // went goes with it.
  const sweeps = filtered(
    state.sweeps,
    (entry) => roster.has(entry.ref.sweeper) || isListedByItsBounty(bounties, entry),
  )
  const unchanged =
    members === state.members && bounties === state.bounties && sweeps === state.sweeps
  if (unchanged) return state
  return { ...state, members, bounties, sweeps }
}

/** Whether any of `bounties`' discovered lists names the sweep `key`. */
function isListedByAnyBounty(
  bounties: ReadonlyMap<RecordKey, BountyEntry>,
  key: RecordKey,
): boolean {
  for (const bounty of bounties.values()) {
    if (bounty.discovered?.sweeps.has(key) === true) return true
  }
  return false
}

/**
 * Whether `bounties` holds the bounty `sweep`'s own record names, and that
 * bounty's discovered list names `sweep`.
 */
function isListedByItsBounty(
  bounties: ReadonlyMap<RecordKey, BountyEntry>,
  sweep: SweepEntry,
): boolean {
  const bounty = bounties.get(bountyKey(sweep.record.bounty))
  return bounty?.discovered?.sweeps.has(sweepKey(sweep.ref)) === true
}

function isInRoster(state: BoardState, key: Pubky): boolean {
  return rosterKeys(state).includes(key)
}

function withoutBounty(state: BoardState, key: RecordKey): BoardState {
  const bounties = withoutEntry(state.bounties, key)
  return bounties === state.bounties ? state : { ...state, bounties }
}

function withoutSweep(state: BoardState, key: RecordKey): BoardState {
  const sweeps = withoutEntry(state.sweeps, key)
  return sweeps === state.sweeps ? state : { ...state, sweeps }
}

// Copy-on-write helpers for the read-only maps: each gives a new map, never
// changing the one it was given. `withoutEntry` and `filtered` give back
// that same map when they remove nothing, so `===` still says "unchanged".

function withEntry<K, V>(map: ReadonlyMap<K, V>, key: K, value: V): ReadonlyMap<K, V> {
  return new Map(map).set(key, value)
}

function withoutEntry<K, V>(map: ReadonlyMap<K, V>, key: K): ReadonlyMap<K, V> {
  if (!map.has(key)) return map
  const copy = new Map(map)
  copy.delete(key)
  return copy
}

function filtered<K, V>(
  map: ReadonlyMap<K, V>,
  keep: (value: V, key: K) => boolean,
): ReadonlyMap<K, V> {
  const kept = new Map([...map].filter(([key, value]) => keep(value, key)))
  return kept.size === map.size ? map : kept
}
