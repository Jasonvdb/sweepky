// The board's poll (04, "Live-ness"; 01, "Circle"): one pass over the
// selected circle, every 30 s, as sweepky-cli's `pull/roster.rs` polls a
// roster once a run. The store (boardStore.ts) runs it on a timer; this
// module is one pass, with no timer and no clock of its own, so tests drive
// it with a fake transport and a fake clock.
//
// One pass, in order:
//
// 1. **The admin's homeserver**, looked up when due (below). An admin that
//    cannot be reached stops the pass there: the state says why
//    (`boardStatus`), and nothing else is requested.
// 2. **circle.json**, read on every pass: one small GET, so a member added
//    or removed shows within one poll. The reducer decides the roster: at
//    most MAX_MEMBERS keys, the admin first, and the admin alone when the
//    file names another admin.
// 3. **Each roster key**, at most MAX_IN_FLIGHT at a time, each one's
//    requests one after another:
//    - its homeserver looked up when due; a key that cannot be reached is
//      skipped, and stays in the roster (unreachable is not untrusted);
//    - *again*: its records that can still change, within
//      MAX_REREADS_PER_MEMBER, shared as `rereadShares` says: open
//      bounties, `running` sweeps, and at most MAX_DONE_REREADS_PER_MEMBER
//      done bounties in rotation, since 01 lets an owner revise credits. A
//      `done` or `aborted` sweep is never read again;
//    - *new*: `bounties/`, then `sweeps/`, listed newest first down to the
//      watermark, and the records listed above it read oldest first, at most
//      MAX_NEW_BOUNTIES_PER_MEMBER and MAX_NEW_SWEEPS_PER_MEMBER a pass. What
//      a cap leaves unread stays above the watermark for the next pass.
//
//    A read that fails ends that key's pass, as in `pull`: its reads all go
//    to one homeserver, which would likely fail the rest too. The failure
//    is noted on the key, so the next pass looks it up again.
//
// **When a lookup is due.** Before a key's first one; an hour after the
// last; on the next pass after a failed read of its storage or a lookup
// that failed. "No pkarr record" is an answer, not a failure, so it waits
// the hour like a found homeserver, as does "not browser-reachable", which
// a new lookup cannot change. The pkarr relays are rate-limited per IP (01).
// This cache decides only which keys are polled and what reachability the
// Circle page shows: `client.fetch` resolves `_pubky.<key>` hosts through
// the SDK's own caches whatever it says.
//
// **Only GETs of public records.** Every request goes through the
// `Transport`'s `getRecord` and `list`, which can only GET a path under
// `/pub/sweepky/` (net/transport.ts), with `cache: 'no-cache'`: the browser
// asks the homeserver each time, sending the validators of its cached copy,
// so an unchanged record costs a 304 and a heuristic cache never answers
// with a stale listing or record. Nothing here reads a feed.

import { listDirNewestFirst } from '../net/listing.ts'
import type { ListedDir, RecordAnswer, Transport } from '../net/transport.ts'
import type { RecordId } from '../records/ids.ts'
import { asKnownBountyStatus, asKnownSweepStatus } from '../records/parse.ts'
import { BOUNTIES_DIR, SWEEPS_DIR } from '../records/paths.ts'
import type { Pubky } from '../records/pubky.ts'
import type { BoardAction } from './actions.ts'
import {
  memberState,
  rosterKeys,
  type BoardState,
  type MemberState,
  type RereadKind,
} from './state.ts'

/** How often the store runs a pass. */
export const POLL_INTERVAL_MS = 30_000

/** How long a homeserver lookup is trusted: an hour (01). */
export const RESOLUTION_TTL_MS = 60 * 60 * 1000

// The per-pass caps, `pull/roster.rs`'s, so one poll of a key costs what one
// `pull` run of it costs.

/** The most new bounty records read of one key in a pass. */
export const MAX_NEW_BOUNTIES_PER_MEMBER = 16
/** The most new sweep records read of one key in a pass. */
export const MAX_NEW_SWEEPS_PER_MEMBER = 32
/** The most records of one key read again in a pass, all kinds together. */
export const MAX_REREADS_PER_MEMBER = 32
/** Of those, the most done bounties: they seldom change. */
export const MAX_DONE_REREADS_PER_MEMBER = 8

/**
 * How many keys are polled at once. Each key's requests go one after
 * another, so this is also the most requests in flight: enough that one
 * slow homeserver does not hold up the rest, few enough to stay polite.
 */
export const MAX_IN_FLIGHT = 4

/** What a pass reads and writes the board through. */
export interface PollDeps {
  readonly transport: Transport
  /** The board's state as it is now: read again after every dispatch. */
  readonly getState: () => BoardState
  readonly dispatch: (action: BoardAction) => void
  /** Milliseconds since 1970, stamped on every action. */
  readonly now: () => number
  /** Once aborted, the pass sends no further request. */
  readonly signal: AbortSignal
}

/**
 * What one pass keeps while it runs: the keys looked up during it, so none
 * is looked up twice in a pass, and those whose read failed, which are read
 * no further this pass.
 */
interface Pass extends PollDeps {
  readonly lookedUp: Set<Pubky>
  readonly failed: Set<Pubky>
}

/** One pass over the selected circle: see the module comment. Resolves when the pass is over. */
export async function pollOnce(deps: PollDeps): Promise<void> {
  const admin = deps.getState().admin
  if (admin === null) return
  const pass: Pass = { ...deps, lookedUp: new Set(), failed: new Set() }
  if (!(await isReachable(pass, admin))) return
  await readCircle(pass, admin)
  await forEachLimited(rosterKeys(deps.getState()), MAX_IN_FLIGHT, (key) => pollKey(pass, key))
}

async function readCircle(pass: Pass, admin: Pubky): Promise<void> {
  if (pass.signal.aborted) return
  const answer = await pass.transport.getRecord(admin, { kind: 'circle' }, { cache: 'no-cache' })
  pass.dispatch({ type: 'circleRead', admin, answer, at: pass.now() })
  if (isFailure(answer)) pass.failed.add(admin)
}

/** One roster key's share of the pass: again, then new bounties, then new sweeps. */
async function pollKey(pass: Pass, key: Pubky): Promise<void> {
  if (pass.failed.has(key) || !(await isReachable(pass, key))) return
  // Each step says whether the key's reads went well; the first that did
  // not ends the key's pass, as `?` does in roster.rs.
  if (!(await rereadKey(pass, key))) return
  if (!(await readNew(pass, key, BOUNTIES_DIR))) return
  await readNew(pass, key, SWEEPS_DIR)
}

/**
 * Whether `key`'s homeserver is known to be reachable, after looking it up
 * if that is due.
 */
async function isReachable(pass: Pass, key: Pubky): Promise<boolean> {
  if (pass.signal.aborted) return false
  const member = memberState(pass.getState(), key)
  if (!pass.lookedUp.has(key) && isLookupDue(member, pass.now())) {
    pass.lookedUp.add(key)
    const lookup = await pass.transport.lookupHomeserver(key)
    pass.dispatch({ type: 'homeserverLookedUp', member: key, lookup, at: pass.now() })
  }
  return memberState(pass.getState(), key).resolution?.kind === 'found'
}

/** Whether `member`'s homeserver is due a lookup at `now`: the module comment says when. */
function isLookupDue({ resolution, readFailedAt }: MemberState, now: number): boolean {
  if (resolution === null || resolution.kind === 'lookupFailed') return true
  // `>=`: a read that failed in the same millisecond as the lookup may have
  // come after it, so it counts.
  if (readFailedAt !== null && readFailedAt >= resolution.resolvedAt) return true
  return now - resolution.resolvedAt >= RESOLUTION_TTL_MS
}

// Again: records that can still change

/** One record to read again: a bounty or a sweep of the key being polled. */
interface Reread {
  readonly kind: RereadKind
  readonly id: RecordId
}

/** Reads `key`'s records that can still change again; `false` when a read failed. */
async function rereadKey(pass: Pass, key: Pubky): Promise<boolean> {
  for (const { kind, id } of rereadsOf(pass.getState(), key)) {
    if (pass.signal.aborted) return false
    const answer =
      kind === 'runningSweeps' ? await readSweep(pass, key, id) : await readBounty(pass, key, id)
    if (isFailure(answer)) return false
    // Its turn moves on past each record read, so the one a failure leaves
    // unread comes first next pass.
    pass.dispatch({ type: 'rereadTurnTaken', member: key, kind, lastRead: id })
  }
  return true
}

/**
 * What a pass reads again of `key`, in the order read: its open bounties,
 * its `running` sweeps, then its done bounties, each kind within its share
 * (`Rereads::this_run` in roster.rs).
 */
function rereadsOf(state: BoardState, key: Pubky): readonly Reread[] {
  const open: RecordId[] = []
  const done: RecordId[] = []
  for (const { ref, record } of state.bounties.values()) {
    if (ref.owner !== key) continue
    const status = asKnownBountyStatus(record.status)
    if (status === 'open') open.push(ref.id)
    else if (status === 'done') done.push(ref.id)
  }
  // Only `running`: a `done` or `aborted` sweep is final, and one whose
  // status this build does not know is not one it watches.
  const running: RecordId[] = []
  for (const { ref, record } of state.sweeps.values()) {
    if (ref.sweeper === key && asKnownSweepStatus(record.status) === 'running') {
      running.push(ref.id)
    }
  }
  // Oldest first: ids compare as strings in time order (records/ids.ts).
  for (const ids of [open, running, done]) ids.sort()

  const shares = rereadShares(open.length, running.length, done.length)
  const after = memberState(state, key).rereadAfter
  const turn = (kind: RereadKind, ids: readonly RecordId[]): Reread[] =>
    ids.map((id) => ({ kind, id }))
  return [
    ...turn('openBounties', wholeOrInTurn(open, after.openBounties, shares.open)),
    ...turn('runningSweeps', wholeOrInTurn(running, after.runningSweeps, shares.running)),
    ...turn('doneBounties', nextTurn(done, after.doneBounties, shares.done)),
  ]
}

/** How many records of each kind one key reads again in a pass. */
interface Shares {
  readonly open: number
  readonly running: number
  readonly done: number
}

/**
 * MAX_REREADS_PER_MEMBER split between a key's open bounties, running
 * sweeps and done bounties, so that no kind starves another (`reread_shares`
 * in roster.rs): the done bounties take at most MAX_DONE_REREADS_PER_MEMBER,
 * the other two half each of the rest, and a kind with fewer than its half
 * leaves the room to the other. Never more than the budget in all.
 */
export function rereadShares(open: number, running: number, done: number): Shares {
  const doneShare = Math.min(done, MAX_DONE_REREADS_PER_MEMBER)
  const room = MAX_REREADS_PER_MEMBER - doneShare
  const openShare = Math.min(open, room - Math.min(running, Math.floor(room / 2)))
  const runningShare = Math.min(running, room - openShare)
  return { open: openShare, running: runningShare, done: doneShare }
}

/**
 * Up to `n` of `ids` (oldest first): the first after `after` and on from
 * there, going round to the start, each at most once (`next_turn` in
 * roster.rs). So each is read again within a bounded number of passes.
 */
function nextTurn(
  ids: readonly RecordId[],
  after: RecordId | null,
  n: number,
): RecordId[] {
  const start = after === null ? 0 : ids.findIndex((id) => id > after)
  const from = start === -1 ? ids.length : start
  return [...ids.slice(from), ...ids.slice(0, from)].slice(0, n)
}

/**
 * All of `ids`, the newest first, when they fit in `share`, as the newest
 * change most; past it, `share` of them in turn after `after`
 * (`whole_or_in_turn` in roster.rs).
 */
function wholeOrInTurn(
  ids: readonly RecordId[],
  after: RecordId | null,
  share: number,
): RecordId[] {
  return ids.length <= share ? [...ids].reverse() : nextTurn(ids, after, share)
}

// New: what a listing names above the watermark

const MAX_NEW: Readonly<Record<ListedDir, number>> = {
  [BOUNTIES_DIR]: MAX_NEW_BOUNTIES_PER_MEMBER,
  [SWEEPS_DIR]: MAX_NEW_SWEEPS_PER_MEMBER,
}

/**
 * Lists `dir` of `key` down to its watermark and reads the records it names
 * that are still unread, oldest first and within the cap. `false` when a
 * request failed or the listing was refused.
 */
async function readNew(pass: Pass, key: Pubky, dir: ListedDir): Promise<boolean> {
  if (pass.signal.aborted) return false
  const { watermark } = memberState(pass.getState(), key).listings[dir]
  const result = await listDirNewestFirst(pass.transport, key, dir, watermark)
  pass.dispatch({ type: 'listingRead', member: key, dir, result, at: pass.now() })
  if (result.kind !== 'listed') return false

  // The reducer has just put what the listing named above the watermark in
  // `listed`, oldest first; a record it already settled is not read twice.
  const unread = memberState(pass.getState(), key)
    .listings[dir].listed.filter((record) => !record.settled)
    .slice(0, MAX_NEW[dir])
  for (const { id } of unread) {
    if (pass.signal.aborted) return false
    const answer =
      dir === BOUNTIES_DIR ? await readBounty(pass, key, id) : await readSweep(pass, key, id)
    if (isFailure(answer)) return false
  }
  return true
}

// Reads

async function readBounty(pass: Pass, owner: Pubky, id: RecordId): Promise<RecordAnswer> {
  const answer = await pass.transport.getRecord(
    owner,
    { kind: 'bounty', id },
    { cache: 'no-cache' },
  )
  pass.dispatch({ type: 'bountyRead', ref: { owner, id }, answer, at: pass.now() })
  return answer
}

async function readSweep(pass: Pass, sweeper: Pubky, id: RecordId): Promise<RecordAnswer> {
  const answer = await pass.transport.getRecord(
    sweeper,
    { kind: 'sweepRecord', id },
    { cache: 'no-cache' },
  )
  pass.dispatch({ type: 'sweepRead', ref: { sweeper, id }, answer, at: pass.now() })
  return answer
}

/**
 * Whether `answer` says the key's homeserver could not be read: a failed
 * request, or no endpoint a browser can reach. A 404 or a record over its
 * cap is an answer about the record, not the homeserver.
 */
function isFailure(answer: RecordAnswer): boolean {
  return answer.kind === 'failed' || answer.kind === 'notBrowserReachable'
}

/**
 * Runs `task` for each of `items`, at most `limit` at once, and resolves
 * when all are done. Each worker takes the next item as it finishes one, so
 * the items start in their order: the admin's first.
 */
async function forEachLimited<T>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0
  const worker = async (): Promise<void> => {
    // `next` is shared: JavaScript runs one worker at a time between
    // `await`s, so no two take the same item.
    while (next < items.length) {
      const item = items[next] as T
      next += 1
      await task(item)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
}
