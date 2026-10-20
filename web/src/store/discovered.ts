// Which discovered-sweeps files and strangers' sweeps a pass reads (04,
// "Live-ness"; 01, "Open bounties"). Pure: the poller (poller.ts) asks these
// functions what is due and sends the requests, so the rules sit here, apart
// from the I/O.
//
// **The files.** A bounty open to strangers (`open: true`) has its owner's
// `bounties/<id>.discovered.json`, where the owner's `pull` publishes the
// strangers' sweeps it accepted. The board reads it, and never a feed: a
// fresh browser cannot replay a homeserver's public history, and does not
// need to. The file's `cursors` are the CLI's business and are not used.
//
// - While the bounty is `open`, its file is read on every pass, so a
//   stranger's sweep shows within one poll of the owner's `pull`.
// - Once it is `done`, its file is read only in a pass that read the bounty
//   itself: the pass that first sees it done (a fresh load, or the re-read
//   that saw it flip), then whenever the done-bounty rotation re-reads it.
//   `pull` stops writing the file once the bounty is done, but 04 says a
//   closed tab misses nothing, so a tab opened after the bounty was done
//   must still read the list once, and then shows the same sweeps as a tab
//   that watched it all along.
// - A bounty with `open: false`, or a status this build does not know, has
//   no file the board reads.
//
// **The strangers' sweeps.** Each sweep a held list names is read from its
// sweeper's own storage, never the owner's word for it: the reducer keeps
// it only when its own record names that bounty. Within caps, because the
// list is long-lived and its sweepers are anyone:
//
// - Of each list, the first MAX_STRANGERS_SWEEPS_PER_BOUNTY strangers'
//   sweeps alone, as `MAX_ACCEPTED_PER_BOUNTY` in sweepky-cli's
//   `pull/feed.rs`, so a list never makes the board hold more strangers'
//   sweeps for one bounty than `pull` would accept.
// - Sweeps by a roster key, the owner's own included, are skipped: the
//   roster poll reads each of those from its own listing, as `pull` does.
// - Like a member's sweep, a stranger's is read again while `running` and
//   never after `done` or `aborted`. Per pass, at most
//   MAX_STRANGERS_REREADS_PER_POLL re-reads and
//   MAX_NEW_STRANGERS_SWEEPS_PER_POLL first reads, across all bounties:
//   their own budget, so strangers never take a member's share.

import { asKnownBountyStatus, asKnownSweepStatus } from '../records/parse.ts'
import type { Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import { rosterKeys, type BoardState, type RecordKey } from './state.ts'

/** The most strangers' sweeps the board takes from one bounty's list: 256, as `pull` accepts. */
export const MAX_STRANGERS_SWEEPS_PER_BOUNTY = 256

/** The most strangers' sweeps read for the first time in one pass, all bounties together. */
export const MAX_NEW_STRANGERS_SWEEPS_PER_POLL = 32

/** The most strangers' `running` sweeps read again in one pass, all bounties together. */
export const MAX_STRANGERS_REREADS_PER_POLL = 32

/**
 * The bounties of `owner` whose discovered.json is due this pass, oldest
 * first: those open to strangers that are `open`, and those that are `done`
 * and in `readThisPass`, the bounties the pass has read.
 */
export function discoveredDue(
  state: BoardState,
  owner: Pubky,
  readThisPass: ReadonlySet<RecordKey>,
): BountyRef[] {
  const due: BountyRef[] = []
  for (const [key, { ref, record }] of state.bounties) {
    if (ref.owner !== owner || !record.open) continue
    const status = asKnownBountyStatus(record.status)
    if (status === 'open' || (status === 'done' && readThisPass.has(key))) due.push(ref)
  }
  // Ids compare as strings in time order (records/ids.ts).
  return due.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
}

/**
 * The strangers' sweeps a pass reads, the re-reads first: see the module
 * comment for which and how many. `turn` is the pass's number (its time
 * over the poll interval): past a cap, each pass starts its share further
 * round the list, so every sweep is read within a bounded number of passes
 * with no position stored between them.
 */
export function strangersSweepsDue(state: BoardState, turn: number): SweepRef[] {
  const roster = new Set(rosterKeys(state))
  const seen = new Set<RecordKey>()
  const rereads: SweepRef[] = []
  const unread: SweepRef[] = []
  for (const bounty of state.bounties.values()) {
    for (const [key, ref] of strangersListedBy(bounty.discovered?.sweeps, roster)) {
      // A sweep two lists name is read once.
      if (seen.has(key)) continue
      seen.add(key)
      const held = state.sweeps.get(key)
      if (held === undefined) unread.push(ref)
      else if (asKnownSweepStatus(held.record.status) === 'running') rereads.push(ref)
    }
  }
  return [
    ...inTurn(rereads, MAX_STRANGERS_REREADS_PER_POLL, turn),
    ...inTurn(unread, MAX_NEW_STRANGERS_SWEEPS_PER_POLL, turn),
  ]
}

/** The first MAX_STRANGERS_SWEEPS_PER_BOUNTY sweeps of `listed` by keys outside `roster`. */
function strangersListedBy(
  listed: ReadonlyMap<RecordKey, SweepRef> | undefined,
  roster: ReadonlySet<Pubky>,
): [RecordKey, SweepRef][] {
  if (listed === undefined) return []
  const strangers: [RecordKey, SweepRef][] = []
  for (const [key, ref] of listed) {
    if (strangers.length === MAX_STRANGERS_SWEEPS_PER_BOUNTY) break
    if (!roster.has(ref.sweeper)) strangers.push([key, ref])
  }
  return strangers
}

/** All of `items` when they fit in `n`; else `n` of them, starting `turn × n` round the list. */
function inTurn<T>(items: readonly T[], n: number, turn: number): readonly T[] {
  if (items.length <= n) return items
  const start = (turn * n) % items.length
  return [...items.slice(start), ...items.slice(0, start)].slice(0, n)
}
