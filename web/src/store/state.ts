// The board's state: every answer the poller has had, as the reducer
// (reducer.ts) folds them in, and what the poller must know from one poll to
// the next (watermarks, homeserver lookups, where each re-read turn stopped).
// The poller keeps nothing of its own, so a view and the next poll read the
// same facts (04, "Live-ness": "Zustand reducer → derived views").
//
// Every object here is read-only and replaced, never changed in place: an
// update builds new objects along the path to what changed and shares the
// rest. So "did this part change?" is `===`, which is how a zustand selector
// decides whether a view renders again.

import type { ListedDir } from '../net/transport.ts'
import type { RecordId } from '../records/ids.ts'
import type { Bounty, Circle, Sweep } from '../records/parse.ts'
import { BOUNTIES_DIR, SWEEPS_DIR } from '../records/paths.ts'
import type { Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'

/**
 * The most roster keys the board polls and trusts, the admin first: 32, as
 * `MAX_MEMBERS` in sweepky-cli's `pull/roster.rs`, so a key the CLI cuts
 * from a long circle is outside it on the board too.
 */
export const MAX_MEMBERS = 32

/**
 * One record, named by its writer's key and its id: `<z32>/<id>`. A `Pubky`
 * and a `RecordId` each have one canonical spelling, so equal keys name the
 * same record, and a `RecordKey` can key a `Map`.
 */
export type RecordKey = string & { readonly __brand: 'RecordKey' }

export function bountyKey(ref: BountyRef): RecordKey {
  return `${ref.owner}/${ref.id}` as RecordKey
}

export function sweepKey(ref: SweepRef): RecordKey {
  return `${ref.sweeper}/${ref.id}` as RecordKey
}

export interface BoardState {
  /** Whose circle the board shows (`?circle=`, or the built-in default); `null` when none. */
  readonly admin: Pubky | null
  /**
   * The roster in effect: the admin's circle.json as last read, each member
   * once, none the admin, at most MAX_MEMBERS keys in all. The admin alone
   * when the file is gone or names another admin. `null` until circle.json
   * has had an answer; the roster is then the admin alone.
   */
  readonly circle: Circle | null
  /** What the poller keeps for each roster key it has heard of; `memberState` fills the gaps. */
  readonly members: ReadonlyMap<Pubky, MemberState>
  /** Every bounty of a roster key the board has read. */
  readonly bounties: ReadonlyMap<RecordKey, BountyEntry>
  /**
   * Every sweep of a roster key the board has read, and every stranger's
   * sweep a held bounty's discovered list names for that same bounty.
   */
  readonly sweeps: ReadonlyMap<RecordKey, SweepEntry>
}

export interface BountyEntry {
  readonly ref: BountyRef
  readonly record: Bounty
  /** Its discovered-sweeps file as last read, kept whatever the bounty's status; `null` before. */
  readonly discovered: DiscoveredList | null
}

export interface DiscoveredList {
  /**
   * The sweeps the last good file listed, in its order and each once; none
   * after a 404. A file that fails or does not parse leaves the list as it
   * was.
   */
  readonly sweeps: ReadonlyMap<RecordKey, SweepRef>
  /**
   * When the file last had an answer (a list, a 404 or a body that does not
   * parse), in milliseconds since 1970. A failed request leaves it as it was.
   */
  readonly readAt: number
}

export interface SweepEntry {
  readonly ref: SweepRef
  readonly record: Sweep
}

/** What the board keeps of one roster key between polls. */
export interface MemberState {
  /** Where its homeserver is, as last learnt; `null` before its first lookup. */
  readonly resolution: Resolution | null
  /**
   * When a read of its storage last failed (a status, a network error, a
   * refused listing), in milliseconds since 1970, or `null`. 04 looks a key
   * up again after a failed read; comparing this with `resolvedAt` says
   * whether that is due.
   */
  readonly readFailedAt: number | null
  /** How far each of its two directories has been read. */
  readonly listings: Readonly<Record<ListedDir, ListingProgress>>
  /**
   * The last record of each kind its latest turn of re-reads took, which the
   * next turn starts after, going round (`next_turn` in pull/roster.rs).
   */
  readonly rereadAfter: Readonly<Record<RereadKind, RecordId | null>>
}

/**
 * Where a key's homeserver is, as last learnt, and when, in milliseconds
 * since 1970. 04 looks a key up again an hour after `resolvedAt`.
 */
export type Resolution =
  | { readonly kind: 'found'; readonly homeserver: Pubky; readonly resolvedAt: number }
  /**
   * A read found no endpoint a browser can reach: no ICANN domain with
   * HTTPS. `homeserver` is the one the lookup before found, if it found one.
   */
  | {
      readonly kind: 'notBrowserReachable'
      readonly homeserver: Pubky | null
      readonly resolvedAt: number
    }
  /** No pkarr record, or a lookup that failed: both shown as "unreachable". */
  | { readonly kind: 'noRecord' | 'lookupFailed'; readonly resolvedAt: number }

/** How far one directory of one key has been read. */
export interface ListingProgress {
  /**
   * The newest record id settled here, which the next listing stops at
   * (`listDirNewestFirst`'s `newestSeen`), or `null` to list it all.
   */
  readonly watermark: RecordId | null
  /**
   * The records the last listing named above the watermark, oldest first,
   * each with whether its read has settled: read, gone, or skipped for good
   * as unreadable. The watermark moves past the settled ones at the front
   * and stops at the first unread one.
   */
  readonly listed: readonly ListedRecord[]
}

export interface ListedRecord {
  readonly id: RecordId
  readonly settled: boolean
}

/** The three kinds of record the poller re-reads in turn, as `pull` does. */
export type RereadKind = 'openBounties' | 'runningSweeps' | 'doneBounties'

/** The state of a board that has read nothing yet. */
export function initialBoardState(admin: Pubky | null): BoardState {
  return { admin, circle: null, members: new Map(), bounties: new Map(), sweeps: new Map() }
}

/** What the board keeps of a roster key it has not heard of yet. */
const NEW_MEMBER: MemberState = {
  resolution: null,
  readFailedAt: null,
  listings: {
    [BOUNTIES_DIR]: { watermark: null, listed: [] },
    [SWEEPS_DIR]: { watermark: null, listed: [] },
  },
  rereadAfter: { openBounties: null, runningSweeps: null, doneBounties: null },
}

/** What the board keeps of `key`. */
export function memberState(state: BoardState, key: Pubky): MemberState {
  return state.members.get(key) ?? NEW_MEMBER
}

/** The roster's keys, the admin first: the keys the board polls and trusts. */
export function rosterKeys(state: BoardState): readonly Pubky[] {
  if (state.admin === null) return []
  if (state.circle === null) return [state.admin]
  return [state.circle.admin, ...state.circle.members.map((member) => member.pubky)]
}
