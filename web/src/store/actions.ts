// What the poller tells the store: one action per answer it had, and the
// time it had it. Times arrive here, in milliseconds since 1970 from the
// poller's clock, so the reducer reads no clock of its own.
//
// Each read carries the transport's answer as it came (net/transport.ts),
// bytes and all: the reducer parses them and decides what each kind of
// answer means, in one place, so the poller has no case to forget.

import type { ListingResult } from '../net/listing.ts'
import type { HomeserverLookup, ListedDir, RecordAnswer } from '../net/transport.ts'
import type { RecordId } from '../records/ids.ts'
import type { Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import type { RereadKind } from './state.ts'

export type BoardAction =
  | CircleRead
  | HomeserverLookedUp
  | ListingRead
  | BountyRead
  | SweepRead
  | DiscoveredRead
  | RereadTurnTaken

/**
 * `admin`'s circle.json. Named, so a late answer for a circle the board no
 * longer shows changes nothing.
 */
export interface CircleRead {
  readonly type: 'circleRead'
  readonly admin: Pubky
  readonly answer: RecordAnswer
  readonly at: number
}

/** A roster key's homeserver, from its pkarr record. */
export interface HomeserverLookedUp {
  readonly type: 'homeserverLookedUp'
  readonly member: Pubky
  readonly lookup: HomeserverLookup
  readonly at: number
}

/** One directory of a roster key, listed newest first down to its watermark. */
export interface ListingRead {
  readonly type: 'listingRead'
  readonly member: Pubky
  readonly dir: ListedDir
  readonly result: ListingResult
  readonly at: number
}

/** `bounties/<id>.json` of a roster key, read for the first time or again. */
export interface BountyRead {
  readonly type: 'bountyRead'
  readonly ref: BountyRef
  readonly answer: RecordAnswer
  readonly at: number
}

/**
 * `sweeps/<id>.json`, from its sweeper's own storage: a roster key's, or a
 * stranger's that a discovered list names.
 */
export interface SweepRead {
  readonly type: 'sweepRead'
  readonly ref: SweepRef
  readonly answer: RecordAnswer
  readonly at: number
}

/** `bounties/<id>.discovered.json`, from the bounty's owner's storage. */
export interface DiscoveredRead {
  readonly type: 'discoveredRead'
  readonly bounty: BountyRef
  readonly answer: RecordAnswer
  readonly at: number
}

/**
 * The poller's turn through one kind of a roster key's re-reads ended at
 * `lastRead`: the next turn starts after it.
 */
export interface RereadTurnTaken {
  readonly type: 'rereadTurnTaken'
  readonly member: Pubky
  readonly kind: RereadKind
  readonly lastRead: RecordId
}
