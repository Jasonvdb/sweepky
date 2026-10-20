// Trust labels: how far the board trusts a pubky, computed from the roster and
// the credits on the bounties its admin and members marked done. Ported from
// sweepky-core's `trust.rs` (`trust_labels`), which the CLI uses.
//
// The rule has these two implementations. fixtures/README.md ("The rule")
// states it for both, and both tests assert fixtures/trust-labels.json, so a
// change to the rule changes that file, core and this module together.

import { asKnownBountyStatus, type Circle } from '../records/parse.ts'
import type { Pubky } from '../records/pubky.ts'

/**
 * How far the board trusts a pubky. A closed union, unlike a record's open
 * strings: a label is computed here and never read from a record, so there
 * is no value a newer client could have written.
 */
export type TrustLabel = 'circle' | 'known' | 'unknown'

/**
 * A pubky's label and the credits behind it: what the badge (`circle`,
 * `known N`, `unknown`) and "credits received" on the Circle page show. The
 * shape of an `expected` entry in fixtures/trust-labels.json.
 */
export interface Trust {
  readonly label: TrustLabel
  /**
   * Counted bounties that credit the pubky. A bounty counts once, however
   * many times its `credits` name the pubky.
   */
  readonly bounties: number
  /**
   * Distinct owners among those bounties. Reputation built by one owner,
   * perhaps through alternate identities, reads as `owners: 1` however many
   * bounties it spans (06, "Known limits").
   */
  readonly owners: number
}

/**
 * What `trustLabels` reads from one bounty. A bounty record does not name
 * its owner; the key in its path does (`pubky://<owner>/pub/sweepky/
 * bounties/<id>.json`), so take `owner` from the `BountyRef` the record was
 * fetched by, never from anything the record says.
 */
export interface CreditedBounty {
  readonly owner: Pubky
  /** As written: only exactly `done` counts. */
  readonly status: string
  /** As written: the list may name the owner, or one sweeper twice. */
  readonly credits: readonly Pubky[]
}

/** The trust of any pubky, from one roster and one set of bounties. */
export interface TrustTable {
  /**
   * The trust of `pubky`. A pubky in neither the roster nor any counted
   * bounty is `unknown` with nothing counted.
   */
  get(pubky: Pubky): Trust
}

/**
 * The trust table for `circle` and `bounties`. The rule, from 01 ("Records
 * (v1)") with the owner count 00's trust model adds to `known`:
 *
 * - A credit counts only on a bounty whose `status` is exactly `done` and
 *   whose owner is trusted: in v1, anyone in the roster, which is the admin
 *   and every entry in `members` (`Circle::is_in_roster` in core). So an
 *   admin missing from `members` is still trusted.
 * - A credit naming the bounty's own owner counts for nothing. The CLI never
 *   writes one, but anyone can hand-write their own records, so the read side
 *   is where the rule holds.
 * - `bounties` counts the counted bounties crediting the pubky, each once,
 *   and `owners` the distinct owners among them.
 * - The label is `circle` for anyone in the roster, whatever the tally; else
 *   `known` if `bounties` > 0; else `unknown`.
 *
 * Pass every bounty you have: open ones, ones from owners outside the roster,
 * ones that credit their own owner. This function drops what does not count,
 * so no caller has a filter to forget. Pass each bounty record once, though:
 * two entries for one record count as two bounties.
 */
export function trustLabels(circle: Circle, bounties: readonly CreditedBounty[]): TrustTable {
  const roster = rosterOf(circle)
  const tallies = countCredits(roster, bounties)
  return {
    get(pubky) {
      const tally = tallies.get(pubky)
      const bountyCount = tally?.bounties ?? 0
      return {
        label: labelFor(roster, pubky, bountyCount),
        bounties: bountyCount,
        owners: tally?.owners.size ?? 0,
      }
    },
  }
}

/** The label for `pubky`, credited on `bountyCount` counted bounties. */
function labelFor(roster: ReadonlySet<Pubky>, pubky: Pubky, bountyCount: number): TrustLabel {
  if (roster.has(pubky)) return 'circle'
  if (bountyCount > 0) return 'known'
  return 'unknown'
}

/**
 * The roster's keys: the admin and every member.
 *
 * A `Pubky` is the one canonical spelling of a key, so a `Set` of them (and
 * every `===` below) compares key bytes, as 01 asks, whichever spelling a
 * record used. Not in constant time, and it need not be: these are public
 * keys.
 */
function rosterOf(circle: Circle): ReadonlySet<Pubky> {
  return new Set([circle.admin, ...circle.members.map((member) => member.pubky)])
}

/** A pubky's counted credits while `countCredits` adds them up. */
interface RunningTally {
  bounties: number
  readonly owners: Set<Pubky>
}

/** For each pubky credited on a counted bounty, those bounties and their owners. */
function countCredits(
  roster: ReadonlySet<Pubky>,
  bounties: readonly CreditedBounty[],
): ReadonlyMap<Pubky, RunningTally> {
  const tallies = new Map<Pubky, RunningTally>()
  for (const bounty of bounties) {
    if (!isCounted(bounty, roster)) continue
    for (const sweeper of creditedSweepers(bounty)) {
      let tally = tallies.get(sweeper)
      if (tally === undefined) {
        tally = { bounties: 0, owners: new Set() }
        tallies.set(sweeper, tally)
      }
      tally.bounties += 1
      // A set, so a second bounty from the same owner adds no owner.
      tally.owners.add(bounty.owner)
    }
  }
  return tallies
}

/** Whether `bounty`'s credits count: it is done and its owner is in the roster. */
function isCounted(bounty: CreditedBounty, roster: ReadonlySet<Pubky>): boolean {
  // `asKnownBountyStatus` matches the string exactly, so `Done`, `closed` or
  // a status a newer client adds is not `done`: when in doubt, a bounty
  // counts for nothing.
  return asKnownBountyStatus(bounty.status) === 'done' && roster.has(bounty.owner)
}

/**
 * The sweepers `bounty` credits, each once and without its owner, in the
 * order its `credits` first name them. The set drops a repeated credit, so
 * one bounty adds at most one to a pubky's `bounties`. Whatever its status:
 * whether the credits count is the caller's rule. The board's credited
 * sweepers come from here too, so the door of a dark room and the tally
 * behind a badge never disagree.
 */
export function creditedSweepers(bounty: CreditedBounty): ReadonlySet<Pubky> {
  return new Set(bounty.credits.filter((credit) => credit !== bounty.owner))
}
