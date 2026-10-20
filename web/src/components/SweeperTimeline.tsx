// The bounty page's sweeper timeline (04, Views): every sweep of the bounty
// the board holds, members' and the strangers' its owner accepted, oldest
// start first, each with its sweeper, badge, status and finish time. The
// rows come from `bountyTimeline` (selectors.ts), so they say only what the
// records say.

import type { SweepSignal, SweepView } from '../store/selectors.ts'
import { sweepKey } from '../store/state.ts'
import type { SweepRef } from '../records/urls.ts'
import { CircleLink } from './CircleLink.tsx'
import { RecordTime } from './RecordTime.tsx'
import { TrustBadge } from './TrustBadge.tsx'

export function SweeperTimeline({ sweeps }: { readonly sweeps: readonly SweepView[] }) {
  if (sweeps.length === 0) return <p className="details__none">No sweeps yet.</p>
  return (
    <ol className="timeline">
      {sweeps.map((sweep) => (
        <li key={sweepKey(sweep.ref)} className="timeline__item">
          <RecordTime ms={sweep.startedAtMs} />
          <SweepLink sweep={sweep.ref} />
          <TrustBadge trust={sweep.trust} />
          <SweepStatus signal={sweep.signal} />
          {sweep.finishedAtMs !== null && (
            <span className="timeline__finished">
              finished <RecordTime ms={sweep.finishedAtMs} />
            </span>
          )}
        </li>
      ))}
    </ol>
  )
}

/** A link to a sweep's page, named by its sweeper's key. */
export function SweepLink({ sweep }: { readonly sweep: SweepRef }) {
  // From the parsed key and id only, as Room.tsx builds its link.
  return (
    <CircleLink to={`/s/${sweep.sweeper}/${sweep.id}`} className="pubky">
      {sweep.sweeper}
    </CircleLink>
  )
}

/** The word for each signal. A `running` sweep past 6 h is the board's "left". */
const STATUS_TEXT: Readonly<Record<SweepSignal, string>> = {
  pulsing: 'running',
  left: 'left (running for over 6 h)',
  done: 'done',
  aborted: 'aborted',
  unrecognised: 'status not recognised',
}

/**
 * A sweep's status as a word. `aborted` is struck, with base.css's
 * destructive mark beside it, so the word, the strike and the mark all say
 * it and colour is never the only cue.
 */
export function SweepStatus({ signal }: { readonly signal: SweepSignal }) {
  return (
    <span className={`sweep-status sweep-status--${signal}`}>
      {signal === 'aborted' && <span className="state-mark state-mark--aborted" aria-hidden="true" />}
      <span className="sweep-status__label">{STATUS_TEXT[signal]}</span>
    </span>
  )
}
