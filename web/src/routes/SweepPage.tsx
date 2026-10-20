// `/s/:sweeper/:id`: one sweep record (04, Views): its sweeper, duration,
// status, playbook and trust badge, aborted ones included. Never its
// findings: they are sealed to the bounty's owner, and the board neither
// reads nor links the package. Drawn from the board's store only: a sweep
// the store does not hold shows the not-on-this-board view.

import { useParams } from 'react-router'
import { useBoard } from '../App.tsx'
import { BountyLink } from '../components/BountyLink.tsx'
import { NotOnThisBoard } from '../components/NotOnThisBoard.tsx'
import { RecordTime } from '../components/RecordTime.tsx'
import { StrangerText } from '../components/StrangerText.tsx'
import { SweepStatus } from '../components/SweeperTimeline.tsx'
import { TrustBadge } from '../components/TrustBadge.tsx'
import { useClock } from '../components/useClock.ts'
import { parseRecordId } from '../records/ids.ts'
import { parsePubky } from '../records/pubky.ts'
import type { SweepRef } from '../records/urls.ts'
import { bountyTimeline, type SweepView } from '../store/selectors.ts'
import { sweepKey, type SweepEntry } from '../store/state.ts'
import { NotFound } from './NotFound.tsx'

export function SweepPage() {
  const ref = useSweepRef()
  return ref === null ? <NotFound /> : <Sweep sweepRef={ref} />
}

/** The sweep the address names, or `null` when its key or id is malformed (as BountyPage). */
function useSweepRef(): SweepRef | null {
  const params = useParams()
  const sweeper = parsePubky(params.sweeper ?? '')
  const id = parseRecordId(params.id ?? '')
  return sweeper === null || id === null ? null : { sweeper, id }
}

function Sweep({ sweepRef }: { readonly sweepRef: SweepRef }) {
  const entry = useBoard((state) => state.sweeps.get(sweepKey(sweepRef)))
  return (
    <div className="container page details">
      <h1>Sweep</h1>
      {entry === undefined ? <NotOnThisBoard record="sweep" /> : <SweepDetails entry={entry} />}
    </div>
  )
}

function SweepDetails({ entry }: { readonly entry: SweepEntry }) {
  const { ref, record } = entry
  const now = useClock()
  // Its row of its bounty's timeline: the status, badge and times the
  // bounty page shows for it, from the one place that derives them.
  const view = useBoard((state) => bountyTimeline(state, record.bounty, now)).find(
    (row) => sweepKey(row.ref) === sweepKey(ref),
  )
  // Every held sweep is in its bounty's timeline; this only satisfies the type.
  if (view === undefined) return null
  return (
    <dl className="details__fields">
      <dt>Sweeper</dt>
      <dd className="pubky">{ref.sweeper}</dd>
      <dt>Trust</dt>
      <dd>
        <TrustBadge trust={view.trust} />
      </dd>
      <dt>Bounty</dt>
      <dd>
        <BountyLink bounty={record.bounty} />
      </dd>
      <dt>Status</dt>
      <dd>
        <SweepStatus signal={view.signal} />
      </dd>
      <dt>Playbook</dt>
      <dd className="mono">
        <StrangerText text={record.playbook} />
      </dd>
      <dt>Targets</dt>
      <dd className="mono">{record.targets.join(', ')}</dd>
      <dt>Started</dt>
      <dd>
        <RecordTime ms={view.startedAtMs} />
      </dd>
      {view.finishedAtMs !== null && (
        <>
          <dt>Finished</dt>
          <dd>
            <RecordTime ms={view.finishedAtMs} />
          </dd>
        </>
      )}
      <dt>Duration</dt>
      <dd>{durationText(view, now)}</dd>
    </dl>
  )
}

const MINUTE_MS = 60_000

/**
 * How long the sweep took, or has run so far while `running`. A sweep with
 * a final status but no `finishedAt`, or times that run backwards (a
 * stranger chooses both), has no duration to show.
 */
function durationText(view: SweepView, now: number): string {
  const running = view.status === 'running'
  const end = running ? now : view.finishedAtMs
  if (end === null || end < view.startedAtMs) return 'not known'
  const minutes = Math.floor((end - view.startedAtMs) / MINUTE_MS)
  const hours = Math.floor(minutes / 60)
  const length =
    minutes < 1 ? 'under a minute' : hours === 0 ? `${minutes} min` : `${hours} h ${minutes % 60} min`
  return running ? `${length} so far` : length
}
