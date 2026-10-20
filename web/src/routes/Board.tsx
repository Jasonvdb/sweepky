// `/board` (04, Views): the intro strip, the floor plan of the circle's
// bounties, sweeps in progress, the activity ticker, sweeps today and
// recently done bounties, every one derived from the store's records.
//
// With nothing to show, the floor plan is the empty state (no sample rooms),
// and when the board cannot read the circle at all, a notice says why: no
// circle selected, or the admin unreachable, worded and marked as the
// Circle page marks an unreachable member.

import { useId, type ReactNode } from 'react'
import { useBoard } from '../App.tsx'
import { BountyLink } from '../components/BountyLink.tsx'
import { CircleLink } from '../components/CircleLink.tsx'
import { FloorPlan } from '../components/FloorPlan.tsx'
import { IntroStrip } from '../components/IntroStrip.tsx'
import { RecordTime } from '../components/RecordTime.tsx'
import { Ticker } from '../components/Ticker.tsx'
import { TrustBadge } from '../components/TrustBadge.tsx'
import { useClock } from '../components/useClock.ts'
import {
  boardStatus,
  floorPlan,
  recentlyDone,
  sweepsInProgress,
  sweepsToday,
  tickerEvents,
  type BoardStatus,
  type DoneBounty,
  type SweepView,
} from '../store/selectors.ts'
import { bountyKey, sweepKey } from '../store/state.ts'

export function Board() {
  const now = useClock()
  const status = useBoard(boardStatus)
  const rooms = useBoard((state) => floorPlan(state, now))
  const inProgress = useBoard((state) => sweepsInProgress(state, now))
  const today = useBoard((state) => sweepsToday(state, now))
  const events = useBoard(tickerEvents)
  const done = useBoard(recentlyDone)

  return (
    <div className="container page board">
      <IntroStrip />
      <h1>The board</h1>
      <StatusNotice status={status} />
      <FloorPlan rooms={rooms} />
      <div className="board__panels">
        <Panel heading="Sweeps in progress">
          <SweepsInProgress sweeps={inProgress} />
        </Panel>
        <Panel heading="Activity">
          <Ticker events={events} />
        </Panel>
        <Panel heading="Sweeps today">
          <p className="board-stat">
            <span className="board-stat__value">{today}</span> {today === 1 ? 'sweep' : 'sweeps'}{' '}
            started today
          </p>
        </Panel>
        <Panel heading="Recently done">
          <RecentlyDone bounties={done} />
        </Panel>
      </div>
    </div>
  )
}

/** Why the board cannot read the circle, or nothing while it can. The Circle page shows it too. */
export function StatusNotice({ status }: { readonly status: BoardStatus }) {
  switch (status) {
    case 'ok':
      return null
    case 'no-circle':
      return (
        <p className="board-notice" role="status">
          No circle selected, so the board has nothing to show.
        </p>
      )
    case 'admin-unreachable':
      // The Circle page's "unreachable": the destructive mark beside the
      // word, which stays in --foreground (base.css).
      return (
        <p className="board-notice" role="status">
          <span className="state-mark state-mark--unreachable" aria-hidden="true" />
          <span>
            Unreachable: the circle's admin could not be reached from this browser, so the board
            cannot read the circle.
          </span>
        </p>
      )
  }
}

/** A card with a heading, labelling the region it holds. */
function Panel({ heading, children }: { readonly heading: string; readonly children: ReactNode }) {
  const headingId = useId()
  return (
    <section className="card board-panel" aria-labelledby={headingId}>
      <h2 id={headingId} className="board-panel__heading">
        {heading}
      </h2>
      {children}
    </section>
  )
}

/** The `running` sweeps; those past 6 h say "left" (selectors.ts). */
function SweepsInProgress({ sweeps }: { readonly sweeps: readonly SweepView[] }) {
  if (sweeps.length === 0) return <p className="board-panel__none">No sweeps in progress.</p>
  return (
    <ul className="sweep-list">
      {sweeps.map((sweep) => (
        <SweepInProgress key={sweepKey(sweep.ref)} sweep={sweep} />
      ))}
    </ul>
  )
}

function SweepInProgress({ sweep }: { readonly sweep: SweepView }) {
  const { ref } = sweep
  return (
    <li className="sweep-list__item" data-sweep={sweepKey(ref)}>
      <span className="sweep-list__state">{sweep.signal === 'pulsing' ? 'sweeping' : 'left'}</span>
      <TrustBadge trust={sweep.trust} />
      <CircleLink to={`/s/${ref.sweeper}/${ref.id}`} className="pubky">
        {ref.sweeper}
      </CircleLink>
      <BountyLink bounty={sweep.bounty} />
      <RecordTime ms={sweep.startedAtMs} />
    </li>
  )
}

/** The done bounties, latest first, each with its credited sweepers. */
function RecentlyDone({ bounties }: { readonly bounties: readonly DoneBounty[] }) {
  if (bounties.length === 0) return <p className="board-panel__none">No bounties done yet.</p>
  return (
    <ul className="done-list">
      {bounties.map((done) => (
        <li key={bountyKey(done.ref)} className="done-list__item" data-bounty={bountyKey(done.ref)}>
          <BountyLink bounty={done.ref} />
          <RecordTime ms={done.doneAtMs} />
          {done.credited.length > 0 && (
            <ul className="door" aria-label="Credited sweepers">
              {done.credited.map((sweeper) => (
                <li key={sweeper} className="pubky">
                  {sweeper}
                </li>
              ))}
            </ul>
          )}
        </li>
      ))}
    </ul>
  )
}
