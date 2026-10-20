// `/b/:owner/:id`: one bounty (04, Views): its targets at their pinned
// revisions with the sweeps of each, the sweeper timeline, the `open`
// marker and, once it is done, the sweepers it credits. Drawn from the
// board's store only: a bounty the store does not hold shows the
// not-on-this-board view, and this page sends nothing of its own.

import { useId, useMemo, type ReactNode } from 'react'
import { useParams } from 'react-router'
import { useBoard } from '../App.tsx'
import { NotOnThisBoard } from '../components/NotOnThisBoard.tsx'
import { RecordTime } from '../components/RecordTime.tsx'
import { StrangerText } from '../components/StrangerText.tsx'
import { SweeperTimeline } from '../components/SweeperTimeline.tsx'
import { TargetList, type TargetedSweep } from '../components/TargetList.tsx'
import { TrustBadge } from '../components/TrustBadge.tsx'
import { useClock } from '../components/useClock.ts'
import { parseRecordId } from '../records/ids.ts'
import { asKnownBountyStatus, recordTimeMs } from '../records/parse.ts'
import { parsePubky } from '../records/pubky.ts'
import type { BountyRef } from '../records/urls.ts'
import { bountyTimeline, creditedSweepers, trustTable } from '../store/selectors.ts'
import { bountyKey, sweepKey, type BountyEntry } from '../store/state.ts'
import { NotFound } from './NotFound.tsx'

export function BountyPage() {
  const ref = useBountyRef()
  return ref === null ? <NotFound /> : <Bounty bountyRef={ref} />
}

/**
 * The bounty the address names, or `null` when its key or id is malformed.
 * The address is anyone's to type, so it is parsed like any other untrusted
 * text: the key raw or `pubky`-prefixed, both kept raw, the id canonical.
 */
function useBountyRef(): BountyRef | null {
  const params = useParams()
  const owner = parsePubky(params.owner ?? '')
  const id = parseRecordId(params.id ?? '')
  return owner === null || id === null ? null : { owner, id }
}

function Bounty({ bountyRef }: { readonly bountyRef: BountyRef }) {
  const entry = useBoard((state) => state.bounties.get(bountyKey(bountyRef)))
  if (entry === undefined) {
    return (
      <div className="container page details">
        <h1>Bounty</h1>
        <NotOnThisBoard record="bounty" />
      </div>
    )
  }
  return <BountyDetails entry={entry} />
}

/** The words for a bounty's status, as the floor plan's rooms say them. */
const STATUS_TEXT = { open: 'active', done: 'done' } as const

function BountyDetails({ entry }: { readonly entry: BountyEntry }) {
  const { ref, record } = entry
  const now = useClock()
  const timeline = useBoard((state) => bountyTimeline(state, ref, now))
  const sweeps = useBoard((state) => state.sweeps)
  const table = useBoard(trustTable)
  const status = asKnownBountyStatus(record.status)

  // Each timeline sweep with the targets its record names, for the sweeps
  // per target. Every timeline sweep is in `sweeps`: the timeline is made
  // from it.
  const withTargets = useMemo(
    (): readonly TargetedSweep[] =>
      timeline.map((view) => ({ view, targets: sweeps.get(sweepKey(view.ref))?.record.targets ?? [] })),
    [timeline, sweeps],
  )
  const credited = useMemo(() => creditedSweepers(entry), [entry])

  return (
    <div className="container page details">
      <p className="section__eyebrow">Bounty</p>
      <h1>
        <StrangerText text={record.title} />
      </h1>
      <p className="details__meta">
        <span>{status === null ? 'status not recognised' : STATUS_TEXT[status]}</span>
        {record.open && (
          <span className="open-marker">
            open<span className="visually-hidden"> to any sweeper</span>
          </span>
        )}
        <span>
          posted by <span className="pubky">{ref.owner}</span>
        </span>
        <RecordTime ms={recordTimeMs(record.createdAt, ref.id)} />
      </p>

      <dl className="details__fields">
        <dt>Focus</dt>
        <dd>
          <StrangerText text={record.focus} />
        </dd>
        {record.playbook.suggested !== null && (
          <>
            <dt>Playbook</dt>
            <dd className="mono">
              <StrangerText text={record.playbook.suggested} />
              {record.playbook.required ? ' (required)' : ' (suggested)'}
            </dd>
          </>
        )}
      </dl>
      {/* Plain text keeping the owner's line breaks (pre-wrap in details.css),
          never markdown rendered as HTML. */}
      <p className="bounty-brief">
        <StrangerText text={record.brief} />
      </p>

      <DetailSection heading="Targets">
        <TargetList targets={record.targets} sweeps={withTargets} />
      </DetailSection>

      <DetailSection heading="Sweeper timeline">
        <SweeperTimeline sweeps={timeline} />
      </DetailSection>

      {status === 'done' && (
        <DetailSection heading="Credited sweepers">
          {record.doneAt !== null && (
            <p className="details__meta">
              done <RecordTime ms={recordTimeMs(record.doneAt, ref.id)} />
            </p>
          )}
          {credited.length === 0 ? (
            <p className="details__none">No sweepers credited.</p>
          ) : (
            <ul className="credited">
              {credited.map((sweeper) => (
                <li key={sweeper} className="credited__item">
                  <TrustBadge trust={table.get(sweeper)} />
                  <span className="pubky">{sweeper}</span>
                </li>
              ))}
            </ul>
          )}
        </DetailSection>
      )}
    </div>
  )
}

/** A titled part of a detail page, labelled by its heading. */
function DetailSection({ heading, children }: { readonly heading: string; readonly children: ReactNode }) {
  const headingId = useId()
  return (
    <section className="details__section" aria-labelledby={headingId}>
      <h2 id={headingId}>{heading}</h2>
      {children}
    </section>
  )
}
