// The board's activity ticker (04, Views): what the held records say happened,
// newest first, from `tickerEvents`. Nothing is made up and nothing loops.
//
// It moves only on real events: when the newest event happened after this
// page opened, the list is drawn again under a new React `key`, which mounts
// it afresh and runs its one-shot CSS scroll (board.css) once. Events the
// first polls bring in that were already past when the page opened, the
// whole history of a busy circle among them, never move it. Under
// prefers-reduced-motion the scroll class is not set at all, on top of
// base.css's global stop.

import { useState, useSyncExternalStore } from 'react'
import type { TickerEvent, TickerKind } from '../store/selectors.ts'
import { BountyLink } from './BountyLink.tsx'
import { CircleLink } from './CircleLink.tsx'
import { RecordTime } from './RecordTime.tsx'

const KIND_TEXT: Readonly<Record<TickerKind, string>> = {
  bountyPosted: 'Bounty posted',
  bountyDone: 'Bounty done',
  sweepStarted: 'Sweep started',
  sweepDone: 'Sweep done',
  sweepAborted: 'Sweep aborted',
}

const REDUCED_MOTION = '(prefers-reduced-motion: reduce)'

/**
 * The prefers-reduced-motion query, or `null` where there is no `matchMedia`
 * (Node, when tests render to a string).
 */
function reducedMotionQuery(): MediaQueryList | null {
  return typeof globalThis.matchMedia === 'function' ? globalThis.matchMedia(REDUCED_MOTION) : null
}

function prefersReducedMotion(): boolean {
  return reducedMotionQuery()?.matches ?? false
}

function subscribeToReducedMotion(onChange: () => void): () => void {
  const query = reducedMotionQuery()
  query?.addEventListener('change', onChange)
  return () => query?.removeEventListener('change', onChange)
}

/**
 * Whether the visitor asked for reduced motion, kept current if they change
 * it while the page is open. `useSyncExternalStore` is React's hook for
 * reading a value that lives outside React; the third argument is what a
 * render to a string reads.
 */
function useReducedMotion(): boolean {
  return useSyncExternalStore(subscribeToReducedMotion, prefersReducedMotion, prefersReducedMotion)
}

export function Ticker({ events }: { readonly events: readonly TickerEvent[] }) {
  const [openedAt] = useState(Date.now)
  const reducedMotion = useReducedMotion()

  const newest = events[0]
  const arrived = newest !== undefined && newest.at > openedAt ? newest.key : null
  const scrolls = arrived !== null && !reducedMotion

  if (events.length === 0) return <p className="board-panel__none">Nothing has happened yet.</p>
  return (
    <ol
      key={arrived ?? 'as-opened'}
      className={scrolls ? 'ticker__items ticker__items--scroll' : 'ticker__items'}
    >
      {events.map((event) => (
        <TickerItem key={event.key} event={event} />
      ))}
    </ol>
  )
}

function TickerItem({ event }: { readonly event: TickerEvent }) {
  const { sweep } = event
  return (
    <li className="ticker__item" data-event={event.key}>
      <RecordTime ms={event.at} />
      <span className="ticker__kind">{KIND_TEXT[event.kind]}</span>
      <BountyLink bounty={event.bounty} />
      {sweep !== null && (
        <CircleLink to={`/s/${sweep.sweeper}/${sweep.id}`} className="pubky">
          {sweep.sweeper}
        </CircleLink>
      )}
    </li>
  )
}
