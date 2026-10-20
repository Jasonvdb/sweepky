// One sweep in its room (04, "Visual direction"): a detector that pulses while
// the sweep is `running` and recent, fades to "left" after 6 h, settles when
// the sweep lands (`done`, the room is swept) and is struck when `aborted`.
// Both motions are CSS animations on a class (board.css), so the global
// reduced-motion rule in base.css stops them; nothing here animates by script.

import type { SweepSignal, SweepView } from '../store/selectors.ts'
import { TrustBadge } from './TrustBadge.tsx'

/** The text label beside each signal, so motion and colour are never the only cue. */
const SIGNAL_TEXT: Readonly<Record<SweepSignal, string>> = {
  pulsing: 'sweeping',
  left: 'left',
  done: 'swept',
  aborted: 'aborted',
  unrecognised: 'status not recognised',
}

export function Detector({ sweep }: { readonly sweep: SweepView }) {
  const { signal, trust } = sweep
  // An aborted sweep's lamp is the shared destructive mark (base.css), the one
  // place on the floor plan --destructive appears.
  const lamp = signal === 'aborted' ? 'detector__lamp state-mark state-mark--aborted' : 'detector__lamp'
  return (
    <li
      className={`detector detector--${signal} detector--${trust.label}`}
      data-sweeper={sweep.ref.sweeper}
    >
      <span className={lamp} aria-hidden="true" />
      <span className="detector__label">{SIGNAL_TEXT[signal]}</span>
      <TrustBadge trust={trust} />
    </li>
  )
}
