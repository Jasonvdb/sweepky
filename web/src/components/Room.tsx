// One bounty on the floor plan (04, "Visual direction"): a lit room while it
// is open, with a detector per sweep, marked swept once a sweep is done; a
// dark room once the bounty is done, with its credited sweepers' marks on the
// door. Each state has a class for its look and a text label.

import { sweepKey } from '../store/state.ts'
import type { Room as FloorPlanRoom } from '../store/selectors.ts'
import { CircleLink } from './CircleLink.tsx'
import { Detector } from './Detector.tsx'
import { StrangerText } from './StrangerText.tsx'

/** The room's state: its modifier class and the label that says it. */
function roomState(room: FloorPlanRoom): { readonly className: string; readonly label: string } {
  switch (room.status) {
    case 'open':
      return { className: 'room--lit', label: 'active' }
    case 'done':
      return { className: 'room--done', label: 'done' }
    case null:
      return { className: 'room--unrecognised', label: 'status not recognised' }
  }
}

export function Room({ room }: { readonly room: FloorPlanRoom }) {
  const state = roomState(room)
  // From the parsed key and id only, never from text a record holds, so the
  // link always names a bounty page and nothing else.
  const href = `/b/${room.ref.owner}/${room.ref.id}`
  return (
    <article className={`card room ${state.className}`}>
      <h3 className="room__title">
        <CircleLink to={href}>
          <StrangerText text={room.title} />
        </CircleLink>
      </h3>
      <p className="room__state">
        <span>{state.label}</span>
        {room.open && (
          <span className="open-marker">
            open<span className="visually-hidden"> to any sweeper</span>
          </span>
        )}
        {room.swept && (
          <span className="swept-mark">
            <span className="swept-mark__tick" aria-hidden="true" />
            swept
          </span>
        )}
      </p>
      {room.detectors.length > 0 && (
        <ul className="room__detectors" aria-label="Sweeps">
          {room.detectors.map((sweep) => (
            <Detector key={sweepKey(sweep.ref)} sweep={sweep} />
          ))}
        </ul>
      )}
      {room.credited.length > 0 && (
        <ul className="door" aria-label="Credited sweepers">
          {room.credited.map((sweeper) => (
            <li key={sweeper} className="pubky truncate">
              {sweeper}
            </li>
          ))}
        </ul>
      )}
    </article>
  )
}
