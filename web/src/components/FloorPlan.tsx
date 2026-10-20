// The floor plan (04, "Visual direction"): every bounty the board holds as a
// room, newest first, or the empty state when it holds none. The board draws
// it full size; the landing hero draws it `compact`, from the same store.

import type { Room as FloorPlanRoom } from '../store/selectors.ts'
import { bountyKey } from '../store/state.ts'
import { EmptyState } from './EmptyState.tsx'
import { Room } from './Room.tsx'

interface FloorPlanProps {
  /** `floorPlan(state, now)` from the selectors. */
  readonly rooms: readonly FloorPlanRoom[]
  /** Smaller rooms for the landing hero's frame. */
  readonly compact?: boolean
}

export function FloorPlan({ rooms, compact = false }: FloorPlanProps) {
  const className = compact ? 'floor-plan floor-plan--compact' : 'floor-plan'
  return (
    <section className={className} aria-label="Floor plan">
      {rooms.length === 0 ? (
        <EmptyState />
      ) : (
        <ul className="floor-plan__rooms">
          {rooms.map((room) => (
            <li key={bountyKey(room.ref)}>
              <Room room={room} />
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
