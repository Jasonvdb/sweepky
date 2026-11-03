// The floor plan (04, "Visual direction"): every bounty the board holds as a
// room, newest first. With none, the loading plan while the store is still on
// its first read, then the empty state: so a board that has bounties never
// says it has none on the way to showing them. The board draws it full size;
// the landing hero draws it `compact`, from the same store.

import type { Room as FloorPlanRoom } from '../store/selectors.ts'
import { bountyKey } from '../store/state.ts'
import { EmptyState } from './EmptyState.tsx'
import { Room } from './Room.tsx'

interface FloorPlanProps {
  /** `floorPlan(state, now)` from the selectors. */
  readonly rooms: readonly FloorPlanRoom[]
  /** Smaller rooms for the landing hero's frame. */
  readonly compact?: boolean
  /** `floorPlanLoading(state)`: the store is still on its first read. */
  readonly loading?: boolean
}

export function FloorPlan({ rooms, compact = false, loading = false }: FloorPlanProps) {
  const className = compact ? 'floor-plan floor-plan--compact' : 'floor-plan'
  return (
    <section className={className} aria-label="Floor plan" aria-busy={rooms.length === 0 && loading}>
      {rooms.length === 0 ? (
        loading ? (
          <LoadingPlan />
        ) : (
          <EmptyState />
        )
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

/**
 * How many outlined rooms the loading plan draws: as many as the landing
 * hero shows at most (HERO_ROOMS in routes/Landing.tsx), so the hero's
 * sheet keeps its height when they turn into bounties.
 */
const LOADING_ROOMS = 3

/**
 * Rooms with walls and nothing inside yet, while the store reads the circle:
 * placeholders that never pass for a bounty, since no title, state or
 * detector is drawn. The status says it in words for assistive technology.
 */
function LoadingPlan() {
  return (
    <div className="floor-plan__loading" role="status">
      <span className="visually-hidden">Reading the circle's bounties</span>
      <ul className="floor-plan__rooms" aria-hidden="true">
        {Array.from({ length: LOADING_ROOMS }, (_, at) => (
          <li key={at}>
            <div className="card room room--loading">
              <span className="room__bar" />
              <span className="room__bar room__bar--short" />
              <span className="room__bar room__bar--pill" />
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
