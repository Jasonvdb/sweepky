// What a detail page shows for a record the board's store does not hold. The
// detail pages read the store only and add no fetch path of their own, so a
// deep link to a record outside the circle's records lands here, as does
// one opened before the first poll has read it.

import { CircleLink } from './CircleLink.tsx'

export function NotOnThisBoard({ record }: { readonly record: 'bounty' | 'sweep' }) {
  return (
    <div className="details__absent">
      <p>
        <strong>Not on this board.</strong> The board shows the bounties and sweeps of its circle,
        and the strangers' sweeps a bounty's owner has accepted. This {record} is not among the
        records it has read, so it is either outside the circle or not read yet; the board reads
        again every 30 seconds.
      </p>
      <p>
        <CircleLink to="/board">Back to the board</CircleLink>
      </p>
    </div>
  )
}
