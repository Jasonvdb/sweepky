// A link to a bounty's page, named by the bounty's title as the board holds
// it. A sweep can name a bounty the board does not hold (a member sweeping
// outside the circle), which gets a fixed name instead.

import { useBoard } from '../App.tsx'
import type { BountyRef } from '../records/urls.ts'
import { bountyKey } from '../store/state.ts'
import { CircleLink } from './CircleLink.tsx'
import { StrangerText } from './StrangerText.tsx'

export function BountyLink({ bounty }: { readonly bounty: BountyRef }) {
  // A string, not the entry, so the link renders again only when the title changes.
  const title = useBoard((state) => state.bounties.get(bountyKey(bounty))?.record.title ?? null)
  // From the parsed key and id only, as Room.tsx builds its link.
  return (
    <CircleLink to={`/b/${bounty.owner}/${bounty.id}`}>
      {title === null ? 'a bounty outside this board' : <StrangerText text={title} />}
    </CircleLink>
  )
}
