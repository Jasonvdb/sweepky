// `/circle`: the circle's members (04, Views). A placeholder listing the
// roster until the circle task adds homeservers, activity and credits.

import { useBoard } from '../App.tsx'
import { circleMembers } from '../store/selectors.ts'

export function CirclePage() {
  const members = useBoard(circleMembers)
  return (
    <div className="container page">
      <h1>The circle</h1>
      <ul>
        {members.map((member) => (
          <li key={member.pubky} className="pubky">
            {member.pubky}
          </li>
        ))}
      </ul>
    </div>
  )
}
