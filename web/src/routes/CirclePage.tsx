// `/circle` (04, Views): the circle's members, admin first, as a ring whose
// brightness is their recent activity, each with its homeserver, last
// activity, credits received and reachability. With no circle selected, or
// an admin the browser cannot reach, the board's notice says why.

import { useBoard } from '../App.tsx'
import { MemberRing } from '../components/MemberRing.tsx'
import { useClock } from '../components/useClock.ts'
import { boardStatus, circleMembers } from '../store/selectors.ts'
import { StatusNotice } from './Board.tsx'

export function CirclePage() {
  const now = useClock()
  const status = useBoard(boardStatus)
  const members = useBoard(circleMembers)
  return (
    <div className="container page circle-page">
      <h1>The circle</h1>
      <StatusNotice status={status} />
      {members.length > 0 && <MemberRing members={members} now={now} />}
    </div>
  )
}
