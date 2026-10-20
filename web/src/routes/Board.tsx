// `/board`: the board (04, Views). A placeholder that says what the store can
// show until the board task draws the intro strip, floor plan, ticker and the
// rest from it.

import { useBoard } from '../App.tsx'
import { boardStatus, type BoardStatus } from '../store/selectors.ts'

const STATUS_TEXT: Readonly<Record<BoardStatus, string>> = {
  'no-circle': 'No circle selected, so there is nothing to show.',
  'admin-unreachable': 'The circle’s admin cannot be reached from a browser.',
  ok: 'Watching the circle.',
}

export function Board() {
  const status = useBoard(boardStatus)
  return (
    <div className="container page">
      <h1>The board</h1>
      <p>{STATUS_TEXT[status]}</p>
    </div>
  )
}
