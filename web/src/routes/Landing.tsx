// `/`: the landing page (04, "Landing page"). A placeholder with the hero's
// heading and actions until the landing task adds the hero's live floor plan
// (from the board's store) and the sections, `#post` and `#sweep` among them.

import { buttonClassName } from '../components/Button.tsx'
import { CircleLink } from '../components/CircleLink.tsx'

export function Landing() {
  return (
    <div className="container page">
      <h1>
        Your spare tokens, <span className="accent">sweeping</span> for bugs.
      </h1>
      <p className="actions">
        <CircleLink to="/board" className={buttonClassName('primary')}>
          Watch the board
        </CircleLink>
        <CircleLink to="/#sweep" className={buttonClassName('default')}>
          Run a sweep
        </CircleLink>
        <CircleLink to="/#post" className={buttonClassName('secondary')}>
          Post a bounty
        </CircleLink>
      </p>
    </div>
  )
}
