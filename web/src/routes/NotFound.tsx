import { CircleLink } from '../components/CircleLink.tsx'

/** Any path the app does not have, and a detail page whose key or id is malformed. */
export function NotFound() {
  return (
    <div className="container page">
      <h1>Page not found</h1>
      <p>
        There is nothing at this address. Try <CircleLink to="/board">the board</CircleLink> or{' '}
        <CircleLink to="/">the front page</CircleLink>.
      </p>
    </div>
  )
}
