// The floor plan with no bounties (04, "Intro strip and empty state"): one
// outlined room labelled "No open bounties yet" and, under it, the two ways
// in side by side. Nothing placeholder is drawn as if it were real: no sample
// rooms, no demo detectors.

export function EmptyState() {
  return (
    <div className="empty-state">
      <article className="card room room--empty">
        <h3 className="room__title">No open bounties yet</h3>
      </article>
      <div className="empty-state__ways">
        <div className="empty-state__way">
          <h4>Owners</h4>
          <p>
            Ask your agent to post a bounty: <code>sweepky post</code>
          </p>
        </div>
        <div className="empty-state__way">
          <h4>Sweepers</h4>
          <ol>
            <li>
              <code>sweepky run</code>
            </li>
            <li>
              <code>/sweepky</code> in Claude Code
            </li>
            <li>
              <code>sweepky submit</code>
            </li>
          </ol>
        </div>
      </div>
    </div>
  )
}
