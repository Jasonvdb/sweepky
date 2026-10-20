// A sweeper's trust badge (04, "Visual direction"): `circle` a solid brand
// mark, `known N` a brand outline with the count, `unknown` a hollow muted
// outline that a credit fills in. The shape differs as well as the colour, and
// the label is always written out, so nothing depends on colour alone.

import type { Trust } from '../trust/trust.ts'

/** What the badge says: `known` carries the count of bounties behind it. */
function badgeText({ label, bounties }: Trust): string {
  return label === 'known' ? `known ${bounties}` : label
}

export function TrustBadge({ trust }: { readonly trust: Trust }) {
  return (
    <span className={`trust-badge trust-badge--${trust.label}`}>
      {/* The shape repeats what the label says, so assistive technology skips it. */}
      <span className="trust-badge__shape" aria-hidden="true" />
      {badgeText(trust)}
    </span>
  )
}
