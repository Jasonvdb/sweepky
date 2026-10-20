// The Circle page's ring of members (04, "Visual direction"): one node per
// member round a dial, brighter the more recent its last activity, and a card
// per member with its homeserver, last activity, credits received and
// reachability.
//
// The dial is drawn only where it fits (details.css); at 375 px the cards
// alone are the list, so nothing scrolls sideways. Brightness repeats what the
// card's "Last activity" says, so nothing depends on it alone, and the dial is
// hidden from assistive technology.

import type { CSSProperties } from 'react'
import type { MemberView, Reachability } from '../store/selectors.ts'
import { RecordTime } from './RecordTime.tsx'
import { StrangerText } from './StrangerText.tsx'

const DAY_MS = 24 * 60 * 60 * 1000

/** How bright a member is: by the age of its newest record, `dark` with none. */
type Brightness = 'bright' | 'lit' | 'dim' | 'dark'

/** Within a day bright, a week lit, thirty days dim, then dark. */
function brightnessOf(lastActivityMs: number | null, now: number): Brightness {
  if (lastActivityMs === null) return 'dark'
  const age = now - lastActivityMs
  if (age <= DAY_MS) return 'bright'
  if (age <= 7 * DAY_MS) return 'lit'
  if (age <= 30 * DAY_MS) return 'dim'
  return 'dark'
}

interface MemberRingProps {
  readonly members: readonly MemberView[]
  /** The time brightness is measured at (useClock). */
  readonly now: number
}

export function MemberRing({ members, now }: MemberRingProps) {
  const shown = members.map((member) => ({
    member,
    brightness: brightnessOf(member.lastActivityMs, now),
  }))
  return (
    <div className="member-ring">
      <div className="member-ring__dial" aria-hidden="true">
        {shown.map(({ member, brightness }, index) => (
          <span
            key={member.pubky}
            className={`member-ring__node member-ring__node--${brightness}`}
            // A custom property, so the CSS places each node its share of a
            // turn round the dial.
            style={{ '--turn': index / shown.length } as CSSProperties}
          />
        ))}
      </div>
      <ol className="member-list">
        {shown.map(({ member, brightness }) => (
          <MemberCard key={member.pubky} member={member} brightness={brightness} />
        ))}
      </ol>
    </div>
  )
}

interface MemberCardProps {
  readonly member: MemberView
  readonly brightness: Brightness
}

function MemberCard({ member, brightness }: MemberCardProps) {
  const { pubky, isAdmin, label, homeserver, reachability, trust, lastActivityMs } = member
  return (
    <li className={`card member member--${brightness}`} data-member={pubky}>
      <p className="member__name">
        <span className="member__glow" aria-hidden="true" />
        {label !== null && <StrangerText text={label} />}
        {isAdmin && <span className="member__role">admin</span>}
      </p>
      <p className="pubky">{pubky}</p>
      <dl className="details__fields">
        <dt>Homeserver</dt>
        {homeserver === null ? (
          <dd className="member__muted">not known</dd>
        ) : (
          <dd className="pubky">{homeserver}</dd>
        )}
        <dt>Last activity</dt>
        <dd>
          {lastActivityMs === null ? (
            <span className="member__muted">no records yet</span>
          ) : (
            <RecordTime ms={lastActivityMs} />
          )}
        </dd>
        <dt>Credits received</dt>
        <dd>
          {plural(trust.bounties, 'bounty', 'bounties')} from{' '}
          {plural(trust.owners, 'owner', 'owners')}
        </dd>
        <dt>Reachability</dt>
        <dd>
          <ReachabilityText reachability={reachability} />
        </dd>
      </dl>
    </li>
  )
}

/**
 * How far the browser reaches the member. Only "unreachable" carries the
 * destructive mark, beside a --foreground word (base.css); "not
 * browser-reachable" stays muted, because the CLI can still reach it.
 */
function ReachabilityText({ reachability }: { readonly reachability: Reachability }) {
  switch (reachability) {
    case 'reachable':
      return <span>reachable</span>
    case 'resolving':
      return <span className="member__muted">looking up</span>
    case 'notBrowserReachable':
      return (
        <span className="member__reach">
          <span className="member__muted">not browser-reachable</span>
          <span className="member__muted">
            Its homeserver has no ICANN HTTPS endpoint, the only kind a browser can use. The
            CLI can still reach it.
          </span>
        </span>
      )
    case 'unreachable':
      return (
        <span className="member__reach member__reach--inline">
          <span className="state-mark state-mark--unreachable" aria-hidden="true" />
          <span>unreachable</span>
        </span>
      )
  }
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`
}
