// Internal links that keep the page's `?circle=` (config/circle.ts), so a
// visitor who came in on someone's circle stays on it from page to page.
// Every link from one page of the app to another goes through these.

import { Link, NavLink, type LinkProps, type NavLinkProps } from 'react-router'
import { useCircle } from '../App.tsx'
import { withCircle } from '../config/circle.ts'

interface CircleLinkProps extends Omit<LinkProps, 'to'> {
  /** A path in this app, perhaps with a `#` fragment: `/board`, `/#sweep`. */
  readonly to: string
}

/** A react-router `Link` to `to`, carrying the circle. */
export function CircleLink({ to, ...rest }: CircleLinkProps) {
  return <Link {...rest} to={withCircle(to, useCircle().linkCircle)} />
}

interface CircleNavLinkProps extends Omit<NavLinkProps, 'to'> {
  readonly to: string
}

/**
 * A `NavLink` to `to`, carrying the circle: as `CircleLink`, plus
 * `aria-current="page"` while its page is open, so a screen reader says
 * which page of the navigation is the current one.
 */
export function CircleNavLink({ to, ...rest }: CircleNavLinkProps) {
  return <NavLink {...rest} to={withCircle(to, useCircle().linkCircle)} />
}
