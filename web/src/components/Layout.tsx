// The frame around every page: a skip link, the header with Sweepky's mark
// and the navigation, any notice about the circle, the page itself in
// `<main>`, and the footer.

import { Outlet } from 'react-router'
import { useCircle } from '../App.tsx'
import type { CircleNotice } from '../config/circle.ts'
import { CircleLink, CircleNavLink } from './CircleLink.tsx'
import { Mark } from './Mark.tsx'

/** The id the skip link jumps to. */
const MAIN_ID = 'main'

const NOTICE_TEXT: Readonly<Record<CircleNotice, string>> = {
  invalidQuery: 'The circle in this link is not a Pubky key, so it was ignored.',
  invalidDefault: 'This build’s default circle is not a Pubky key, so it was ignored.',
  noCircle: 'No circle selected: add ?circle=<admin pubky> to the address.',
}

export function Layout() {
  const { notices } = useCircle()
  return (
    <>
      {/* First on the page, so one Tab reaches it. A plain fragment link: it
          keeps the address's query as it is. */}
      <a className="skip-link" href={`#${MAIN_ID}`}>
        Skip to content
      </a>
      <header className="site-header">
        <div className="container site-header__inner">
          <CircleLink to="/" className="site-header__home">
            <Mark className="mark" />
            Sweepky
          </CircleLink>
          <nav aria-label="Main">
            <ul className="site-nav">
              <li>
                <CircleNavLink to="/board">Board</CircleNavLink>
              </li>
              <li>
                <CircleNavLink to="/circle">Circle</CircleNavLink>
              </li>
            </ul>
          </nav>
        </div>
      </header>
      {notices.length > 0 && (
        <div className="container circle-notice" role="status">
          {notices.map((notice) => (
            <p key={notice}>{NOTICE_TEXT[notice]}</p>
          ))}
        </div>
      )}
      {/* `tabIndex={-1}` lets the skip link move keyboard focus here, not
          only scroll, without adding `<main>` to the Tab order. */}
      <main id={MAIN_ID} tabIndex={-1}>
        <Outlet />
      </main>
      <footer className="site-footer">
        <div className="container site-footer__inner">
          <a href="https://pubky.org">Built on Pubky</a>
          <span>MIT licensed</span>
        </div>
      </footer>
    </>
  )
}
