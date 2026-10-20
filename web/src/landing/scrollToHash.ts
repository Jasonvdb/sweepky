// Scrolling to `/#post` and `/#sweep` (04, "Landing page"). The browser
// scrolls to a fragment only on a full page load, and react-router's links
// navigate without one, so a click on "Run a sweep" would change the address
// and leave the page where it was.
//
// react-router 8.4.0's <ScrollRestoration> does scroll to the hash, but it
// also keeps every page's scroll position in session storage and takes over
// scrolling on every route. The intro strip's dismissal is meant to stay the
// app's one use of browser storage (P4, Notes), so the landing scrolls to its
// own anchors with this small effect instead.

import { useLayoutEffect } from 'react'
import { useLocation } from 'react-router'

/** The one part of `document` this needs, so a test can pass a stand-in. */
export interface ElementLookup {
  getElementById(id: string): Pick<Element, 'scrollIntoView'> | null
}

/**
 * Scrolls the element `hash` (`#sweep`) names into view, or does nothing when
 * no element has that id or the hash is not valid percent-encoding.
 *
 * `behavior: 'auto'` asks for no smooth scroll of its own and leaves it to
 * the page's `scroll-behavior`, which base.css turns off under
 * `prefers-reduced-motion: reduce`.
 */
export function scrollToHash(hash: string, lookup: ElementLookup): void {
  if (hash.length <= 1) return
  let id: string
  try {
    id = decodeURIComponent(hash.slice(1))
  } catch {
    // A malformed escape in the address is the visitor's typo, not an error.
    return
  }
  lookup.getElementById(id)?.scrollIntoView({ behavior: 'auto', block: 'start' })
}

/**
 * Scrolls to the address's fragment after every navigation that sets one.
 * A layout effect runs after React has put the page in the document and
 * before the browser paints it, so the anchor exists and the page never
 * flashes at the top first. Keyed on the location's `key` as well as its
 * hash, so a second click on the same link scrolls back to it.
 */
export function useScrollToHash(): void {
  const { hash, key } = useLocation()
  useLayoutEffect(() => {
    scrollToHash(hash, document)
  }, [hash, key])
}
