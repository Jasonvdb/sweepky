// Which circle the board shows. 04 (Stack): `?circle=<admin pubky>` picks it,
// over a default fixed when the app is built, `VITE_SWEEPKY_CIRCLE`. With
// neither, no circle is selected: the store sends nothing and the pages say
// so.
//
// The choice is made once, when the page loads, because the board's store is
// built for one admin. Internal links keep a `?circle=` from the address, so
// moving between pages never drops back to the default.
//
// Like network.ts, nothing here reads `import.meta.env` or `window`: the
// caller passes them in, so tests need neither.

import { parsePubky, type Pubky } from '../records/pubky.ts'

/** The query parameter that names the circle's admin. */
const CIRCLE_PARAM = 'circle'

/** Something about the choice the pages should say. */
export type CircleNotice =
  /** `?circle=` was not a key, so it was ignored. */
  | 'invalidQuery'
  /** The build's `VITE_SWEEPKY_CIRCLE` is not a key, so there is no default. */
  | 'invalidDefault'
  /** No circle is selected. */
  | 'noCircle'

export interface CircleSelection {
  /** The admin whose circle the board shows, or `null` for none. */
  readonly admin: Pubky | null
  /**
   * The key internal links carry as `?circle=`: the query's, when it chose
   * the circle. `null` when the default chose it (a link without the query
   * gets the same default) or nothing did.
   */
  readonly linkCircle: Pubky | null
  /** What to tell the visitor, in this order. */
  readonly notices: readonly CircleNotice[]
}

/**
 * The circle for a page whose address has `search` as its query (as
 * `location.search` gives it, `?` included), when the build's default is
 * `buildDefault` (`import.meta.env.VITE_SWEEPKY_CIRCLE`).
 *
 * Either may hold a key raw or `pubky`-prefixed; a value that is not a key
 * is ignored with a notice, never guessed at.
 */
export function selectCircle(search: string, buildDefault: string | undefined): CircleSelection {
  const notices: CircleNotice[] = []

  const query = new URLSearchParams(search).get(CIRCLE_PARAM)
  if (query !== null) {
    const fromQuery = parsePubky(query)
    if (fromQuery !== null) return { admin: fromQuery, linkCircle: fromQuery, notices }
    notices.push('invalidQuery')
  }

  let admin: Pubky | null = null
  // An empty `VITE_SWEEPKY_CIRCLE=` is "no default", as unset is.
  if (buildDefault !== undefined && buildDefault !== '') {
    admin = parsePubky(buildDefault)
    if (admin === null) notices.push('invalidDefault')
  }
  if (admin === null) notices.push('noCircle')
  return { admin, linkCircle: null, notices }
}

/**
 * The internal link `to` (a path, perhaps with a query and a `#` fragment)
 * with `?circle=<circle>` added, replacing any it had; `to` unchanged when
 * `circle` is `null`. The query goes before the fragment, so `/#sweep`
 * becomes `/?circle=<circle>#sweep`.
 */
export function withCircle(to: string, circle: Pubky | null): string {
  if (circle === null) return to
  const [beforeHash, hash] = splitAt(to, '#')
  const [path, query] = splitAt(beforeHash, '?')
  // URLSearchParams, so the rest of the query is kept as it was and the key
  // is encoded as a value. A z-base32 key needs no escaping anyway.
  const params = new URLSearchParams(query)
  params.set(CIRCLE_PARAM, circle)
  return `${path}?${params.toString()}${hash === '' ? '' : `#${hash}`}`
}

/** `text` split at the first `separator`, which neither part keeps; `[text, '']` without one. */
function splitAt(text: string, separator: string): [string, string] {
  const at = text.indexOf(separator)
  return at < 0 ? [text, ''] : [text.slice(0, at), text.slice(at + 1)]
}
