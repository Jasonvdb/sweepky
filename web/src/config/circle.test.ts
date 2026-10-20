// Which circle the board shows: `?circle=<admin pubky>` over the build-time
// default `VITE_SWEEPKY_CIRCLE` (04, Stack), and the internal links that
// carry the choice from page to page.
import { describe, expect, it } from 'vitest'
import type { Pubky } from '../records/pubky.ts'
import { selectCircle, withCircle } from './circle.ts'

// Synthetic keys: canonical z-base32, owned by nobody.
const QUERY_KEY = '8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo'
const DEFAULT_KEY = `${'y'.repeat(51)}o`

describe('selectCircle', () => {
  it('takes ?circle= over the build-time default, and links carry it', () => {
    expect(selectCircle(`?circle=${QUERY_KEY}`, DEFAULT_KEY)).toEqual({
      admin: QUERY_KEY,
      linkCircle: QUERY_KEY,
      notices: [],
    })
  })

  it('reads a pubky-prefixed key in the query as the raw key', () => {
    expect(selectCircle(`?circle=pubky${QUERY_KEY}`, undefined).admin).toBe(QUERY_KEY)
  })

  it('uses the default when there is no query, and links need not carry it', () => {
    expect(selectCircle('', DEFAULT_KEY)).toEqual({
      admin: DEFAULT_KEY,
      linkCircle: null,
      notices: [],
    })
  })

  it.each(['?circle=not-a-key', '?circle=', `?circle=${QUERY_KEY.toUpperCase()}`])(
    'ignores an invalid %s with a notice, and links drop it',
    (search) => {
      expect(selectCircle(search, DEFAULT_KEY)).toEqual({
        admin: DEFAULT_KEY,
        linkCircle: null,
        notices: ['invalidQuery'],
      })
    },
  )

  it('selects no circle with neither a default nor a query', () => {
    expect(selectCircle('', undefined)).toEqual({
      admin: null,
      linkCircle: null,
      notices: ['noCircle'],
    })
  })

  it('treats an invalid default as none, with a notice', () => {
    expect(selectCircle('', 'not-a-key')).toEqual({
      admin: null,
      linkCircle: null,
      notices: ['invalidDefault', 'noCircle'],
    })
  })

  it('reports both an ignored query and no circle', () => {
    expect(selectCircle('?circle=bad', undefined).notices).toEqual(['invalidQuery', 'noCircle'])
  })
})

describe('withCircle', () => {
  it('leaves a link alone when the circle is not carried', () => {
    expect(withCircle('/#sweep', null)).toBe('/#sweep')
  })

  it.each([
    ['/board', `/board?circle=${QUERY_KEY}`],
    ['/#sweep', `/?circle=${QUERY_KEY}#sweep`],
    ['/circle?x=1#top', `/circle?x=1&circle=${QUERY_KEY}#top`],
    [`/board?circle=${DEFAULT_KEY}`, `/board?circle=${QUERY_KEY}`],
  ])('carries the circle on %s', (to, expected) => {
    expect(withCircle(to, QUERY_KEY as Pubky)).toBe(expected)
  })
})
