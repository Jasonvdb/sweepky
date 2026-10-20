// The app shell: 04's five routes and a not-found view, under the shared
// layout, rendered to HTML in Node through a memory router (no DOM needed).
import { renderToStaticMarkup } from 'react-dom/server'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { describe, expect, it } from 'vitest'
import { App } from '../App.tsx'
import { selectCircle, type CircleSelection } from '../config/circle.ts'
import { recordIdFromMicros } from '../records/ids.ts'
import { createBoardStore } from '../store/boardStore.ts'
import { routes } from '../router.tsx'

// Synthetic: a canonical key owned by nobody, and an id from a fixed time.
const KEY = '8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo'
const ID = recordIdFromMicros(1_700_000_000_000_000n)

const WITH_CIRCLE = selectCircle(`?circle=${KEY}`, undefined)

/**
 * The page at `path`. Rendering to a string never subscribes to the store,
 * so the poll never starts and the transport is never loaded.
 */
function render(path: string, circle: CircleSelection = WITH_CIRCLE): string {
  const store = createBoardStore({
    admin: circle.admin,
    loadTransport: () => Promise.reject(new Error('a render test sends nothing')),
    scheduler: { schedule: () => () => {} },
    now: () => 0,
  })
  const router = createMemoryRouter(routes, { initialEntries: [path] })
  return renderToStaticMarkup(
    <App services={{ store, circle }}>
      <RouterProvider router={router} />
    </App>,
  )
}

/** The text of the page's one `h1`. */
function heading(html: string): string {
  const h1s = [...html.matchAll(/<h1\b[^>]*>([\s\S]*?)<\/h1>/g)]
  expect(h1s).toHaveLength(1)
  return (h1s[0]?.[1] ?? '').replace(/<[^>]*>/g, '')
}

const NOT_FOUND = 'Page not found'

describe('routes', () => {
  it.each([
    ['/', 'Your spare tokens, sweeping for bugs.'],
    ['/board', 'The board'],
    [`/b/${KEY}/${ID}`, 'Bounty'],
    [`/s/${KEY}/${ID}`, 'Sweep'],
    ['/circle', 'The circle'],
  ])('%s renders its view', (path, expected) => {
    expect(heading(render(path))).toBe(expected)
  })

  it.each(['/nowhere', '/board/extra', '/b', `/b/${KEY}`])(
    'an unknown path %s renders NotFound',
    (path) => {
      expect(heading(render(path))).toBe(NOT_FOUND)
    },
  )

  it.each(['b', 's'])('/%s/ takes a raw or a pubky-prefixed key', (route) => {
    for (const key of [KEY, `pubky${KEY}`]) {
      const html = render(`/${route}/${key}/${ID}`)
      expect(heading(html)).not.toBe(NOT_FOUND)
      // The page names the key in its raw form, whichever spelling the link used.
      expect(html).toContain(KEY)
      expect(html).not.toContain(`pubky${KEY}`)
    }
  })

  it.each([
    ['b', 'not-a-key', ID],
    ['b', KEY.toUpperCase(), ID],
    ['b', KEY, 'not-an-id'],
    ['b', KEY, ID.toLowerCase()],
    ['s', 'not-a-key', ID],
    ['s', KEY, 'not-an-id'],
  ])('/%s/%s/%s renders NotFound', (route, key, id) => {
    expect(heading(render(`/${route}/${key}/${id}`))).toBe(NOT_FOUND)
  })
})

describe('layout', () => {
  const html = render('/board')

  it('opens with a skip link to the main content', () => {
    const firstLink = html.match(/<a\b[^>]*>/)?.[0] ?? ''
    expect(firstLink).toContain('href="#main"')
    expect(html).toMatch(/<main\b[^>]*\bid="main"/)
  })

  it('navigates with links only, each carrying the circle', () => {
    const nav = html.match(/<nav\b[^>]*>([\s\S]*?)<\/nav>/)?.[1] ?? ''
    expect(nav).not.toBe('')
    expect(nav).not.toMatch(/<button\b|onclick|tabindex/i)
    const hrefs = [...nav.matchAll(/<a\b[^>]*\bhref="([^"]*)"/g)].map((match) => match[1])
    expect(hrefs).toEqual([`/board?circle=${KEY}`, `/circle?circle=${KEY}`])
  })

  it("says it is built on Pubky with a text link, and that it is MIT", () => {
    const footer = html.match(/<footer\b[^>]*>([\s\S]*?)<\/footer>/)?.[1] ?? ''
    expect(footer).toMatch(/<a\b[^>]*href="https:\/\/pubky\.org"[^>]*>Built on Pubky<\/a>/)
    expect(footer).toContain('MIT')
  })

  it('keeps the circle on hash links', () => {
    expect(render('/')).toContain(`href="/?circle=${KEY}#sweep"`)
  })

  it('shows a notice for an ignored ?circle=', () => {
    const page = render('/board', selectCircle('?circle=bad', undefined))
    expect(page).toContain('not a Pubky key')
    expect(page).toContain('No circle selected')
  })

  it('shows no notice when a circle is selected', () => {
    expect(html).not.toContain('role="status"')
  })
})
