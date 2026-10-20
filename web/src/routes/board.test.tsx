// `/board` (04, Views): the intro strip, the floor plan, sweeps in progress,
// the activity ticker, sweeps today and recently done bounties, or the empty
// state with a notice when there is nothing the board can read. Rendered to
// HTML in Node, from a store whose state the test sets, at a fixed clock.
import { readdirSync, readFileSync } from 'node:fs'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { create } from 'zustand'
import { App } from '../App.tsx'
import { forgetIntroDismissed, isIntroDismissed, rememberIntroDismissed } from '../components/introDismissal.ts'
import { selectCircle, type CircleSelection } from '../config/circle.ts'
import { recordIdFromMicros, type RecordId } from '../records/ids.ts'
import type { Bounty, Sweep } from '../records/parse.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import { recentlyDone, sweepsInProgress, sweepsToday, tickerEvents } from '../store/selectors.ts'
import {
  bountyKey,
  initialBoardState,
  memberState,
  sweepKey,
  type BoardState,
  type BountyEntry,
  type Resolution,
  type SweepEntry,
} from '../store/state.ts'
import { Board } from './Board.tsx'

// Synthetic keys from fixtures/trust-labels.json: A is the circle's admin and
// owns every bounty, B a member, C and D strangers.
const A = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
const B = pubky('btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy')
const C = pubky('a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy')
const D = pubky('5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco')

/** The page opens at noon UTC, so "today" holds the hours before. */
const NOW = Date.UTC(2026, 9, 20, 12)
const HOUR = 60 * 60 * 1000

const WITH_CIRCLE = selectCircle(`?circle=${A}`, undefined)

const INTRO = "Coding agents sweeping code for bugs. Findings go only to each bounty's owner."
const EMPTY_LABEL = 'No open bounties yet'

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`test key ${text} is not a key`)
  return key
}

/** The id of the time `ms`, so ids sort as their times do. */
function idAt(ms: number): RecordId {
  return recordIdFromMicros(BigInt(ms) * 1000n)
}

function time(ms: number): string {
  return new Date(ms).toISOString().replace('.000Z', 'Z')
}

function bounty(ref: BountyRef, fields: Partial<Bounty> = {}): BountyEntry {
  const record: Bounty = {
    title: `Bounty ${ref.id}`,
    focus: 'security',
    brief: 'A brief.',
    playbook: { suggested: null, required: false },
    targets: [],
    open: false,
    status: 'open',
    credits: [],
    createdAt: time(NOW - 30 * HOUR),
    doneAt: null,
    ...fields,
  }
  return { ref, record, discovered: null }
}

function sweep(sweeper: Pubky, startedMs: number, of: BountyRef, fields: Partial<Sweep> = {}): SweepEntry {
  const ref: SweepRef = { sweeper, id: idAt(startedMs) }
  const record: Sweep = {
    bounty: of,
    targets: ['t1'],
    playbook: 'cloudflare/security-audit@c1c8a8c',
    status: 'running',
    startedAt: time(startedMs),
    finishedAt: null,
    sha256: null,
    ...fields,
  }
  return { ref, record }
}

/** A's circle with member B, holding these records. */
function board(bounties: readonly BountyEntry[], sweeps: readonly SweepEntry[] = []): BoardState {
  return {
    ...initialBoardState(A),
    circle: { name: 'Test circle', admin: A, members: [{ pubky: B, label: null }] },
    bounties: new Map(bounties.map((entry) => [bountyKey(entry.ref), entry])),
    sweeps: new Map(sweeps.map((entry) => [sweepKey(entry.ref), entry])),
  }
}

/** A's circle before anything is read, the admin's lookup having answered `resolution`. */
function adminLookedUp(resolution: Resolution): BoardState {
  const state = initialBoardState(A)
  return { ...state, members: new Map([[A, { ...memberState(state, A), resolution }]]) }
}

/**
 * The board drawing `state` at NOW. The store is a plain zustand store
 * holding `state` from the start, with no poll behind it: a render to a
 * string reads a store's initial state (its server snapshot), never a later
 * one, and sends nothing.
 */
function render(state: BoardState, circle: CircleSelection = WITH_CIRCLE): string {
  const store = create<BoardState>()(() => state)
  return renderToStaticMarkup(
    <App services={{ store, circle }}>
      <MemoryRouter>
        <Board />
      </MemoryRouter>
    </App>,
  )
}

/** What a reader sees: the markup without its tags, entities decoded. */
function text(html: string): string {
  return html
    .replace(/<[^>]*>/g, '')
    .replace(/&#x27;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
}

/** The elements whose class list holds `name`, each as its opening tag. */
function withClass(html: string, name: string): string[] {
  return [...html.matchAll(/<[a-z0-9]+\b[^>]*\bclass="([^"]*)"[^>]*>/g)]
    .filter((match) => (match[1] ?? '').split(/\s+/).includes(name))
    .map((match) => match[0])
}

/** Each `<li>` whose class list holds `name`, whole. None of these nest a list item. */
function items(html: string, name: string): string[] {
  return [...html.matchAll(/<li\b[^>]*\bclass="([^"]*)"[^>]*>[\s\S]*?<\/li>/g)]
    .filter((match) => (match[1] ?? '').split(/\s+/).includes(name))
    .map((match) => match[0])
}

/** The values of `attribute` on the opening tags in `tags`, in order; HTML names ignore case. */
function attributes(tags: readonly string[], attribute: string): string[] {
  return tags.map((tag) => tag.match(new RegExp(`\\b${attribute}="([^"]*)"`, 'i'))?.[1] ?? '')
}

/** A stand-in for the browser's storage, recording what was written. */
function fakeStorage(): Storage & { readonly entries: Map<string, string> } {
  const entries = new Map<string, string>()
  return {
    entries,
    get length() {
      return entries.size
    },
    clear: () => entries.clear(),
    getItem: (key) => entries.get(key) ?? null,
    key: (index) => [...entries.keys()][index] ?? null,
    removeItem: (key) => void entries.delete(key),
    setItem: (key, value) => void entries.set(key, String(value)),
  }
}

/** A `matchMedia` answering `reduce` for prefers-reduced-motion as `reduce` says. */
function stubReducedMotion(reduce: boolean): void {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: reduce && query === '(prefers-reduced-motion: reduce)',
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }))
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('the intro strip', () => {
  it('says what the board is and links to how it works and to running a sweep', () => {
    const html = render(board([]))
    const strip = withClass(html, 'intro-strip')
    expect(strip).toHaveLength(1)
    expect(text(html)).toContain(INTRO)
    expect(html).toMatch(new RegExp(`<a\\b[^>]*href="/\\?circle=${A}"[^>]*>How it works</a>`))
    expect(html).toMatch(new RegExp(`<a\\b[^>]*href="/\\?circle=${A}#sweep"[^>]*>Run a sweep</a>`))
  })

  it('is dismissed with a button, and the dismissal writes one key', () => {
    const storage = fakeStorage()
    vi.stubGlobal('localStorage', storage)
    expect(withClass(render(board([])), 'intro-strip__dismiss')[0]).toMatch(/^<button\b[^>]*type="button"/)

    rememberIntroDismissed()
    expect([...storage.entries.keys()]).toHaveLength(1)
    expect(isIntroDismissed()).toBe(true)
  })

  it("leaves a '?' button in its place that brings it back", () => {
    vi.stubGlobal('localStorage', fakeStorage())
    rememberIntroDismissed()
    const dismissed = render(board([]))
    expect(text(dismissed)).not.toContain(INTRO)
    const restore = dismissed.match(/<button\b[^>]*class="intro-strip__restore"[^>]*>([\s\S]*?)<\/button>/)
    expect(restore?.[0]).toContain('type="button"')
    expect(text(restore?.[1] ?? '')).toBe('?')

    forgetIntroDismissed()
    expect(isIntroDismissed()).toBe(false)
    expect(text(render(board([])))).toContain(INTRO)
  })

  it('renders when localStorage cannot even be reached', () => {
    // Safari inside a cross-site frame: reading the property itself throws.
    vi.stubGlobal('localStorage', undefined)
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      get() {
        throw new DOMException('denied', 'SecurityError')
      },
    })
    expect(() => rememberIntroDismissed()).not.toThrow()
    expect(text(render(board([])))).toContain(INTRO)
  })

  it('renders when every localStorage call throws', () => {
    const fail = () => {
      throw new DOMException('quota', 'QuotaExceededError')
    }
    vi.stubGlobal('localStorage', { ...fakeStorage(), getItem: fail, setItem: fail, removeItem: fail })
    expect(() => rememberIntroDismissed()).not.toThrow()
    expect(() => forgetIntroDismissed()).not.toThrow()
    expect(text(render(board([])))).toContain(INTRO)
  })
})

describe('the empty state', () => {
  /** No sample rooms, detectors or ticker items: only the empty state's one outlined room. */
  function expectEmpty(html: string): void {
    expect(text(html)).toContain(EMPTY_LABEL)
    const roomsDrawn = withClass(html, 'room')
    expect(roomsDrawn).toHaveLength(1)
    expect(roomsDrawn[0]).toContain('room--empty')
    expect(withClass(html, 'detector')).toHaveLength(0)
    expect(withClass(html, 'ticker__item')).toHaveLength(0)
    expect(withClass(html, 'sweep-list__item')).toHaveLength(0)
    expect(withClass(html, 'done-list__item')).toHaveLength(0)
  }

  it('is all an empty store draws, with no notice', () => {
    const html = render(board([]))
    expectEmpty(html)
    expect(withClass(html, 'board-notice')).toHaveLength(0)
  })

  it.each<Resolution>([
    { kind: 'lookupFailed', resolvedAt: NOW },
    { kind: 'noRecord', resolvedAt: NOW },
    { kind: 'notBrowserReachable', homeserver: null, resolvedAt: NOW },
  ])("says the circle's admin could not be reached ($kind)", (resolution) => {
    const html = render(adminLookedUp(resolution))
    expectEmpty(html)
    const [notice, ...rest] = withClass(html, 'board-notice')
    expect(rest).toHaveLength(0)
    expect(notice).toContain('role="status"')
    // The Circle page's "unreachable": the destructive mark beside the word.
    expect(withClass(html, 'state-mark--unreachable')).toHaveLength(1)
    expect(text(html)).toMatch(/unreachable/i)
    expect(text(html)).toContain('admin could not be reached')
  })

  it('says no circle is selected', () => {
    const none = selectCircle('', undefined)
    const html = render(initialBoardState(null), none)
    expectEmpty(html)
    expect(withClass(html, 'board-notice')).toHaveLength(1)
    expect(text(html)).toMatch(/no circle selected/i)
  })
})

describe('a board with records', () => {
  const X: BountyRef = { owner: A, id: idAt(NOW - 30 * HOUR) }
  const Y: BountyRef = { owner: A, id: idAt(NOW - 29 * HOUR) }
  const Z: BountyRef = { owner: A, id: idAt(NOW - 28 * HOUR) }
  const W: BountyRef = { owner: A, id: idAt(NOW - 27 * HOUR) }
  const state = board(
    [
      bounty(X, { open: true }),
      bounty(Y),
      // A credits itself and B twice: B and C are credited, each once.
      bounty(Z, { status: 'done', credits: [A, B, B, C], doneAt: time(NOW - 2 * HOUR) }),
      bounty(W, { status: 'done', credits: [D], doneAt: time(NOW - 5 * HOUR) }),
    ],
    [
      sweep(B, NOW - 3 * HOUR, X),
      sweep(C, NOW - 2 * HOUR, X, { status: 'done', finishedAt: time(NOW - HOUR) }),
      sweep(D, NOW - 9 * HOUR, Y),
      // Yesterday: not one of today's sweeps.
      sweep(B, NOW - 20 * HOUR, Y, { status: 'aborted', finishedAt: time(NOW - 19 * HOUR) }),
    ],
  )
  // Drawn in each test, once beforeEach has set the clock.
  let html = ''
  beforeEach(() => {
    html = render(state)
  })

  it('lists the running sweeps newest first, as sweepsInProgress gives them', () => {
    const listed = items(html, 'sweep-list__item')
    const expected = sweepsInProgress(state, NOW)
    expect(expected).toHaveLength(2)
    expect(attributes(listed, 'data-sweep')).toEqual(expected.map((view) => sweepKey(view.ref)))
    // Each names its sweeper and badge and links to its sweep and bounty page.
    const [recent, old] = listed
    expect(recent).toContain(`href="/s/${B}/${expected[0]?.ref.id}?circle=${A}"`)
    expect(recent).toContain(`href="/b/${A}/${X.id}?circle=${A}"`)
    expect(text(recent ?? '')).toContain('sweeping')
    expect(text(recent ?? '')).toContain('circle')
    expect(text(old ?? '')).toContain('left')
    // D is credited on A's done bounty W.
    expect(text(old ?? '')).toContain('known 1')
  })

  it('counts the sweeps started today', () => {
    // From the selector: "today" starts at local midnight, which depends on
    // the machine's time zone.
    const count = sweepsToday(state, NOW)
    expect(count).toBeGreaterThan(0)
    expect(withClass(html, 'board-stat')).toHaveLength(1)
    expect(text(html)).toContain(`${count} ${count === 1 ? 'sweep' : 'sweeps'} started today`)
  })

  it('lists the done bounties, latest done first, with their credited sweepers', () => {
    // Each item holds a list of its own, so items are cut at the next one's start.
    const list = html.slice(html.indexOf('class="done-list"'))
    const listed = list.split('<li class="done-list__item"').slice(1)
    const expected = recentlyDone(state)
    expect(listed.map((item) => item.match(/data-bounty="([^"]*)"/)?.[1])).toEqual(
      expected.map((done) => bountyKey(done.ref)),
    )
    const credited = listed.map((item) => {
      const door = item.match(/<ul\b[^>]*class="door"[^>]*>([\s\S]*?)<\/ul>/)?.[1] ?? ''
      return [...door.matchAll(/<li\b[^>]*>([\s\S]*?)<\/li>/g)].map((match) => text(match[1] ?? ''))
    })
    expect(credited).toEqual([[B, C], [D]])
  })

  it('draws the floor plan with a room per bounty and no empty state', () => {
    expect(withClass(html, 'room')).toHaveLength(4)
    expect(text(html)).not.toContain(EMPTY_LABEL)
  })
})

describe('the activity ticker', () => {
  const X: BountyRef = { owner: A, id: idAt(NOW - 30 * HOUR) }

  it('shows only events from records, newest first', () => {
    const state = board(
      [bounty(X, { title: 'Parser' })],
      [
        sweep(B, NOW - 3 * HOUR, X, { status: 'done', finishedAt: time(NOW - 2 * HOUR) }),
        sweep(C, NOW - HOUR, X),
      ],
    )
    const listed = items(render(state), 'ticker__item')
    const expected = tickerEvents(state)
    expect(expected.map((event) => event.kind)).toEqual(['sweepStarted', 'sweepDone', 'sweepStarted', 'bountyPosted'])
    expect(attributes(listed, 'data-event')).toEqual(expected.map((event) => event.key))
    expect(attributes(listed.map((item) => item.match(/<time\b[^>]*>/)?.[0] ?? ''), 'datetime')).toEqual(
      expected.map((event) => new Date(event.at).toISOString()),
    )
    expect(text(listed[0] ?? '')).toContain('Parser')
  })

  /** A board whose newest event happened after the page opened at NOW. */
  const sinceOpen = board([bounty(X)], [sweep(C, NOW + HOUR, X)])

  it('scrolls for an event that happened after the page opened', () => {
    stubReducedMotion(false)
    expect(withClass(render(sinceOpen), 'ticker__items--scroll')).toHaveLength(1)
  })

  it('never scrolls when reduced motion is preferred', () => {
    stubReducedMotion(true)
    const html = render(sinceOpen)
    expect(withClass(html, 'ticker__items')).toHaveLength(1)
    expect(withClass(html, 'ticker__items--scroll')).toHaveLength(0)
  })

  it('stays still for events that were already past when the page opened', () => {
    stubReducedMotion(false)
    const html = render(board([bounty(X)], [sweep(C, NOW - HOUR, X)]))
    expect(withClass(html, 'ticker__items--scroll')).toHaveLength(0)
  })

  it('scrolls once, never in a loop', () => {
    const css = readFileSync(new URL('../styles/board.css', import.meta.url), 'utf8')
    const rule = css.match(/\.ticker__items--scroll\b[^{]*\{([^}]*)\}/)?.[1] ?? ''
    expect(rule).toMatch(/animation:[^;]*\b1\b/)
    expect(css).not.toMatch(/ticker[^{]*\{[^}]*infinite/)
  })
})

describe('strangers’ times', () => {
  it('renders a sweep whose time no Date can hold', () => {
    // A stranger picks a sweep's id and its startedAt; past year 275760 a
    // Date is invalid, and printing one throws.
    const X: BountyRef = { owner: A, id: idAt(NOW - HOUR) }
    const far: SweepEntry = {
      ...sweep(D, NOW, X, { startedAt: 'whenever' }),
      ref: { sweeper: D, id: recordIdFromMicros((1n << 64n) - 1n) },
    }
    const html = render(board([bounty(X)], [far]))
    expect(items(html, 'sweep-list__item')).toHaveLength(1)
  })
})

describe('browser storage', () => {
  const SRC_DIR = new URL('../', import.meta.url)
  const sources = readdirSync(SRC_DIR, { recursive: true, encoding: 'utf8' }).filter(
    (path) => /\.(ts|tsx)$/.test(path) && !/\.test\./.test(path),
  )

  // Nothing essential lives in browser storage (04, Stack): Safari drops it
  // inside a cross-site frame. Only the strip's dismissal, which is fine to lose.
  it('is used only by the intro strip’s dismissal', () => {
    const users = sources.filter((path) =>
      /\b(?:localStorage|sessionStorage|indexedDB)\b/.test(readFileSync(new URL(path, SRC_DIR), 'utf8')),
    )
    expect(users).toEqual(['components/introDismissal.ts'])
  })
})
