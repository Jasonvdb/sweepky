// `/` (04, "Landing page"): six sections in order, a hero drawn from the
// board's store, the `#post` and `#sweep` anchors, an install block that
// points at the README, and copy whose every claim names where in 00, 02 or
// 06's known limits it comes from. Rendered to HTML in Node, from a store
// whose state the test sets, at a fixed clock.
import { readdirSync, readFileSync } from 'node:fs'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { create } from 'zustand'
import { App } from '../App.tsx'
import { selectCircle } from '../config/circle.ts'
import { recordIdFromMicros } from '../records/ids.ts'
import type { Bounty } from '../records/parse.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import { Landing } from '../routes/Landing.tsx'
import {
  bountyKey,
  initialBoardState,
  memberState,
  type BoardState,
  type BountyEntry,
  type Resolution,
} from '../store/state.ts'
import { LANDING_COPY, README_URL, KNOWN_LIMITS_URL } from './copy.ts'
import { scrollToHash } from './scrollToHash.ts'

// A synthetic key from fixtures/trust-labels.json: the circle's admin.
const A = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
const NOW = Date.UTC(2026, 9, 20, 12)
const EMPTY_LABEL = 'No open bounties yet'

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`test key ${text} is not a key`)
  return key
}

function readRepoFile(path: string): string {
  return readFileSync(new URL(`../../../${path}`, import.meta.url), 'utf8')
}

/** A's circle holding `bounties`. */
function board(bounties: readonly BountyEntry[]): BoardState {
  return {
    ...initialBoardState(A),
    circle: { name: 'Test circle', admin: A, members: [] },
    bounties: new Map(bounties.map((entry) => [bountyKey(entry.ref), entry])),
  }
}

function openBounty(title: string): BountyEntry {
  const record: Bounty = {
    title,
    focus: 'security',
    brief: 'A brief.',
    playbook: { suggested: null, required: false },
    targets: [],
    open: false,
    status: 'open',
    credits: [],
    createdAt: '2026-10-20T10:00:00Z',
    doneAt: null,
  }
  return { ref: { owner: A, id: recordIdFromMicros(BigInt(NOW - 1000) * 1000n) }, record, discovered: null }
}

/** A's circle before anything is read, the admin's lookup having answered `resolution`. */
function adminLookedUp(resolution: Resolution): BoardState {
  const state = initialBoardState(A)
  return { ...state, members: new Map([[A, { ...memberState(state, A), resolution }]]) }
}

/** The landing page drawing `state`; a render to a string sends nothing. */
function render(state: BoardState): string {
  const store = create<BoardState>()(() => state)
  return renderToStaticMarkup(
    <App services={{ store, circle: selectCircle(`?circle=${A}`, undefined) }}>
      <MemoryRouter>
        <Landing />
      </MemoryRouter>
    </App>,
  )
}

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

/** The hero's own markup, up to the first section after it. */
function hero(html: string): string {
  const start = html.indexOf('class="landing-hero"')
  const end = html.indexOf('class="section"', start)
  expect(start).toBeGreaterThanOrEqual(0)
  return html.slice(start, end < 0 ? undefined : end)
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
})

afterEach(() => {
  vi.useRealTimers()
})

describe('the sections', () => {
  const html = render(board([]))

  it("renders 04's six sections in order", () => {
    expect(withClass(html, 'landing-hero')).toHaveLength(1)
    expect(withClass(html, 'section')).toHaveLength(5)
    const order = [
      'Your spare tokens, sweeping for bugs.',
      'The problem',
      'How it works',
      'Safe by design',
      'Reputation',
      'Start sweeping.',
    ].map((marker) => text(html).indexOf(marker))
    expect(order.every((at) => at >= 0)).toBe(true)
    expect([...order].sort((a, b) => a - b)).toEqual(order)
  })

  it('has the #post and #sweep anchors', () => {
    expect(html).toMatch(/\bid="post"/)
    expect(html).toMatch(/\bid="sweep"/)
  })

  it('styles every class the landing adds', () => {
    const stylesDir = new URL('../styles/', import.meta.url)
    const css = readdirSync(stylesDir)
      .filter((name) => name.endsWith('.css'))
      .map((name) => readFileSync(new URL(name, stylesDir), 'utf8'))
      .join('\n')
    const names = new Set(
      [...html.matchAll(/class="([^"]*)"/g)]
        .flatMap((match) => (match[1] ?? '').split(/\s+/))
        .filter((name) => name.startsWith('landing-')),
    )
    expect(names.size).toBeGreaterThan(5)
    for (const name of names) {
      expect(css, `.${name}`).toMatch(new RegExp(`\\.${name}(?![\\w-])`))
    }
  })
})

describe('the hero', () => {
  it("draws the store's bounties as the compact floor plan", () => {
    const part = hero(render(board([openBounty('Audit the parser')])))
    expect(withClass(part, 'floor-plan--compact')).toHaveLength(1)
    expect(text(part)).toContain('Audit the parser')
    expect(withClass(part, 'room--empty')).toHaveLength(0)
  })

  it('draws the empty state, and no sample room, with no bounties', () => {
    const part = hero(render(board([])))
    expect(text(part)).toContain(EMPTY_LABEL)
    const rooms = withClass(part, 'room')
    expect(rooms).toHaveLength(1)
    expect(rooms[0]).toContain('room--empty')
    expect(withClass(part, 'detector')).toHaveLength(0)
  })

  it('shows the empty state and the notice when the admin is unreachable', () => {
    const part = hero(render(adminLookedUp({ kind: 'lookupFailed', resolvedAt: NOW })))
    expect(text(part)).toContain('Unreachable')
    expect(withClass(part, 'state-mark--unreachable')).toHaveLength(1)
    expect(text(part)).toContain(EMPTY_LABEL)
    expect(withClass(part, 'room')).toEqual([expect.stringContaining('room--empty')])
  })

  it('keeps the circle on its hash links', () => {
    const part = hero(render(board([])))
    expect(part).toContain(`href="/?circle=${A}#sweep"`)
    expect(part).toContain(`href="/?circle=${A}#post"`)
    expect(part).toContain(`href="/board?circle=${A}"`)
  })
})

describe('scrollToHash', () => {
  /** A document holding the elements `ids`, recording each scroll. */
  function fakeDocument(ids: readonly string[]) {
    const scrolls: Array<{ id: string; options: ScrollIntoViewOptions | undefined }> = []
    return {
      scrolls,
      getElementById: (id: string) =>
        ids.includes(id)
          ? { scrollIntoView: (options?: ScrollIntoViewOptions) => scrolls.push({ id, options }) }
          : null,
    }
  }

  it('scrolls the element the hash names into view, with no smooth scroll of its own', () => {
    const doc = fakeDocument(['post', 'sweep'])
    scrollToHash('#sweep', doc)
    // `auto` leaves the choice to CSS, which turns smooth scrolling off under
    // prefers-reduced-motion: reduce (base.css).
    expect(doc.scrolls).toEqual([{ id: 'sweep', options: { behavior: 'auto', block: 'start' } }])
  })

  it.each(['', '#', '#nowhere', '#%E0%A4%A'])('does nothing for %j', (hash) => {
    const doc = fakeDocument(['post', 'sweep'])
    expect(() => scrollToHash(hash, doc)).not.toThrow()
    expect(doc.scrolls).toEqual([])
  })
})

describe('install and known limits', () => {
  const html = render(board([]))

  it('ships no install command', () => {
    for (const shipped of [html, JSON.stringify(LANDING_COPY)]) {
      expect(shipped).not.toMatch(/cargo install|brew install|\bnpx\b|curl[^\n]*\|/i)
    }
  })

  it('points the install block and the known limits link at the README', () => {
    expect(README_URL).toMatch(/\/README\.md#install$/)
    expect(KNOWN_LIMITS_URL).toMatch(/\/README\.md#known-limits$/)
    const install = withClass(html, 'landing-install')
    expect(install).toHaveLength(1)
    const block = html.slice(html.indexOf(install[0] ?? ''))
    expect(block).toMatch(new RegExp(`<a\\b[^>]*href="${literal(README_URL)}"`))
    expect(html).toMatch(new RegExp(`<a\\b[^>]*href="${literal(KNOWN_LIMITS_URL)}"`))
  })

  it("carries 06's known limits in the README", () => {
    const limits06 = listUnder(readRepoFile('docs/plan/06-verification-and-limits.md'), 'Known limits (say them in the README)')
    const readme = listUnder(readRepoFile('README.md'), 'Known limits')
    expect(limits06.length).toBeGreaterThan(0)
    expect(readme).toEqual(limits06)
  })

  /** The `- ` items under the `## heading`, links reduced to their text. */
  function listUnder(markdown: string, heading: string): string[] {
    const start = markdown.indexOf(`\n## ${heading}\n`)
    expect(start, heading).toBeGreaterThanOrEqual(0)
    const rest = markdown.slice(start + heading.length + 5)
    const end = rest.search(/\n## /)
    return (end < 0 ? rest : rest.slice(0, end))
      .split('\n')
      .filter((line) => line.startsWith('- '))
      .map((line) => line.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1'))
  }
})

describe('the copy', () => {
  const DOCS = {
    '00-overview.md': readRepoFile('docs/plan/00-overview.md'),
    '02-encryption-and-safety.md': readRepoFile('docs/plan/02-encryption-and-safety.md'),
    '06-verification-and-limits.md': readRepoFile('docs/plan/06-verification-and-limits.md'),
  }
  /** Keys whose strings are labels, links or commands, not claims. */
  const NOT_CLAIMS = new Set(['sources', 'eyebrow', 'label', 'href', 'id', 'command'])

  /** Every object in the copy that holds a string other than a label. */
  function claimHolders(value: unknown, path = 'LANDING_COPY'): Array<[string, Record<string, unknown>]> {
    if (Array.isArray(value)) return value.flatMap((item, at) => claimHolders(item, `${path}[${at}]`))
    if (typeof value !== 'object' || value === null) return []
    const object = value as Record<string, unknown>
    const own = Object.entries(object).some(([key, field]) => typeof field === 'string' && !NOT_CLAIMS.has(key))
    const nested = Object.entries(object)
      .filter(([key]) => key !== 'sources')
      .flatMap(([key, field]) => claimHolders(field, `${path}.${key}`))
    return own ? [[path, object], ...nested] : nested
  }

  /** GitHub's anchor for each heading of `markdown`. */
  function anchors(markdown: string): Set<string> {
    return new Set(
      [...markdown.matchAll(/^#{2,4} (.+)$/gm)].map((match) =>
        (match[1] ?? '').toLowerCase().replace(/[^\w\- ]/g, '').replace(/ /g, '-'),
      ),
    )
  }

  it('gives every claim a source in 00, 02 or the known limits in 06', () => {
    const holders = claimHolders(LANDING_COPY)
    expect(holders.length).toBeGreaterThan(20)
    for (const [path, holder] of holders) {
      const sources = holder.sources
      expect(Array.isArray(sources) && sources.length > 0, path).toBe(true)
      for (const source of sources as unknown[]) {
        const [doc, anchor] = String(source).split('#')
        expect(Object.keys(DOCS), `${path}: ${String(source)}`).toContain(doc)
        if (doc === '06-verification-and-limits.md') {
          expect(anchor, path).toBe('known-limits-say-them-in-the-readme')
        }
        expect([...anchors(DOCS[doc as keyof typeof DOCS])], `${path}: ${String(source)}`).toContain(anchor)
      }
    }
  })

  // 06: open-bounty discovery sees only watched homeservers, so a stranger
  // elsewhere can sweep an open bounty without the owner ever seeing it.
  it('promises the owner only the reports discovery can see', () => {
    const card = LANDING_COPY.problem.cards.find((each) => each.title === 'No claims, no locks')
    expect(card?.text).toMatch(/strangers' sweeps on watched homeservers/)
    expect(card?.sources).toContain('06-verification-and-limits.md#known-limits-say-them-in-the-readme')
  })

  it("never says 'private'", () => {
    for (const shipped of [JSON.stringify(LANDING_COPY), text(render(board([])))]) {
      expect(shipped).not.toMatch(/\bprivate\b/i)
    }
  })

  it('adds no request of its own: no fetch, image, script or frame', () => {
    const html = render(board([]))
    expect(html).not.toMatch(/<(img|script|iframe|link|video|audio|source)\b/i)
    for (const file of ['routes/Landing.tsx', 'landing/copy.ts', 'landing/scrollToHash.ts']) {
      const source = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8')
      expect(source, file).not.toMatch(/\bfetch\(|XMLHttpRequest|sendBeacon|new Image\b/)
    }
  })
})

/** `text` as a literal in a regular expression. */
function literal(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
