// `/b/:owner/:id` and `/s/:sweeper/:id` (04, Views): the bounty page with its
// pinned targets, sweeps per target, sweeper timeline, `open` marker and
// credited sweepers, and the sweep page with the sweep record only, never
// findings. Both render from the store alone, so a record the store does not
// hold shows the not-on-this-board view. Rendered to HTML in Node, from a
// store whose state the test sets, at a fixed clock.
import { renderToStaticMarkup } from 'react-dom/server'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { create } from 'zustand'
import { App } from '../App.tsx'
import { githubPullUrl, githubRevUrl } from '../components/githubLinks.ts'
import { selectCircle } from '../config/circle.ts'
import { recordIdFromMicros, type RecordId } from '../records/ids.ts'
import type { Bounty, Sweep, Target } from '../records/parse.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import {
  bountyKey,
  initialBoardState,
  sweepKey,
  type BoardState,
  type BountyEntry,
  type SweepEntry,
} from '../store/state.ts'
import { BountyPage } from './BountyPage.tsx'
import { SweepPage } from './SweepPage.tsx'

// Synthetic keys from fixtures/trust-labels.json: A is the circle's admin and
// owns the bounty, B a member, C and D strangers.
const A = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
const B = pubky('btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy')
const C = pubky('a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy')
const D = pubky('5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco')

const NOW = Date.UTC(2026, 9, 20, 12)
const MINUTE = 60 * 1000
const HOUR = 60 * MINUTE

// Synthetic object names.
const SHA_REV = 'a'.repeat(40)
const SHA_HEAD = 'b'.repeat(40)
const SHA_BASE = 'c'.repeat(40)
const SHA_MERGE_BASE = 'd'.repeat(40)

const BOUNTY_REF: BountyRef = { owner: A, id: idAt(NOW - 30 * HOUR) }
const OTHER_BOUNTY: BountyRef = { owner: A, id: idAt(NOW - 40 * HOUR) }

const NOT_ON_BOARD = 'Not on this board'

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`test key ${text} is not a key`)
  return key
}

function idAt(ms: number): RecordId {
  return recordIdFromMicros(BigInt(ms) * 1000n)
}

function time(ms: number): string {
  return new Date(ms).toISOString().replace('.000Z', 'Z')
}

function target(id: string, kind: string, fields: Record<string, unknown>): Target {
  return { id, kind, fields: new Map(Object.entries(fields)) }
}

const REPO_TARGET = target('t1', 'repo', {
  repo: 'github.com/org/name',
  rev: SHA_REV,
  paths: ['src/auth/', 'src/session.rs'],
})
const COMMIT_TARGET = target('t2', 'commit', { repo: 'github.com/org/name', rev: SHA_HEAD })
const PR_TARGET = target('t3', 'pr', {
  repo: 'github.com/org/name',
  number: 42,
  head: SHA_HEAD,
  base: SHA_BASE,
  mergeBase: SHA_MERGE_BASE,
})

function bounty(fields: Partial<Bounty> = {}): BountyEntry {
  const record: Bounty = {
    title: 'Audit the session code',
    focus: 'security',
    brief: 'Look at the login.\nThen the logout.',
    playbook: { suggested: null, required: false },
    targets: [REPO_TARGET, COMMIT_TARGET, PR_TARGET],
    open: true,
    status: 'open',
    credits: [],
    createdAt: time(NOW - 30 * HOUR),
    doneAt: null,
    ...fields,
  }
  return { ref: BOUNTY_REF, record, discovered: null }
}

function sweep(sweeper: Pubky, startedMs: number, fields: Partial<Sweep> = {}): SweepEntry {
  const ref: SweepRef = { sweeper, id: idAt(startedMs) }
  const record: Sweep = {
    bounty: BOUNTY_REF,
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

const DETAIL_ROUTES = [
  { path: 'b/:owner/:id', element: <BountyPage /> },
  { path: 's/:sweeper/:id', element: <SweepPage /> },
]

/** The page at `path` drawing `state` at NOW, from a store with no poll behind it. */
function render(path: string, state: BoardState): string {
  const store = create<BoardState>()(() => state)
  const circle = selectCircle(`?circle=${A}`, undefined)
  const router = createMemoryRouter(DETAIL_ROUTES, { initialEntries: [path] })
  return renderToStaticMarkup(
    <App services={{ store, circle }}>
      <RouterProvider router={router} />
    </App>,
  )
}

function bountyPath(ref: BountyRef): string {
  return `/b/${ref.owner}/${ref.id}`
}

function sweepPath(ref: SweepRef): string {
  return `/s/${ref.sweeper}/${ref.id}`
}

/** What a reader sees: the markup without its tags, entities decoded. */
function text(html: string): string {
  return html
    .replace(/<[^>]*>/g, ' ')
    .replace(/&#x27;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
}

/** Each element whose class list holds `name`, from its opening tag to the first `</tag>` closing it. */
function blocks(html: string, name: string, tag = 'li'): string[] {
  const pattern = new RegExp(`<${tag}\\b[^>]*\\bclass="([^"]*)"[^>]*>[\\s\\S]*?</${tag}>`, 'g')
  return [...html.matchAll(pattern)]
    .filter((match) => (match[1] ?? '').split(/\s+/).includes(name))
    .map((match) => match[0])
}

/** The opening tags whose class list holds `name`. */
function withClass(html: string, name: string): string[] {
  return [...html.matchAll(/<[a-z0-9]+\b[^>]*\bclass="([^"]*)"[^>]*>/g)]
    .filter((match) => (match[1] ?? '').split(/\s+/).includes(name))
    .map((match) => match[0])
}

function hrefs(html: string): string[] {
  return [...html.matchAll(/\bhref="([^"]*)"/g)].map((match) => match[1] ?? '')
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
})

afterEach(() => {
  vi.useRealTimers()
})

describe('githubLinks', () => {
  it('builds a revision link for a github.com repository and a 40-hex SHA', () => {
    expect(githubRevUrl('github.com/org/name', SHA_REV, 'tree')).toBe(
      `https://github.com/org/name/tree/${SHA_REV}`,
    )
    expect(githubRevUrl('github.com/Org-1/my.repo_x', SHA_REV, 'commit')).toBe(
      `https://github.com/Org-1/my.repo_x/commit/${SHA_REV}`,
    )
  })

  it('builds a pull request link for a positive whole number', () => {
    expect(githubPullUrl('github.com/org/name', 42)).toBe('https://github.com/org/name/pull/42')
  })

  it.each([
    'javascript:alert(1)',
    'https://github.com/org/name',
    'gitlab.com/org/name',
    'github.com.evil.example/org/name',
    'evil.example/github.com/org/name',
    'GitHub.com/org/name',
    'github.com/org',
    'github.com/org/name/extra',
    'github.com/org/..',
    'github.com/-org/name',
    'github.com/org/name?x=1',
    'github.com/org/name#x',
    'github.com/org/na me',
    '',
  ])('builds no link for the repository %j', (repo) => {
    expect(githubRevUrl(repo, SHA_REV, 'tree')).toBeNull()
    expect(githubPullUrl(repo, 42)).toBeNull()
  })

  it.each([
    'a'.repeat(39),
    'a'.repeat(41),
    'A'.repeat(40),
    'e'.repeat(64),
    'javascript:alert(1)',
    `${'a'.repeat(39)}/`,
  ])('builds no revision link for the SHA %j', (sha) => {
    expect(githubRevUrl('github.com/org/name', sha, 'tree')).toBeNull()
  })

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, '42', null])(
    'builds no pull request link for the number %j',
    (number) => {
      expect(githubPullUrl('github.com/org/name', number)).toBeNull()
    },
  )
})

describe('the bounty page', () => {
  it('shows each target at its pinned revision, linked to GitHub', () => {
    const html = render(bountyPath(BOUNTY_REF), board([bounty()]))
    const [repo, commit, pr, ...rest] = blocks(html, 'target', 'article')
    expect(rest).toHaveLength(0)

    expect(text(repo ?? '')).toContain('github.com/org/name')
    expect(text(repo ?? '')).toContain(SHA_REV)
    expect(text(repo ?? '')).toContain('src/auth/')
    expect(text(repo ?? '')).toContain('src/session.rs')
    expect(hrefs(repo ?? '')).toContain(`https://github.com/org/name/tree/${SHA_REV}`)

    expect(text(commit ?? '')).toContain(SHA_HEAD)
    expect(hrefs(commit ?? '')).toContain(`https://github.com/org/name/commit/${SHA_HEAD}`)

    for (const sha of [SHA_HEAD, SHA_BASE, SHA_MERGE_BASE]) expect(text(pr ?? '')).toContain(sha)
    expect(text(pr ?? '')).toContain('#42')
    expect(hrefs(pr ?? '')).toContain('https://github.com/org/name/pull/42')
  })

  it('opens GitHub links without handing over the page', () => {
    const html = render(bountyPath(BOUNTY_REF), board([bounty()]))
    const external = [...html.matchAll(/<a\b[^>]*href="https:[^"]*"[^>]*>/g)].map((m) => m[0])
    expect(external.length).toBeGreaterThan(0)
    for (const tag of external) expect(tag).toMatch(/rel="noreferrer"/)
  })

  it("never puts a stranger's repository into an href", () => {
    const hostile = target('t1', 'repo', { repo: 'javascript:alert(1)', rev: SHA_REV })
    const elsewhere = target('t2', 'commit', { repo: 'evil.example/org/name', rev: SHA_REV })
    const html = render(bountyPath(BOUNTY_REF), board([bounty({ targets: [hostile, elsewhere] })]))
    // Shown, as text.
    expect(text(html)).toContain('javascript:alert(1)')
    expect(text(html)).toContain('evil.example/org/name')
    for (const href of hrefs(html)) {
      expect(href.startsWith('/') || href.startsWith('https://github.com/')).toBe(true)
      expect(href).not.toContain('javascript')
      expect(href).not.toContain('evil.example')
    }
  })

  it('shows a target of a kind this build does not know as a placeholder', () => {
    const crate = target('t1', 'crate', { name: 'serde', version: '1.0.0' })
    const broken = target('t2', 'pr', { repo: 'github.com/org/name', number: 'many' })
    const html = render(bountyPath(BOUNTY_REF), board([bounty({ targets: [crate, broken] })]))
    const [unknown, malformed] = blocks(html, 'target', 'article')
    expect(text(unknown ?? '')).toContain('t1')
    expect(text(unknown ?? '')).toContain('crate')
    expect(text(unknown ?? '')).toContain('a kind this board does not show')
    expect(text(malformed ?? '')).toContain('cannot be read')
    expect(hrefs(unknown ?? '')).toHaveLength(0)
    expect(hrefs(malformed ?? '')).toHaveLength(0)
    expect(text(html)).not.toContain('serde')
  })

  it('shows the open marker on an open bounty only', () => {
    const open = render(bountyPath(BOUNTY_REF), board([bounty({ open: true })]))
    expect(withClass(open, 'open-marker')).toHaveLength(1)
    const closed = render(bountyPath(BOUNTY_REF), board([bounty({ open: false })]))
    expect(withClass(closed, 'open-marker')).toHaveLength(0)
  })

  it('lists the sweeps of each target with their badges', () => {
    const member = sweep(B, NOW - 3 * HOUR, { targets: ['t1', 't3'] })
    const stranger = sweep(C, NOW - 2 * HOUR, { targets: ['t3'] })
    const html = render(bountyPath(BOUNTY_REF), board([bounty()], [member, stranger]))
    const [repo, commit, pr] = blocks(html, 'target', 'article')

    const onRepo = blocks(repo ?? '', 'target-sweep')
    expect(onRepo).toHaveLength(1)
    expect(onRepo[0]).toContain(B)
    expect(withClass(onRepo[0] ?? '', 'trust-badge--circle')).toHaveLength(1)

    expect(blocks(commit ?? '', 'target-sweep')).toHaveLength(0)
    expect(text(commit ?? '')).toContain('No sweeps yet')

    const onPr = blocks(pr ?? '', 'target-sweep')
    expect(onPr).toHaveLength(2)
    expect(onPr[0]).toContain(B)
    expect(onPr[1]).toContain(C)
    expect(withClass(onPr[1] ?? '', 'trust-badge--unknown')).toHaveLength(1)
    expect(hrefs(onPr[1] ?? '')).toContain(`/s/${C}/${stranger.ref.id}?circle=${A}`)
  })

  it('lists the credited sweepers of a done bounty, never the owner and each once', () => {
    const done = bounty({
      status: 'done',
      open: false,
      doneAt: time(NOW - HOUR),
      credits: [A, B, C, B],
    })
    const html = render(bountyPath(BOUNTY_REF), board([done]))
    const credited = blocks(html, 'credited__item')
    expect(credited).toHaveLength(2)
    expect(credited[0]).toContain(B)
    expect(credited[1]).toContain(C)
    expect(credited.join('')).not.toContain(A)
    // B is in the circle; C, credited on a done bounty from the circle's admin, is known 1.
    expect(withClass(credited[0] ?? '', 'trust-badge--circle')).toHaveLength(1)
    expect(text(credited[1] ?? '')).toContain('known 1')
  })

  it('lists no credited sweepers before the bounty is done', () => {
    const html = render(bountyPath(BOUNTY_REF), board([bounty({ credits: [B] })]))
    expect(blocks(html, 'credited__item')).toHaveLength(0)
  })

  it("draws the timeline from the bounty's sweeps, members' and strangers', oldest first", () => {
    const late = sweep(B, NOW - HOUR)
    const early = sweep(C, NOW - 5 * HOUR, {
      status: 'done',
      finishedAt: time(NOW - 4 * HOUR),
    })
    const aborted = sweep(D, NOW - 3 * HOUR, {
      status: 'aborted',
      finishedAt: time(NOW - 2 * HOUR),
    })
    const elsewhere = sweep(B, NOW - 2 * HOUR, { bounty: OTHER_BOUNTY })
    const html = render(bountyPath(BOUNTY_REF), board([bounty()], [late, elsewhere, aborted, early]))
    const rows = blocks(html, 'timeline__item')
    expect(rows).toHaveLength(3)
    expect(rows[0]).toContain(C)
    expect(rows[1]).toContain(D)
    expect(rows[2]).toContain(B)
    expect(text(rows[0] ?? '')).toContain('done')
    expect(rows[0]).toMatch(new RegExp(`datetime="${new Date(NOW - 4 * HOUR).toISOString()}"`, 'i'))
    expect(text(rows[1] ?? '')).toContain('aborted')
    expect(withClass(rows[1] ?? '', 'state-mark--aborted')).toHaveLength(1)
    expect(text(rows[2] ?? '')).toContain('running')
    expect(rows.join('')).not.toContain(elsewhere.ref.id)
  })

  it("renders a stranger's title and brief as text, the brief keeping its lines", () => {
    const hostile = bounty({ title: '<img src=x onerror=alert(1)>', brief: '<b>bold</b>\nnext' })
    const html = render(bountyPath(BOUNTY_REF), board([hostile]))
    expect(html).not.toContain('<img')
    expect(html).not.toContain('<b>')
    expect(text(html)).toContain('<img src=x onerror=alert(1)>')
    const [brief] = withClass(html, 'bounty-brief')
    expect(brief).toBeDefined()
    expect(html).toMatch(/class="bounty-brief"[^>]*>(?:<bdi[^>]*>)?&lt;b&gt;bold&lt;\/b&gt;\nnext/)
  })

  it('shows the not-on-this-board view for a bounty the store does not hold', () => {
    const html = render(bountyPath(OTHER_BOUNTY), board([bounty()]))
    expect(text(html)).toContain(NOT_ON_BOARD)
    expect(blocks(html, 'target', 'article')).toHaveLength(0)
  })
})

describe('the sweep page', () => {
  it('shows the sweeper, duration, status, playbook and trust badge', () => {
    const done = sweep(B, NOW - 3 * HOUR, {
      status: 'done',
      finishedAt: time(NOW - 3 * HOUR + 95 * MINUTE),
    })
    const html = render(sweepPath(done.ref), board([bounty()], [done]))
    expect(text(html)).toContain(B)
    expect(text(html)).toContain('1 h 35 min')
    expect(text(html)).toContain('done')
    expect(text(html)).toContain('cloudflare/security-audit@c1c8a8c')
    expect(withClass(html, 'trust-badge--circle')).toHaveLength(1)
    expect(hrefs(html)).toContain(`/b/${A}/${BOUNTY_REF.id}?circle=${A}`)
  })

  it("shows a stranger's sweep with the unknown badge", () => {
    const stranger = sweep(C, NOW - HOUR)
    const html = render(sweepPath(stranger.ref), board([bounty()], [stranger]))
    expect(withClass(html, 'trust-badge--unknown')).toHaveLength(1)
    expect(text(html)).toContain('running')
  })

  it('shows no findings and no link to the sealed package', () => {
    const done = sweep(B, NOW - 3 * HOUR, {
      status: 'done',
      finishedAt: time(NOW - 2 * HOUR),
      sha256: 'f'.repeat(64),
    })
    const html = render(sweepPath(done.ref), board([bounty()], [done]))
    expect(text(html)).not.toMatch(/finding/i)
    expect(html).not.toMatch(/finding/i)
    for (const href of hrefs(html)) expect(href).not.toMatch(/\.age\b/)
  })

  it('strikes an aborted sweep, with the destructive mark and the word', () => {
    const aborted = sweep(D, NOW - 3 * HOUR, {
      status: 'aborted',
      finishedAt: time(NOW - 2 * HOUR),
    })
    const html = render(sweepPath(aborted.ref), board([bounty()], [aborted]))
    const [status] = withClass(html, 'sweep-status--aborted')
    expect(status).toBeDefined()
    // The word follows the mark inside the struck status.
    expect(text(html.slice(html.indexOf(status ?? '<none>'))).trimStart()).toMatch(/^aborted/)
    expect(withClass(html, 'state-mark--aborted')).toHaveLength(1)
  })

  it('shows the not-on-this-board view for a sweep the store does not hold', () => {
    const html = render(sweepPath({ sweeper: C, id: idAt(NOW - HOUR) }), board([bounty()]))
    expect(text(html)).toContain(NOT_ON_BOARD)
    expect(withClass(html, 'trust-badge')).toHaveLength(0)
  })
})
