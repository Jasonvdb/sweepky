// The board's visual pieces (04, "Visual direction"): the floor plan, its
// rooms and detectors, the trust badge and the empty state, rendered to HTML
// in Node from state the selectors derive. Every state is carried by a class
// for its shape and a text label, so nothing depends on colour alone.
import { readFileSync } from 'node:fs'
import type { ReactNode } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { App } from '../App.tsx'
import { selectCircle } from '../config/circle.ts'
import { recordIdFromMicros, type RecordId } from '../records/ids.ts'
import type { Bounty, Sweep } from '../records/parse.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import { createBoardStore } from '../store/boardStore.ts'
import { floorPlan, LEFT_AFTER_MS } from '../store/selectors.ts'
import {
  bountyKey,
  initialBoardState,
  sweepKey,
  type BoardState,
  type BountyEntry,
  type SweepEntry,
} from '../store/state.ts'
import type { Trust } from '../trust/trust.ts'
import { FloorPlan } from './FloorPlan.tsx'
import { TrustBadge } from './TrustBadge.tsx'

// Synthetic keys from fixtures/trust-labels.json: A is the circle's admin and
// owns every bounty, B a member, C and D strangers.
const A = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
const B = pubky('btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy')
const C = pubky('a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy')
const D = pubky('5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco')

const NOW = Date.UTC(2026, 9, 20, 12)
const HOUR = 60 * 60 * 1000

/** X is open to strangers, Y is for the circle only, Z is done. */
const X: BountyRef = { owner: A, id: id(1) }
const Y: BountyRef = { owner: A, id: id(2) }
const Z: BountyRef = { owner: A, id: id(3) }

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`test key ${text} is not a key`)
  return key
}

function id(n: number): RecordId {
  return recordIdFromMicros(BigInt(n))
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
    createdAt: time(NOW - 10 * HOUR),
    doneAt: null,
    ...fields,
  }
  return { ref, record, discovered: null }
}

function sweep(sweeper: Pubky, n: number, of: BountyRef, fields: Partial<Sweep> = {}): SweepEntry {
  const ref: SweepRef = { sweeper, id: id(n) }
  const record: Sweep = {
    bounty: of,
    targets: ['t1'],
    playbook: 'cloudflare/security-audit@c1c8a8c',
    status: 'running',
    startedAt: time(NOW - HOUR),
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

/** `node` as HTML, inside the app's context and a router, so its links render. */
function render(node: ReactNode): string {
  const circle = selectCircle(`?circle=${A}`, undefined)
  const store = createBoardStore({
    admin: circle.admin,
    loadTransport: () => Promise.reject(new Error('a render test sends nothing')),
    scheduler: { schedule: () => () => {} },
    now: () => NOW,
  })
  return renderToStaticMarkup(
    <App services={{ store, circle }}>
      <MemoryRouter>{node}</MemoryRouter>
    </App>,
  )
}

/** The floor plan `state` draws at NOW. */
function renderPlan(state: BoardState, compact = false): string {
  return render(<FloorPlan rooms={floorPlan(state, NOW)} compact={compact} />)
}

/** The elements whose class list holds `name`, each as its opening tag. */
function withClass(html: string, name: string): string[] {
  return [...html.matchAll(/<[a-z]+\b[^>]*\bclass="([^"]*)"[^>]*>/g)]
    .filter((match) => (match[1] ?? '').split(/\s+/).includes(name))
    .map((match) => match[0])
}

/** Each room's `<article>`, whole. Rooms never nest, so the first close ends one. */
function rooms(html: string): string[] {
  return [...html.matchAll(/<article\b[^>]*>[\s\S]*?<\/article>/g)].map((match) => match[0])
}

/** The room drawn for `ref`, found by the title `bounty` gives it. */
function roomOf(html: string, ref: BountyRef): string {
  const room = rooms(html).find((markup) => markup.includes(`Bounty ${ref.id}<`))
  if (room === undefined) throw new Error(`no room for ${ref.id}`)
  return room
}

/** Each detector's `<li>`, whole: a detector holds no list of its own. */
function detectors(html: string): string[] {
  return [...html.matchAll(/<li\b[^>]*\bclass="detector\b[^"]*"[^>]*>[\s\S]*?<\/li>/g)].map(
    (match) => match[0],
  )
}

/** The one detector in `html` for `sweeper`'s sweep. */
function detectorOf(html: string, sweeper: Pubky): string {
  const found = detectors(html).filter((markup) => markup.includes(`data-sweeper="${sweeper}"`))
  expect(found).toHaveLength(1)
  return found[0] ?? ''
}

/** The markup with its tags removed: what a reader sees. */
function text(html: string): string {
  return html.replace(/<[^>]*>/g, '')
}

const EMPTY_LABEL = 'No open bounties yet'

describe('the empty state', () => {
  it.each([false, true])('draws one outlined room and the ways in, compact %s', (compact) => {
    const html = renderPlan(board([]), compact)
    const roomsDrawn = withClass(html, 'room')
    expect(roomsDrawn).toHaveLength(1)
    expect(roomsDrawn[0]).toContain('room--empty')
    expect(withClass(html, 'detector')).toHaveLength(0)
    expect(rooms(html)).toHaveLength(1)

    // The label first, then the owners' way in, then the sweepers' in order.
    const seen = text(html)
    const order = [
      EMPTY_LABEL,
      'sweepky post',
      'sweepky run',
      '/sweepky',
      'Claude Code',
      'sweepky submit',
    ].map((part) => seen.indexOf(part))
    expect(order.every((at) => at >= 0)).toBe(true)
    expect([...order].sort((a, b) => a - b)).toEqual(order)
  })

  it('is not drawn once there is a room', () => {
    expect(renderPlan(board([bounty(X)]))).not.toContain(EMPTY_LABEL)
  })
})

describe('the floor plan', () => {
  const state = board(
    [
      bounty(X, { open: true }),
      bounty(Y),
      // A credits itself and B twice: the door shows B and C, each once.
      bounty(Z, { status: 'done', credits: [A, B, B, C], doneAt: time(NOW - HOUR) }),
    ],
    [
      sweep(B, 10, X),
      sweep(C, 11, X, { status: 'done', finishedAt: time(NOW - HOUR / 2) }),
      sweep(D, 12, X, { startedAt: time(NOW - LEFT_AFTER_MS - HOUR) }),
      sweep(B, 13, Y, { status: 'aborted', finishedAt: time(NOW - HOUR / 2) }),
    ],
  )
  const html = renderPlan(state)

  it('draws one room per bounty, each linking to its page', () => {
    expect(rooms(html)).toHaveLength(3)
    for (const ref of [X, Y, Z]) {
      expect(roomOf(html, ref)).toContain(`href="/b/${A}/${ref.id}?circle=${A}"`)
    }
  })

  it('marks open only the bounty whose record says open', () => {
    expect(withClass(html, 'open-marker')).toHaveLength(1)
    expect(withClass(roomOf(html, X), 'open-marker')).toHaveLength(1)
    expect(text(roomOf(html, X))).toContain('open')
  })

  it('draws a labelled detector per sweep, pulsing only while running and recent', () => {
    const room = roomOf(html, X)
    expect(detectors(room)).toHaveLength(3)
    const running = detectorOf(room, B)
    const swept = detectorOf(room, C)
    const left = detectorOf(room, D)
    expect(running).toContain('detector--pulsing')
    expect(text(running)).toContain('sweeping')
    expect(swept).toContain('detector--done')
    expect(text(swept)).toContain('swept')
    expect(left).not.toContain('detector--pulsing')
    expect(text(left)).toContain('left')
  })

  it('marks a room with a done sweep as swept', () => {
    expect(withClass(roomOf(html, X), 'swept-mark')).toHaveLength(1)
    expect(withClass(roomOf(html, Y), 'swept-mark')).toHaveLength(0)
  })

  it('strikes an aborted sweep with the destructive mark and no pulse', () => {
    const [aborted, ...rest] = detectors(roomOf(html, Y))
    expect(rest).toHaveLength(0)
    expect(aborted).toContain('detector--aborted')
    expect(aborted).toContain('state-mark--aborted')
    expect(aborted).not.toContain('detector--pulsing')
    expect(text(aborted ?? '')).toContain('aborted')
    // The destructive mark appears on the aborted sweep and nowhere else.
    expect(withClass(html, 'state-mark--aborted')).toHaveLength(1)
  })

  it("draws a done bounty as a dark room with its credited sweepers' marks on the door", () => {
    const room = roomOf(html, Z)
    expect(withClass(room, 'room')[0]).toContain('room--done')
    expect(text(room)).toContain('done')
    const door = room.match(/<ul\b[^>]*\bclass="door"[^>]*>[\s\S]*?<\/ul>/)?.[0] ?? ''
    const marks = [...door.matchAll(/<li\b[^>]*>([\s\S]*?)<\/li>/g)].map((match) =>
      text(match[1] ?? ''),
    )
    expect(marks).toEqual([B, C])
    expect(withClass(html, 'door')).toHaveLength(1)
  })

  it("badges each detector with its sweeper's trust, an unknown one hollow", () => {
    const room = roomOf(html, X)
    // B is a member, C is credited on A's done bounty Z, D is no one yet.
    expect(text(detectorOf(room, B))).toContain('circle')
    expect(text(detectorOf(room, C))).toContain('known 1')
    expect(text(detectorOf(room, D))).toContain('unknown')
    expect(detectorOf(room, D)).toContain('detector--unknown')
  })

  it('draws the same rooms in compact form, for the landing hero', () => {
    const compact = renderPlan(state, true)
    expect(withClass(compact, 'floor-plan--compact')).toHaveLength(1)
    expect(rooms(compact)).toHaveLength(3)
  })
})

describe('the trust badge', () => {
  it.each<readonly [Trust, string, string]>([
    [{ label: 'circle', bounties: 0, owners: 0 }, 'circle', 'trust-badge--circle'],
    [{ label: 'known', bounties: 3, owners: 2 }, 'known 3', 'trust-badge--known'],
    [{ label: 'unknown', bounties: 0, owners: 0 }, 'unknown', 'trust-badge--unknown'],
  ])('%o reads %s with its own shape', (trust, label, shape) => {
    const html = renderToStaticMarkup(<TrustBadge trust={trust} />)
    expect(text(html)).toBe(label)
    const badge = withClass(html, 'trust-badge')
    expect(badge).toHaveLength(1)
    expect(badge[0]).toContain(shape)
    // The shape sits beside the label, hidden from assistive technology,
    // which reads the label.
    expect(withClass(html, 'trust-badge__shape')[0]).toContain('aria-hidden="true"')
  })
})

describe("strangers' text", () => {
  it('renders a hostile title as escaped text isolated in a bdi', () => {
    const title = '<img src=x onerror=alert(1)>‮gnp.exe​'
    const html = renderPlan(board([bounty(X, { title })]))
    expect(html).not.toContain('<img')
    expect(html).toContain(
      '<bdi class="stranger-text">&lt;img src=x onerror=alert(1)&gt;‮gnp.exe​</bdi>',
    )
  })
})

describe('motion', () => {
  const css = readFileSync(new URL('../styles/board.css', import.meta.url), 'utf8').replace(
    /\/\*[\s\S]*?\*\//g,
    '',
  )
  const base = readFileSync(new URL('../styles/base.css', import.meta.url), 'utf8')

  /** The keyframes the rules for `selector` animate with. */
  function animationOf(selector: string): string {
    const rule = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].find((match) =>
      (match[1] ?? '').includes(selector),
    )
    return rule?.[2]?.match(/animation:\s*([\w-]+)/)?.[1] ?? ''
  }

  it.each([
    ['.detector--pulsing', 'detector-pulse'],
    ['.detector--done', 'detector-settle'],
  ])('%s animates with %s, defined in board.css', (selector, keyframes) => {
    expect(animationOf(selector)).toBe(keyframes)
    expect(css).toContain(`@keyframes ${keyframes}`)
  })

  it('leaves every animation to the global reduced-motion stop', () => {
    // No `!important` here, so base.css's `animation: none !important`
    // under reduce wins over every rule in board.css.
    expect(css).not.toContain('!important')
    expect(css).not.toContain('prefers-reduced-motion')
    expect(base).toMatch(/prefers-reduced-motion:\s*reduce[\s\S]*animation:\s*none !important/)
  })

  it('animates through classes only, never inline styles', () => {
    const html = renderPlan(
      board([bounty(X)], [sweep(B, 10, X), sweep(C, 11, X, { status: 'done' })]),
    )
    expect(html).not.toMatch(/\bstyle="|<animate/)
  })
})
