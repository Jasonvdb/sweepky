// `/circle` (04, Views): the circle's members as a ring whose brightness is
// their recent activity, each with its homeserver, last activity, credits
// received and reachability. Rendered to HTML in Node, from a store whose
// state the test sets, at a fixed clock.
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { create } from 'zustand'
import { App } from '../App.tsx'
import { selectCircle } from '../config/circle.ts'
import { recordIdFromMicros, type RecordId } from '../records/ids.ts'
import type { Bounty, Sweep } from '../records/parse.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import { boardReducer } from '../store/reducer.ts'
import { trustLabels } from '../trust/trust.ts'
import {
  bountyKey,
  initialBoardState,
  MAX_MEMBERS,
  memberState,
  sweepKey,
  type BoardState,
  type BountyEntry,
  type Resolution,
  type SweepEntry,
} from '../store/state.ts'
import { CirclePage } from './CirclePage.tsx'

// Synthetic keys from fixtures/trust-labels.json: A is the circle's admin,
// B a member, S2 and S3 homeservers.
const A = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
const B = pubky('btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy')
const S2 = pubky('kmjs3ec6imcijf5wknsbfrh1bk4ariso7en8tteestniygu159xo')
const S3 = pubky('qwujy4epafpmfei7bxn8fccfm1shzqp516sbenxi7qr6gua4n77o')

const NOW = Date.UTC(2026, 9, 20, 12)
const HOUR = 60 * 60 * 1000
const DAY = 24 * HOUR

const FOUND: Resolution = { kind: 'found', homeserver: S3, resolvedAt: NOW }

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`test key ${text} is not a key`)
  return key
}

/** A key of its own for member `n`, as reducer.test.ts makes them. */
function syntheticKey(n: number): Pubky {
  const z32 = 'ybndrfg8ejkmcpqxot1uwisza345h769'
  const digits = [...n.toString(32)].map((digit) => z32.charAt(parseInt(digit, 32))).join('')
  return pubky(`${digits.padStart(51, 'y')}y`)
}

function idAt(ms: number): RecordId {
  return recordIdFromMicros(BigInt(ms) * 1000n)
}

function time(ms: number): string {
  return new Date(ms).toISOString().replace('.000Z', 'Z')
}

/** `owner`'s open bounty, posted at `postedMs`, with `fields` set over it. */
function bounty(owner: Pubky, postedMs: number, fields: Partial<Bounty> = {}): BountyEntry {
  const ref: BountyRef = { owner, id: idAt(postedMs) }
  const record: Bounty = {
    title: 'Audit the session code',
    focus: 'security',
    brief: 'Look at the login.',
    playbook: { suggested: null, required: false },
    targets: [],
    open: true,
    status: 'open',
    credits: [],
    createdAt: time(postedMs),
    doneAt: null,
    ...fields,
  }
  return { ref, record, discovered: null }
}

/** `sweeper`'s running sweep of `of`, started at `startedMs`. */
function sweep(sweeper: Pubky, of: BountyRef, startedMs: number): SweepEntry {
  const ref: SweepRef = { sweeper, id: idAt(startedMs) }
  const record: Sweep = {
    bounty: of,
    targets: ['t1'],
    playbook: 'cloudflare/security-audit@c1c8a8c',
    status: 'running',
    startedAt: time(startedMs),
    finishedAt: null,
    sha256: null,
  }
  return { ref, record }
}

interface Board {
  readonly members?: readonly { readonly pubky: Pubky; readonly label: string | null }[]
  readonly bounties?: readonly BountyEntry[]
  readonly sweeps?: readonly SweepEntry[]
  readonly resolutions?: ReadonlyArray<readonly [Pubky, Resolution]>
}

/** A's circle listing `members`, holding these records and lookups. */
function board({ members = [], bounties = [], sweeps = [], resolutions = [] }: Board): BoardState {
  const state = initialBoardState(A)
  return {
    ...state,
    circle: { name: 'Test circle', admin: A, members },
    bounties: new Map(bounties.map((entry) => [bountyKey(entry.ref), entry])),
    sweeps: new Map(sweeps.map((entry) => [sweepKey(entry.ref), entry])),
    members: new Map(
      resolutions.map(([key, resolution]) => [key, { ...memberState(state, key), resolution }]),
    ),
  }
}

/** The circle page drawing `state` at NOW, from a store with no poll behind it. */
function render(state: BoardState, query = `?circle=${A}`): string {
  const store = create<BoardState>()(() => state)
  const circle = selectCircle(query, undefined)
  return renderToStaticMarkup(
    <App services={{ store, circle }}>
      <MemoryRouter initialEntries={['/circle']}>
        <CirclePage />
      </MemoryRouter>
    </App>,
  )
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

/** Each member card, keyed by the member it shows, in page order. */
function memberCards(html: string): Array<readonly [string, string]> {
  return [...html.matchAll(/<li\b[^>]*data-member="([^"]*)"[^>]*>[\s\S]*?<\/li>/g)].map(
    (match) => [match[1] ?? '', match[0]] as const,
  )
}

function cardOf(html: string, key: Pubky): string {
  const card = memberCards(html).find(([member]) => member === key)
  if (card === undefined) throw new Error(`no card for ${key}`)
  return card[1]
}

/** The class list of a card's opening tag. */
function classesOf(card: string): string[] {
  return (card.match(/^<li\b[^>]*\bclass="([^"]*)"/)?.[1] ?? '').split(/\s+/)
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
})

afterEach(() => {
  vi.useRealTimers()
})

describe('a member', () => {
  it('shows its homeserver, its last activity and the credits received trustLabels counts', () => {
    // B is credited by two of A's done bounties; A's own credit on one counts
    // for nothing (01).
    const credited = [
      bounty(A, NOW - 5 * DAY, { status: 'done', credits: [B, A], doneAt: time(NOW - 4 * DAY) }),
      bounty(A, NOW - 3 * DAY, { status: 'done', credits: [B], doneAt: time(NOW - 2 * DAY) }),
    ]
    // B's newest record is a sweep, newer than its bounty.
    const bBounty = bounty(B, NOW - 6 * DAY)
    const bSweep = sweep(B, bBounty.ref, NOW - 3 * HOUR)
    const state = board({
      members: [{ pubky: B, label: 'Bea' }],
      bounties: [...credited, bBounty],
      sweeps: [bSweep],
      resolutions: [
        [A, FOUND],
        [B, FOUND],
      ],
    })
    const card = cardOf(render(state), B)

    expect(card).toMatch(new RegExp(`<dd[^>]*class="pubky"[^>]*>${S3}</dd>`))
    expect(card).toContain(`dateTime="${new Date(NOW - 3 * HOUR).toISOString()}"`)
    const expected = trustLabels(
      { name: '', admin: A, members: [{ pubky: B, label: null }] },
      credited.map(({ ref, record }) => ({ owner: ref.owner, ...record })),
    ).get(B)
    expect(expected).toMatchObject({ bounties: 2, owners: 1 })
    expect(text(card)).toContain(`${expected.bounties} bounties from ${expected.owners} owner`)
    expect(text(card)).not.toContain(`${expected.owners} owners`)
  })

  it('shows its label from circle.json as escaped, isolated text', () => {
    const state = board({ members: [{ pubky: B, label: '<b>Bea</b>‮' }] })
    const card = cardOf(render(state), B)
    expect(card).toContain('<bdi class="stranger-text">&lt;b&gt;Bea&lt;/b&gt;‮</bdi>')
    expect(card).not.toContain('<b>')
  })

  it('says it has no activity yet when the board holds none of its records', () => {
    const card = cardOf(render(board({ members: [{ pubky: B, label: null }] })), B)
    expect(text(card)).toMatch(/no records yet/i)
    expect(card).not.toContain('<time')
  })
})

describe('the ring', () => {
  it('lists the members admin first, at most MAX_MEMBERS of them', () => {
    // Through the reducer, so the cap is the one the poller keeps.
    const many = Array.from({ length: MAX_MEMBERS + 8 }, (_, n) => syntheticKey(n + 1))
    const listed = many.map((key) => ({ pubky: key }))
    const body = new TextEncoder().encode(
      JSON.stringify({ schemaVersion: 1, name: 'Big circle', admin: A, members: listed }),
    )
    const state = boardReducer(initialBoardState(A), {
      type: 'circleRead',
      admin: A,
      answer: { kind: 'body', body },
      at: NOW,
    })
    const shown = memberCards(render(state)).map(([member]) => member)
    expect(shown).toEqual([A, ...many.slice(0, MAX_MEMBERS - 1)])
  })

  it.each([
    ['an hour', HOUR, 'member--bright'],
    ['three days', 3 * DAY, 'member--lit'],
    ['twenty days', 20 * DAY, 'member--dim'],
    ['ninety days', 90 * DAY, 'member--dark'],
  ])("brightens a member whose newest record is %s old as %s", (_, age, brightness) => {
    const state = board({
      members: [{ pubky: B, label: null }],
      bounties: [bounty(B, NOW - 200 * DAY), bounty(B, NOW - age)],
    })
    const classes = classesOf(cardOf(render(state), B))
    expect(classes).toContain(brightness)
    expect(classes.filter((name) => name.startsWith('member--'))).toEqual([brightness])
  })

  it('leaves a member with no records dark', () => {
    const state = board({ members: [{ pubky: B, label: null }] })
    expect(classesOf(cardOf(render(state), B))).toContain('member--dark')
  })
})

describe('reachability', () => {
  it.each(['noRecord', 'lookupFailed'] as const)(
    'marks a member whose lookup is %s unreachable, in the ring still',
    (kind) => {
      const state = board({
        members: [{ pubky: B, label: null }],
        resolutions: [[B, { kind, resolvedAt: NOW }]],
      })
      const cards = memberCards(render(state))
      expect(cards.map(([member]) => member)).toEqual([A, B])
      const card = cardOf(render(state), B)
      expect(card).toMatch(/class="state-mark state-mark--unreachable"/)
      expect(text(card)).toMatch(/\bunreachable\b/)
    },
  )

  it('says a member whose homeserver has no ICANN HTTPS endpoint is not browser-reachable, muted', () => {
    const state = board({
      members: [{ pubky: B, label: null }],
      resolutions: [[B, { kind: 'notBrowserReachable', homeserver: S2, resolvedAt: NOW }]],
    })
    const cards = memberCards(render(state))
    expect(cards.map(([member]) => member)).toEqual([A, B])
    const card = cardOf(render(state), B)
    expect(card).toMatch(/<span class="member__muted">not browser-reachable<\/span>/)
    expect(text(card)).toMatch(/ICANN HTTPS/)
    expect(card).toContain(S2)
    // Muted, not destructive: the CLI can still reach it.
    expect(card).not.toContain('state-mark--unreachable')
  })

  it('marks a reachable member reachable, with no destructive mark', () => {
    const state = board({ members: [{ pubky: B, label: null }], resolutions: [[B, FOUND]] })
    const card = cardOf(render(state), B)
    expect(text(card)).toMatch(/\breachable\b/)
    expect(card).not.toContain('state-mark--unreachable')
  })
})

describe('with no circle selected', () => {
  it('renders the no-circle notice and no members', () => {
    const html = render(initialBoardState(null), '')
    expect(text(html)).toMatch(/no circle selected/i)
    expect(memberCards(html)).toEqual([])
  })
})
