// Open bounties' discovered sweeps, read the way 04's "Live-ness" says: the
// owner's `bounties/<id>.discovered.json`, then each listed stranger's sweep
// from that stranger's own storage. Driven through `pollOnce`, with a fake
// transport and a fake clock, as poller.test.ts drives the rest of a pass.

import { describe, expect, it } from 'vitest'
import type {
  CacheMode,
  HomeserverLookup,
  ListedDir,
  ListingAnswer,
  ListOptions,
  RecordAnswer,
  RecordOptions,
  Transport,
} from '../net/transport.ts'
import { recordIdFromMicros, type RecordId } from '../records/ids.ts'
import { formatSweepkyPath, SWEEPS_DIR, type SweepkyPath } from '../records/paths.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import {
  MAX_NEW_STRANGERS_SWEEPS_PER_POLL,
  MAX_STRANGERS_SWEEPS_PER_BOUNTY,
} from './discovered.ts'
import { MAX_DONE_REREADS_PER_MEMBER, POLL_INTERVAL_MS, pollOnce } from './poller.ts'
import { boardReducer } from './reducer.ts'
import { bountyKey, initialBoardState, sweepKey, type BoardState } from './state.ts'

// Keys from fixtures/trust-labels.json: A is the circle's admin, B a member,
// C and E strangers the circle does not name.
const A = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
const B = pubky('btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy')
const C = pubky('a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy')
const E = pubky('5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco')

const T0 = Date.UTC(2026, 9, 20, 12, 0, 0)

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`test key ${text} is not a key`)
  return key
}

/** The record id of timestamp `n`: a larger `n` is a newer record. */
function id(n: number): RecordId {
  return recordIdFromMicros(BigInt(n))
}

/** The z-base32 alphabet, in value order. */
const Z32 = 'ybndrfg8ejkmcpqxot1uwisza345h769'

/** Stranger number `n`, a synthetic key none of the named ones is. */
function strangerKey(n: number): Pubky {
  const digits = [...n.toString(32)].map((digit) => Z32.charAt(parseInt(digit, 32))).join('')
  return pubky(`${digits.padStart(51, 'y')}y`)
}

type BountyStatus = 'open' | 'done'
type SweepStatus = 'running' | 'done' | 'aborted'

function bountyJson(status: BountyStatus, open: boolean): unknown {
  return {
    schemaVersion: 1,
    title: 'Auth and session handling',
    focus: 'security',
    brief: 'Look at `src/auth/`.',
    playbook: { suggested: null, required: false },
    targets: [{ id: 't1', kind: 'repo', repo: 'github.com/org/name', rev: 'a'.repeat(40) }],
    open,
    status,
    credits: status === 'done' ? [C] : [],
    createdAt: '2026-10-20T10:00:00Z',
    doneAt: status === 'done' ? '2026-10-20T12:30:00Z' : null,
  }
}

function sweepJson(bounty: BountyRef, status: SweepStatus): unknown {
  return {
    schemaVersion: 1,
    bounty: `pubky://${bounty.owner}/pub/sweepky/bounties/${bounty.id}.json`,
    targets: ['t1'],
    playbook: 'cloudflare/security-audit@c1c8a8c',
    status,
    startedAt: '2026-10-20T11:00:00Z',
    finishedAt: status === 'running' ? null : '2026-10-20T11:52:00Z',
  }
}

function sweepUrl(ref: SweepRef): string {
  return `pubky://${ref.sweeper}/pub/sweepky/sweeps/${ref.id}.json`
}

/** A discovered-sweeps file listing `sweeps`, with a cursor the board ignores. */
function discoveredJson(sweeps: readonly string[]): unknown {
  return { schemaVersion: 1, sweeps, cursors: { [E]: '1234' } }
}

/** One request the poller made, as the fake transport saw it. */
interface Request {
  readonly op: 'get' | 'list' | 'lookup'
  readonly owner: Pubky
  readonly path: string
  readonly cache: CacheMode | null
}

/**
 * Homeservers in memory: each key's public files, listed newest first. Every
 * request is logged. Keys in `unreachable` have no endpoint a browser can
 * reach, as a stranger whose homeserver does not resolve.
 */
class FakeNetwork implements Transport {
  readonly requests: Request[] = []
  private readonly files = new Map<Pubky, Map<string, string>>()
  readonly unreachable = new Set<Pubky>()

  put(owner: Pubky, path: SweepkyPath, value: unknown): void {
    const files = this.files.get(owner) ?? new Map<string, string>()
    files.set(formatSweepkyPath(path), JSON.stringify(value))
    this.files.set(owner, files)
  }

  putCircle(members: readonly Pubky[]): void {
    const listed = members.map((key) => ({ pubky: key }))
    this.put(A, { kind: 'circle' }, { schemaVersion: 1, name: 'Test', admin: A, members: listed })
  }

  putBounty(ref: BountyRef, status: BountyStatus, open = true): void {
    this.put(ref.owner, { kind: 'bounty', id: ref.id }, bountyJson(status, open))
  }

  putSweep(ref: SweepRef, bounty: BountyRef, status: SweepStatus = 'running'): void {
    this.put(ref.sweeper, { kind: 'sweepRecord', id: ref.id }, sweepJson(bounty, status))
  }

  putDiscovered(bounty: BountyRef, sweeps: readonly string[]): void {
    this.put(bounty.owner, { kind: 'discovered', id: bounty.id }, discoveredJson(sweeps))
  }

  async getRecord(owner: Pubky, path: SweepkyPath, options: RecordOptions): Promise<RecordAnswer> {
    const text = formatSweepkyPath(path)
    this.requests.push({ op: 'get', owner, path: text, cache: options.cache })
    if (this.unreachable.has(owner)) return { kind: 'notBrowserReachable' }
    const file = this.files.get(owner)?.get(text)
    return file === undefined ? { kind: 'absent' } : { kind: 'body', body: encode(file) }
  }

  async list(owner: Pubky, dir: ListedDir, options: ListOptions): Promise<ListingAnswer> {
    this.requests.push({ op: 'list', owner, path: dir, cache: options.cache })
    const cursor = options.cursor?.path
    const paths = [...(this.files.get(owner)?.keys() ?? [])]
      .filter((path) => path.startsWith(dir) && (cursor === undefined || path < cursor))
      .sort()
      .reverse()
      .slice(0, options.limit)
    if (paths.length === 0 && cursor === undefined) return { kind: 'empty' }
    return { kind: 'body', body: encode(paths.map((path) => `pubky://${owner}${path}`).join('\n')) }
  }

  async lookupHomeserver(owner: Pubky): Promise<HomeserverLookup> {
    this.requests.push({ op: 'lookup', owner, path: '', cache: null })
    return { kind: 'found', homeserver: E }
  }

  /** The requests logged since the last call, which starts a new log. */
  take(): Request[] {
    return this.requests.splice(0)
  }
}

const encoder = new TextEncoder()
function encode(text: string): Uint8Array {
  return encoder.encode(text)
}

/** A board of A's circle over `net`, polled by hand on a fake clock. */
function harness(net = new FakeNetwork()) {
  let state: BoardState = initialBoardState(A)
  let clock = T0
  return {
    net,
    state: () => state,
    /** One pass at the clock's time, then the clock moves on `POLL_INTERVAL_MS`. */
    async poll(): Promise<Request[]> {
      await pollOnce({
        transport: net,
        getState: () => state,
        dispatch: (action) => {
          state = boardReducer(state, action)
        },
        now: () => clock,
        signal: new AbortController().signal,
      })
      clock += POLL_INTERVAL_MS
      return net.take()
    },
  }
}

const discoveredPath = (ref: BountyRef) => formatSweepkyPath({ kind: 'discovered', id: ref.id })
const bountyPath = (ref: BountyRef) => formatSweepkyPath({ kind: 'bounty', id: ref.id })

/** The paths of the discovered files `requests` read. */
const discoveredReads = (requests: readonly Request[]) =>
  requests.filter((r) => r.path.endsWith('.discovered.json')).map((r) => r.path)
/** The sweep records `requests` read of keys other than the roster's. */
const strangersReads = (requests: readonly Request[], roster: readonly Pubky[] = [A, B]) =>
  requests.filter(
    (r) => r.op === 'get' && r.path.startsWith(SWEEPS_DIR) && !roster.includes(r.owner),
  )

/**
 * A's open bounty X, open to strangers, whose discovered.json lists C's
 * sweep CS: the state 06's end-to-end test reaches after the owner's pull.
 */
function openBountyWithStranger() {
  const board = harness()
  const X: BountyRef = { owner: A, id: id(1) }
  const CS: SweepRef = { sweeper: C, id: id(5) }
  board.net.putCircle([B])
  board.net.putBounty(X, 'open')
  board.net.putSweep(CS, X)
  board.net.putDiscovered(X, [sweepUrl(CS)])
  return { board, X, CS }
}

describe('discovered sweeps: open bounties', () => {
  it(
    "reads an open bounty's discovered.json on every poll, and the stranger's sweep from the stranger's storage",
    async () => {
      const { board, X, CS } = openBountyWithStranger()
      for (let n = 0; n < 3; n += 1) {
        const requests = await board.poll()
        const reads = requests.filter((r) => r.path === discoveredPath(X))
        expect(reads.map((r) => r.owner)).toEqual([A])
      }
      // Read from C's own storage, never from the owner's.
      const sweepRead = await board.poll()
      expect(strangersReads(sweepRead).map((r) => r.owner)).toEqual([C])
      expect(board.state().sweeps.get(sweepKey(CS))?.record.status).toBe('running')
    },
  )

  it("shows a stranger's sweep within one poll of the owner's pull publishing it", async () => {
    const { board, X, CS } = openBountyWithStranger()
    board.net.putDiscovered(X, [])
    await board.poll()
    expect(board.state().sweeps.has(sweepKey(CS))).toBe(false)
    board.net.putDiscovered(X, [sweepUrl(CS)])
    await board.poll()
    expect(board.state().sweeps.has(sweepKey(CS))).toBe(true)
  })

  it('never reads discovered.json of a bounty with open: false', async () => {
    const board = harness()
    const X: BountyRef = { owner: A, id: id(1) }
    const Y: BountyRef = { owner: A, id: id(2) }
    board.net.putCircle([])
    board.net.putBounty(X, 'open', false)
    board.net.putBounty(Y, 'done', false)
    board.net.putDiscovered(X, [sweepUrl({ sweeper: C, id: id(5) })])
    for (let n = 0; n < 3; n += 1) expect(discoveredReads(await board.poll())).toEqual([])
  })

  it("re-reads a stranger's sweep while it is running, and never after it is done", async () => {
    const { board, X, CS } = openBountyWithStranger()
    await board.poll()
    expect(strangersReads(await board.poll())).toHaveLength(1)
    board.net.putSweep(CS, X, 'done')
    expect(strangersReads(await board.poll())).toHaveLength(1)
    expect(board.state().sweeps.get(sweepKey(CS))?.record.status).toBe('done')
    expect(strangersReads(await board.poll())).toEqual([])
  })
})

describe('discovered sweeps: done bounties', () => {
  it(
    'reads discovered.json of a bounty first seen done once, then only when the rotation re-reads it',
    async () => {
      const board = harness()
      // More done bounties than a pass re-reads, so the rotation leaves some out.
      const done = Array.from({ length: 10 }, (_, n): BountyRef => ({ owner: A, id: id(n + 1) }))
      board.net.putCircle([])
      for (const ref of done) {
        board.net.putBounty(ref, 'done')
        board.net.putDiscovered(ref, [])
      }
      expect(discoveredReads(await board.poll())).toEqual(done.map(discoveredPath))
      for (let n = 0; n < 3; n += 1) {
        const requests = await board.poll()
        const reread = done.filter((ref) => requests.some((r) => r.path === bountyPath(ref)))
        expect(reread).toHaveLength(MAX_DONE_REREADS_PER_MEMBER)
        expect(discoveredReads(requests)).toEqual(reread.map(discoveredPath))
      }
    },
  )

  it(
    'flips a bounty to done with its credits and keeps the stranger, as a reloaded tab shows it',
    async () => {
      const { board: live, X, CS } = openBountyWithStranger()
      live.net.putSweep(CS, X, 'done')
      await live.poll()
      live.net.putBounty(X, 'done')
      const flipped = await live.poll()
      // Read once more when first seen done, in the pass that saw it.
      expect(discoveredReads(flipped)).toEqual([discoveredPath(X)])
      expect(live.state().bounties.get(bountyKey(X))?.record.credits).toEqual([C])

      // A fresh tab over the same homeservers.
      const reloaded = harness(live.net)
      const first = await reloaded.poll()
      expect(discoveredReads(first)).toEqual([discoveredPath(X)])
      expect(strangersReads(first).map((r) => r.owner)).toEqual([C])
      expect([...reloaded.state().sweeps.keys()]).toEqual([...live.state().sweeps.keys()])
      const strangersSweep = (board: typeof live) => board.state().sweeps.get(sweepKey(CS))
      expect(strangersSweep(reloaded)).toEqual(strangersSweep(live))
    },
  )
})

describe('discovered sweeps: what a list may name', () => {
  it('reads no listed URL that is not a sweep record, and keeps the last good list', async () => {
    const { board, X, CS } = openBountyWithStranger()
    await board.poll()
    board.net.putDiscovered(X, [
      sweepUrl(CS),
      `pubky://${E}/pub/sweepky/sweeps/${id(6)}.age`,
      `pubky://${E}/pub/other/${id(7)}.json`,
    ])
    const requests = await board.poll()
    expect(requests.filter((r) => r.owner === E && r.op === 'get')).toEqual([])
    expect(board.state().sweeps.has(sweepKey(CS))).toBe(true)
  })

  it("reads no listed sweep under the owner's own key, or a member's, as a stranger's", async () => {
    const board = harness()
    const X: BountyRef = { owner: A, id: id(1) }
    const own: SweepRef = { sweeper: A, id: id(5) }
    const members: SweepRef = { sweeper: B, id: id(6) }
    board.net.putCircle([B])
    board.net.putBounty(X, 'open')
    board.net.putDiscovered(X, [sweepUrl(own), sweepUrl(members)])
    const requests = await board.poll()
    // Each is read once, through its own key's listing, which finds none.
    const sweepGets = requests.filter((r) => r.op === 'get' && r.path.startsWith(SWEEPS_DIR))
    expect(sweepGets).toEqual([])
  })

  it(
    `keeps at most ${MAX_STRANGERS_SWEEPS_PER_BOUNTY} strangers' sweeps a bounty, reading at most ${MAX_NEW_STRANGERS_SWEEPS_PER_POLL} new ones a poll`,
    async () => {
      const board = harness()
      const X: BountyRef = { owner: A, id: id(1) }
      board.net.putCircle([])
      board.net.putBounty(X, 'open')
      const listed = Array.from({ length: 300 }, (_, n): SweepRef => ({
        sweeper: strangerKey(n + 1),
        id: id(1000 + n),
      }))
      for (const ref of listed) board.net.putSweep(ref, X, 'done')
      board.net.putDiscovered(X, listed.map(sweepUrl))

      const everRead = new Set<Pubky>()
      for (let n = 0; n < 10; n += 1) {
        const reads = strangersReads(await board.poll(), [A])
        expect(reads.length).toBeLessThanOrEqual(MAX_NEW_STRANGERS_SWEEPS_PER_POLL)
        for (const read of reads) everRead.add(read.owner)
      }
      const kept = listed.slice(0, MAX_STRANGERS_SWEEPS_PER_BOUNTY).map((ref) => ref.sweeper)
      expect(everRead).toEqual(new Set(kept))
      expect(board.state().sweeps.size).toBe(MAX_STRANGERS_SWEEPS_PER_BOUNTY)
    },
  )

  it('skips a stranger whose homeserver does not resolve, and not the bounty', async () => {
    const { board, X, CS } = openBountyWithStranger()
    const ES: SweepRef = { sweeper: E, id: id(6) }
    board.net.putSweep(ES, X)
    board.net.putDiscovered(X, [sweepUrl(CS), sweepUrl(ES)])
    board.net.unreachable.add(C)
    await board.poll()
    const state = board.state()
    expect(state.sweeps.has(sweepKey(CS))).toBe(false)
    expect(state.sweeps.has(sweepKey(ES))).toBe(true)
    expect(state.bounties.get(bountyKey(X))?.discovered?.sweeps.size).toBe(2)
    expect(state.members.get(A)?.readFailedAt).toBeNull()

    board.net.unreachable.delete(C)
    await board.poll()
    expect(board.state().sweeps.has(sweepKey(CS))).toBe(true)
  })
})

describe('discovered sweeps: requests', () => {
  it("sends every read with cache 'no-cache', and never requests /events", async () => {
    const { board, X, CS } = openBountyWithStranger()
    const all: Request[] = []
    for (let n = 0; n < 4; n += 1) {
      if (n === 2) board.net.putBounty(X, 'done')
      if (n === 3) board.net.putSweep(CS, X, 'done')
      all.push(...(await board.poll()))
    }
    expect(discoveredReads(all).length).toBeGreaterThan(0)
    expect(strangersReads(all).length).toBeGreaterThan(0)
    for (const request of all.filter((r) => r.op !== 'lookup')) {
      expect(request.cache).toBe('no-cache')
      expect(request.path).not.toContain('/events')
    }
  })
})
