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
import { BOUNTIES_DIR, formatSweepkyPath, SWEEPS_DIR, type SweepkyPath } from '../records/paths.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import type { BountyRef, SweepRef } from '../records/urls.ts'
import { createBoardStore, type Scheduler } from './boardStore.ts'
import {
  MAX_DONE_REREADS_PER_MEMBER,
  MAX_NEW_BOUNTIES_PER_MEMBER,
  MAX_NEW_SWEEPS_PER_MEMBER,
  MAX_REREADS_PER_MEMBER,
  POLL_INTERVAL_MS,
  pollOnce,
  RESOLUTION_TTL_MS,
  rereadShares,
} from './poller.ts'
import { boardReducer } from './reducer.ts'
import { boardStatus } from './selectors.ts'
import { bountyKey, initialBoardState, MAX_MEMBERS, sweepKey, type BoardState } from './state.ts'

// Keys from fixtures/trust-labels.json: A is the circle's admin, B a member,
// C someone the circle does not name, D a homeserver.
const A = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
const B = pubky('btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy')
const C = pubky('a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy')
const HOMESERVER = pubky('5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco')

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

/** Key number `n`, a synthetic key none of the named ones is. */
function syntheticKey(n: number): Pubky {
  const digits = [...n.toString(32)].map((digit) => Z32.charAt(parseInt(digit, 32))).join('')
  return pubky(`${digits.padStart(51, 'y')}y`)
}

function circleJson(members: readonly Pubky[], admin: Pubky = A): unknown {
  const listed = members.map((key) => ({ pubky: key }))
  return { schemaVersion: 1, name: 'Test circle', admin, members: listed }
}

function bountyJson(status: 'open' | 'done' = 'open'): unknown {
  return {
    schemaVersion: 1,
    title: 'Auth and session handling',
    focus: 'security',
    brief: 'Look at `src/auth/`.',
    playbook: { suggested: null, required: false },
    targets: [{ id: 't1', kind: 'repo', repo: 'github.com/org/name', rev: 'a'.repeat(40) }],
    open: false,
    status,
    credits: status === 'done' ? [B] : [],
    createdAt: '2026-10-20T10:00:00Z',
    doneAt: status === 'done' ? '2026-10-20T12:30:00Z' : null,
  }
}

function sweepJson(bounty: BountyRef, status: 'running' | 'done' | 'aborted' = 'running'): unknown {
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

/** One request the poller made, as the fake transport saw it. */
type Request = Read | { readonly op: 'lookup'; readonly owner: Pubky }

/** A `getRecord` or a `list`: a GET of one path of `owner`'s storage. */
interface Read {
  readonly op: 'get' | 'list'
  readonly owner: Pubky
  readonly path: string
  readonly cache: CacheMode
}

/**
 * Homeservers in memory: each key's public files, served as a 0.16.2
 * homeserver serves them, listings newest first by path with a cursor. Every
 * request is logged.
 */
class FakeNetwork implements Transport {
  readonly requests: Request[] = []
  /** Each key's files, by path, as JSON text. */
  private readonly files = new Map<Pubky, Map<string, string>>()
  /** Keys whose lookup gives this instead of a homeserver. */
  readonly lookups = new Map<Pubky, HomeserverLookup>()
  /** Keys whose every read fails. */
  readonly failing = new Set<Pubky>()

  put(owner: Pubky, path: SweepkyPath, value: unknown): void {
    const files = this.files.get(owner) ?? new Map<string, string>()
    files.set(formatSweepkyPath(path), JSON.stringify(value))
    this.files.set(owner, files)
  }

  putBounty(ref: BountyRef, status: 'open' | 'done' = 'open'): void {
    this.put(ref.owner, { kind: 'bounty', id: ref.id }, bountyJson(status))
  }

  putSweep(ref: SweepRef, bounty: BountyRef, status: 'running' | 'done' | 'aborted' = 'running') {
    this.put(ref.sweeper, { kind: 'sweepRecord', id: ref.id }, sweepJson(bounty, status))
  }

  putCircle(members: readonly Pubky[], admin: Pubky = A): void {
    this.put(A, { kind: 'circle' }, circleJson(members, admin))
  }

  async getRecord(owner: Pubky, path: SweepkyPath, options: RecordOptions): Promise<RecordAnswer> {
    const text = formatSweepkyPath(path)
    this.requests.push({ op: 'get', owner, path: text, cache: options.cache })
    if (this.failing.has(owner)) return { kind: 'failed', message: 'the homeserver answered 503' }
    const file = this.files.get(owner)?.get(text)
    return file === undefined ? { kind: 'absent' } : { kind: 'body', body: encode(file) }
  }

  async list(owner: Pubky, dir: ListedDir, options: ListOptions): Promise<ListingAnswer> {
    this.requests.push({ op: 'list', owner, path: dir, cache: options.cache })
    if (this.failing.has(owner)) return { kind: 'failed', message: 'the homeserver answered 503' }
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
    this.requests.push({ op: 'lookup', owner })
    return this.lookups.get(owner) ?? { kind: 'found', homeserver: HOMESERVER }
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

/** A board of `admin`'s circle over a `FakeNetwork`, polled by hand on a fake clock. */
function harness(admin: Pubky | null = A) {
  const net = new FakeNetwork()
  let state: BoardState = initialBoardState(admin)
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
    advance(ms: number): void {
      clock += ms
    },
  }
}

const circlePath = formatSweepkyPath({ kind: 'circle' })
const bountyPath = (ref: BountyRef) => formatSweepkyPath({ kind: 'bounty', id: ref.id })
const sweepPath = (ref: SweepRef) => formatSweepkyPath({ kind: 'sweepRecord', id: ref.id })

/** What `requests` asked for, in a form short enough to compare. */
function summary(requests: readonly Request[]): string[] {
  return requests.map((request) =>
    request.op === 'lookup'
      ? `lookup ${request.owner}`
      : `${request.op} ${request.owner} ${request.path}`,
  )
}

const readsOf = (requests: readonly Request[]) =>
  requests.filter((r): r is Read => r.op !== 'lookup')
const gets = (requests: readonly Request[], owner: Pubky, dir: ListedDir) =>
  readsOf(requests).filter((r) => r.op === 'get' && r.owner === owner && r.path.startsWith(dir))
const lookups = (requests: readonly Request[]) =>
  requests.filter((r) => r.op === 'lookup').map((r) => r.owner)
/** The keys whose storage was listed: a set, as the keys run side by side. */
const listedKeys = (requests: readonly Request[]) =>
  new Set(requests.filter((r) => r.op === 'list').map((r) => r.owner))

/** The circle of 06's end-to-end test: A owns the open bounty X, B sweeps it. */
function circleOfTwo() {
  const board = harness()
  const X: BountyRef = { owner: A, id: id(1) }
  const BS: SweepRef = { sweeper: B, id: id(5) }
  board.net.putCircle([B])
  board.net.putBounty(X)
  board.net.putSweep(BS, X)
  return { board, X, BS }
}

describe('pollOnce: the first pass', () => {
  it(
    'reads circle.json, looks each key up once, lists both directories and reads what is new',
    async () => {
      const { board, X, BS } = circleOfTwo()
      const requests = await board.poll()
      // The admin's lookup and circle.json come first; the keys then run side
      // by side, each one's requests in order.
      expect(summary(requests.slice(0, 2))).toEqual([`lookup ${A}`, `get ${A} ${circlePath}`])
      expect(lookups(requests)).toEqual([A, B])
      const ofKey = (key: Pubky) => summary(requests.slice(2).filter((r) => r.owner === key))
      expect(ofKey(A)).toEqual([
        `list ${A} ${BOUNTIES_DIR}`,
        `get ${A} ${bountyPath(X)}`,
        `list ${A} ${SWEEPS_DIR}`,
      ])
      expect(ofKey(B)).toEqual([
        `lookup ${B}`,
        `list ${B} ${BOUNTIES_DIR}`,
        `list ${B} ${SWEEPS_DIR}`,
        `get ${B} ${sweepPath(BS)}`,
      ])
      expect(board.state().bounties.has(bountyKey(X))).toBe(true)
      expect(board.state().sweeps.get(sweepKey(BS))?.record.status).toBe('running')
    },
  )
})

describe('pollOnce: the passes after', () => {
  it(
    'reads circle.json again and re-reads the open bounty and the running sweep: done in one poll',
    async () => {
      const { board, X, BS } = circleOfTwo()
      await board.poll()
      board.net.putSweep(BS, X, 'done')
      const requests = await board.poll()
      expect(summary(requests)).toEqual(
        expect.arrayContaining([
          `get ${A} ${circlePath}`,
          `get ${A} ${bountyPath(X)}`,
          `get ${B} ${sweepPath(BS)}`,
        ]),
      )
      expect(lookups(requests)).toEqual([])
      expect(board.state().sweeps.get(sweepKey(BS))?.record.status).toBe('done')
    },
  )

  it('never re-reads a done or aborted sweep', async () => {
    const board = harness()
    const X: BountyRef = { owner: A, id: id(1) }
    const done: SweepRef = { sweeper: A, id: id(2) }
    const aborted: SweepRef = { sweeper: A, id: id(3) }
    board.net.putCircle([])
    board.net.putBounty(X)
    board.net.putSweep(done, X, 'done')
    board.net.putSweep(aborted, X, 'aborted')
    const first = await board.poll()
    expect(gets(first, A, SWEEPS_DIR)).toHaveLength(2)
    for (let n = 0; n < 3; n += 1) {
      expect(gets(await board.poll(), A, SWEEPS_DIR)).toEqual([])
    }
  })

  it('re-reads at most 8 done bounties a pass, in rotation', async () => {
    const board = harness()
    board.net.putCircle([])
    const done = Array.from({ length: 10 }, (_, n): BountyRef => ({ owner: A, id: id(n + 1) }))
    for (const ref of done) board.net.putBounty(ref, 'done')
    await board.poll()
    const reread = async () =>
      gets(await board.poll(), A, BOUNTIES_DIR).map((r) => r.path)
    const paths = done.map(bountyPath)
    expect(await reread()).toEqual(paths.slice(0, MAX_DONE_REREADS_PER_MEMBER))
    expect(await reread()).toEqual([...paths.slice(8), ...paths.slice(0, 6)])
  })

  it(
    'polls a member added to circle.json on the next pass and stops polling one removed',
    async () => {
      const { board } = circleOfTwo()
      await board.poll()
      board.net.putCircle([C])
      const requests = await board.poll()
      expect(listedKeys(requests)).toEqual(new Set([A, C]))
      expect(lookups(requests)).toEqual([C])
    },
  )
})

describe('pollOnce: requests', () => {
  it(
    "sends every get and list with cache 'no-cache': circle, listings, first reads, re-reads",
    async () => {
      const { board, X, BS } = circleOfTwo()
      const all = [...(await board.poll())]
      board.net.putSweep(BS, X, 'done')
      board.net.putBounty({ owner: B, id: id(9) })
      all.push(...(await board.poll()), ...(await board.poll()))
      const reads = readsOf(all)
      expect(reads.length).toBeGreaterThan(10)
      for (const read of reads) expect(read.cache).toBe('no-cache')
    },
  )

  it('only ever GETs public Sweepky paths, and never /events', async () => {
    const { board, X, BS } = circleOfTwo()
    const all: Request[] = []
    for (let n = 0; n < 6; n += 1) {
      if (n === 2) board.net.putSweep(BS, X, 'done')
      if (n === 3) board.net.putCircle([B, C])
      all.push(...(await board.poll()))
    }
    // The fake has no other method, as the `Transport` has none: no write,
    // no feed. Every path is one the transport can only GET.
    for (const request of readsOf(all)) {
      expect(request.path.startsWith('/pub/sweepky/')).toBe(true)
      expect(request.path).not.toContain('/events')
    }
  })
})

describe('pollOnce: homeserver lookups', () => {
  it('looks a key up again only after an hour, or after a failed read', async () => {
    const { board } = circleOfTwo()
    expect(lookups(await board.poll())).toEqual([A, B])
    expect(lookups(await board.poll())).toEqual([])
    board.advance(RESOLUTION_TTL_MS - 2 * POLL_INTERVAL_MS)
    expect(lookups(await board.poll())).toEqual([A, B])

    board.net.failing.add(B)
    expect(lookups(await board.poll())).toEqual([])
    board.net.failing.delete(B)
    expect(lookups(await board.poll())).toEqual([B])
    expect(lookups(await board.poll())).toEqual([])
  })

  it('stops a key at its first failed read, and polls the others', async () => {
    const { board } = circleOfTwo()
    board.net.failing.add(B)
    const requests = await board.poll()
    expect(summary(requests.filter((r) => r.owner === B))).toEqual([
      `lookup ${B}`,
      `list ${B} ${BOUNTIES_DIR}`,
    ])
    expect(listedKeys(requests)).toEqual(new Set([A, B]))
  })

  it(
    'reads no more of the admin after circle.json fails, and looks it up again next pass',
    async () => {
      const { board } = circleOfTwo()
      await board.poll()
      board.net.failing.add(A)
      const failed = await board.poll()
      expect(summary(failed.filter((r) => r.owner === A))).toEqual([`get ${A} ${circlePath}`])
      // The roster read before still holds, so B is polled.
      expect(listedKeys(failed)).toEqual(new Set([B]))
      board.net.failing.delete(A)
      expect(lookups(await board.poll())).toEqual([A])
    },
  )

  it('keeps a key it cannot reach in the roster, and polls none of its storage', async () => {
    const { board } = circleOfTwo()
    board.net.lookups.set(B, { kind: 'unreachable', reason: 'noRecord' })
    const requests = await board.poll()
    expect(listedKeys(requests)).toEqual(new Set([A]))
    expect(board.state().circle?.members.map((member) => member.pubky)).toEqual([B])
  })

  it('says when the admin cannot be reached, and requests nothing else', async () => {
    const board = harness()
    board.net.putCircle([B])
    board.net.lookups.set(A, { kind: 'unreachable', reason: 'lookupFailed' })
    expect(summary(await board.poll())).toEqual([`lookup ${A}`])
    expect(boardStatus(board.state())).toBe('admin-unreachable')
  })
})

describe('pollOnce: caps', () => {
  it(`polls only the first ${MAX_MEMBERS} roster keys, the admin first`, async () => {
    const board = harness()
    const members = Array.from({ length: 40 }, (_, n) => syntheticKey(n + 1))
    board.net.putCircle(members)
    const requests = await board.poll()
    expect(lookups(requests)).toEqual([A, ...members.slice(0, MAX_MEMBERS - 1)])
    expect(listedKeys(requests)).toEqual(new Set([A, ...members.slice(0, MAX_MEMBERS - 1)]))
  })

  it(
    'reads at most 16 new bounties and 32 new sweeps of a key a pass, the rest the pass after',
    async () => {
      const board = harness()
      board.net.putCircle([B])
      const X: BountyRef = { owner: A, id: id(1) }
      for (let n = 0; n < 20; n += 1) board.net.putBounty({ owner: B, id: id(100 + n) }, 'done')
      for (let n = 0; n < 40; n += 1) board.net.putSweep({ sweeper: B, id: id(200 + n) }, X, 'done')
      const first = await board.poll()
      expect(gets(first, B, BOUNTIES_DIR)).toHaveLength(MAX_NEW_BOUNTIES_PER_MEMBER)
      expect(gets(first, B, SWEEPS_DIR)).toHaveLength(MAX_NEW_SWEEPS_PER_MEMBER)
      const second = await board.poll()
      // The 4 bounties left, plus the 8 done ones re-read in rotation.
      expect(gets(second, B, BOUNTIES_DIR)).toHaveLength(4 + MAX_DONE_REREADS_PER_MEMBER)
      expect(gets(second, B, SWEEPS_DIR)).toHaveLength(8)
      expect(board.state().sweeps.size).toBe(40)
    },
  )

  it('re-reads at most 32 records of a key a pass', async () => {
    const board = harness()
    board.net.putCircle([])
    const X: BountyRef = { owner: A, id: id(1) }
    for (let n = 0; n < 40; n += 1) board.net.putSweep({ sweeper: A, id: id(200 + n) }, X)
    await board.poll()
    await board.poll()
    expect(board.state().sweeps.size).toBe(40)
    expect(gets(await board.poll(), A, SWEEPS_DIR)).toHaveLength(MAX_REREADS_PER_MEMBER)
  })

  it('shares the re-reads so no kind starves another', () => {
    expect(rereadShares(20, 20, 10)).toEqual({ open: 12, running: 12, done: 8 })
    expect(rereadShares(40, 2, 0)).toEqual({ open: 30, running: 2, done: 0 })
    expect(rereadShares(2, 40, 1)).toEqual({ open: 2, running: 29, done: 1 })
  })

  it('counts a circle.json that names another admin as the admin alone', async () => {
    const board = harness()
    board.net.putCircle([B], C)
    const requests = await board.poll()
    expect(lookups(requests)).toEqual([A])
    expect(listedKeys(requests)).toEqual(new Set([A]))
  })
})

/** A scheduler whose timers run only when a test says so. */
class FakeScheduler implements Scheduler {
  private readonly timers = new Map<number, { run: () => void; delayMs: number }>()
  private nextHandle = 0

  schedule(run: () => void, delayMs: number): () => void {
    const handle = this.nextHandle++
    this.timers.set(handle, { run, delayMs })
    return () => this.timers.delete(handle)
  }

  /** The delays of the timers waiting. */
  pending(): number[] {
    return [...this.timers.values()].map((timer) => timer.delayMs)
  }

  /** Runs every timer waiting, then lets the passes they start finish. */
  async fire(): Promise<void> {
    const due = [...this.timers.values()]
    this.timers.clear()
    for (const timer of due) timer.run()
    await settle()
  }
}

/**
 * Lets every promise the fake network started resolve: they are all
 * microtasks, and `setImmediate` runs after them.
 */
function settle(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve))
}

function storeOver(net: FakeNetwork, admin: Pubky | null) {
  const scheduler = new FakeScheduler()
  let loads = 0
  const store = createBoardStore({
    admin,
    loadTransport: async () => {
      loads += 1
      return net
    },
    scheduler,
    now: () => T0,
  })
  return { store, scheduler, loads: () => loads }
}

describe('createBoardStore', () => {
  it('sends no request at all with no circle selected', async () => {
    const net = new FakeNetwork()
    const { store, scheduler, loads } = storeOver(net, null)
    const unsubscribe = store.subscribe(() => {})
    await settle()
    expect(net.requests).toEqual([])
    expect(scheduler.pending()).toEqual([])
    expect(loads()).toBe(0)
    unsubscribe()
  })

  it('reads only circle.json and the admin’s two listings for an empty circle', async () => {
    const net = new FakeNetwork()
    net.putCircle([])
    const { store } = storeOver(net, A)
    const unsubscribe = store.subscribe(() => {})
    await settle()
    expect(summary(net.take())).toEqual([
      `lookup ${A}`,
      `get ${A} ${circlePath}`,
      `list ${A} ${BOUNTIES_DIR}`,
      `list ${A} ${SWEEPS_DIR}`,
    ])
    unsubscribe()
  })

  it(
    'polls every 30 s while anyone is subscribed, one poll for all, and stops when all leave',
    async () => {
      const { board, X, BS } = circleOfTwo()
      const { store, scheduler, loads } = storeOver(board.net, A)
      expect(board.net.requests).toEqual([])

      const hero = store.subscribe(() => {})
      const page = store.subscribe(() => {})
      await settle()
      expect(lookups(board.net.take())).toEqual([A, B])
      expect(scheduler.pending()).toEqual([POLL_INTERVAL_MS])

      board.net.putSweep(BS, X, 'done')
      await scheduler.fire()
      expect(store.getState().sweeps.get(sweepKey(BS))?.record.status).toBe('done')
      expect(board.net.take().length).toBeGreaterThan(0)

      hero()
      expect(scheduler.pending()).toEqual([POLL_INTERVAL_MS])
      page()
      expect(scheduler.pending()).toEqual([])
      await settle()
      expect(board.net.requests).toEqual([])
      expect(loads()).toBe(1)
    },
  )

  it('loads the transport again on the next pass when a load fails', async () => {
    const net = new FakeNetwork()
    net.putCircle([])
    const scheduler = new FakeScheduler()
    let loads = 0
    const store = createBoardStore({
      admin: A,
      loadTransport: async () => {
        loads += 1
        if (loads === 1) throw new Error('chunk did not load')
        return net
      },
      scheduler,
      now: () => T0,
    })
    const unsubscribe = store.subscribe(() => {})
    await settle()
    expect(net.requests).toEqual([])
    expect(scheduler.pending()).toEqual([POLL_INTERVAL_MS])
    await scheduler.fire()
    expect(loads).toBe(2)
    expect(lookups(net.take())).toEqual([A])
    unsubscribe()
  })
})
