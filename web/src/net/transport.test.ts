import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { parseRecordId, type RecordId } from '../records/ids.ts'
import { MAX_RECORD_BYTES, maxPageBytes } from '../records/limits.ts'
import { BOUNTIES_DIR, SWEEPS_DIR, type SweepkyPath } from '../records/paths.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import { formatPubkyUrl, type PubkyUrl } from '../records/urls.ts'
import type { PubkySdk } from './sdk.ts'
import { createSdkTransport, REQUEST_FAILED, REQUEST_TIMEOUT_MS } from './sdkTransport.ts'
import type { CacheMode, Transport } from './transport.ts'

/** A, the roster's admin in fixtures/trust-labels.json, as the owner read from. */
const OWNER = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
/** The local testnet homeserver's key (pubky-testnet 0.16.2). */
const HOMESERVER = pubky('8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo')
/** A record id from fixtures/trust-labels.json. */
const ID = recordId('0035G87EK4XFE')

const BOUNTY: SweepkyPath = { kind: 'bounty', id: ID }
/** Where every request for OWNER's Sweepky files goes: the SDK's transport form. */
const STORAGE = `https://_pubky.${OWNER}/storage/${OWNER}/pub/sweepky/`

/** Text a homeserver or the SDK might send, which no failure may repeat. */
const SERVER_TEXT = 'server-words-<script>'
const SDK_TEXT = `TypeError: Failed to fetch ${STORAGE}`

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`test key ${text} is not a key`)
  return key
}

function recordId(text: string): RecordId {
  const id = parseRecordId(text)
  if (id === null) throw new Error(`test id ${text} is not an id`)
  return id
}

interface FetchCall {
  readonly url: string
  readonly init: RequestInit
}

/**
 * What the fake's `fetch` answers: a response, an error it throws, or a
 * promise of a response, for one that never settles.
 */
type Answer = Response | Error | Promise<Response>

/** A fake SDK that records each call and answers every fetch with `answer()`. */
interface FakeSdk extends PubkySdk {
  readonly fetches: FetchCall[]
  readonly lookups: string[]
}

function fakeSdk(
  answer: () => Answer = () => new Response(''),
  homeserverOf: () => Promise<string | undefined> = async () => HOMESERVER,
): FakeSdk {
  const fetches: FetchCall[] = []
  const lookups: string[] = []
  return {
    fetches,
    lookups,
    async fetch(url, init) {
      fetches.push({ url, init })
      const result = answer()
      if (result instanceof Error) throw result
      return result
    },
    resolvePubky,
    async getHomeserverOf(user) {
      lookups.push(user)
      return homeserverOf()
    },
  }
}

/**
 * The SDK's own `resolvePubky` for the two forms it takes, `pubky<z32>/...`
 * and `pubky://<z32>/...`, written as pubky-sdk 0.16.2's
 * `PubkyResource::to_transport_url` writes them.
 */
function resolvePubky(identifier: string): string {
  const match = /^(?:pubky:\/\/|pubky)([a-z0-9]{52})(\/.*)$/.exec(identifier)
  if (match === null) throw new Error('not a pubky identifier')
  const [, owner, path] = match
  return `https://_pubky.${owner}/storage/${owner}${path}`
}

/** A PkarrError as the SDK throws it: a JS `Error` whose `name` is the error's kind. */
function pubkyError(name: string, message: string): Error {
  return Object.assign(new Error(message), { name })
}

/**
 * A body that counts how often it is read from and whether it was
 * cancelled. `highWaterMark: 0` keeps the stream from reading ahead, so
 * `pulls` counts only the chunks the transport asked for.
 */
function countedBody(chunks: readonly Uint8Array[]) {
  const seen = { pulls: 0, cancelled: false }
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        const chunk = chunks[seen.pulls]
        seen.pulls += 1
        if (chunk === undefined) controller.close()
        else controller.enqueue(chunk)
      },
      cancel() {
        seen.cancelled = true
      },
    },
    { highWaterMark: 0 },
  )
  return { stream, seen }
}

function bytes(length: number, fill = 0x61): Uint8Array<ArrayBuffer> {
  return new Uint8Array(length).fill(fill)
}

/** Each kind of request the board sends, run against `transport`. */
const REQUESTS: readonly [string, CacheMode, (transport: Transport, cache: CacheMode) => unknown][] =
  [
    ['a record', 'default', (t, cache) => t.getRecord(OWNER, BOUNTY, { cache })],
    ['a record re-GET', 'no-cache', (t, cache) => t.getRecord(OWNER, BOUNTY, { cache })],
    [
      'a first listing page',
      'no-cache',
      (t, cache) => t.list(OWNER, SWEEPS_DIR, { limit: 100, reverse: true, cache }),
    ],
    [
      'a later listing page',
      'default',
      (t, cache) =>
        t.list(OWNER, BOUNTIES_DIR, {
          limit: 100,
          reverse: true,
          cursor: { user: OWNER, path: `/pub/sweepky/bounties/${ID}.json` },
          cache,
        }),
    ],
  ]

describe('every request', () => {
  // Done when: every request sent without credentials and nothing written;
  // the board never requests `/events/`.
  it.each(REQUESTS)(
    '%s is one GET without credentials or redirects, under /pub/sweepky/ in the transport form',
    async (_what, cache, send) => {
      const sdk = fakeSdk()
      await send(createSdkTransport(sdk), cache)

      expect(sdk.fetches).toHaveLength(1)
      const [{ url, init }] = sdk.fetches as [FetchCall]
      // `toEqual` with the whole init: a method, a body or a header of our
      // own would show up here.
      expect(init).toEqual({
        method: 'GET',
        credentials: 'omit',
        redirect: 'error',
        cache,
        signal: expect.any(AbortSignal),
      })
      expect(url.startsWith(STORAGE)).toBe(true)
      expect(url).not.toContain('pubky://')
      expect(new URL(url).pathname).not.toContain('/events')
    },
  )

  it("asks for a record at its path's transport URL", async () => {
    const sdk = fakeSdk()
    await createSdkTransport(sdk).getRecord(OWNER, BOUNTY, { cache: 'default' })
    expect(sdk.fetches[0]?.url).toBe(`${STORAGE}bounties/${ID}.json`)
  })
})

describe('listing requests', () => {
  it('asks for the directory, with the limit and reverse=true, and no cursor on the first page', async () => {
    const sdk = fakeSdk()
    await createSdkTransport(sdk).list(OWNER, SWEEPS_DIR, {
      limit: 100,
      reverse: true,
      cache: 'no-cache',
    })
    expect(sdk.fetches[0]?.url).toBe(`${STORAGE}sweeps/?limit=100&reverse=true`)
  })

  it('leaves reverse out for an oldest-first listing', async () => {
    const sdk = fakeSdk()
    await createSdkTransport(sdk).list(OWNER, SWEEPS_DIR, {
      limit: 7,
      reverse: false,
      cache: 'no-cache',
    })
    expect(sdk.fetches[0]?.url).toBe(`${STORAGE}sweeps/?limit=7`)
  })

  it("adds the cursor entry's pubky:// URL after the first page", async () => {
    const sdk = fakeSdk()
    const cursor: PubkyUrl = { user: OWNER, path: `/pub/sweepky/sweeps/${ID}.json` }
    await createSdkTransport(sdk).list(OWNER, SWEEPS_DIR, {
      limit: 100,
      reverse: true,
      cursor,
      cache: 'no-cache',
    })
    const url = new URL(sdk.fetches[0]?.url ?? '')
    expect(`${url.origin}${url.pathname}`).toBe(`${STORAGE}sweeps/`)
    expect([...url.searchParams]).toEqual([
      ['limit', '100'],
      ['reverse', 'true'],
      ['cursor', `pubky://${OWNER}/pub/sweepky/sweeps/${ID}.json`],
    ])
  })

  // As remote.rs's page_url does with append_pair: a stranger's entry is the
  // cursor, so its text must not be able to change the query.
  it('percent-encodes a cursor holding &, =, # or ?, so it cannot add a parameter', async () => {
    const sdk = fakeSdk()
    const cursor: PubkyUrl = { user: OWNER, path: '/pub/sweepky/sweeps/a&limit=1000#x?reverse=false' }
    await createSdkTransport(sdk).list(OWNER, SWEEPS_DIR, {
      limit: 100,
      reverse: true,
      cursor,
      cache: 'no-cache',
    })
    const sent = sdk.fetches[0]?.url ?? ''
    expect(sent).not.toMatch(/[#]/)
    const url = new URL(sent)
    expect([...url.searchParams.keys()]).toEqual(['limit', 'reverse', 'cursor'])
    expect(url.searchParams.get('limit')).toBe('100')
    expect(url.searchParams.get('reverse')).toBe('true')
    expect(url.searchParams.get('cursor')).toBe(formatPubkyUrl(cursor))
  })

  // A homeserver sends at most 1000 entries whatever `limit=` says, which
  // would read as a short last page (limits.ts, MAX_PAGE_SIZE).
  it.each([0, 1001, 2.5, Number.NaN])('refuses a limit of %s before sending anything', async (limit) => {
    const sdk = fakeSdk()
    const transport = createSdkTransport(sdk)
    await expect(
      transport.list(OWNER, SWEEPS_DIR, { limit, reverse: true, cache: 'no-cache' }),
    ).rejects.toThrow(RangeError)
    expect(sdk.fetches).toHaveLength(0)
  })
})

describe('bodies', () => {
  const getRecord = (sdk: PubkySdk) =>
    createSdkTransport(sdk).getRecord(OWNER, BOUNTY, { cache: 'default' })
  const listPage = (sdk: PubkySdk, limit = 2) =>
    createSdkTransport(sdk).list(OWNER, SWEEPS_DIR, { limit, reverse: true, cache: 'no-cache' })

  it('returns the bytes as sent, never decoded text', async () => {
    // 0xff is never valid UTF-8, so a decode would have replaced it.
    const sent = new Uint8Array([0x7b, 0xff, 0xc3, 0x7d])
    const answer = await getRecord(fakeSdk(() => new Response(sent)))
    expect(answer).toEqual({ kind: 'body', body: sent })
    expect(answer.kind === 'body' && answer.body).toBeInstanceOf(Uint8Array)
  })

  it.each([200, 203])('reads a %i as a body', async (status) => {
    const answer = await getRecord(fakeSdk(() => new Response('{}', { status })))
    expect(answer).toEqual({ kind: 'body', body: new TextEncoder().encode('{}') })
  })

  it('takes a record of exactly 1 MiB, in chunks', async () => {
    const half = bytes(MAX_RECORD_BYTES / 2)
    const { stream } = countedBody([half, half])
    const answer = await getRecord(fakeSdk(() => new Response(stream)))
    expect(answer.kind === 'body' && answer.body.byteLength).toBe(MAX_RECORD_BYTES)
  })

  it('refuses a Content-Length over 1 MiB without reading the body', async () => {
    const { stream, seen } = countedBody([bytes(10)])
    const tooLong = String(MAX_RECORD_BYTES + 1)
    const answer = await getRecord(
      fakeSdk(() => new Response(stream, { headers: { 'content-length': tooLong } })),
    )
    expect(answer).toEqual({ kind: 'tooLarge' })
    expect(seen).toEqual({ pulls: 0, cancelled: true })
  })

  it('refuses a streamed record at the chunk that crosses 1 MiB, and reads no further', async () => {
    const { stream, seen } = countedBody([bytes(MAX_RECORD_BYTES), bytes(1), bytes(10)])
    const answer = await getRecord(fakeSdk(() => new Response(stream)))
    expect(answer).toEqual({ kind: 'tooLarge' })
    expect(seen).toEqual({ pulls: 2, cancelled: true })
  })

  it('caps a listing page at limit x 4098 bytes', async () => {
    const cap = maxPageBytes(2)
    expect(cap).toBe(2 * 4098)
    const full = await listPage(fakeSdk(() => new Response(bytes(cap))))
    expect(full.kind === 'body' && full.body.byteLength).toBe(cap)

    const { stream, seen } = countedBody([bytes(cap), bytes(1)])
    expect(await listPage(fakeSdk(() => new Response(stream)))).toEqual({ kind: 'tooLarge' })
    expect(seen.cancelled).toBe(true)

    const declared = { 'content-length': String(cap + 1) }
    const overLength = await listPage(fakeSdk(() => new Response(bytes(1), { headers: declared })))
    expect(overLength).toEqual({ kind: 'tooLarge' })
  })

  it.each([
    ['a record', getRecord, 'absent'],
    ['a listing', listPage, 'empty'],
  ] as const)('reads a 404 for %s as %s, without reading its body', async (_what, send, kind) => {
    const { stream, seen } = countedBody([new TextEncoder().encode(SERVER_TEXT)])
    expect(await send(fakeSdk(() => new Response(stream, { status: 404 })))).toEqual({ kind })
    expect(seen.pulls).toBe(0)
  })

  it.each([301, 304, 400, 403, 410, 429, 500, 503])(
    'reads a %i as a failure naming the status alone, with its body unread',
    async (status) => {
      const { stream, seen } = countedBody([new TextEncoder().encode(SERVER_TEXT)])
      // A 304 may not carry a body, so it gets none.
      const body = status === 304 ? null : stream
      const answer = await getRecord(fakeSdk(() => new Response(body, { status })))
      expect(answer).toEqual({ kind: 'failed', message: `the homeserver answered HTTP ${status}` })
      expect(seen.pulls).toBe(0)
    },
  )

  const brokenBody = () =>
    new Response(
      new ReadableStream({
        pull(controller) {
          controller.error(new Error(SDK_TEXT))
        },
      }),
    )

  it.each([
    ['fetch throws', () => pubkyError('RequestError', SDK_TEXT)],
    ['the body fails part way', brokenBody],
  ])('reads a request where %s as a failure with fixed text', async (_what, answer) => {
    expect(await getRecord(fakeSdk(answer))).toEqual({ kind: 'failed', message: REQUEST_FAILED })
  })
})

describe('resolution', () => {
  // The message pubky-sdk 0.16.2 throws from `client.fetch` when the
  // homeserver has no endpoint with a domain (`client/http_targets/wasm.rs`),
  // URL and all.
  const NO_HTTPS = pubkyError(
    'PkarrError',
    `Pkarr operation failed: Pkarr record is malformed or missing required data: No HTTPS endpoints found in PKARR record for \`_pubky.${OWNER}\` (original URL: ${STORAGE})`,
  )

  it("reads the SDK's \"No HTTPS endpoints\" as not browser-reachable, for records and listings", async () => {
    const sdk = fakeSdk(() => NO_HTTPS)
    const transport = createSdkTransport(sdk)
    expect(await transport.getRecord(OWNER, BOUNTY, { cache: 'default' })).toEqual({
      kind: 'notBrowserReachable',
    })
    expect(
      await transport.list(OWNER, SWEEPS_DIR, { limit: 100, reverse: true, cache: 'no-cache' }),
    ).toEqual({ kind: 'notBrowserReachable' })
  })

  it.each([
    ['another PkarrError', pubkyError('PkarrError', 'Failed to resolve the DHT record: timeout')],
    ['the same words under another name', pubkyError('RequestError', 'No HTTPS endpoints')],
  ])('reads %s as a plain failure', async (_what, error) => {
    const answer = await createSdkTransport(fakeSdk(() => error)).getRecord(OWNER, BOUNTY, {
      cache: 'default',
    })
    expect(answer).toEqual({ kind: 'failed', message: REQUEST_FAILED })
  })

  it("finds the owner's homeserver", async () => {
    const sdk = fakeSdk()
    expect(await createSdkTransport(sdk).lookupHomeserver(OWNER)).toEqual({
      kind: 'found',
      homeserver: HOMESERVER,
    })
    expect(sdk.lookups).toEqual([OWNER])
  })

  const unreachable: readonly [string, () => Promise<string | undefined>, string][] = [
    ['getHomeserverOf gives undefined', async () => undefined, 'noRecord'],
    [
      'getHomeserverOf throws',
      async () => {
        throw pubkyError('PkarrError', SDK_TEXT)
      },
      'lookupFailed',
    ],
    ['getHomeserverOf gives something that is not a key', async () => SERVER_TEXT, 'lookupFailed'],
  ]

  it.each(unreachable)('shows the owner as unreachable when %s', async (_what, homeserverOf, reason) => {
    const sdk = fakeSdk(undefined, homeserverOf)
    expect(await createSdkTransport(sdk).lookupHomeserver(OWNER)).toEqual({
      kind: 'unreachable',
      reason,
    })
  })
})

describe('deadlines', () => {
  // Only the timers the deadline uses: the streams' own scheduling stays real.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  const FAILED = { kind: 'failed', message: REQUEST_FAILED }
  const never = () => new Promise<Response>(() => {})

  /** A body that sends one byte a second, for ever: far below any cap. */
  function tricklingBody() {
    const seen = { cancelled: false }
    const stream = new ReadableStream<Uint8Array>(
      {
        pull: (controller) =>
          new Promise<void>((resolve) => {
            setTimeout(() => {
              if (!seen.cancelled) controller.enqueue(bytes(1))
              resolve()
            }, 1000)
          }),
        cancel() {
          seen.cancelled = true
        },
      },
      { highWaterMark: 0 },
    )
    return { stream, seen }
  }

  it.each(REQUESTS)('fails %s whose answer never comes, at the deadline', async (_what, cache, send) => {
    const sent = send(createSdkTransport(fakeSdk(never)), cache) as Promise<unknown>
    let settled = false
    void sent.then(() => (settled = true))
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS - 1)
    expect(settled).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    expect(await sent).toEqual(FAILED)
  })

  it('cuts a body that trickles in below the cap at the deadline, and cancels the rest', async () => {
    const { stream, seen } = tricklingBody()
    const sent = createSdkTransport(fakeSdk(() => new Response(stream))).getRecord(OWNER, BOUNTY, {
      cache: 'no-cache',
    })
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS)
    expect(await sent).toEqual(FAILED)
    expect(seen.cancelled).toBe(true)
  })

  it.each(REQUESTS)('fails %s at once when its signal is aborted', async (_what, cache) => {
    const controller = new AbortController()
    const sdk = fakeSdk(never)
    const transport = createSdkTransport(sdk)
    const sent =
      cache === 'default'
        ? transport.getRecord(OWNER, BOUNTY, { cache, signal: controller.signal })
        : transport.list(OWNER, SWEEPS_DIR, {
            limit: 100,
            reverse: true,
            cache,
            signal: controller.signal,
          })
    controller.abort()
    // No timer moves: the abort alone settles it, and reaches the fetch.
    expect(await sent).toEqual(FAILED)
    expect(sdk.fetches[0]?.init.signal?.aborted).toBe(true)
  })

  it('fails a body being read at once when its signal is aborted', async () => {
    const controller = new AbortController()
    const { stream, seen } = tricklingBody()
    const sent = createSdkTransport(fakeSdk(() => new Response(stream))).getRecord(OWNER, BOUNTY, {
      cache: 'no-cache',
      signal: controller.signal,
    })
    await vi.advanceTimersByTimeAsync(2500)
    controller.abort()
    expect(await sent).toEqual(FAILED)
    expect(seen.cancelled).toBe(true)
  })

  it('leaves an answer within the deadline as it is, and no timer behind', async () => {
    const sdk = fakeSdk(() => new Response('{}'))
    const answer = await createSdkTransport(sdk).getRecord(OWNER, BOUNTY, { cache: 'no-cache' })
    expect(answer).toEqual({ kind: 'body', body: new TextEncoder().encode('{}') })
    expect(sdk.fetches[0]?.init.signal?.aborted).toBe(false)
    expect(vi.getTimerCount()).toBe(0)
  })
})
