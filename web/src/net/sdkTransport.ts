// The `Transport` over the Pubky SDK: every request is a `GET` the board
// sends itself through `pubky.client.fetch`, to the URL `resolvePubky`
// gives, with an init of its own.
//
// Why not the SDK's `publicStorage`: at 0.16.2 its `get` and `list` build
// their requests with `cross_request`, which sends `credentials: 'include'`
// in a browser (pubky-sdk `actors/storage/core.rs` and `list.rs`), so a
// homeserver cookie another app left would ride along. `client.fetch` keeps
// the caller's own credentials, redirect and cache modes instead.
//
// The rules, the same as the CLI's `remote.rs`:
// - `credentials: 'omit'`: no cookie or other credential, ever.
// - `redirect: 'error'`: a redirected answer is refused, never followed, as
//   the CLI's `get_unredirected` refuses one. (A browser's redirect is
//   refused before it is followed, which the CLI cannot do.)
// - Every body is read as bytes under a cap: a `Content-Length` over it is
//   refused before a byte is read, a streamed body at the chunk that crosses
//   it, and either way the rest is cancelled, never read.
// - An error answer's body is never read, and no message quotes a server,
//   a URL or the SDK: the SDK's fetch errors carry the browser's own text,
//   which names the URL.

import { MAX_PAGE_SIZE, MAX_RECORD_BYTES, maxPageBytes } from '../records/limits.ts'
import { formatSweepkyPath } from '../records/paths.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import { formatPubkyUrl } from '../records/urls.ts'
import type { PubkySdk } from './sdk.ts'
import type { Body, CacheMode, Failure, ListOptions, Transport } from './transport.ts'

/** What a request that did not complete is reported as: fixed text. */
export const REQUEST_FAILED = 'the request to the homeserver did not complete'

/** One `GET`'s answer, before a 404 is given its meaning for a record or a listing. */
type Fetched = Body | { readonly kind: 'notFound' } | Failure

/** One anonymous `GET` of a file or directory of `owner`'s public storage. */
interface StorageRequest {
  readonly owner: Pubky
  /** An absolute path under `/pub/sweepky/`: a file, or a directory ending in `/`. */
  readonly path: string
  /** Query parameters, in the order they are sent. */
  readonly query: readonly (readonly [string, string])[]
  readonly cache: CacheMode
  /** The most body bytes read. */
  readonly cap: number
}

const NOT_FOUND = { kind: 'notFound' } as const
const TOO_LARGE = { kind: 'tooLarge' } as const
const NOT_BROWSER_REACHABLE = { kind: 'notBrowserReachable' } as const
const DID_NOT_COMPLETE = { kind: 'failed', message: REQUEST_FAILED } as const
const LOOKUP_FAILED = { kind: 'unreachable', reason: 'lookupFailed' } as const

/** A `Transport` that reaches homeservers through `sdk`. */
export function createSdkTransport(sdk: PubkySdk): Transport {
  return {
    async getRecord(owner, path, { cache }) {
      const fetched = await fetchCapped(sdk, {
        owner,
        path: formatSweepkyPath(path),
        query: [],
        cache,
        cap: MAX_RECORD_BYTES,
      })
      return fetched.kind === 'notFound' ? { kind: 'absent' } : fetched
    },

    async list(owner, dir, options) {
      checkLimit(options.limit)
      const fetched = await fetchCapped(sdk, {
        owner,
        path: dir,
        query: listingQuery(options),
        cache: options.cache,
        cap: maxPageBytes(options.limit),
      })
      return fetched.kind === 'notFound' ? { kind: 'empty' } : fetched
    },

    async lookupHomeserver(owner) {
      try {
        const homeserver = await sdk.getHomeserverOf(owner)
        if (homeserver === undefined) return { kind: 'unreachable', reason: 'noRecord' }
        // The SDK gives a key it parsed itself, so this check never fails
        // in practice; it is what turns the SDK's plain string into a
        // `Pubky`.
        const key = parsePubky(homeserver)
        return key === null ? LOOKUP_FAILED : { kind: 'found', homeserver: key }
      } catch {
        return LOOKUP_FAILED
      }
    },
  }
}

/**
 * Throws a `RangeError` for a page size the homeserver does not honour:
 * below 1, not whole, or over `MAX_PAGE_SIZE`, which it would quietly cut to
 * 1000 and so make a full page read as the last one.
 */
function checkLimit(limit: number): void {
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) {
    throw new RangeError(`a listing's limit is a whole number from 1 to ${MAX_PAGE_SIZE}`)
  }
}

/**
 * A listing's query, in the order and spelling the CLI's `page_url` sends
 * it: `limit=<n>`, then `reverse=true` for newest first, then
 * `cursor=<the last entry's pubky:// URL>`.
 */
function listingQuery({ limit, reverse, cursor }: ListOptions): [string, string][] {
  const query: [string, string][] = [['limit', String(limit)]]
  if (reverse) query.push(['reverse', 'true'])
  if (cursor !== undefined) query.push(['cursor', formatPubkyUrl(cursor)])
  return query
}

/**
 * Sends one `StorageRequest` and reads its body under its cap. A 404 is
 * `notFound`; what that means is the caller's to say.
 *
 * The query goes in through `URLSearchParams`, which percent-encodes every
 * name and value, so a cursor holding `&`, `=`, `#` or `?` stays one value
 * and cannot add a parameter, as `append_pair` keeps it in the CLI.
 */
async function fetchCapped(
  sdk: PubkySdk,
  { owner, path, query, cache, cap }: StorageRequest,
): Promise<Fetched> {
  let response: Response
  try {
    // The `pubky<key>/<path>` form, which `resolvePubky` prefers. It gives
    // an `https://_pubky.<key>/...` URL: `client.fetch` refuses `pubky://`.
    // Building the URL is inside the `try` too: `resolvePubky` throws for a
    // key that is well formed but not a valid Ed25519 point.
    const url = new URL(sdk.resolvePubky(`pubky${owner}${path}`))
    for (const [name, value] of query) url.searchParams.append(name, value)
    // A new init for every request: `client.fetch` adds its `pubky-host`
    // header to the init object it is given.
    response = await sdk.fetch(url.href, {
      method: 'GET',
      credentials: 'omit',
      redirect: 'error',
      cache,
    })
  } catch (error) {
    return isNoHttpsEndpoints(error) ? NOT_BROWSER_REACHABLE : DID_NOT_COMPLETE
  }
  if (response.status === 404) {
    discardBody(response)
    return NOT_FOUND
  }
  if (!response.ok) {
    discardBody(response)
    // The status is a number the browser checked, not the server's text.
    return { kind: 'failed', message: `the homeserver answered HTTP ${response.status}` }
  }
  return readCapped(response, cap)
}

/**
 * Whether `error` is the SDK saying the owner's homeserver has no endpoint a
 * browser can use: the `PkarrError` "No HTTPS endpoints found in PKARR
 * record" that `client.fetch` throws when no endpoint in the record has a
 * domain (pubky-sdk 0.16.2, `client/http_targets/wasm.rs`). The SDK gives
 * no code for it, so its message is matched, never shown.
 */
function isNoHttpsEndpoints(error: unknown): boolean {
  return (
    error instanceof Error &&
    error.name === 'PkarrError' &&
    error.message.includes('No HTTPS endpoints')
  )
}

/**
 * `response`'s whole body, at most `cap` bytes: `tooLarge` when its
 * `Content-Length` is over the cap, before anything is read, or at the first
 * chunk that would take it past, without asking for another.
 */
async function readCapped(response: Response, cap: number): Promise<Body | Failure> {
  const declared = declaredLength(response)
  if (declared !== null && declared > cap) {
    discardBody(response)
    return TOO_LARGE
  }
  if (response.body === null) return { kind: 'body', body: new Uint8Array(0) }

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > cap) {
        // The chunk that crosses the cap is dropped, not copied in.
        ignoreRejection(reader.cancel())
        return TOO_LARGE
      }
      chunks.push(value)
    }
  } catch {
    return DID_NOT_COMPLETE
  }
  return { kind: 'body', body: concat(chunks, length) }
}

/**
 * The `Content-Length` the answer declared, or `null` when it gave none or
 * one that is not plain digits (the streamed count still holds the cap).
 * A browser decompresses a body as it streams it, so the header can be
 * smaller than what is read, never a reason to skip the count.
 */
function declaredLength(response: Response): number | null {
  const header = response.headers.get('content-length')
  return header !== null && /^\d+$/.test(header) ? Number(header) : null
}

/** Stops the browser downloading a body nobody will read. */
function discardBody(response: Response): void {
  if (response.body !== null) ignoreRejection(response.body.cancel())
}

/**
 * Lets `promise` fail quietly. Cancelling a body can fail once the stream has
 * broken, and there is nothing left to do about it then.
 */
function ignoreRejection(promise: Promise<unknown>): void {
  promise.catch(() => {})
}

/** `chunks` copied into one array of `length` bytes, their total. */
function concat(chunks: readonly Uint8Array[], length: number): Uint8Array {
  const body = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }
  return body
}
