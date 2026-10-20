// The board's only way onto the network (04, "Live-ness"): read one public
// record, read one page of a directory listing, find an owner's homeserver.
// Nothing here writes, and nothing reads a feed: the board never asks for
// `/events/`, and the types below cannot name a path outside
// `/pub/sweepky/`.
//
// Every answer is a value, never an exception, so a stranger's homeserver
// that is down, slow to resolve or misbehaving changes what the board shows
// and cannot break the poll. A read also has a deadline, so one that never
// answers cannot stall it either: it answers `failed` once the deadline or
// its caller's signal ends it. Bodies come back as bytes, capped, for the
// parsers in `records/parse.ts` to read: the transport decodes nothing.
//
// `sdkTransport.ts` is the implementation over the Pubky SDK; tests give the
// store a fake `Transport` instead.

import type { BOUNTIES_DIR, SweepkyPath, SWEEPS_DIR } from '../records/paths.ts'
import type { Pubky } from '../records/pubky.ts'
import type { PubkyUrl } from '../records/urls.ts'

/**
 * How the browser's HTTP cache may answer a request. `default` lets a fresh
 * cached copy answer without asking the homeserver. `no-cache` always asks,
 * sending the validators the cache holds (`If-None-Match`), so an unchanged
 * record costs a 304 that the browser hands back as the cached 200: the
 * board's conditional re-GET, with no ETag kept by the board itself.
 */
export type CacheMode = 'default' | 'no-cache'

/** The two directories the board lists. */
export type ListedDir = typeof BOUNTIES_DIR | typeof SWEEPS_DIR

export interface RecordOptions {
  readonly cache: CacheMode
  /** Ends the request when aborted: it then answers `failed`. */
  readonly signal?: AbortSignal
}

export interface ListOptions {
  /**
   * The entries asked for, sent as `limit=`: a whole number from 1 to
   * `MAX_PAGE_SIZE` (1000). It also sets the page's byte cap,
   * `maxPageBytes(limit)`.
   */
  readonly limit: number
  /** Newest first, sent as `reverse=true`. */
  readonly reverse: boolean
  /** The last entry of the page before, sent as `cursor=`; none on the first page. */
  readonly cursor?: PubkyUrl
  readonly cache: CacheMode
  /** Ends the request when aborted: it then answers `failed`. */
  readonly signal?: AbortSignal
}

/** A 2xx answer's body, every byte the homeserver sent, within the cap. */
export interface Body {
  readonly kind: 'body'
  readonly body: Uint8Array
}

/** Why a request gave no body. */
export type Failure =
  /** The body is over its cap. The record or page is refused, and the rest of it is never read. */
  | { readonly kind: 'tooLarge' }
  /**
   * The owner's homeserver has no endpoint a browser can reach: no ICANN
   * domain with HTTPS. A key with no pkarr record at all gets this too;
   * `lookupHomeserver` tells the two apart.
   */
  | { readonly kind: 'notBrowserReachable' }
  /**
   * Any other status, or a request that did not complete. The message is
   * fixed text, with at most the HTTP status: never the server's words, a
   * URL or the SDK's own message, since the board may show or log it.
   */
  | { readonly kind: 'failed'; readonly message: string }

/** A record's answer: its body, `absent` for a 404 (there is no such record), or a failure. */
export type RecordAnswer = Body | { readonly kind: 'absent' } | Failure

/** A listing page's answer: its body, `empty` for a 404 (an empty directory), or a failure. */
export type ListingAnswer = Body | { readonly kind: 'empty' } | Failure

/**
 * Where an owner's homeserver is, from their pkarr record. `noRecord` (the
 * key has published none) and `lookupFailed` (the lookup itself failed) are
 * both shown as "unreachable" (04, "Live-ness").
 */
export type HomeserverLookup =
  | { readonly kind: 'found'; readonly homeserver: Pubky }
  | { readonly kind: 'unreachable'; readonly reason: 'noRecord' | 'lookupFailed' }

export interface Transport {
  /** One `GET` of `path` of `owner`'s public storage, read under `MAX_RECORD_BYTES`. */
  getRecord(owner: Pubky, path: SweepkyPath, options: RecordOptions): Promise<RecordAnswer>

  /**
   * One `GET` of a page of `dir` of `owner`'s public storage, read under
   * `maxPageBytes(options.limit)`. Paging is the caller's: it passes the
   * last entry back as the next page's cursor.
   *
   * Rejects with a `RangeError`, before sending anything, when the limit is
   * not one the homeserver honours: a mistake in the caller, never the
   * network's doing.
   */
  list(owner: Pubky, dir: ListedDir, options: ListOptions): Promise<ListingAnswer>

  /** Resolves `owner`'s pkarr record to the key of their homeserver. */
  lookupHomeserver(owner: Pubky): Promise<HomeserverLookup>
}
