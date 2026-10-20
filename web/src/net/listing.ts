// The board's directory listing (04, "Live-ness"): one directory of one
// owner, newest first, page by page, stopping at the newest record already
// seen there. A port of sweepky-cli's `remote.rs` (`ListingParser::page`,
// `read_listing` and `ListOrder::NewestFirst`), so the board reads a listing
// the way the CLI's `pull` does and refuses what it refuses.
//
// A listing page is plain text from someone else's homeserver, one entry per
// line. The rules, and why:
//
// - **Bounded by line, by page and in total** (`ListLimits`). A homeserver
//   could send an endless page, an endless line or endless pages; each cap
//   stops it, and the page cap counts blank lines too, so padding cannot
//   stretch a page.
// - **A protocol break refuses the listing whole**: a line over
//   MAX_LISTING_LINE_BYTES, one that is not UTF-8 (never decoded lossily),
//   one that is not a resource URL, more entries than were asked for. The
//   rest of a page is still checked after the stop, so a stop on the first
//   line does not let the page break the protocol unseen.
// - **Entries are checked, not trusted.** One of another owner, one outside
//   the directory and one that is not a Sweepky file are skipped and
//   counted, never fatal. The count is kept, never the names, which are the
//   homeserver's text.
// - **Refusals are fixed text** (`REFUSAL_TEXT`), never a line of the page.
//
// Where the board's reading differs from the CLI's: lines go through
// `parseListingLine` (records/urls.ts) rather than the SDK, so a line with a
// space, `?` or control character is refused where the SDK percent-encodes it
// and the CLI skips the entry, and a `pubky://pubky<z32>/` line is read
// where the SDK refuses the prefix. A path with a `.`, `..` or empty segment
// is refused, as the SDK refuses one in a `pubky://` line (the form 0.16.2
// homeservers write), where the CLI's URL parser resolves `.` and `..` in an
// `https://` line instead. Sweepky's own entries never hold any of these.

import type { RecordId } from '../records/ids.ts'
import { MAX_LISTING_LINE_BYTES, maxPageBytes } from '../records/limits.ts'
import { parseSweepkyPath, type SweepkyPath } from '../records/paths.ts'
import type { Pubky } from '../records/pubky.ts'
import { parseListingLine, type PubkyUrl } from '../records/urls.ts'
import type { Failure, ListedDir, Transport } from './transport.ts'

/** How much of a directory `listDirNewestFirst` reads: `ListLimits` in remote.rs. */
export interface ListLimits {
  /**
   * Entries asked for per page, sent as `limit=`: a whole number from 1 to
   * MAX_PAGE_SIZE, which the transport checks. A page with fewer entries is
   * the last; one with more breaks the protocol.
   */
  readonly pageSize: number
  /** The most entries read across all pages; one more refuses the listing. */
  readonly maxEntries: number
  /** The most pages read; one more refuses the listing. */
  readonly maxPages: number
}

/**
 * The CLI's `ListLimits::DEFAULT`: 100 entries a page, at most 1000 entries
 * in 11 pages. Ten full pages take 1000 entries, and the eleventh is the
 * empty page that says the listing is over.
 */
export const DEFAULT_LIST_LIMITS: ListLimits = { pageSize: 100, maxEntries: 1000, maxPages: 11 }

/** What a listing found in a directory. */
export interface Listing {
  /** The Sweepky files newer than the newest record seen, in the homeserver's order. */
  readonly entries: readonly SweepkyPath[]
  /** How many entries were skipped: another owner's, outside the directory, not a Sweepky file. */
  readonly skipped: number
}

/** Why a listing was refused: remote.rs's `ListingError`, variant for variant. */
export type ListingRefusal =
  | 'pageTooLarge'
  | 'lineTooLong'
  | 'notUtf8'
  | 'notAResource'
  | 'pageOverLimit'
  | 'tooManyEntries'
  | 'tooManyPages'
  | 'noCursor'

/**
 * What each refusal says, in the CLI's words. A `Record` over the union, so a
 * refusal added later does not compile until it has a message.
 */
export const REFUSAL_TEXT: Readonly<Record<ListingRefusal, string>> = {
  pageTooLarge: 'a page of the listing is over its byte limit',
  lineTooLong: `a line of the listing is over ${MAX_LISTING_LINE_BYTES} bytes`,
  notUtf8: 'a line of the listing is not UTF-8',
  notAResource: 'a line of the listing is not a pubky:// or https:// URL',
  pageOverLimit: 'a page of the listing has more entries than were asked for',
  tooManyEntries: 'the listing has more entries than Sweepky reads',
  tooManyPages: 'the listing runs to more pages than Sweepky reads',
  noCursor: 'a full page of the listing names no entry to continue from',
}

/**
 * A listing's outcome: what it found, why it was refused, or the transport's
 * own failure (unreachable, or a request that failed). A transport's
 * `tooLarge` is a page over its byte cap, so it comes back as `pageTooLarge`.
 */
export type ListingResult =
  | { readonly kind: 'listed'; readonly listing: Listing }
  | { readonly kind: 'refused'; readonly reason: ListingRefusal; readonly message: string }
  | Exclude<Failure, { readonly kind: 'tooLarge' }>

/**
 * Lists `dir` of `owner`'s public storage newest first (`reverse=true`), page
 * by page through `transport`, within `limits`.
 *
 * The listing stops at the first Sweepky file whose record id is at or below
 * `newestSeen`, the newest id already seen in this directory: neither it nor
 * anything after it is kept, and no further page is asked for. Every file
 * named by a record id counts (`<id>.json`, `<id>.discovered.json`,
 * `<id>.age`), as in the CLI. `null` lists the whole directory.
 *
 * Paging also stops at a page shorter than the limit, an empty page or a
 * 404; a 404 on the first page is an empty directory. Any failure on any page
 * fails the whole listing: nothing read before it is returned.
 *
 * Every page is asked for with `signal`, so aborting it fails the listing.
 *
 * Rejects with the transport's `RangeError` only when `limits.pageSize` is
 * not one the homeserver honours, a mistake in the caller.
 */
export async function listDirNewestFirst(
  transport: Transport,
  owner: Pubky,
  dir: ListedDir,
  newestSeen: RecordId | null,
  limits: ListLimits = DEFAULT_LIST_LIMITS,
  signal?: AbortSignal,
): Promise<ListingResult> {
  const parser = new ListingParser(owner, dir, newestSeen, limits)
  let cursor: PubkyUrl | undefined
  try {
    for (;;) {
      const answer = await transport.list(owner, dir, {
        limit: limits.pageSize,
        reverse: true,
        cursor,
        // A poll wants the directory as it is now, so the browser asks the
        // homeserver every time rather than answering from its cache.
        cache: 'no-cache',
        signal,
      })
      if (answer.kind === 'empty') break
      if (answer.kind === 'tooLarge') return refused('pageTooLarge')
      if (answer.kind !== 'body') return answer
      const next = parser.page(answer.body)
      if (next === null) break
      cursor = next
    }
  } catch (error) {
    if (error instanceof Refusal) return refused(error.reason)
    throw error
  }
  return { kind: 'listed', listing: parser.finish() }
}

function refused(reason: ListingRefusal): ListingResult {
  return { kind: 'refused', reason, message: REFUSAL_TEXT[reason] }
}

/**
 * A rule a page broke, thrown inside this module only and caught by
 * `listDirNewestFirst`, which returns it as a value: the `?` on a
 * `ListingError` in remote.rs.
 */
class Refusal extends Error {
  readonly reason: ListingRefusal

  constructor(reason: ListingRefusal) {
    super(REFUSAL_TEXT[reason])
    this.name = 'Refusal'
    this.reason = reason
  }
}

/** The byte that ends a line. In UTF-8 it only ever means newline, so splitting first is safe. */
const LF = 0x0a
/** The byte one of which is dropped from a line's end: a `\r\n` line ending. */
const CR = 0x0d

/**
 * Strict UTF-8: `fatal` throws on any invalid sequence rather than putting
 * U+FFFD in its place. `ignoreBOM: true` (despite its name) keeps a leading
 * byte-order mark in the text instead of dropping it, as Rust's
 * `str::from_utf8` keeps it, so a line that starts with one is refused as
 * the CLI refuses it.
 */
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

/** One character with the Unicode White_Space property, the set Rust's `str::trim` takes. */
const WHITE_SPACE = /^\p{White_Space}$/u

/**
 * Reads the pages of one directory's listing into a `Listing`, one `page` at
 * a time. Pure: `listDirNewestFirst` does the network. The counts run across
 * pages, so one parser serves one listing.
 */
class ListingParser {
  private readonly owner: Pubky
  private readonly dir: ListedDir
  private readonly newestSeen: RecordId | null
  private readonly limits: ListLimits
  private readonly entries: SweepkyPath[] = []
  private skipped = 0
  private entriesRead = 0
  private pagesRead = 0

  constructor(owner: Pubky, dir: ListedDir, newestSeen: RecordId | null, limits: ListLimits) {
    this.owner = owner
    this.dir = dir
    this.newestSeen = newestSeen
    this.limits = limits
  }

  /**
   * Reads one page and gives the entry to ask for the next page after (its
   * cursor), or `null` when this page was the last: one with fewer entries
   * than the limit, or one that reached the stop. Throws a `Refusal` when
   * the page breaks a rule.
   *
   * The checks run in remote.rs's order: the page count, the page's bytes,
   * then for each line its bytes and UTF-8, the counts on the page and in
   * all, and its form as a URL; and only for a line before the stop, whether
   * it is inside the directory, then what Sweepky file it is.
   */
  page(body: Uint8Array): PubkyUrl | null {
    this.pagesRead += 1
    if (this.pagesRead > this.limits.maxPages) throw new Refusal('tooManyPages')
    if (body.byteLength > maxPageBytes(this.limits.pageSize)) throw new Refusal('pageTooLarge')

    let onPage = 0
    let last: PubkyUrl | null = null
    let stopped = false
    for (const rawLine of splitLines(body)) {
      const line = decodeLine(rawLine)
      if (line === null) continue
      onPage += 1
      this.entriesRead += 1
      if (onPage > this.limits.pageSize) throw new Refusal('pageOverLimit')
      if (this.entriesRead > this.limits.maxEntries) throw new Refusal('tooManyEntries')
      const entry = parseEntry(line)
      // Past the stop, each line is still checked above, and nothing more is kept.
      if (stopped) continue
      if (!this.isInside(entry)) {
        this.skipped += 1
        continue
      }
      const path = parseSweepkyPath(entry.path)
      if (path === null) this.skipped += 1
      else if (this.stopsAt(path)) stopped = true
      else this.entries.push(path)
      // The cursor is the last entry inside the directory, Sweepky file or not.
      last = entry
    }

    if (stopped || onPage < this.limits.pageSize) return null
    // A full page: the next one starts after its last entry, so a full page
    // without one cannot go on.
    if (last === null) throw new Refusal('noCursor')
    return last
  }

  /** Everything read so far. */
  finish(): Listing {
    return { entries: this.entries, skipped: this.skipped }
  }

  /**
   * Whether `entry` is this owner's and strictly inside the directory. A
   * `Pubky` has one spelling per key, so `===` compares the keys themselves
   * (records/pubky.ts). `parseEntry` has refused `.`, `..` and empty
   * segments, so a plain prefix test on the path is sound.
   */
  private isInside(entry: PubkyUrl): boolean {
    return (
      entry.user === this.owner &&
      entry.path.startsWith(this.dir) &&
      entry.path.length > this.dir.length
    )
  }

  /** Whether the listing stops at `path`: a file of a record at or below the newest id seen. */
  private stopsAt(path: SweepkyPath): boolean {
    const id = recordIdOf(path)
    // Ids compare as strings in timestamp order (records/ids.ts).
    return this.newestSeen !== null && id !== null && id <= this.newestSeen
  }
}

/**
 * `body` split at every `\n` byte, as Rust's `split` does: an empty body is
 * one empty line, and a body ending in `\n` ends with one. `subarray` is a
 * view of `body`, so nothing is copied.
 */
function* splitLines(body: Uint8Array): Generator<Uint8Array> {
  let start = 0
  for (;;) {
    const newline = body.indexOf(LF, start)
    if (newline === -1) {
      yield body.subarray(start)
      return
    }
    yield body.subarray(start, newline)
    start = newline + 1
  }
}

/**
 * One line, split off at `\n`, as its trimmed text, or `null` when it is
 * blank. One `\r` at its end is dropped first. Its length is counted in
 * bytes before it is decoded, never as a string's `length`, which counts
 * UTF-16 units: U+3000 is one unit but three bytes.
 */
function decodeLine(rawLine: Uint8Array): string | null {
  const line = rawLine.at(-1) === CR ? rawLine.subarray(0, -1) : rawLine
  if (line.byteLength > MAX_LISTING_LINE_BYTES) throw new Refusal('lineTooLong')
  let text: string
  try {
    text = STRICT_UTF8.decode(line)
  } catch {
    throw new Refusal('notUtf8')
  }
  const trimmed = trimWhiteSpace(text)
  return trimmed === '' ? null : trimmed
}

/**
 * `text` without White_Space at either end, as Rust's `str::trim`.
 *
 * Not `String.prototype.trim`, which differs from Rust on two characters: it
 * strips U+FEFF, which is not White_Space, and keeps U+0085, which is. And
 * not a regex over the whole line: `\s+$` backtracks on a long run of white
 * space in the middle of a line, which a homeserver chooses. Every
 * White_Space character is a single UTF-16 unit, so testing one unit at a
 * time is exact.
 */
function trimWhiteSpace(text: string): string {
  let start = 0
  let end = text.length
  while (start < end && WHITE_SPACE.test(text.charAt(start))) start += 1
  while (end > start && WHITE_SPACE.test(text.charAt(end - 1))) end -= 1
  return text.slice(start, end)
}

/** One listing line as the URL it names. Throws `notAResource` for anything else. */
function parseEntry(line: string): PubkyUrl {
  const entry = parseListingLine(line)
  if (entry === null || !isResourcePath(entry.path)) throw new Refusal('notAResource')
  return entry
}

/**
 * Whether `path` (which starts with `/`) has no `.` or `..` segment and no
 * empty one but a trailing `/`'s: the SDK's `ResourcePath` refuses those
 * (pubky 0.16.2, `actors/storage/resource.rs`), and so the CLI refuses a
 * `pubky://` line holding one.
 */
function isResourcePath(path: string): boolean {
  const segments = path.slice(1).split('/')
  return segments.every((segment, index) =>
    segment === '' ? index === segments.length - 1 : segment !== '.' && segment !== '..',
  )
}

/** The record id in `path`'s name, if it has one. */
function recordIdOf(path: SweepkyPath): RecordId | null {
  // No `default`: a new kind of path does not compile until someone decides
  // whether its name carries an id.
  switch (path.kind) {
    case 'bounty':
    case 'discovered':
    case 'sweepRecord':
    case 'sweepPackage':
      return path.id
    case 'circle':
    case 'key':
      return null
  }
}
