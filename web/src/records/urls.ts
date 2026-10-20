// `pubky://` URLs, ported from sweepky-core's `url.rs`, and the lines of a
// homeserver's directory listing, after sweepky-cli's `remote.rs`.
//
// A `pubky://` URL names a file by its owner's key and its path, as in
// `pubky://<z32>/pub/sweepky/bounties/<id>.json`. The host is a key in either
// spelling, raw or `pubky<z32>`; it is kept raw, so two spellings of one URL
// parse to equal values.
//
// These URLs come from records and listings that strangers' homeservers
// serve, so a malformed one is `null`, never an exception.

import type { RecordId } from './ids.ts'
import { MAX_PATH_LEN, utf8Length } from './limits.ts'
import { parseSweepkyPath } from './paths.ts'
import { parsePubky, type Pubky } from './pubky.ts'

/** A file of any app: its owner's key and its path, which starts with `/`. */
export interface PubkyUrl {
  readonly user: Pubky
  readonly path: string
}

/** A bounty record, `pubky://<owner>/pub/sweepky/bounties/<id>.json`. */
export interface BountyRef {
  readonly owner: Pubky
  readonly id: RecordId
}

/** A sweep record, `pubky://<sweeper>/pub/sweepky/sweeps/<id>.json`. */
export interface SweepRef {
  readonly sweeper: Pubky
  readonly id: RecordId
}

/** The one scheme a record's URL may have, in lower case only. */
const SCHEME = 'pubky://'

/** The start of a listing line in the SDK's transport form. */
const TRANSPORT_SCHEME_AND_HOST = 'https://_pubky.'

/** What follows the transport form's host. */
const STORAGE_DIR = '/storage/'

/**
 * What a path may not hold: `?` and `#` (a query or a fragment), Unicode
 * whitespace, a control character (C0, DEL and C1, so NUL, a newline and the
 * escape that starts a terminal sequence), and the bidirectional controls
 * that make printed text read as something else ("Trojan Source"): U+061C,
 * U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069. The same list as
 * core's `check_path`; any other path, `..` and `%` included, is another
 * app's business and kept as written. The `u` flag is what makes `\p{...}`
 * (a Unicode property) work.
 */
const FORBIDDEN_IN_PATH = /[?#\p{White_Space}\p{Cc}\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u

/**
 * The `pubky://` URL `text` is, or `null`. The host must be a key in either
 * spelling and the path must pass `isAcceptablePath`.
 */
export function parsePubkyUrl(text: string): PubkyUrl | null {
  if (!text.startsWith(SCHEME)) return null
  const parts = splitAtFirstSlash(text.slice(SCHEME.length))
  if (parts === null) return null
  const user = parsePubky(parts.head)
  return user !== null && isAcceptablePath(parts.path) ? { user, path: parts.path } : null
}

/**
 * One line of a directory listing, already split off and trimmed, as the URL
 * it names, or `null`.
 *
 * A 0.16.2 homeserver writes `pubky://<owner>/<path>` lines. The SDK also
 * reads the transport form, `https://_pubky.<owner>/storage/<owner>/<path>`,
 * so this does too, with both owners raw z-base32 (as the SDK requires) and
 * the same key. The path rules are `parsePubkyUrl`'s in both forms.
 *
 * Stricter than the CLI's listing parser, which goes through the SDK: the SDK
 * percent-encodes a space, a `?` or a control character in a `pubky://` line
 * and percent-decodes a transport path, so the CLI skips such an entry as not
 * one of Sweepky's files where this refuses the line. Sweepky's own entries
 * never hold such characters, so for an honest homeserver the two agree.
 */
export function parseListingLine(line: string): PubkyUrl | null {
  return line.startsWith(SCHEME) ? parsePubkyUrl(line) : parseTransportUrl(line)
}

/** `url` written back as `pubky://<raw z32><path>`. */
export function formatPubkyUrl(url: PubkyUrl): string {
  return `${SCHEME}${url.user}${url.path}`
}

/** The bounty record `text` points at, or `null` for any other URL. */
export function parseBountyRef(text: string): BountyRef | null {
  const url = parsePubkyUrl(text)
  if (url === null) return null
  const path = parseSweepkyPath(url.path)
  return path?.kind === 'bounty' ? { owner: url.user, id: path.id } : null
}

/**
 * The sweep record `text` points at, or `null` for any other URL, the
 * sweep's own `.age` package included.
 */
export function parseSweepRef(text: string): SweepRef | null {
  const url = parsePubkyUrl(text)
  if (url === null) return null
  const path = parseSweepkyPath(url.path)
  return path?.kind === 'sweepRecord' ? { sweeper: url.user, id: path.id } : null
}

/** A transport-form listing line, `https://_pubky.<owner>/storage/<owner>/<path>`. */
function parseTransportUrl(text: string): PubkyUrl | null {
  if (!text.startsWith(TRANSPORT_SCHEME_AND_HOST)) return null
  const host = splitAtFirstSlash(text.slice(TRANSPORT_SCHEME_AND_HOST.length))
  if (host === null || !host.path.startsWith(STORAGE_DIR)) return null
  const storage = splitAtFirstSlash(host.path.slice(STORAGE_DIR.length))
  if (storage === null) return null
  // `parsePubky` gives back its input unchanged only when that input was
  // already the raw form, so this refuses a `pubky`-prefixed owner. Keys are
  // canonical, so comparing the two strings compares the two keys.
  const owner = parsePubky(host.head)
  if (owner === null || owner !== host.head || storage.head !== owner) return null
  return isAcceptablePath(storage.path) ? { user: owner, path: storage.path } : null
}

/**
 * `text` split before its first `/`: what comes before, and the rest, which
 * starts with that `/`. `null` when there is no `/`.
 */
function splitAtFirstSlash(text: string): { head: string; path: string } | null {
  const slash = text.indexOf('/')
  return slash === -1 ? null : { head: text.slice(0, slash), path: text.slice(slash) }
}

/** Whether `path` is at most `MAX_PATH_LEN` bytes and has nothing `FORBIDDEN_IN_PATH`. */
function isAcceptablePath(path: string): boolean {
  return utf8Length(path) <= MAX_PATH_LEN && !FORBIDDEN_IN_PATH.test(path)
}
