// The caps the board applies to what it reads, under the names they have in
// the Rust code and from the same sources, so the board refuses what the CLI
// refuses (04, "Live-ness": the same rules as the CLI). Records and listings
// come from strangers' homeservers: a cap stops one of them from handing the
// board an endless document, line or list.
//
// Every byte count is UTF-8 bytes, the unit Rust's `len()` counts, never
// JavaScript's `length`, which counts UTF-16 code units: an accented letter
// such as U+00E9 is one code unit but two bytes.

/**
 * The most bytes a record under `/pub/sweepky/` may have: 1 MiB.
 * `MAX_RECORD_BYTES` in sweepky-core's `schema.rs`.
 */
export const MAX_RECORD_BYTES = 1024 * 1024

/**
 * The longest path a `pubky://` URL may have, in bytes, the leading `/`
 * included: 1024. `PubkyUrl::MAX_PATH_LEN` in sweepky-core's `url.rs`.
 */
export const MAX_PATH_LEN = 1024

/**
 * The longest status, in bytes, a bounty or sweep may have and still be kept:
 * 32. `MAX_STATUS_BYTES` in sweepky-cli's `pull/roster.rs`, which skips a
 * longer one. Every status Sweepky writes is a short word.
 */
export const MAX_STATUS_BYTES = 32

/**
 * The most credits a bounty may list and still be kept: 128. `MAX_CREDITS` in
 * sweepky-cli's `pull/roster.rs` (`Polled for Bounty`).
 */
export const MAX_CREDITS = 128

/**
 * The most targets a sweep record may name and still be kept: 32.
 * `MAX_TARGETS` in sweepky-cli's `post/draft.rs`, which `pull/roster.rs`
 * applies to sweeps (`Polled for Sweep`), not to bounties.
 */
export const MAX_TARGETS = 32

/**
 * The longest listing line, in bytes, before its `\n` or `\r\n`: 4096.
 * `MAX_LISTING_LINE_BYTES` in sweepky-cli's `remote.rs`. A Sweepky entry is
 * under 250 bytes even in the longer `https://` form.
 */
export const MAX_LISTING_LINE_BYTES = 4096

/**
 * The most entries a homeserver sends on one listing page, whatever `limit=`
 * asks for: 1000. `MAX_PAGE_SIZE` in sweepky-cli's `remote.rs`. Asking for
 * more would read as a short last page and cut the listing off.
 */
export const MAX_PAGE_SIZE = 1000

/**
 * The most bytes one listing page of `pageSize` entries may have: a full line
 * plus `\r\n` for each entry, so blank lines cannot stretch a page.
 * `ListLimits::max_page_bytes` in sweepky-cli's `remote.rs`.
 */
export function maxPageBytes(pageSize: number): number {
  return pageSize * (MAX_LISTING_LINE_BYTES + 2)
}

const encoder = new TextEncoder()

/** The length of `text` in UTF-8 bytes, the unit every cap above counts. */
export function utf8Length(text: string): number {
  return encoder.encode(text).length
}
