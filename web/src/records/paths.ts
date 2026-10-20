// The paths of Sweepky's files under `/pub/sweepky/`, ported from
// sweepky-core's `paths.rs`:
//
// | Path                                         | Kind           |
// |----------------------------------------------|----------------|
// | `/pub/sweepky/circle.json`                   | `circle`       |
// | `/pub/sweepky/keys/<deviceId>.json`          | `key`          |
// | `/pub/sweepky/bounties/<id>.json`            | `bounty`       |
// | `/pub/sweepky/bounties/<id>.discovered.json` | `discovered`   |
// | `/pub/sweepky/sweeps/<id>.json`              | `sweepRecord`  |
// | `/pub/sweepky/sweeps/<id>.age`               | `sweepPackage` |
//
// `parseSweepkyPath` reads paths that listings from strangers' homeservers
// carry, so it is strict: the exact directory, the exact extension and a
// valid id, with no extra segment, `..`, `//` or trailing `/`. A path it
// accepts is always exactly the one `formatSweepkyPath` writes back.

import { parseRecordId, type RecordId } from './ids.ts'

/** The directory of bounty records and their discovered-sweeps files, for listing. */
export const BOUNTIES_DIR = '/pub/sweepky/bounties/'
/** The directory of sweep records and sweep packages, for listing. */
export const SWEEPS_DIR = '/pub/sweepky/sweeps/'
/** The directory of device keys. */
export const KEYS_DIR = '/pub/sweepky/keys/'
/** The roster's path. */
export const CIRCLE_PATH = '/pub/sweepky/circle.json'

/** One of Sweepky's files, classified by its path. */
export type SweepkyPath =
  | { readonly kind: 'circle' }
  | { readonly kind: 'key'; readonly deviceId: string }
  | { readonly kind: 'bounty'; readonly id: RecordId }
  | { readonly kind: 'discovered'; readonly id: RecordId }
  | { readonly kind: 'sweepRecord'; readonly id: RecordId }
  | { readonly kind: 'sweepPackage'; readonly id: RecordId }

const JSON_EXT = '.json'
const DISCOVERED_EXT = '.discovered.json'
const AGE_EXT = '.age'

/**
 * A device id, the `<deviceId>` in `keys/<deviceId>.json`: 1 to 64
 * characters of `A-Z`, `a-z`, `0-9`, `-` and `_`, the first a letter or digit
 * (`DeviceId` in sweepky-core's `names.rs`).
 */
const DEVICE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/

/** What `path` names, or `null` when it is not exactly one of Sweepky's files. */
export function parseSweepkyPath(path: string): SweepkyPath | null {
  if (path === CIRCLE_PATH) return { kind: 'circle' }
  const bountiesFile = fileIn(BOUNTIES_DIR, path)
  if (bountiesFile !== null) return parseBountiesFile(bountiesFile)
  const sweepsFile = fileIn(SWEEPS_DIR, path)
  if (sweepsFile !== null) return parseSweepsFile(sweepsFile)
  const keysFile = fileIn(KEYS_DIR, path)
  if (keysFile !== null) return parseKeysFile(keysFile)
  return null
}

/** The path `path` names, exactly as `parseSweepkyPath` reads it back. */
export function formatSweepkyPath(path: SweepkyPath): string {
  switch (path.kind) {
    case 'circle':
      return CIRCLE_PATH
    case 'key':
      return `${KEYS_DIR}${path.deviceId}${JSON_EXT}`
    case 'bounty':
      return `${BOUNTIES_DIR}${path.id}${JSON_EXT}`
    case 'discovered':
      return `${BOUNTIES_DIR}${path.id}${DISCOVERED_EXT}`
    case 'sweepRecord':
      return `${SWEEPS_DIR}${path.id}${JSON_EXT}`
    case 'sweepPackage':
      return `${SWEEPS_DIR}${path.id}${AGE_EXT}`
  }
}

/**
 * The file name in `path` when `path` is a single file directly inside `dir`,
 * else `null`. One test, no further `/`, refuses an extra segment, a `..`
 * that climbs into a sibling directory, a `//` and a trailing `/`, since each
 * puts a `/` after the directory's own.
 */
function fileIn(dir: string, path: string): string | null {
  if (!path.startsWith(dir)) return null
  const name = path.slice(dir.length)
  return name.includes('/') ? null : name
}

/** What `name`, a file directly in `bounties/`, names. */
function parseBountiesFile(name: string): SweepkyPath | null {
  // `.discovered.json` first: it ends in `.json` too.
  const discovered = idBefore(DISCOVERED_EXT, name)
  if (discovered !== null) return { kind: 'discovered', id: discovered }
  const bounty = idBefore(JSON_EXT, name)
  return bounty === null ? null : { kind: 'bounty', id: bounty }
}

/** What `name`, a file directly in `sweeps/`, names. */
function parseSweepsFile(name: string): SweepkyPath | null {
  const record = idBefore(JSON_EXT, name)
  if (record !== null) return { kind: 'sweepRecord', id: record }
  const pkg = idBefore(AGE_EXT, name)
  return pkg === null ? null : { kind: 'sweepPackage', id: pkg }
}

/** What `name`, a file directly in `keys/`, names. */
function parseKeysFile(name: string): SweepkyPath | null {
  const deviceId = name.endsWith(JSON_EXT) ? name.slice(0, -JSON_EXT.length) : ''
  return DEVICE_ID.test(deviceId) ? { kind: 'key', deviceId } : null
}

/** The record id before `ext` at the end of `name`, or `null`. */
function idBefore(ext: string, name: string): RecordId | null {
  return name.endsWith(ext) ? parseRecordId(name.slice(0, -ext.length)) : null
}
