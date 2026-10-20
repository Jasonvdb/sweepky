// The record parsers the board reads with: circle, bounty, sweep and
// discovered-sweeps records, ported from sweepky-core's `schema.rs` and
// `records/`, plus the caps sweepky-cli's `pull/roster.rs` puts on what it
// keeps (limits.ts).
//
// Every parser takes the bytes a homeserver sent and goes through the same
// steps as core's `parse_record`: refuse a body over MAX_RECORD_BYTES before
// looking at it, decode it as strict UTF-8, parse the JSON, refuse a
// `schemaVersion` newer than 1 before reading anything else (a v2 record may
// have renamed v1 fields, and "too new" is the honest error), then check each
// field. A record that fails any step is refused whole, as core refuses it.
//
// What is kept verbatim, as core keeps it:
// - Open strings (`status`, `focus`, a target's `kind`) stay plain strings,
//   never closed unions, so a value a newer client writes is shown as a
//   placeholder instead of failing the poll. `asKnown...` says whether this
//   build knows a value.
// - Free text (`title`, `brief`, a circle's `name`, the `label`s, the
//   suggested playbook) holds whatever its writer put there, controls and
//   bidi characters included. Display safety is the views' job.
// - Time fields are opaque strings; `recordTimeMs` reads the one form
//   Sweepky writes.
//
// Fields this build does not know are ignored: the board never rewrites a
// record, so there is nothing to keep them for.
//
// What core refuses and this does not see, because `JSON.parse` hides it or
// the field is one this does not check: a key repeated in one object (the
// last one wins), nesting deeper than serde_json's 128 levels, an escaped
// lone surrogate (`"\ud800"`) in an unchecked field, and a `schemaVersion`
// written as `1.0`. Each makes a record the CLI skips and the board shows;
// none changes what a well-formed record says.

import { recordIdMicros, type RecordId } from './ids.ts'
import {
  MAX_CREDITS,
  MAX_RECORD_BYTES,
  MAX_STATUS_BYTES,
  MAX_TARGETS,
  utf8Length,
} from './limits.ts'
import { parsePubky, type Pubky } from './pubky.ts'
import { parseBountyRef, parseSweepRef, type BountyRef, type SweepRef } from './urls.ts'

/** `circle.json`: the roster an admin keeps, the default trust and discovery set. */
export interface Circle {
  readonly name: string
  readonly admin: Pubky
  readonly members: readonly CircleMember[]
}

export interface CircleMember {
  readonly pubky: Pubky
  readonly label: string | null
}

/** `bounties/<id>.json`: a bounty post (01, "The bounty post"). */
export interface Bounty {
  readonly title: string
  readonly focus: string
  readonly brief: string
  readonly playbook: BountyPlaybook
  /** Each with an id of its own. */
  readonly targets: readonly Target[]
  readonly open: boolean
  readonly status: string
  /** As written: may name the owner or one sweeper twice. The trust badge skips those. */
  readonly credits: readonly Pubky[]
  readonly createdAt: string
  readonly doneAt: string | null
}

export interface BountyPlaybook {
  readonly suggested: string | null
  readonly required: boolean
}

/**
 * One of a bounty's `targets`. Only `id` and `kind` are checked, as core
 * reads a bounty: `fields` holds the rest exactly as written, unchecked, so a
 * target of a kind this build does not know still parses.
 */
export interface Target {
  readonly id: string
  readonly kind: string
  readonly fields: ReadonlyMap<string, unknown>
}

/** `sweeps/<id>.json`: one sweep, on the sweeper's own homeserver. */
export interface Sweep {
  readonly bounty: BountyRef
  readonly targets: readonly string[]
  readonly playbook: string
  readonly status: string
  readonly startedAt: string
  readonly finishedAt: string | null
  readonly sha256: string | null
}

/** `bounties/<id>.discovered.json`: the strangers' sweeps an open bounty's owner accepted. */
export interface Discovered {
  readonly sweeps: readonly SweepRef[]
  /** Each watched homeserver's feed position, a decimal event id. The board does not need them. */
  readonly cursors: ReadonlyMap<Pubky, string>
}

/**
 * Which step refused a record. `invalid` is a field that breaks one of core's
 * rules or goes past one of the CLI's poll caps.
 */
export type RecordErrorKind = 'tooLarge' | 'notUtf8' | 'notJson' | 'unsupportedVersion' | 'invalid'

/**
 * Why a record was refused. The message is fixed text naming the field,
 * never the record's own text: records are written by strangers, and an
 * error that quoted one would put their words into the console.
 */
export class RecordError extends Error {
  readonly kind: RecordErrorKind
  /** The field that failed, or `record` for the body as a whole. */
  readonly field: string

  constructor(kind: RecordErrorKind, field: string, reason: string) {
    super(`${field} ${reason}`)
    this.name = 'RecordError'
    this.kind = kind
    this.field = field
  }
}

/** A parser's answer: the record, or why it was refused. */
export type Parsed<T> =
  | { readonly ok: true; readonly record: T }
  | { readonly ok: false; readonly error: RecordError }

// The values of each open string this build knows, as core's `Known...`
// enums list them. A record may hold any other string.

const BOUNTY_STATUSES = ['open', 'done'] as const
export type KnownBountyStatus = (typeof BOUNTY_STATUSES)[number]

const SWEEP_STATUSES = ['running', 'done', 'aborted'] as const
export type KnownSweepStatus = (typeof SWEEP_STATUSES)[number]

const TARGET_KINDS = ['pr', 'commit', 'repo'] as const
export type KnownTargetKind = (typeof TARGET_KINDS)[number]

/** `status` when this build knows it, else `null` (show a placeholder). */
export function asKnownBountyStatus(status: string): KnownBountyStatus | null {
  return asKnown(status, BOUNTY_STATUSES)
}

/** `status` when this build knows it, else `null` (show a placeholder). */
export function asKnownSweepStatus(status: string): KnownSweepStatus | null {
  return asKnown(status, SWEEP_STATUSES)
}

/** `kind` when this build knows it, else `null` (skip the target, show a placeholder). */
export function asKnownTargetKind(kind: string): KnownTargetKind | null {
  return asKnown(kind, TARGET_KINDS)
}

export function parseCircle(bytes: Uint8Array): Parsed<Circle> {
  return parseRecord(bytes, readCircle)
}

/**
 * Also refuses a bounty the CLI's poll would skip: a status over
 * MAX_STATUS_BYTES or more than MAX_CREDITS credits. Its targets have no cap
 * here, as in the CLI.
 */
export function parseBounty(bytes: Uint8Array): Parsed<Bounty> {
  return parseRecord(bytes, (json) => {
    const bounty = readBounty(json)
    checkStatusCap(bounty.status)
    if (bounty.credits.length > MAX_CREDITS) {
      throw invalid('credits', `lists more than the ${MAX_CREDITS} credits the CLI keeps`)
    }
    return bounty
  })
}

/**
 * Also refuses a sweep the CLI's poll would skip: a status over
 * MAX_STATUS_BYTES or more than MAX_TARGETS targets.
 */
export function parseSweep(bytes: Uint8Array): Parsed<Sweep> {
  return parseRecord(bytes, (json) => {
    const sweep = readSweep(json)
    checkStatusCap(sweep.status)
    if (sweep.targets.length > MAX_TARGETS) {
      throw invalid('targets', `names more than the ${MAX_TARGETS} targets one run sweeps`)
    }
    return sweep
  })
}

export function parseDiscovered(bytes: Uint8Array): Parsed<Discovered> {
  return parseRecord(bytes, readDiscovered)
}

/** RFC 3339 in UTC to the second, the one form Sweepky writes (P2a). */
const SWEEPKY_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/

/**
 * `time` as milliseconds since 1970 when it is in the form Sweepky writes,
 * such as `2026-10-16T09:41:07Z`; otherwise the time `id` encodes. Any other
 * form is a stranger's choice with no agreed meaning, so it is not guessed
 * at. Pass the record's own id: a record is written when its id is made.
 */
export function recordTimeMs(time: string, id: RecordId): number {
  if (SWEEPKY_TIME.test(time)) {
    // `Date.parse` rolls an impossible date over (February 30 becomes March
    // 2) instead of refusing it, so only a time that prints back as itself
    // is taken.
    const ms = Date.parse(time)
    if (!Number.isNaN(ms) && new Date(ms).toISOString() === time.replace('Z', '.000Z')) return ms
  }
  return Number(recordIdMicros(id) / 1000n)
}

// What follows reads one record. Each reader throws a RecordError, and
// `parseRecord` turns the first one into the parser's answer, so a reader
// can check a field where it reads it and stay a straight line of code.

/** The newest `schemaVersion` this build reads. */
const SCHEMA_VERSION = 1

/**
 * Strict UTF-8. `fatal` refuses a byte sequence that is not UTF-8 instead of
 * replacing it with U+FFFD, as serde_json refuses it. `ignoreBOM` keeps a
 * leading byte-order mark in the text, where `JSON.parse` refuses it as
 * serde_json does, instead of dropping it silently.
 */
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

type JsonObject = { readonly [key: string]: unknown }

function parseRecord<T>(bytes: Uint8Array, read: (json: JsonObject) => T): Parsed<T> {
  try {
    const json = decodeJsonObject(bytes)
    checkSchemaVersion(json)
    return { ok: true, record: read(json) }
  } catch (error) {
    // Only a refusal is an answer. Anything else is a bug here, and is
    // rethrown rather than passed off as a bad record.
    if (error instanceof RecordError) return { ok: false, error }
    throw error
  }
}

/** The body as a JSON object, read within the size cap and as strict UTF-8. */
function decodeJsonObject(bytes: Uint8Array): JsonObject {
  if (bytes.byteLength > MAX_RECORD_BYTES) {
    throw new RecordError('tooLarge', 'record', `is over the ${MAX_RECORD_BYTES}-byte limit`)
  }
  let text: string
  try {
    text = utf8.decode(bytes)
  } catch {
    throw new RecordError('notUtf8', 'record', 'is not UTF-8')
  }
  let json: unknown
  try {
    json = JSON.parse(text)
  } catch {
    throw new RecordError('notJson', 'record', 'is not JSON')
  }
  return objectOf(json, 'record')
}

function checkSchemaVersion(json: JsonObject): void {
  const version = json.schemaVersion
  if (typeof version !== 'number' || !Number.isInteger(version) || version < 0) {
    throw invalid('schemaVersion', 'is not a whole number of 0 or more')
  }
  // 01: reject only a major version above the one supported. The version
  // is one number, so the whole number is the major.
  if (version > SCHEMA_VERSION) {
    const reason = `is newer than the ${SCHEMA_VERSION} this build reads`
    throw new RecordError('unsupportedVersion', 'schemaVersion', reason)
  }
}

function readCircle(json: JsonObject): Circle {
  return {
    name: stringOf(json.name, 'name'),
    admin: pubkyOf(json.admin, 'admin'),
    members: arrayOf(json.members, 'members').map((value) => {
      const member = objectOf(value, 'members')
      return {
        pubky: pubkyOf(member.pubky, 'members'),
        label: optional(member.label, 'label', stringOf),
      }
    }),
  }
}

function readBounty(json: JsonObject): Bounty {
  const playbook = objectOf(json.playbook, 'playbook')
  // Core reads a missing `open` as false and missing `credits` as empty, but
  // a `null` in either as malformed.
  const open = json.open === undefined ? false : booleanOf(json.open, 'open')
  const credits = json.credits === undefined ? [] : arrayOf(json.credits, 'credits')
  return {
    title: stringOf(json.title, 'title'),
    focus: stringOf(json.focus, 'focus'),
    brief: stringOf(json.brief, 'brief'),
    playbook: {
      suggested: optional(playbook.suggested, 'playbook', stringOf),
      required: booleanOf(playbook.required, 'playbook'),
    },
    targets: uniqueTargets(arrayOf(json.targets, 'targets').map(readTarget)),
    open,
    status: stringOf(json.status, 'status'),
    credits: credits.map((credit) => pubkyOf(credit, 'credits')),
    createdAt: timeOf(json.createdAt, 'createdAt'),
    doneAt: optional(json.doneAt, 'doneAt', timeOf),
  }
}

/**
 * A target id: 1 to 32 characters of `A-Z`, `a-z`, `0-9`, `-` and `_`, the
 * first a letter or digit (`TargetId` in core's `names.rs`).
 */
const TARGET_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/

function readTarget(value: unknown): Target {
  // Rest destructuring copies every other own key into `fields`, as plain
  // data: a stranger's `__proto__` key becomes an ordinary entry.
  const { id, kind, ...fields } = objectOf(value, 'targets')
  return {
    id: matching(TARGET_ID, id, 'targets'),
    kind: stringOf(kind, 'targets'),
    fields: new Map(Object.entries(fields)),
  }
}

/**
 * `targets`, refused when two share an id (core's `unique_targets`): a sweep
 * names its targets by id. Compared case-sensitively, as core compares them.
 */
function uniqueTargets(targets: Target[]): Target[] {
  if (new Set(targets.map((target) => target.id)).size !== targets.length) {
    throw invalid('targets', 'has two targets that share an id')
  }
  return targets
}

/** 01's playbook pattern for a sweep record. */
const PLAYBOOK = /^[A-Za-z0-9._/-]{1,64}(@[0-9a-f]{7,40})?$/

/** A SHA-256 digest in lower-case hex. */
const SHA256_HEX = /^[0-9a-f]{64}$/

function readSweep(json: JsonObject): Sweep {
  const bounty = typeof json.bounty === 'string' ? parseBountyRef(json.bounty) : null
  if (bounty === null) throw invalid('bounty', "is not a bounty record's URL")
  return {
    bounty,
    targets: arrayOf(json.targets, 'targets').map((id) => matching(TARGET_ID, id, 'targets')),
    playbook: matching(PLAYBOOK, json.playbook, 'playbook'),
    status: stringOf(json.status, 'status'),
    startedAt: timeOf(json.startedAt, 'startedAt'),
    finishedAt: optional(json.finishedAt, 'finishedAt', timeOf),
    sha256: optional(json.sha256, 'sha256', (value, field) => matching(SHA256_HEX, value, field)),
  }
}

/** An event id: canonical decimal, no sign and no leading zero, at most 20 digits. */
const EVENT_CURSOR = /^(0|[1-9][0-9]{0,19})$/

const U64_MAX = (1n << 64n) - 1n

function readDiscovered(json: JsonObject): Discovered {
  const sweeps = arrayOf(json.sweeps, 'sweeps').map((value) => {
    const sweep = typeof value === 'string' ? parseSweepRef(value) : null
    if (sweep === null) throw invalid('sweeps', "has an entry that is not a sweep record's URL")
    return sweep
  })
  // Keyed by the raw key, so if one homeserver is listed in both spellings
  // the later entry wins, as in core.
  const cursors = new Map<Pubky, string>()
  for (const [key, value] of Object.entries(objectOf(json.cursors, 'cursors'))) {
    const cursor = matching(EVENT_CURSOR, value, 'cursors')
    if (BigInt(cursor) > U64_MAX) throw invalid('cursors', 'has an event id over 2^64 - 1')
    cursors.set(pubkyOf(key, 'cursors'), cursor)
  }
  return { sweeps, cursors }
}

function checkStatusCap(status: string): void {
  if (utf8Length(status) > MAX_STATUS_BYTES) {
    throw invalid('status', `is longer than the ${MAX_STATUS_BYTES} bytes the CLI keeps`)
  }
}

// The field readers. Each takes a value from the parsed JSON and the name of
// the field it came from, which a refusal names.

function invalid(field: string, reason: string): RecordError {
  return new RecordError('invalid', field, reason)
}

function objectOf(value: unknown, field: string): JsonObject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid(field, 'is not a JSON object')
  }
  return value as JsonObject
}

function arrayOf(value: unknown, field: string): readonly unknown[] {
  if (!Array.isArray(value)) throw invalid(field, 'is not a JSON array')
  return value
}

function booleanOf(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') throw invalid(field, 'is not true or false')
  return value
}

/**
 * A string. A JSON escape can spell half of a UTF-16 surrogate pair
 * (`"\ud800"`), which is not text at all; core's strings are always valid
 * Unicode and serde_json refuses one, so this does too.
 */
function stringOf(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.isWellFormed()) throw invalid(field, 'is not a string')
  return value
}

function pubkyOf(value: unknown, field: string): Pubky {
  const pubky = typeof value === 'string' ? parsePubky(value) : null
  if (pubky === null) throw invalid(field, 'is not a pubky')
  return pubky
}

/**
 * A time field: 1 to 64 printable ASCII characters, `!` to `~`, so no
 * whitespace or control character (`RecordTime` in core's `time.rs`).
 */
const RECORD_TIME = /^[!-~]{1,64}$/

function timeOf(value: unknown, field: string): string {
  return matching(RECORD_TIME, value, field)
}

/** A string that `pattern` matches whole. */
function matching(pattern: RegExp, value: unknown, field: string): string {
  if (typeof value !== 'string' || !pattern.test(value)) throw invalid(field, 'is malformed')
  return value
}

/** `null` for a missing or `null` value, as serde reads an `Option`; else `read`'s answer. */
function optional<T>(
  value: unknown,
  field: string,
  read: (value: unknown, field: string) => T,
): T | null {
  return value === undefined || value === null ? null : read(value, field)
}

function asKnown<T extends string>(value: string, known: readonly T[]): T | null {
  return known.find((name) => name === value) ?? null
}
