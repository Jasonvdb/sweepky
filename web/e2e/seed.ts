// A synthetic circle on the local testnet for testnet.spec.ts: three new
// keys signed up on the testnet homeserver, and the records 01 describes
// written to their own storage as the CLI would write them.
//
// The seed stands in for the CLI's writes: circle.json for `circle`, the
// bounty and its discovered.json for `post --open`, the sweep records for
// `run` and `submit`, the discovered.json that lists a stranger's sweep for
// `pull`, and the bounty rewritten done for `done`. P5 repeats the check
// with the real CLI. Every record goes through the board's own parser before
// it is written, so a seed that drifted from 01's shapes fails here, not as
// a board that silently shows nothing.
//
// Only the local testnet: `Pubky.testnet(TESTNET_HOST)` takes its pkarr
// relay and homeserver from that one host, the auth relay is built from the
// same host, and the host is a constant, so no setting can point the seed at
// a production relay.
//
// Each key signs up through a grant flow asking for `/pub/sweepky/:rw`, the
// scope sweepky-cli itself asks for (03, "Two ways to log in"), and its own
// Signer approves the request in-process. `Signer.signup` plus `signin` would
// ask for root (`/:rw`) instead, which homeservers may refuse: they can allow
// grants under `/pub/` only. A homeserver too old for grant auth (no
// `/auth/grant/signup` route, or no HTTP relay on the testnet's port) fails the
// flow; the seed then falls back to the legacy cookie signup with a new key and
// says so on the console. Either way every write stays under `/pub/sweepky/`.

import { AuthFlowKind, Keypair, Pubky, PublicKey, type Session } from '@synonymdev/pubky'
import { recordIdFromMicros, type RecordId } from '../src/records/ids.ts'
import {
  parseBounty,
  parseCircle,
  parseDiscovered,
  parseSweep,
  type Parsed,
} from '../src/records/parse.ts'
import { formatSweepkyPath, type SweepkyPath } from '../src/records/paths.ts'
import { parsePubky, type Pubky as PubkyKey } from '../src/records/pubky.ts'
import { formatPubkyUrl, type BountyRef, type SweepRef } from '../src/records/urls.ts'

/** The only host the seed talks to. */
const TESTNET_HOST = 'localhost'

/** The static testnet's homeserver (06, "Testnet"); `SWEEPKY_E2E_HOMESERVER` overrides it. */
const DEFAULT_TESTNET_HOMESERVER = '8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo'

/** The app name the seed's grants are issued to. */
const CLIENT_ID = 'sweepky-e2e'

/** The scope each grant asks for: sweepky-cli's own (03, "Two ways to log in"). */
const SWEEPKY_CAPABILITIES = '/pub/sweepky/:rw'

/** The static testnet's HTTP relay, which carries the grant approval (06, "Testnet"). */
const TESTNET_AUTH_RELAY = `http://${TESTNET_HOST}:15412/inbox`

/** A synthetic target: nothing in the board or this seed ever fetches it. */
const SYNTHETIC_TARGET = {
  id: 't1',
  kind: 'repo',
  repo: 'github.com/sweepky-e2e/synthetic-target',
  rev: '0123456789abcdef0123456789abcdef01234567',
  paths: ['src/'],
} as const

/** A key signed up on the testnet, with a session that writes to its own storage. */
export interface Writer {
  readonly pubky: PubkyKey
  /** Writes `record` at `path` after the board's parser accepts it. */
  put(path: SweepkyPath, record: SeedRecord): Promise<void>
}

/** A record as the seed writes it, tagged with the parser that must accept it. */
export interface SeedRecord {
  readonly json: object
  readonly parse: (bytes: Uint8Array) => Parsed<unknown>
}

/** The three writers of the scenario: the circle's admin and owner, a member, a stranger. */
export interface Cast {
  readonly owner: Writer
  readonly member: Writer
  readonly stranger: Writer
}

/** Signs up three new keys on the testnet homeserver. */
export async function signUpCast(): Promise<Cast> {
  const pubky = Pubky.testnet(TESTNET_HOST)
  const homeserver = PublicKey.from(testnetHomeserver())
  const signUp = async (): Promise<Writer> => writerOf(await signUpSession(pubky, homeserver))
  // One after another: three signups are quick, and the testnet's logs stay
  // in an order a reader can follow.
  const owner = await signUp()
  const member = await signUp()
  const stranger = await signUp()
  return { owner, member, stranger }
}

/** A new key's writing session: a `/pub/sweepky/:rw` grant, else a legacy cookie session. */
async function signUpSession(pubky: Pubky, homeserver: PublicKey): Promise<Session> {
  try {
    return await signUpWithGrant(pubky, homeserver)
  } catch (error) {
    console.warn(
      `seed: grant signup failed (${error instanceof Error ? error.message : String(error)}); ` +
        'falling back to the legacy cookie signup',
    )
    return pubky.signer(Keypair.random()).signupCookie(homeserver, null)
  }
}

/**
 * Starts a signup grant flow for a new key and approves it with that key's
 * own Signer, as Ring would on a phone. The approval and the session both
 * travel through the testnet relay, so the two promises run together.
 */
async function signUpWithGrant(pubky: Pubky, homeserver: PublicKey): Promise<Session> {
  const flow = await pubky.startGrantAuthFlow(
    SWEEPKY_CAPABILITIES,
    AuthFlowKind.signup(homeserver, null),
    { clientId: CLIENT_ID, relay: TESTNET_AUTH_RELAY },
  )
  const signer = pubky.signer(Keypair.random())
  const [session] = await Promise.all([
    flow.awaitApproval(),
    signer.approveAuthRequest(flow.authorizationUrl),
  ])
  return session
}

function testnetHomeserver(): string {
  const value = process.env.SWEEPKY_E2E_HOMESERVER ?? DEFAULT_TESTNET_HOMESERVER
  if (parsePubky(value) === null) throw new Error('SWEEPKY_E2E_HOMESERVER is not a pubky')
  return value
}

function writerOf(session: Session): Writer {
  const pubky = parsePubky(session.info.publicKey.z32())
  if (pubky === null) throw new Error('the SDK gave a session whose key does not parse')
  return {
    pubky,
    async put(path, { json, parse }) {
      const parsed = parse(new TextEncoder().encode(JSON.stringify(json)))
      if (!parsed.ok) {
        throw new Error(`the seed built a record the board refuses: ${parsed.error.message}`)
      }
      await session.storage.putJson(formatSweepkyPath(path) as `/pub/${string}`, json)
    },
  }
}

/** A new record id for now, as the CLI makes one. */
export function newRecordId(): RecordId {
  return recordIdFromMicros(BigInt(Date.now()) * 1000n)
}

/** Now in RFC 3339 UTC to the second, the one form Sweepky writes. */
export function recordTimeNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
}

/** `circle.json` naming `admin` and `members`, the admin listed among them too. */
export function circleRecord(admin: PubkyKey, members: readonly PubkyKey[]): SeedRecord {
  return {
    json: {
      schemaVersion: 1,
      name: 'Sweepky e2e circle',
      admin,
      members: [admin, ...members].map((pubky) => ({ pubky })),
    },
    parse: parseCircle,
  }
}

/** The bounty `post --open` writes and `done` rewrites. */
export interface BountyState {
  readonly createdAt: string
  /** `null` while open; when done, its time and the sweepers credited. */
  readonly done: { readonly at: string; readonly credits: readonly PubkyKey[] } | null
}

export function bountyRecord({ createdAt, done }: BountyState): SeedRecord {
  return {
    json: {
      schemaVersion: 1,
      title: 'Synthetic e2e bounty',
      focus: 'security',
      brief: 'A synthetic bounty for the board’s browser checks. Nothing to sweep.',
      playbook: { suggested: null, required: false },
      targets: [SYNTHETIC_TARGET],
      open: true,
      reward: null,
      status: done === null ? 'open' : 'done',
      credits: done?.credits ?? [],
      createdAt,
      doneAt: done?.at ?? null,
    },
    parse: parseBounty,
  }
}

/** `bounties/<id>.discovered.json` listing `sweeps`; cursors, which the board ignores, empty. */
export function discoveredRecord(sweeps: readonly SweepRef[]): SeedRecord {
  return {
    json: { schemaVersion: 1, sweeps: sweeps.map(sweepUrl), cursors: {} },
    parse: parseDiscovered,
  }
}

/** A sweep record of `bounty`'s one target, running or done. */
export function sweepRecord(
  bounty: BountyRef,
  startedAt: string,
  finishedAt: string | null,
): SeedRecord {
  return {
    json: {
      schemaVersion: 1,
      bounty: bountyUrl(bounty),
      targets: [SYNTHETIC_TARGET.id],
      playbook: 'sweepky-e2e',
      status: finishedAt === null ? 'running' : 'done',
      startedAt,
      finishedAt,
    },
    parse: parseSweep,
  }
}

function bountyUrl({ owner, id }: BountyRef): string {
  return formatPubkyUrl({ user: owner, path: formatSweepkyPath({ kind: 'bounty', id }) })
}

function sweepUrl({ sweeper, id }: SweepRef): string {
  return formatPubkyUrl({ user: sweeper, path: formatSweepkyPath({ kind: 'sweepRecord', id }) })
}
