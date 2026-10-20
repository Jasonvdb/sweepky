import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parseBounty, parseCircle, type Circle, type Parsed } from '../records/parse.ts'
import { parsePubky, type Pubky } from '../records/pubky.ts'
import { trustLabels, type CreditedBounty } from './trust.ts'

/**
 * fixtures/trust-labels.json, the file sweepky-core's trust-label test loads
 * too: fixtures/README.md is its spec.
 */
interface Fixture {
  readonly roster: unknown
  readonly bounties: readonly FixtureBounty[]
  readonly expected: Readonly<Record<string, unknown>>
}

/** A reduced test shape: the real record takes `owner` and `id` from its path. */
interface FixtureBounty {
  readonly id: string
  readonly owner: string
  readonly status: string
  readonly credits: readonly string[]
}

const FIXTURE = JSON.parse(
  readFileSync(new URL('../../../fixtures/trust-labels.json', import.meta.url), 'utf8'),
) as Fixture

/**
 * Roster members A (the admin), B and D, and sweepers S2 and S3, outside it.
 * Names as in fixtures/README.md.
 */
const A = pubky('ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo')
const B = pubky('btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy')
const D = pubky('5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco')
const S2 = pubky('kmjs3ec6imcijf5wknsbfrh1bk4ariso7en8tteestniygu159xo')
const S3 = pubky('qwujy4epafpmfei7bxn8fccfm1shzqp516sbenxi7qr6gua4n77o')

function pubky(text: string): Pubky {
  const key = parsePubky(text)
  if (key === null) throw new Error(`not a pubky: ${text}`)
  return key
}

function recordOf<T>(parsed: Parsed<T>): T {
  if (!parsed.ok) throw new Error(`refused: ${parsed.error.message}`)
  return parsed.record
}

function bytesOf(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value))
}

/** The fixture's roster, read through the parser the board reads `circle.json` with. */
function roster(): Circle {
  return recordOf(parseCircle(bytesOf(FIXTURE.roster)))
}

/** The fixture's roster with its admin, A, left out of `members`: A is in it as admin alone. */
function rosterWithoutAdminInMembers(): Circle {
  const circle = roster()
  return { ...circle, members: circle.members.filter((member) => member.pubky !== circle.admin) }
}

/** Every bounty in the file, the open ones and the outsider X's included. */
function bounties(): CreditedBounty[] {
  return FIXTURE.bounties.map((bounty) => ({
    owner: pubky(bounty.owner),
    status: bounty.status,
    credits: bounty.credits.map(pubky),
  }))
}

/** A done bounty owned by `owner` that credits `credits`. */
function done(owner: Pubky, credits: readonly Pubky[]): CreditedBounty {
  return { owner, status: 'done', credits }
}

describe('trustLabels against fixtures/trust-labels.json', () => {
  it.each([
    ['the fixture roster', roster],
    ['the roster with the admin left out of members', rosterWithoutAdminInMembers],
  ])('gives every expected entry its label and counts, with %s', (_roster, circle) => {
    // 01: the roster is the admin and every entry in `members`, so leaving
    // the admin out of `members` changes no expected value.
    const table = trustLabels(circle(), bounties())
    for (const [key, expected] of Object.entries(FIXTURE.expected)) {
      // An entry is `{label, bounties, owners}`, the shape of a `Trust`, so
      // one comparison checks the label and both counts.
      expect(table.get(pubky(key)), key).toEqual(expected)
    }
  })

  it('has exactly one expected entry per pubky in the file', () => {
    // The admin, the members, every owner and every credited sweeper, on
    // counted bounties or not. Compared as parsed keys, so a pubky spelt two
    // ways in the file is still one.
    const circle = roster()
    const named = new Set([
      circle.admin,
      ...circle.members.map((member) => member.pubky),
      ...bounties().flatMap((bounty) => [bounty.owner, ...bounty.credits]),
    ])
    const expected = Object.keys(FIXTURE.expected).map(pubky)
    expect(expected).toHaveLength(named.size)
    expect(new Set(expected)).toEqual(named)
  })
})

describe('trustLabels', () => {
  it('trusts an admin left out of members as an owner, and labels it circle', () => {
    // A's done bounty credits B, a member, and S3, a stranger. S3 would stay
    // `unknown` if A were not a trusted owner.
    const table = trustLabels(rosterWithoutAdminInMembers(), [done(A, [B, S3])])
    expect(table.get(A)).toEqual({ label: 'circle', bounties: 0, owners: 0 })
    expect(table.get(B)).toEqual({ label: 'circle', bounties: 1, owners: 1 })
    expect(table.get(S3)).toEqual({ label: 'known', bounties: 1, owners: 1 })
  })

  it('labels a pubky in no bounty and no roster unknown, with nothing counted', () => {
    const stranger = pubky('y'.repeat(52))
    expect(trustLabels(roster(), bounties()).get(stranger)).toEqual({
      label: 'unknown',
      bounties: 0,
      owners: 0,
    })
  })

  it.each(['Done', 'DONE', 'done ', 'closed', ''])(
    'counts nothing on a bounty whose status is %j, not exactly done',
    (status) => {
      const table = trustLabels(roster(), [{ ...done(A, [S3]), status }])
      expect(table.get(S3)).toEqual({ label: 'unknown', bounties: 0, owners: 0 })
    },
  )

  it('skips a self-credit written in the pubky-prefixed spelling', () => {
    // A hand-written record of D's that credits D as `pubky<z32>`. The
    // parser reads every credit as a raw key and the owner comes from the
    // record's path, so the two compare equal and the self-credit is skipped.
    // `owner` goes last so the path's key wins over anything in the record.
    const record = recordOf(
      parseBounty(
        bytesOf({
          schemaVersion: 1,
          title: "D's own bounty",
          focus: 'security',
          brief: 'Hand-written.',
          playbook: { required: false },
          targets: [],
          status: 'done',
          credits: [`pubky${D}`, S2],
          createdAt: '2026-09-01T10:00:00Z',
          doneAt: '2026-09-08T10:00:00Z',
        }),
      ),
    )
    const table = trustLabels(roster(), [{ ...record, owner: D }])
    expect(table.get(D)).toEqual({ label: 'circle', bounties: 0, owners: 0 })
    expect(table.get(S2)).toEqual({ label: 'known', bounties: 1, owners: 1 })
  })
})
