// P4 "Done when", against the local testnet with seeded records (seed.ts):
// - the reachable-but-empty circle shows the empty state, with no sample rooms;
// - a member's sweep turns from `running` to `done`, a stranger's sweep
//   appears with the `unknown` badge once the owner's discovered.json lists
//   it, and the bounty flips to done with its credits while the stranger's
//   badge becomes `known 1`, each within one poll;
// - layout, keyboard and reduced motion hold with data on the page;
// - the network log: every request sent without credentials and nothing
//   written, never `/events`, and the landing page reaching nothing but the
//   font, the relay and the homeserver its hero's store reads.
//
// This spec WRITES to the testnet: it signs up three new keys and puts
// synthetic records in their storage. It is skipped unless
// SWEEPKY_E2E_TESTNET=1 says a local testnet is running, and runs only with
// `--grep @testnet` or a run of every spec. The board's poll interval is the
// real one: each wait is one poll and a margin.

import { expect, test, type Page, type Request } from '@playwright/test'
import type { BountyRef, SweepRef } from '../src/records/urls.ts'
import { POLL_INTERVAL_MS } from '../src/store/poller.ts'
import {
  bountyRecord,
  circleRecord,
  discoveredRecord,
  newRecordId,
  recordTimeNow,
  signUpCast,
  sweepRecord,
  type Cast,
} from './seed.ts'

/** One poll and a margin for the pass itself. */
const ONE_POLL_MS = POLL_INTERVAL_MS + 5_000

const TESTNET_RELAY = 'http://localhost:15411'
const FONT_ORIGINS = ['https://fonts.googleapis.com', 'https://fonts.gstatic.com']
const READ_METHODS = ['GET', 'HEAD', 'OPTIONS']

/** Where homeserver storage reads go, in every spelling the SDK sends them. */
const STORAGE_PATH = '/pub/sweepky/'

/**
 * Planted for `localhost`, which a cookie applies to on every port: the
 * app's own, the relay's and the testnet homeserver's. A request sent with
 * credentials would carry it.
 */
const PLANTED_COOKIE = 'sweepky_e2e_planted'

interface Sent {
  /** The app path the page was on when it sent the request. */
  readonly page: string
  readonly url: URL
  readonly method: string
  /** The headers Chrome sent, or `null` for a request it never sent (see `wireHeaders`). */
  readonly headers: Record<string, string> | null
}

/** The pages 04's layout rules cover, as layout.spec.ts checks them without data. */
const LAYOUT_PAGES = ['/board', '/', '/circle'] as const

function hasCredentials({ headers }: Sent): boolean {
  return headers !== null && ('cookie' in headers || 'authorization' in headers)
}

/** How long a request of a finished test gets to report the headers Chrome sent. */
const WIRE_HEADERS_WAIT_MS = 5_000

/**
 * The headers Chrome put on the wire (`allHeaders` includes `cookie`, which
 * `headers` leaves out), or `null` when it never reports them: a request
 * answered from the memory cache, or cancelled by a navigation before it
 * was sent, carried nothing, and `allHeaders` would wait for it forever.
 */
async function wireHeaders(request: Request): Promise<Record<string, string> | null> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const unreported = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), WIRE_HEADERS_WAIT_MS)
  })
  try {
    return await Promise.race([request.allHeaders(), unreported])
  } finally {
    clearTimeout(timer)
  }
}

test.describe('the board against a seeded testnet', { tag: '@testnet' }, () => {
  test.skip(
    process.env.SWEEPKY_E2E_TESTNET !== '1',
    'writes to the local testnet: set SWEEPKY_E2E_TESTNET=1',
  )
  // Each test builds on the records the one before wrote.
  test.describe.configure({ mode: 'serial', timeout: 4 * ONE_POLL_MS + 60_000 })

  let cast: Cast
  let bounty: BountyRef
  let bountyCreatedAt = ''
  let memberSweep: SweepRef
  let memberStartedAt = ''
  let appOrigin = ''

  /** Every request every page sent, for the network-log test at the end. */
  const sent: Sent[] = []
  let watched: { readonly page: string; readonly request: Request }[] = []
  let currentPath = ''

  test.beforeAll(async ({}, testInfo) => {
    appOrigin = new URL(testInfo.project.use.baseURL ?? '').origin
    cast = await signUpCast()
  })

  test.beforeEach(async ({ page }) => {
    await page.context().addCookies([
      { name: PLANTED_COOKIE, value: '1', domain: 'localhost', path: '/' },
    ])
    page.on('request', (request) => watched.push({ page: currentPath, request }))
  })

  test.afterEach(async () => {
    // Before the page closes: `allHeaders` needs the page that sent the request.
    const resolved = await Promise.all(
      watched.map(async ({ page, request }) => ({
        page,
        url: new URL(request.url()),
        method: request.method(),
        headers: await wireHeaders(request),
      })),
    )
    sent.push(...resolved)
    watched = []
  })

  /** Opens `path` for the seeded circle. */
  async function visit(page: Page, path: string): Promise<void> {
    currentPath = path
    await page.goto(`${path}?circle=${cast.owner.pubky}`)
  }

  const detector = (page: Page, sweep: SweepRef) =>
    page.locator(`.floor-plan .detector[data-sweeper="${sweep.sweeper}"]`)

  const roomOf = (page: Page) =>
    page.locator('.floor-plan .room').filter({
      has: page.locator(`a[href^="/b/${bounty.owner}/${bounty.id}"]`),
    })

  test('a reachable circle with no bounties shows the empty state', async ({ page }) => {
    await cast.owner.put({ kind: 'circle' }, circleRecord(cast.owner.pubky, [cast.member.pubky]))

    for (const [path, floorPlan] of [
      ['/board', '.floor-plan'],
      ['/', '.landing-hero .floor-plan--compact'],
    ] as const) {
      // The owner's bounties listing (a 404, empty) is read after
      // circle.json, so once it is answered the store has read the circle.
      const listing = page.waitForResponse((response) =>
        response.url().includes(`${STORAGE_PATH}bounties/`),
      )
      await visit(page, path)
      await listing
      await expect(page.locator(floorPlan).locator('.empty-state')).toContainText(
        'No open bounties yet',
      )
      await expect(page.locator('.room:not(.room--empty)')).toHaveCount(0)
      await expect(page.locator('.board-notice')).toHaveCount(0)
    }
  })

  test('with a member sweeping, the pages fit, walk by keyboard and keep still', async ({
    page,
  }) => {
    bountyCreatedAt = recordTimeNow()
    bounty = { owner: cast.owner.pubky, id: newRecordId() }
    await cast.owner.put(
      { kind: 'bounty', id: bounty.id },
      bountyRecord({ createdAt: bountyCreatedAt, done: null }),
    )
    await cast.owner.put({ kind: 'discovered', id: bounty.id }, discoveredRecord([]))
    memberStartedAt = recordTimeNow()
    memberSweep = { sweeper: cast.member.pubky, id: newRecordId() }
    await cast.member.put(
      { kind: 'sweepRecord', id: memberSweep.id },
      sweepRecord(bounty, memberStartedAt, null),
    )

    /** Opens `path` and waits for what it draws from the seeded records. */
    const open = async (path: string) => {
      await visit(page, path)
      const drawn =
        path === '/circle'
          ? page.locator(`[data-member="${cast.member.pubky}"]`)
          : detector(page, memberSweep)
      await expect(drawn).toBeVisible({ timeout: ONE_POLL_MS })
    }

    for (const width of [375, 1440]) {
      await page.setViewportSize({ width, height: 900 })
      for (const path of LAYOUT_PAGES) {
        await open(path)
        const { scrollWidth, innerWidth } = await page.evaluate(() => ({
          scrollWidth: document.documentElement.scrollWidth,
          innerWidth: window.innerWidth,
        }))
        expect(scrollWidth, `${path} at ${width} px`).toBeLessThanOrEqual(innerWidth)
      }
    }

    // The Circle page draws members, not rooms.
    for (const path of ['/board', '/']) {
      await open(path)
      expect(await tabsToRoomLink(page), `Tab reaches the room link on ${path}`).toBe(true)
    }

    // The running sweep's detector pulses unless motion is reduced.
    await page.emulateMedia({ reducedMotion: 'reduce' })
    for (const path of LAYOUT_PAGES) {
      await open(path)
      const running = await page.evaluate(() => document.getAnimations().length)
      expect(running, `animations on ${path}`).toBe(0)
    }
  })

  /**
   * Presses Tab until the room's title link has focus, at most once per
   * visible control, and says whether it got there with a focus ring.
   */
  async function tabsToRoomLink(page: Page): Promise<boolean> {
    const controls = await page.locator('a[href], button:not([disabled])').count()
    const href = `/b/${bounty.owner}/${bounty.id}`
    for (let pressed = 0; pressed < controls; pressed++) {
      await page.keyboard.press('Tab')
      const atRoom = await page.evaluate((roomHref) => {
        const el = document.activeElement
        if (!(el instanceof HTMLAnchorElement) || el.closest('.room') === null) return false
        const style = getComputedStyle(el)
        const ring = style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0
        return ring && new URL(el.href).pathname === roomHref
      }, href)
      if (atRoom) return true
    }
    return false
  }

  test('the board follows each record change within one poll', async ({ page }) => {
    await visit(page, '/board')
    await expect(detector(page, memberSweep).locator('.detector__label')).toHaveText('sweeping', {
      timeout: ONE_POLL_MS,
    })

    await test.step("the member's sweep turns done", async () => {
      await cast.member.put(
        { kind: 'sweepRecord', id: memberSweep.id },
        sweepRecord(bounty, memberStartedAt, recordTimeNow()),
      )
      await expect(detector(page, memberSweep).locator('.detector__label')).toHaveText('swept', {
        timeout: ONE_POLL_MS,
      })
    })

    const strangerSweep: SweepRef = { sweeper: cast.stranger.pubky, id: newRecordId() }
    await test.step("the stranger's sweep appears, unknown, once discovered.json lists it", async () => {
      const startedAt = recordTimeNow()
      await cast.stranger.put(
        { kind: 'sweepRecord', id: strangerSweep.id },
        sweepRecord(bounty, startedAt, recordTimeNow()),
      )
      // What `pull` would publish on finding it in the homeserver's feed.
      await cast.owner.put({ kind: 'discovered', id: bounty.id }, discoveredRecord([strangerSweep]))
      await expect(detector(page, strangerSweep).locator('.trust-badge')).toHaveText('unknown', {
        timeout: ONE_POLL_MS,
      })
    })

    await test.step('the bounty turns done with both credits, and the stranger is known 1', async () => {
      const credits = [cast.member.pubky, cast.stranger.pubky]
      await cast.owner.put(
        { kind: 'bounty', id: bounty.id },
        bountyRecord({ createdAt: bountyCreatedAt, done: { at: recordTimeNow(), credits } }),
      )
      await expect(roomOf(page)).toHaveClass(/\broom--done\b/, { timeout: ONE_POLL_MS })
      await expect(roomOf(page).locator('.door li')).toHaveText(credits)
      await expect(detector(page, strangerSweep).locator('.trust-badge')).toHaveText('known 1')
      await expect(detector(page, memberSweep).locator('.trust-badge')).toHaveText('circle')
    })

    await test.step("after a reload, the done bounty's page still lists the stranger's sweep", async () => {
      await visit(page, `/b/${bounty.owner}/${bounty.id}`)
      const row = page.locator('.timeline__item').filter({ hasText: cast.stranger.pubky })
      await expect(row).toBeVisible({ timeout: ONE_POLL_MS })
      await page.reload()
      await expect(row).toBeVisible({ timeout: ONE_POLL_MS })
      await expect(row.locator('.trust-badge')).toHaveText('known 1')
    })
  })

  test('the network log holds across the run', () => {
    expect(sent.length).toBeGreaterThan(0)

    // Chrome reports the planted cookie on the app's own requests, so the
    // checks below cannot pass because no cookie is ever reported.
    const own = sent.filter((request) => request.url.origin === appOrigin)
    expect(own.some((request) => request.headers?.cookie?.includes(PLANTED_COOKIE))).toBe(true)

    // Only reads Chrome sent count as seen, so this check cannot pass blind.
    const storage = sent.filter(
      (request) => request.headers !== null && request.url.pathname.includes(STORAGE_PATH),
    )
    expect(storage.length, 'homeserver storage reads seen').toBeGreaterThan(0)
    expect(storage.filter(hasCredentials).map((request) => request.url.href)).toEqual([])

    const credentialed = sent
      .filter((request) => request.url.origin !== appOrigin)
      .filter(hasCredentials)
      .map((request) => request.url.href)
    expect(credentialed).toEqual([])

    const writes = sent
      .filter((request) => !READ_METHODS.includes(request.method))
      .map((request) => `${request.method} ${request.url.href}`)
    expect(writes).toEqual([])

    const events = sent
      .filter((request) => request.url.pathname.includes('/events'))
      .map((request) => request.url.href)
    expect(events).toEqual([])

    // Apart from the font, the landing page reaches only the relay and the
    // homeserver its hero's store reads: that homeserver's storage, and its
    // `/info`, which the SDK reads itself to learn the server's features
    // (pubky 0.16.2 `client/http_targets/features.rs`, credentials omitted).
    const homeservers = new Set(storage.map((request) => request.url.origin))
    const landingElsewhere = sent
      .filter((request) => request.page === '/' && request.url.origin !== appOrigin)
      .filter((request) => ![...FONT_ORIGINS, TESTNET_RELAY].includes(request.url.origin))
      .filter((request) => !request.url.pathname.includes(STORAGE_PATH))
      .filter(
        (request) => !(homeservers.has(request.url.origin) && request.url.pathname === '/info'),
      )
      .map((request) => request.url.href)
    expect(landingElsewhere).toEqual([])
  })
})
