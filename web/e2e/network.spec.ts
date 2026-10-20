// P4 "Done when": the network log shows every request sent without
// credentials and nothing written; the board never requests `/events/`; apart
// from the font, the landing page requests nothing but what its hero's store
// reads. Also B10: the dev server sends no header that would stop Vibes
// framing the board.
//
// What these checks can see: a random circle has no pkarr record, so the
// store's only reads are relay lookups and no homeserver is ever asked.
// Homeserver reads, and whether they carry credentials, are checked against
// a seeded testnet in the e2e-testnet task.

import { expect, test, type Page, type Request } from '@playwright/test'
import { randomCircle } from './randomCircle.ts'

/** `Pubky.testnet()`'s pkarr relay, which the dev server's build reads from. */
const TESTNET_RELAY = 'http://localhost:15411'

/** Where the landing page may go beyond its own origin: the font and the relay. */
const LANDING_ORIGINS = [
  'https://fonts.googleapis.com',
  'https://fonts.gstatic.com',
  TESTNET_RELAY,
]

const READ_METHODS = ['GET', 'HEAD', 'OPTIONS']

/**
 * Planted for every host the page talks to. A cookie for `localhost` applies
 * to every port, so a relay request sent with credentials would carry it.
 */
const PLANTED_COOKIE = 'sweepky_e2e_planted'
const PLANTED_DOMAINS = ['localhost', 'fonts.googleapis.com', 'fonts.gstatic.com']

interface Sent {
  url: URL
  method: string
  headers: Record<string, string>
}

/**
 * Opens `path` with cookies planted and a random circle, waits for the
 * store's first relay lookup and for the network to go quiet, and returns
 * every request the page sent with its full headers (`allHeaders` includes
 * `cookie`, which `headers` leaves out).
 *
 * The relay is answered here with a 404, a key with no record, as the real
 * relay answers for a random key. Chrome reports the cookies of a request
 * only once it is sent: one refused because no relay is listening would show
 * none, and the credentials check would pass whatever the app did. An
 * intercepted request shows them, and the run needs no testnet.
 */
async function requestsOf(page: Page, path: string): Promise<Sent[]> {
  await page.context().addCookies(
    PLANTED_DOMAINS.map((domain) => ({ name: PLANTED_COOKIE, value: '1', domain, path: '/' })),
  )
  await page.route(`${TESTNET_RELAY}/**`, (route) =>
    route.fulfill({ status: 404, headers: { 'access-control-allow-origin': '*' } }),
  )
  const seen: Request[] = []
  page.on('request', (request) => seen.push(request))

  const relayLookup = page.waitForRequest((request) => request.url().startsWith(TESTNET_RELAY))
  await page.goto(`${path}?circle=${randomCircle()}`)
  await relayLookup
  await page.waitForLoadState('networkidle')

  return Promise.all(
    seen.map(async (request) => ({
      url: new URL(request.url()),
      method: request.method(),
      headers: await request.allHeaders(),
    })),
  )
}

for (const path of ['/', '/board'] as const) {
  test.describe(`the network log of ${path}`, () => {
    let sent: Sent[] = []
    let appOrigin = ''

    test.beforeEach(async ({ page, baseURL }) => {
      appOrigin = new URL(baseURL ?? '').origin
      sent = await requestsOf(page, path)
    })

    test('can see the planted cookie on the app’s own requests', () => {
      // The app's own requests carry it, as they should. Without this, the
      // next check would pass if Chrome reported no cookies at all.
      const own = sent.filter((request) => request.url.origin === appOrigin)
      expect(own.some((request) => request.headers.cookie?.includes(PLANTED_COOKIE))).toBe(true)
    })

    test('sends no Cookie or Authorization header to another origin', () => {
      const credentialed = sent
        .filter((request) => request.url.origin !== appOrigin)
        .filter((request) => 'cookie' in request.headers || 'authorization' in request.headers)
        .map((request) => request.url.href)
      expect(credentialed).toEqual([])
    })

    test('only reads', () => {
      const writes = sent
        .filter((request) => !READ_METHODS.includes(request.method))
        .map((request) => `${request.method} ${request.url.href}`)
      expect(writes).toEqual([])
    })

    test('never requests /events', () => {
      const events = sent
        .filter((request) => request.url.href.includes('/events'))
        .map((request) => request.url.href)
      expect(events).toEqual([])
    })
  })
}

test('the landing page reaches no origin but the font’s and the relay’s', async ({
  page,
  baseURL,
}) => {
  const appOrigin = new URL(baseURL ?? '').origin
  const elsewhere = (await requestsOf(page, '/'))
    .map((request) => request.url.origin)
    .filter((origin) => origin !== appOrigin && !LANDING_ORIGINS.includes(origin))
  expect(elsewhere).toEqual([])
})

test('the dev server sends no header that stops the board being framed', async ({ page }) => {
  const response = await page.goto(`/board?circle=${randomCircle()}`)
  expect(response).not.toBeNull()
  const headers = (await response?.allHeaders()) ?? {}
  expect(headers['x-frame-options']).toBeUndefined()
  expect(headers['content-security-policy'] ?? '').not.toContain('frame-ancestors')
})
