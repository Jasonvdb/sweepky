// P4 "Done when": against an empty testnet, /board and the landing hero both
// show the empty state, with no sample rooms.
//
// Reads only, from the local testnet the fixed ports answer on (06,
// "Testnet"): a fresh random key has no pkarr record, so the relay answers
// its lookup with nothing and the board has no record to draw. Unlike
// network.spec.ts nothing here answers the relay, so the answer the board
// draws from is the testnet's own. Skipped unless SWEEPKY_E2E_TESTNET=1
// says a testnet is running.

import { expect, test, type Page } from '@playwright/test'
import { randomCircle } from './randomCircle.ts'

const TESTNET_RELAY = 'http://localhost:15411'

test.describe('an empty testnet', { tag: '@empty' }, () => {
  test.skip(
    process.env.SWEEPKY_E2E_TESTNET !== '1',
    'needs the local testnet: set SWEEPKY_E2E_TESTNET=1',
  )

  /**
   * Opens `path` for a fresh key and waits for the relay's answer to its
   * lookup and the notice it leads to, so the floor plan is checked after
   * the store has heard back, not before it has asked.
   */
  async function openForFreshKey(page: Page, path: string): Promise<void> {
    const lookup = page.waitForResponse((response) => response.url().startsWith(TESTNET_RELAY))
    await page.goto(`${path}?circle=${randomCircle()}`)
    await lookup
    // No pkarr record: the board says the admin is unreachable.
    await expect(page.locator('.board-notice')).toContainText('Unreachable')
  }

  for (const [path, floorPlan] of [
    ['/board', '.floor-plan'],
    ['/', '.landing-hero .floor-plan--compact'],
  ] as const) {
    test(`${path} shows the empty state, with no room or detector`, async ({ page }) => {
      await openForFreshKey(page, path)
      const plan = page.locator(floorPlan)
      await expect(plan.locator('.empty-state')).toContainText('No open bounties yet')
      await expect(page.locator('.room:not(.room--empty)')).toHaveCount(0)
      await expect(page.locator('.detector')).toHaveCount(0)
    })
  }
})
