// P4 "Done when": the landing page and the board render at 375 px and at
// desktop width with no horizontal scroll, are keyboard navigable, and show
// no motion under reduced-motion emulation. Also B8: the board's intro strip
// reaches the landing page's #sweep anchor.

import { expect, test, type Page } from '@playwright/test'
import { randomCircle } from './randomCircle.ts'

const PAGES = ['/', '/board', '/circle'] as const

const VIEWPORTS = [
  { name: 'phone', width: 375, height: 812 },
  { name: 'desktop', width: 1440, height: 900 },
] as const

/** Opens `path` for `circle` once the route has drawn into `<main>`. */
async function open(page: Page, path: string, circle: string): Promise<void> {
  await page.goto(`${path}?circle=${circle}`)
  await expect(page.locator('main')).not.toBeEmpty()
}

for (const viewport of VIEWPORTS) {
  test.describe(`at ${viewport.width} px`, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height } })

    for (const path of PAGES) {
      test(`${path} does not scroll sideways`, async ({ page }) => {
        await open(page, path, randomCircle())
        const { scrollWidth, innerWidth } = await page.evaluate(() => ({
          scrollWidth: document.documentElement.scrollWidth,
          innerWidth: window.innerWidth,
        }))
        expect(scrollWidth).toBeLessThanOrEqual(innerWidth)
      })
    }
  })
}

for (const path of PAGES) {
  test(`Tab walks every link and button on ${path} in order, with a focus ring`, async ({
    page,
  }) => {
    await open(page, path, randomCircle())

    // Every control a visitor can see, in document order: the order Tab
    // should take, since the app sets no positive tabindex. Each is tagged
    // with its place, so a focused element can be matched to it.
    const tabOrder = await page.evaluate(() => {
      const controls = document.querySelectorAll<HTMLElement>('a[href], button:not([disabled])')
      const places: string[] = []
      for (const control of controls) {
        if (!control.checkVisibility({ visibilityProperty: true })) continue
        control.dataset.e2eOrder = String(places.length)
        places.push(control.dataset.e2eOrder)
      }
      return places
    })
    expect(tabOrder.length).toBeGreaterThan(0)

    for (const order of tabOrder) {
      await page.keyboard.press('Tab')
      const focused = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null
        if (el === null) return null
        const style = getComputedStyle(el)
        return {
          order: el.dataset.e2eOrder ?? `untracked <${el.tagName.toLowerCase()}>`,
          ring: style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0,
        }
      })
      expect(focused).toEqual({ order, ring: true })
    }
  })
}

test.describe('under prefers-reduced-motion: reduce', () => {
  test.use({ reducedMotion: 'reduce' })

  for (const path of PAGES) {
    test(`${path} runs no animation`, async ({ page }) => {
      await open(page, path, randomCircle())
      await page.waitForLoadState('load')
      // CSS animations and transitions show up here as Animation objects;
      // base.css's `animation: none` and `transition: none` leave none.
      const running = await page.evaluate(() => document.getAnimations().length)
      expect(running).toBe(0)
    })
  }
})

test("the intro strip's Run a sweep lands on the landing page's #sweep", async ({ page }) => {
  const circle = randomCircle()
  await open(page, '/board', circle)

  await page.getByRole('complementary', { name: 'About this board' })
    .getByRole('link', { name: 'Run a sweep' })
    .click()

  await expect(page).toHaveURL(`/?circle=${circle}#sweep`)
  await expect(page.locator('#sweep')).toBeInViewport()
})
