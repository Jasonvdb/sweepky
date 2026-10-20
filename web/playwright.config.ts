// Browser checks for P4's "Done when" items that unit tests cannot see:
// layout, keyboard, reduced motion and the network log (web/e2e/). They run
// on the Google Chrome already installed on this machine (`channel:
// 'chrome'`), so no browser is downloaded, and only through `pnpm e2e`:
// neither `pnpm test` nor CI runs them.

import { defineConfig } from '@playwright/test'

/** A fixed port, so the specs and the server agree on the app's origin. */
const PORT = 5179
const APP_ORIGIN = `http://localhost:${PORT}`

export default defineConfig({
  testDir: './e2e',
  // One dev server and one random circle per spec; nothing to gain from
  // racing several Chrome windows against it.
  workers: 1,
  forbidOnly: true,
  reporter: 'list',
  use: {
    baseURL: APP_ORIGIN,
    channel: 'chrome',
    trace: 'off',
  },
  webServer: {
    // The dev server on the testnet switch, so the SDK's pkarr relay is the
    // local one (`http://localhost:15411`) and never a production relay.
    // `--strictPort` fails the run rather than moving to another port.
    command: `pnpm exec vite --port ${PORT} --strictPort`,
    url: APP_ORIGIN,
    env: { VITE_PUBKY_TESTNET: '1' },
    // Always a server of this run's own, which Playwright stops at the end.
    reuseExistingServer: false,
  },
})
