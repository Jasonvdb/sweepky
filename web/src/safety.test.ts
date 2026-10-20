// Display safety: strangers write the titles, paths and labels the board
// shows, and core's checks let zero-width and default-ignorable characters
// through (P1a carry-forward), so the board never turns their text into
// markup. React escapes text nodes; this scan holds the app to them.
import { readdirSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const SRC_DIR = new URL('./', import.meta.url)

/** Every source file under src/ but the tests, which name the strings below. */
const SOURCES = readdirSync(SRC_DIR, { recursive: true, encoding: 'utf8' }).filter(
  (path) => /\.(ts|tsx)$/.test(path) && !/\.test\./.test(path),
)

/** Ways to put a string into the page as markup instead of text. */
const RAW_HTML = /dangerouslySetInnerHTML|\.(?:inner|outer)HTML\b|insertAdjacentHTML|document\.write/

describe('display safety', () => {
  it('finds the sources it scans', () => {
    expect(SOURCES.length).toBeGreaterThan(0)
  })

  it.each(SOURCES)('%s writes no raw HTML', (path) => {
    expect(readFileSync(new URL(path, SRC_DIR), 'utf8')).not.toMatch(RAW_HTML)
  })
})
