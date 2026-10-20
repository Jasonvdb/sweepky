// Checks on the files a static host serves as they are, outside the bundle.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

function readWebFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8')
}

describe('hosting', () => {
  it('serves /health.json as a JSON object', () => {
    const health: unknown = JSON.parse(readWebFile('public/health.json'))
    expect(health).toBeTypeOf('object')
    expect(health).not.toBeNull()
    expect(Array.isArray(health)).toBe(false)
  })

  // vibes.pubky.app shows the board in an iframe, so nothing may forbid framing.
  it.each(['index.html', 'vite.config.ts'])('%s sets no frame restriction', (path) => {
    const text = readWebFile(path).toLowerCase()
    expect(text).not.toContain('x-frame-options')
    expect(text).not.toContain('frame-ancestors')
  })

  // A crossorigin (anonymous) load keeps Google's cookies off the font request,
  // like every other request the app makes.
  it('index.html loads Inter Tight without credentials', () => {
    const fontLink = readWebFile('index.html').match(
      /<link\b[^>]*href="https:\/\/fonts\.googleapis\.com\/css2\?family=Inter\+Tight[^"]*"[^>]*>/,
    )
    expect(fontLink).not.toBeNull()
    expect(fontLink?.[0]).toContain('rel="stylesheet"')
    expect(fontLink?.[0]).toMatch(/\scrossorigin(\s|>|="anonymous")/)
  })
})
