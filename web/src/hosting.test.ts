// Checks on the files a static host serves as they are, outside the bundle.
import { existsSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { KNOWN_LIMITS_URL, LANDING_COPY, README_URL } from './landing/copy.ts'

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

  // An agent pointed at the site gets an empty page from the SPA, so
  // /llms.txt carries the landing's setup prompt (04, Page rules).
  describe('/llms.txt', () => {
    const llms = readWebFile('public/llms.txt')

    it("carries the landing's setup prompt verbatim", () => {
      expect(llms).toContain(LANDING_COPY.start.agent.prompt.text)
    })

    it("opens with the name and the hero's subtitle as its summary", () => {
      expect(llms.startsWith(`# Sweepky\n\n> ${LANDING_COPY.hero.subtitle.text}\n`)).toBe(true)
    })

    it('links to the README and its known limits', () => {
      expect(llms).toContain(`(${README_URL.replace(/#.*$/, '')})`)
      expect(llms).toContain(`(${KNOWN_LIMITS_URL})`)
    })

    it('follows the copy rules: no install command, never "private"', () => {
      expect(llms).not.toMatch(/cargo install|brew install|\bnpx\b|curl[^\n]*\|/i)
      expect(llms).not.toMatch(/\bprivate\b/i)
    })
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

  // Link previews work without JavaScript (04, Page rules).
  describe('index.html link preview', () => {
    const html = readWebFile('index.html')

    /** The `content` of the `<meta>` whose `attribute` is `name`. */
    function meta(attribute: 'name' | 'property', name: string): string | undefined {
      const tag = html.match(new RegExp(`<meta\\b[^>]*\\b${attribute}="${name}"[^>]*>`))?.[0]
      return tag?.match(/\bcontent="([^"]*)"/)?.[1]
    }

    it('has a title and a description', () => {
      expect(html).toMatch(/<title>[^<]+<\/title>/)
      expect(meta('name', 'description')).toMatch(/\S/)
    })

    it.each(['og:title', 'og:description', 'og:image'])('has %s', (property) => {
      expect(meta('property', property)).toMatch(/\S/)
    })

    it('has a large twitter card', () => {
      expect(meta('name', 'twitter:card')).toBe('summary_large_image')
    })

    it("points og:image at Sweepky's own cover, a file the host serves", () => {
      const image = meta('property', 'og:image') ?? ''
      expect(image).toMatch(/^\/[\w-]+\.png$/)
      expect(existsSync(new URL(`../public${image}`, import.meta.url))).toBe(true)
    })
  })
})
