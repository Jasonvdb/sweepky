// Checks on the app's hand-written CSS against 04's design reference and page
// rules: the copied pubky-app tokens, one accent, `--destructive` only for
// `aborted` and "unreachable", WCAG AA contrast on every text pair the CSS
// draws, and no motion under `prefers-reduced-motion: reduce`.
import { readdirSync, readFileSync } from 'node:fs'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { Button } from '../components/Button.tsx'
import { Section } from '../components/Section.tsx'
import { contrastRatio, over, parseColor, withAlpha, type Rgb } from './contrast.ts'

const STYLES_DIR = new URL('./', import.meta.url)
const CSS_FILES = readdirSync(STYLES_DIR).filter((name) => name.endsWith('.css'))

function readCss(name: string): string {
  return readFileSync(new URL(name, STYLES_DIR), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')
}

const ALL_CSS = CSS_FILES.map(readCss).join('\n')

interface Rule {
  readonly selector: string
  readonly declarations: ReadonlyMap<string, string>
}

/**
 * Every innermost `selector { declarations }` block, so a rule nested in an
 * `@media` block is found too. Enough for hand-written CSS without strings
 * that hold braces.
 */
function rules(css: string): Rule[] {
  return [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((match) => {
    const declarations = new Map<string, string>()
    for (const declaration of (match[2] ?? '').split(';')) {
      const colon = declaration.indexOf(':')
      if (colon > 0) {
        declarations.set(declaration.slice(0, colon).trim(), declaration.slice(colon + 1).trim())
      }
    }
    return { selector: (match[1] ?? '').trim(), declarations }
  })
}

/** The custom properties tokens.css defines on `:root`. */
function tokens(): ReadonlyMap<string, string> {
  const root = rules(readCss('tokens.css')).find((rule) => rule.selector === ':root')
  if (root === undefined) {
    throw new Error('tokens.css has no :root rule')
  }
  return root.declarations
}

function token(name: string): string {
  const value = tokens().get(`--${name}`)
  if (value === undefined) {
    throw new Error(`tokens.css does not define --${name}`)
  }
  return value
}

describe('tokens', () => {
  // The values 04's design reference lists, copied from pubky-app's globals.css.
  it.each([
    ['background', 'oklch(0.118 0.014 284.115)'],
    ['card', 'oklch(0.232 0.006 285.946)'],
    ['foreground', 'oklch(1 0 0)'],
    ['card-foreground', 'oklch(0.951 0.011 286.195)'],
    ['muted-foreground', '#89898f'],
    ['secondary', '#303034'],
    ['border', 'oklch(0.311 0.007 285.98)'],
    ['brand', 'oklch(0.928 0.23 123.978)'],
    ['destructive', 'oklch(0.628 0.258 29.234)'],
    ['radius', '0.625rem'],
  ])('--%s is %s', (name, value) => {
    expect(token(name)).toBe(value)
  })
})

describe('one accent', () => {
  const COLOUR_LITERAL = /#[0-9a-f]{3,8}\b|\b(?:rgba?|hsla?|oklch|oklab|lab|lch|hwb)\(/i

  it.each(CSS_FILES.filter((name) => name !== 'tokens.css'))(
    '%s holds no colour literal, only tokens',
    (name) => {
      expect(readCss(name)).not.toMatch(COLOUR_LITERAL)
    },
  )

  it('uses --destructive only for aborted and unreachable', () => {
    const destructive = rules(ALL_CSS).filter((rule) =>
      [...rule.declarations.values()].some((value) => value.includes('var(--destructive)')),
    )
    for (const rule of destructive) {
      expect(rule.selector).toMatch(/aborted|unreachable/)
    }
  })
})

describe('contrast at WCAG AA', () => {
  const AA_TEXT = 4.5
  const AA_NON_TEXT = 3

  const background = (): Rgb => over(parseColor(token('background')), [0, 0, 0])
  const onBackground = (name: string, alpha = 1): Rgb =>
    over(withAlpha(parseColor(token(name)), alpha), background())
  // A card is `--card` at 80 % over the page (sections.css).
  const card = (): Rgb => onBackground('card', 0.8)
  const text = (name: string): Rgb => onBackground(name)

  // Each pair the CSS draws: [what, text colour, surface].
  const TEXT_PAIRS: ReadonlyArray<readonly [string, () => Rgb, () => Rgb]> = [
    ['foreground on the page', () => text('foreground'), background],
    ['card-foreground on the page', () => text('card-foreground'), background],
    ['muted-foreground on the page', () => text('muted-foreground'), background],
    ['foreground on a card', () => text('foreground'), card],
    ['card-foreground on a card', () => text('card-foreground'), card],
    ['muted-foreground on a card', () => text('muted-foreground'), card],
    ['background on brand (primary button)', () => text('background'), () => text('brand')],
    ['brand on the page (eyebrow, accent word)', () => text('brand'), background],
    ['brand on brand at 16 % (default button)', () => text('brand'), () => onBackground('brand', 0.16)],
    ['brand on brand at 30 % (default button, hover)', () => text('brand'), () => onBackground('brand', 0.3)],
    ['foreground on secondary (secondary button)', () => text('foreground'), () => text('secondary')],
  ]

  it.each(TEXT_PAIRS)('%s reaches 4.5:1', (_what, foreground, surface) => {
    expect(contrastRatio(foreground(), surface())).toBeGreaterThanOrEqual(AA_TEXT)
  })

  // Destructive text fails on a card, so the label stays in --foreground and a
  // destructive mark beside it carries the colour: a non-text element, held to
  // 3:1 on every surface it can sit on (base.css).
  it.each([
    ['the page', background],
    ['a card', card],
  ])('the destructive mark reaches 3:1 on %s', (_what, surface) => {
    expect(contrastRatio(text('destructive'), surface())).toBeGreaterThanOrEqual(AA_NON_TEXT)
  })

  it('sets no destructive text colour, only the mark', () => {
    for (const rule of rules(ALL_CSS)) {
      expect(rule.declarations.get('color') ?? '').not.toContain('var(--destructive)')
    }
  })

  it.each([
    ['the page', background],
    ['a card', card],
  ])('the focus ring reaches 3:1 on %s', (_what, surface) => {
    expect(contrastRatio(text('foreground'), surface())).toBeGreaterThanOrEqual(AA_NON_TEXT)
  })

  it('the focus ring is drawn in --foreground', () => {
    const focus = rules(ALL_CSS).filter((rule) => rule.selector.includes(':focus-visible'))
    expect(focus.length).toBeGreaterThan(0)
    for (const rule of focus) {
      expect(rule.declarations.get('outline')).toContain('var(--foreground)')
    }
  })

  // The pair is below AA, so no rule may draw it.
  it('sets no muted-foreground text on a --secondary background', () => {
    expect(contrastRatio(text('muted-foreground'), text('secondary'))).toBeLessThan(AA_TEXT)
    for (const rule of rules(ALL_CSS)) {
      const fill = [...rule.declarations]
        .filter(([property]) => property.startsWith('background'))
        .some(([, value]) => value.includes('var(--secondary)'))
      const colour = rule.declarations.get('color') ?? ''
      expect(fill && colour.includes('var(--muted-foreground)')).toBe(false)
    }
  })
})

describe('the contrast arithmetic', () => {
  it('reads hex and oklch white and black alike', () => {
    expect(over(parseColor('#ffffff'), [0, 0, 0])).toEqual([1, 1, 1])
    expect(over(parseColor('oklch(1 0 0)'), [0, 0, 0])).toEqual([1, 1, 1].map(() => expect.closeTo(1, 4)))
    expect(over(parseColor('#000'), [1, 1, 1])).toEqual([0, 0, 0])
  })

  it('gives black on white 21:1', () => {
    expect(contrastRatio([0, 0, 0], [1, 1, 1])).toBeCloseTo(21, 6)
  })

  it('composites alpha over the surface beneath', () => {
    expect(over(withAlpha(parseColor('#ffffff'), 0.5), [0, 0, 0])).toEqual([0.5, 0.5, 0.5])
  })

  it('refuses a colour it cannot read', () => {
    expect(() => parseColor('var(--brand)')).toThrow()
    expect(() => parseColor('#12345')).toThrow()
  })
})

describe('reduced motion', () => {
  it('stops every animation, transition and smooth scroll under reduce', () => {
    const block = ALL_CSS.match(
      /@media\s*\(\s*prefers-reduced-motion:\s*reduce\s*\)\s*\{((?:[^{}]*\{[^{}]*\})*[^{}]*)\}/,
    )
    expect(block).not.toBeNull()
    const global = rules(block?.[1] ?? '').find((rule) =>
      rule.selector.split(',').some((part) => part.trim() === '*'),
    )
    expect(global).toBeDefined()
    const value = (property: string) =>
      global?.declarations.get(property)?.replace(/\s*!important$/, '')
    expect(value('animation')).toBe('none')
    expect(value('transition')).toBe('none')
    expect(value('scroll-behavior')).toBe('auto')
  })
})

describe('components', () => {
  const PROBLEM_SECTION = {
    eyebrow: 'The problem',
    heading: { lead: 'One pass ', accent: 'misses', tail: ' things.' },
    subtitle: 'A subtitle.',
  }

  function classNames(markup: string): string[] {
    return [...markup.matchAll(/class="([^"]*)"/g)].flatMap((match) => (match[1] ?? '').split(/\s+/))
  }

  // Every class a component emits has a rule, so no variant renders unstyled.
  it('emit only classes the CSS styles', () => {
    const markup = [
      ...(['primary', 'default', 'secondary'] as const).map((variant) =>
        renderToStaticMarkup(createElement(Button, { variant }, 'Go')),
      ),
      renderToStaticMarkup(createElement(Section, PROBLEM_SECTION, 'cards')),
    ].join('')
    const selectors = rules(ALL_CSS).map((rule) => rule.selector)
    for (const name of new Set(classNames(markup))) {
      expect(selectors.some((selector) => new RegExp(`\\.${name}(?![\\w-])`).test(selector))).toBe(true)
    }
  })

  it('renders a section as the pubky-app pattern', () => {
    const markup = renderToStaticMarkup(createElement(Section, PROBLEM_SECTION))
    expect(markup).toMatch(/<p class="section__eyebrow">The problem<\/p>/)
    expect(markup).toMatch(/<h2[^>]*>One pass <span class="accent">misses<\/span> things.<\/h2>/)
    expect(markup).toMatch(/<p class="section__subtitle">A subtitle.<\/p>/)
  })

  it('renders a button that does not submit a form by default', () => {
    expect(renderToStaticMarkup(createElement(Button, { variant: 'primary' }, 'Go'))).toContain(
      'type="button"',
    )
  })
})
