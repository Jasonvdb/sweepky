// WCAG 2 contrast for the token values in tokens.css, so styles.test.ts can
// hold every text pair the CSS draws to AA (04, Page rules). It reads the two
// forms the tokens use, `#rgb`/`#rrggbb` and `oklch(L C H [/ A])`, and nothing
// else, so a token in a new form fails the test instead of passing unchecked.

/** Gamma-encoded sRGB channels in 0..1, as a browser blends them. */
export type Rgb = readonly [number, number, number]

/** A colour with its alpha in 0..1. */
export interface Rgba {
  readonly rgb: Rgb
  readonly alpha: number
}

/** Reads a token value: hex or oklch, with an optional oklch alpha. */
export function parseColor(value: string): Rgba {
  const text = value.trim().toLowerCase()
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/.exec(text)?.[1]
  if (hex !== undefined) {
    return { rgb: parseHex(hex), alpha: 1 }
  }
  const oklch = /^oklch\(\s*(\S+)\s+(\S+)\s+(\S+)\s*(?:\/\s*(\S+)\s*)?\)$/.exec(text)
  if (oklch !== null) {
    const alpha = oklch[4] === undefined ? 1 : parseNumber(oklch[4])
    return {
      rgb: oklchToSrgb(parseNumber(oklch[1]), parseNumber(oklch[2]), parseNumber(oklch[3])),
      alpha,
    }
  }
  throw new Error(`not a hex or oklch colour: ${value}`)
}

/** The colour at `alpha`, as `color-mix(in srgb, <colour> <alpha>, transparent)` gives it. */
export function withAlpha(colour: Rgba, alpha: number): Rgba {
  return { rgb: colour.rgb, alpha: colour.alpha * alpha }
}

/** `colour` composited over an opaque `surface`, channel by channel. */
export function over(colour: Rgba, surface: Rgb): Rgb {
  const blend = (index: 0 | 1 | 2) =>
    colour.rgb[index] * colour.alpha + surface[index] * (1 - colour.alpha)
  return [blend(0), blend(1), blend(2)]
}

/** WCAG 2's contrast ratio, from 1 (none) to 21 (black on white). */
export function contrastRatio(a: Rgb, b: Rgb): number {
  const [first, second] = [relativeLuminance(a), relativeLuminance(b)]
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05)
}

/** WCAG 2's relative luminance of a gamma-encoded sRGB colour. */
export function relativeLuminance([r, g, b]: Rgb): number {
  return 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b)
}

/** `hex` is 3 or 6 hex digits, already checked; `#abc` is short for `#aabbcc`. */
function parseHex(hex: string): Rgb {
  const full = hex.length === 3 ? [...hex].map((digit) => digit + digit).join('') : hex
  const channel = (offset: number) => Number.parseInt(full.slice(offset, offset + 2), 16) / 255
  return [channel(0), channel(2), channel(4)]
}

function parseNumber(text: string | undefined): number {
  const number = Number(text)
  if (text === undefined || text === '' || !Number.isFinite(number)) {
    throw new Error(`not a number: ${text}`)
  }
  return number
}

/**
 * oklch to gamma-encoded sRGB, through OKLab and linear sRGB with Björn
 * Ottosson's matrices (https://bottosson.github.io/posts/oklab/). A colour
 * outside the sRGB gamut, such as `--brand`, is clamped per channel. Browsers
 * map it into the gamut by reducing chroma instead, so the result can differ a
 * little from what a screen shows; the checks keep a margin above AA for that.
 */
function oklchToSrgb(lightness: number, chroma: number, hueDegrees: number): Rgb {
  const hue = (hueDegrees * Math.PI) / 180
  const a = chroma * Math.cos(hue)
  const b = chroma * Math.sin(hue)

  const l = (lightness + 0.3963377774 * a + 0.2158037573 * b) ** 3
  const m = (lightness - 0.1055613458 * a - 0.0638541728 * b) ** 3
  const s = (lightness - 0.0894841775 * a - 1.291485548 * b) ** 3

  const linear: Rgb = [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ]
  return [toGamma(linear[0]), toGamma(linear[1]), toGamma(linear[2])]
}

function clamp01(channel: number): number {
  return Math.min(1, Math.max(0, channel))
}

/** The sRGB transfer function, linear light to the encoded channel. */
function toGamma(channel: number): number {
  const c = clamp01(channel)
  return c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055
}

/** The inverse of `toGamma`, with WCAG 2's threshold. */
function toLinear(channel: number): number {
  return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
}
