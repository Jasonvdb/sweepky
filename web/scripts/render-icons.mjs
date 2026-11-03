// Renders the raster icons in public/ from public/favicon.svg, Sweepky's
// mark: favicon.ico (16, 32 and 48 px) and favicon.png (192 px), both on a
// transparent background, for browsers and tools that do not read SVG icons;
// and apple-touch-icon.png (180 px, for iOS home screens), on the page's dark
// background because iOS fills a transparent touch icon with black anyway and
// rounds the corners itself. A raster cannot follow the light scheme as the
// SVG does, so these draw the brand amber the dark scheme uses. Uses the
// Google Chrome installed on this machine, as the browser specs do; nothing
// is downloaded.
//
//   node scripts/render-icons.mjs   (from web/)

import { readFileSync, writeFileSync } from 'node:fs'
import { chromium } from '@playwright/test'

const PUBLIC = new URL('../public/', import.meta.url)
const favicon = readFileSync(new URL('favicon.svg', PUBLIC), 'utf8')

// The touch icon: the mark in the brand amber, a little smaller so iOS's
// mask never clips the ring, on a full square of the page's background.
const touch = favicon
  .replace(/<style>[\s\S]*?<\/style>/, '<rect width="32" height="32" fill="#05050a"/>')
  .replace(
    '<g class="mark">',
    '<g style="color: #ffb336" transform="translate(16 16) scale(0.78) translate(-16 -16)">',
  )
if (!touch.includes('#05050a') || !touch.includes('scale(0.78)')) {
  throw new Error('favicon.svg no longer has the <style> and <g class="mark"> this script rewrites')
}

const browser = await chromium.launch({ channel: 'chrome' })

/**
 * `svg` drawn at `size` px square as a PNG with a transparent background, on
 * a page of its own at that size: resizing one page between sizes stitched
 * stale tiles into the larger images. The dark scheme, so the favicon's own
 * CSS picks the brand amber.
 */
async function png(svg, size) {
  const page = await browser.newPage({ colorScheme: 'dark', viewport: { width: size, height: size } })
  const src = `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`
  await page.setContent(
    `<style>html,body{margin:0;background:transparent}img{display:block}</style><img src="${src}" width="${size}" height="${size}">`,
  )
  await page.locator('img').evaluate((img) => img.decode())
  const data = await page.screenshot({ omitBackground: true })
  await page.close()
  return data
}

/** An ICO file holding each PNG as is (PNG entries need Windows Vista or later). */
function ico(images) {
  const header = Buffer.alloc(6 + 16 * images.length)
  header.writeUInt16LE(0, 0)
  header.writeUInt16LE(1, 2)
  header.writeUInt16LE(images.length, 4)
  let offset = header.length
  images.forEach(({ size, data }, at) => {
    const entry = 6 + 16 * at
    header.writeUInt8(size % 256, entry)
    header.writeUInt8(size % 256, entry + 1)
    header.writeUInt16LE(1, entry + 4)
    header.writeUInt16LE(32, entry + 6)
    header.writeUInt32LE(data.length, entry + 8)
    header.writeUInt32LE(offset, entry + 12)
    offset += data.length
  })
  return Buffer.concat([header, ...images.map((image) => image.data)])
}

const sizes = [16, 32, 48]
const images = []
for (const size of sizes) images.push({ size, data: await png(favicon, size) })
writeFileSync(new URL('favicon.ico', PUBLIC), ico(images))
writeFileSync(new URL('favicon.png', PUBLIC), await png(favicon, 192))
writeFileSync(new URL('apple-touch-icon.png', PUBLIC), await png(touch, 180))
await browser.close()
