// A button that copies a string to the clipboard, for the landing page's
// setup prompt and commands. It only writes the clipboard: no request leaves
// the page.

import { useEffect, useState } from 'react'
import { Button, type ButtonVariant } from './Button.tsx'

/** How long "Copied" stays before the button reads as ready again. */
const COPIED_FOR_MS = 2000

/** The one part of `navigator.clipboard` this needs, so a test can pass a stand-in. */
export type ClipboardWriter = Pick<Clipboard, 'writeText'>

export type CopyResult = 'copied' | 'failed'

/**
 * Writes `text` to `clipboard`. `failed` when there is no clipboard (the
 * browser gives none outside a secure context) or the browser refuses, so
 * the caller can ask the visitor to select the text instead.
 */
export async function copyText(text: string, clipboard: ClipboardWriter | undefined): Promise<CopyResult> {
  if (clipboard === undefined) return 'failed'
  try {
    await clipboard.writeText(text)
    return 'copied'
  } catch {
    return 'failed'
  }
}

/** The button's visible label, and what the live region says after a click. */
export interface CopyLabels {
  readonly idle: string
  readonly copied: string
  readonly failed: string
}

interface CopyButtonProps {
  /** What a click puts on the clipboard. */
  readonly text: string
  /** What is copied, in words: "the setup prompt". The accessible name is `labels.idle` then this, so the visible label is always part of it. */
  readonly subject: string
  readonly labels: CopyLabels
  readonly variant: ButtonVariant
}

export function CopyButton({ text, subject, labels, variant }: CopyButtonProps) {
  const [result, setResult] = useState<CopyResult | null>(null)

  // "Copied" fades back after a moment; "select the text" stays until the
  // next click, since the visitor still has to act on it. The cleanup clears
  // the timer on unmount and on every new result.
  useEffect(() => {
    if (result !== 'copied') return
    const timer = setTimeout(() => setResult(null), COPIED_FOR_MS)
    return () => clearTimeout(timer)
  }, [result])

  async function copy() {
    setResult(null)
    // `navigator.clipboard` is undefined outside a secure context, whatever
    // the DOM types say.
    const clipboard = navigator.clipboard as ClipboardWriter | undefined
    setResult(await copyText(text, clipboard))
  }

  return (
    <span className="copy-button">
      <Button variant={variant} aria-label={`${labels.idle} ${subject}`} onClick={() => void copy()}>
        {labels.idle}
      </Button>
      <span className="copy-button__status" aria-live="polite">
        {result === null ? '' : labels[result]}
      </span>
    </span>
  )
}
