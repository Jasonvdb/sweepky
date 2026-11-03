// A button that copies a string to the clipboard, for the landing page's
// setup prompt and commands. It only writes the clipboard: no request leaves
// the page.

import { useEffect, useState } from 'react'
import { buttonClassName, type ButtonVariant } from './Button.tsx'

/** How long "Copied" stays before the button reads as ready again. */
export const COPIED_FOR_MS = 2000

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
  /** The accessible name, naming what is copied: "Copy the setup prompt". It starts with `labels.idle`, so the visible label is part of it. */
  readonly name: string
  readonly labels: CopyLabels
  readonly variant: ButtonVariant
}

export function CopyButton({ text, name, labels, variant }: CopyButtonProps) {
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
      <button type="button" className={buttonClassName(variant)} aria-label={name} onClick={() => void copy()}>
        {labels.idle}
      </button>
      <span className="copy-button__status" aria-live="polite">
        {result === null ? '' : labels[result]}
      </span>
    </span>
  )
}
