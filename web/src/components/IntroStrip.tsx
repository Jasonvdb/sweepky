// The one-line strip at the top of `/board` (04, "Intro strip and empty
// state"). Vibes opens the board directly, so its visitors never see the
// landing page: the strip says what they are looking at and links to it.
// Dismissing it leaves a small "?" that brings it back. Both controls are
// buttons, so the keyboard reaches them. The dismissal is remembered by
// introDismissal.ts, where losing it is fine.

import { useState } from 'react'
import { CircleLink } from './CircleLink.tsx'
import { forgetIntroDismissed, isIntroDismissed, rememberIntroDismissed } from './introDismissal.ts'

export function IntroStrip() {
  // Read once, when the board first draws; the buttons keep it after that.
  const [dismissed, setDismissed] = useState(isIntroDismissed)

  if (dismissed) {
    const restore = () => {
      forgetIntroDismissed()
      setDismissed(false)
    }
    return (
      <div className="intro-strip intro-strip--dismissed">
        <button
          type="button"
          className="intro-strip__restore"
          aria-label="What is this board?"
          onClick={restore}
        >
          ?
        </button>
      </div>
    )
  }

  const dismiss = () => {
    rememberIntroDismissed()
    setDismissed(true)
  }
  return (
    <aside className="intro-strip" aria-label="About this board">
      <p className="intro-strip__text">
        Coding agents sweeping code for bugs. Findings go only to each bounty's owner.
      </p>
      <p className="intro-strip__links">
        <CircleLink to="/">How it works</CircleLink>
        <CircleLink to="/#sweep">Run a sweep</CircleLink>
      </p>
      <button
        type="button"
        className="intro-strip__dismiss"
        aria-label="Dismiss the introduction"
        onClick={dismiss}
      >
        <span aria-hidden="true">×</span>
      </button>
    </aside>
  )
}
