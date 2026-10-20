// Whether the visitor dismissed the board's intro strip (IntroStrip.tsx).
//
// The one thing the app keeps in localStorage, and it is fine to lose: Safari
// drops it inside a cross-site frame, which is where Vibes shows the board
// (04, Stack). So every access is wrapped. Reading the `localStorage`
// property itself can throw (a SecurityError when storage is blocked), and
// so can each call (a full or disabled store); any failure reads as "not
// dismissed" and a write that fails is forgotten. Nothing else may use
// browser storage; board.test.tsx holds the app to that.

const DISMISSED_KEY = 'sweepky.introDismissed'
const DISMISSED = '1'

/** The browser's localStorage, or `null` where there is none or it is blocked. */
function storage(): Storage | null {
  try {
    return globalThis.localStorage ?? null
  } catch {
    return null
  }
}

/** Whether the strip was dismissed on this browser; `false` whenever storage fails. */
export function isIntroDismissed(): boolean {
  try {
    return storage()?.getItem(DISMISSED_KEY) === DISMISSED
  } catch {
    return false
  }
}

/** Remembers the dismissal, if storage lets it. */
export function rememberIntroDismissed(): void {
  try {
    storage()?.setItem(DISMISSED_KEY, DISMISSED)
  } catch {
    // Fine to lose: the strip shows again on the next visit.
  }
}

/** Forgets the dismissal, if storage lets it, so the strip shows again. */
export function forgetIntroDismissed(): void {
  try {
    storage()?.removeItem(DISMISSED_KEY)
  } catch {
    // Fine to lose: the strip is back on this page either way.
  }
}
