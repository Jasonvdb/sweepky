// The time a page's views are derived at (selectors.ts takes `now` as an
// argument and never reads the clock itself).

import { useEffect, useState } from 'react'

/**
 * How often the clock moves on, so a sweep fades to "left" and "today" rolls
 * over without a new record. Not motion: nothing animates on a tick, the
 * views are only derived again.
 */
const CLOCK_TICK_MS = 60_000

/** The time the views are derived at, moving on every CLOCK_TICK_MS. */
export function useClock(): number {
  const [now, setNow] = useState(Date.now)
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), CLOCK_TICK_MS)
    return () => clearInterval(timer)
  }, [])
  return now
}
