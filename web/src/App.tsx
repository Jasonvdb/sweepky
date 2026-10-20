// The services every page shares, the board's store and the circle choice,
// handed down through React context. main.tsx builds them once per page load
// and renders the browser router inside `App`; tests render a memory router
// inside it with a store of their own.

import { createContext, useContext, type ReactNode } from 'react'
import type { CircleSelection } from './config/circle.ts'
import type { BoardStore } from './store/boardStore.ts'
import type { BoardState } from './store/state.ts'

export interface AppServices {
  readonly store: BoardStore
  readonly circle: CircleSelection
}

const AppContext = createContext<AppServices | null>(null)

interface AppProps {
  readonly services: AppServices
  /** The router. */
  readonly children: ReactNode
}

export function App({ services, children }: AppProps) {
  return <AppContext value={services}>{children}</AppContext>
}

function useServices(): AppServices {
  const services = useContext(AppContext)
  // Only a component placed outside `App` gets here: a bug in this app,
  // never something a visitor or a homeserver can cause.
  if (services === null) throw new Error('a page component was rendered outside <App>')
  return services
}

/**
 * What `selector` picks from the board's state, rendering again when that
 * changes. Subscribing is what starts the 30 s poll (boardStore.ts), so a
 * page that reads the store is a page that polls. `selector` must give back
 * the same object for the same state, as the memoised selectors in
 * selectors.ts do, or React renders without end.
 */
export function useBoard<T>(selector: (state: BoardState) => T): T {
  return useServices().store(selector)
}

/** Which circle this page load shows, and the key its links carry. */
export function useCircle(): CircleSelection {
  return useServices().circle
}
