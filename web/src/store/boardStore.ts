// The board's store: a zustand store whose state is the reducer's
// `BoardState` (state.ts), fed by the poller (poller.ts) every 30 s.
//
// It polls only while someone is watching: the first subscriber (a view's
// `useBoardStore(selector)`, the landing hero's or the board's) starts the
// poll, and when the last one leaves, the poll stops. So the hero and the
// board share one poll, and a page with neither sends nothing.
//
// The timer and the clock are passed in, so tests run polls by hand with no
// real timers, and the transport is loaded on the first poll only: with no
// circle selected, nothing is loaded and nothing is sent.

import { create, type StoreApi, type UseBoundStore } from 'zustand'
import type { Transport } from '../net/transport.ts'
import type { Pubky } from '../records/pubky.ts'
import type { BoardAction } from './actions.ts'
import { POLL_INTERVAL_MS, pollOnce } from './poller.ts'
import { boardReducer } from './reducer.ts'
import { initialBoardState, type BoardState } from './state.ts'

/** Runs a callback later: `setTimeout` in the browser, a fake in tests. */
export interface Scheduler {
  schedule(run: () => void, delayMs: number): () => void
}

export interface BoardStoreDeps {
  /** Whose circle to show, or `null` for none. */
  readonly admin: Pubky | null
  /** Called once, on the first poll: the SDK is loaded only when it is needed (net/sdk.ts). */
  readonly loadTransport: () => Promise<Transport>
  readonly scheduler: Scheduler
  /** Milliseconds since 1970. */
  readonly now: () => number
}

/** The hook views call with a selector, and the store's own `getState` and `subscribe`. */
export type BoardStore = UseBoundStore<StoreApi<BoardState>>

/** The browser's timer as a `Scheduler`. */
export const browserScheduler: Scheduler = {
  schedule(run, delayMs) {
    const handle = setTimeout(run, delayMs)
    return () => clearTimeout(handle)
  },
}

export function createBoardStore(deps: BoardStoreDeps): BoardStore {
  // zustand 5's `create` hands its initializer the store's `api`; replacing
  // `api.subscribe` there (as zustand's own middleware does) means every
  // subscriber, the React hook's included, goes through the count below.
  return create<BoardState>()((_set, _get, api) => {
    const poller = createPollLoop(api, deps)
    const subscribe = api.subscribe
    let subscribers = 0
    api.subscribe = (listener) => {
      const unsubscribe = subscribe(listener)
      subscribers += 1
      if (subscribers === 1) poller.start()
      let subscribed = true
      return () => {
        // React may call an unsubscribe twice; it counts once.
        if (!subscribed) return
        subscribed = false
        unsubscribe()
        subscribers -= 1
        if (subscribers === 0) poller.stop()
      }
    }
    return initialBoardState(deps.admin)
  })
}

/** The poll on its timer: one pass at once, then one 30 s after each ends. */
function createPollLoop(api: StoreApi<BoardState>, deps: BoardStoreDeps) {
  let transport: Promise<Transport> | null = null
  /** The running pass's controller, or `null` between passes. */
  let running: AbortController | null = null
  let cancelTimer: (() => void) | null = null
  let watching = false

  const dispatch = (action: BoardAction): void => {
    // `true` replaces the state rather than merging it: the reducer gives
    // back the whole next state, the same object when nothing changed, and
    // zustand then tells nobody.
    api.setState(boardReducer(api.getState(), action), true)
  }

  /** The transport, loaded on first use and kept; `null` when the load failed. */
  const loadTransportOnce = async (): Promise<Transport | null> => {
    transport ??= deps.loadTransport()
    try {
      return await transport
    } catch {
      transport = null
      return null
    }
  }

  const runPass = async (): Promise<void> => {
    cancelTimer = null
    const controller = new AbortController()
    running = controller
    try {
      const loaded = await loadTransportOnce()
      // A transport that could not load (the SDK's chunk did not arrive)
      // is tried again next pass. Anything `pollOnce` throws is a bug, not
      // the network: every answer reaches it as a value, so it is left to
      // surface as an unhandled rejection.
      if (loaded === null) return
      await pollOnce({
        transport: loaded,
        getState: api.getState,
        dispatch,
        now: deps.now,
        signal: controller.signal,
      })
    } finally {
      running = null
      // A pass cut short by `stop` and wanted again by a quick `start`
      // runs again at once; otherwise the next waits the interval.
      if (watching) schedule(controller.signal.aborted ? 0 : POLL_INTERVAL_MS)
    }
  }

  const schedule = (delayMs: number): void => {
    cancelTimer = deps.scheduler.schedule(() => void runPass(), delayMs)
  }

  return {
    start(): void {
      if (api.getState().admin === null) return
      watching = true
      // A pass still finishing after a `stop` schedules the next itself.
      if (running === null && cancelTimer === null) void runPass()
    },
    stop(): void {
      watching = false
      cancelTimer?.()
      cancelTimer = null
      running?.abort()
    },
  }
}
