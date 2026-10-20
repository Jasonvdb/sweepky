import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter } from 'react-router'
// The DOM build of `RouterProvider`: it updates the page through react-dom's
// `flushSync` where the plain 'react-router' one cannot.
import { RouterProvider } from 'react-router/dom'
import { App, type AppServices } from './App.tsx'
import { selectCircle } from './config/circle.ts'
import { networkFromEnv } from './config/network.ts'
import { loadPubkySdk } from './net/sdk.ts'
import { createSdkTransport } from './net/sdkTransport.ts'
import { routes } from './router.tsx'
import { browserScheduler, createBoardStore } from './store/boardStore.ts'
// Later sheets win ties between equally specific rules, so the general ones
// come first.
import './styles/tokens.css'
import './styles/base.css'
import './styles/buttons.css'
import './styles/sections.css'
import './styles/layout.css'
import './styles/board.css'

const root = document.getElementById('root')
if (root === null) {
  throw new Error('index.html has no #root element to render into')
}

// Chosen once per page load: the store is built for one circle, and links
// carry `?circle=` so moving between pages keeps it.
const circle = selectCircle(window.location.search, import.meta.env.VITE_SWEEPKY_CIRCLE)
const network = networkFromEnv(import.meta.env)
const services: AppServices = {
  circle,
  store: createBoardStore({
    admin: circle.admin,
    // Loads the SDK's chunk on the first poll only (net/sdk.ts).
    loadTransport: async () => createSdkTransport(await loadPubkySdk(network)),
    scheduler: browserScheduler,
    now: Date.now,
  }),
}

createRoot(root).render(
  <StrictMode>
    <App services={services}>
      <RouterProvider router={createBrowserRouter(routes)} />
    </App>
  </StrictMode>,
)
