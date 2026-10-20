// The app's routes (04, Views), all inside the shared layout. main.tsx serves
// them from the browser's address; tests from a memory router.
//
// The static host must answer every path with index.html (a SPA fallback),
// so a deep link such as /board reaches this router at all; that is set
// where the app is hosted (P4, Notes).

import type { RouteObject } from 'react-router'
import { Layout } from './components/Layout.tsx'
import { Board } from './routes/Board.tsx'
import { BountyPage } from './routes/BountyPage.tsx'
import { CirclePage } from './routes/CirclePage.tsx'
import { Landing } from './routes/Landing.tsx'
import { NotFound } from './routes/NotFound.tsx'
import { SweepPage } from './routes/SweepPage.tsx'

export const routes: RouteObject[] = [
  {
    element: <Layout />,
    children: [
      { index: true, element: <Landing /> },
      { path: 'board', element: <Board /> },
      { path: 'b/:owner/:id', element: <BountyPage /> },
      { path: 's/:sweeper/:id', element: <SweepPage /> },
      { path: 'circle', element: <CirclePage /> },
      { path: '*', element: <NotFound /> },
    ],
  },
]
