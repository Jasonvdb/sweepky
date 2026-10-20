import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.tsx'

const root = document.getElementById('root')
if (root === null) {
  throw new Error('index.html has no #root element to render into')
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
