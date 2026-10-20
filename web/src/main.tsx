import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.tsx'
// Later sheets win ties between equally specific rules, so the general ones
// come first.
import './styles/tokens.css'
import './styles/base.css'
import './styles/buttons.css'
import './styles/sections.css'

const root = document.getElementById('root')
if (root === null) {
  throw new Error('index.html has no #root element to render into')
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
