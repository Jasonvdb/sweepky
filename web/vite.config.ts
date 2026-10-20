/// <reference types="vitest/config" />
// The reference above adds vitest's `test` key to Vite's config type, so the
// test runner's settings typecheck under `tsc -b` alongside the build's.
import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'
import { assertProductionBuildEnv } from './src/config/network.ts'

// The directory holding this file. Vite reads `.env` files from `envDir`, and
// the assertion below reads them from the same place, so the two cannot
// disagree about what reached the build, whatever directory Vite runs from.
const webDir = fileURLToPath(new URL('.', import.meta.url))

export default defineConfig(({ mode }) => {
  // `loadEnv` merges the `.env` files for this mode with the shell's own
  // `VITE_` variables, so neither can slip the testnet switch into a
  // production build.
  assertProductionBuildEnv(mode, loadEnv(mode, webDir))

  return {
    envDir: webDir,
    plugins: [react()],
    test: {
      // Unit tests under src/ only, so browser specs kept outside it never
      // load under vitest.
      include: ['src/**/*.test.{ts,tsx}'],
      // Plain Node: component tests render through react-dom/server, so no
      // DOM emulation such as jsdom is installed.
      environment: 'node',
    },
  }
})
