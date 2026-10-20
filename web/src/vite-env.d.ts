/// <reference types="vite/client" />

// Make `import.meta.env` strict: reading a variable not declared below is a
// type error instead of an untyped `any`, so a misspelt name cannot pass.
interface ViteTypeOptions {
  strictImportMetaEnv: unknown
}

interface ImportMetaEnv {
  /** `"1"` selects the local Pubky testnet in development; see src/config/network.ts. */
  readonly VITE_PUBKY_TESTNET?: string
  /** The default circle's admin key, raw or `pubky`-prefixed; see src/config/circle.ts. */
  readonly VITE_SWEEPKY_CIRCLE?: string
}
