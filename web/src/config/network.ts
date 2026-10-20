// Which Pubky network the board reads from. Production is the default; the
// local testnet (`Pubky.testnet()`, pkarr relay on port 15411) is opt-in for
// development only, and a production build refuses to be made with the switch
// set at all (docs/plan/04-board.md, Stack).
//
// vite.config.ts imports this module and runs in Node, where `import.meta.env`
// does not exist, so nothing here reads it: callers pass the environment in.

export type Network = 'production' | 'testnet'

/** The part of `import.meta.env` the switch reads. */
type BundleEnv = { readonly PROD: boolean; readonly VITE_PUBKY_TESTNET?: string }

/**
 * The network a bundle talks to: the testnet only when `VITE_PUBKY_TESTNET` is
 * exactly `"1"` and the bundle is not a production one. Pass `import.meta.env`.
 *
 * The `PROD` check is a second lock behind `assertProductionBuildEnv`: a
 * production bundle can never pick the testnet, whatever reached the build.
 */
export function networkFromEnv(env: BundleEnv): Network {
  return !env.PROD && env.VITE_PUBKY_TESTNET === '1' ? 'testnet' : 'production'
}

/**
 * vite.config.ts calls this with the mode and the environment from Vite's
 * `loadEnv`. A production build fails if `VITE_PUBKY_TESTNET` is defined with
 * any value, `0` and the empty string included: only an unset variable is an
 * unambiguous "no".
 */
export function assertProductionBuildEnv(
  mode: string,
  env: Readonly<Record<string, string | undefined>>,
): void {
  if (mode === 'production' && env.VITE_PUBKY_TESTNET !== undefined) {
    throw new Error(
      'VITE_PUBKY_TESTNET must be unset for a production build: it selects the local testnet and is for development only.',
    )
  }
}
