// The three calls the board makes into the Pubky SDK (`@synonymdev/pubky`),
// behind an interface of its own so that the transport can be tested with a
// fake and the SDK is loaded only when the board first needs the network.
//
// Why a dynamic `import()`: the SDK's browser entry inlines its 2.5 MB WASM
// module as base64, so the file is about 3.5 MB and compiles the module as
// soon as it is evaluated. Imported this way it becomes a chunk of its own,
// fetched on first use, and the page around it renders without waiting for
// it. Tests never call `loadPubkySdk`, so they never load the SDK.

import type { Network } from '../config/network.ts'

/** What the transport needs from the SDK, and nothing more. */
export interface PubkySdk {
  /**
   * `pubky.client.fetch`: `fetch`, after resolving a `_pubky.<key>` host
   * through pkarr to the homeserver's endpoint. It refuses `pubky://` URLs,
   * adds a `pubky-host` header, and uses the caller's `credentials`,
   * `redirect` and `cache` as given (pubky-sdk 0.16.2,
   * `bindings/js/src/client/http.rs`); with no `credentials` at all it
   * would send cookies.
   */
  fetch(url: string, init: RequestInit): Promise<Response>

  /**
   * `resolvePubky`: `pubky<key>/<path>` as the transport URL
   * `https://_pubky.<key>/storage/<key>/<path>`. Pure string work, no
   * network. Throws on a malformed identifier.
   */
  resolvePubky(identifier: string): string

  /**
   * `pubky.getHomeserverOf`, keys in raw z-base32 both ways: the
   * homeserver's key, or `undefined` when `user` has no homeserver record.
   * Throws when the lookup fails or `user` is not a valid key.
   */
  getHomeserverOf(user: string): Promise<string | undefined>
}

/**
 * Loads the SDK and wires it for `network`: `Pubky.testnet()`, whose pkarr
 * relay is the local testnet's, or `new Pubky()` with the SDK's default
 * relays. Call it once and share the result: the SDK asks for a single
 * `Pubky` per app.
 */
export async function loadPubkySdk(network: Network): Promise<PubkySdk> {
  const { Pubky, PublicKey, resolvePubky } = await import('@synonymdev/pubky')
  const pubky = network === 'testnet' ? Pubky.testnet() : new Pubky()
  // `pubky.client` is a getter that hands out a new handle on the same
  // client each time it is read, so it is read once here.
  //
  // The SDK's objects (this client, the `PublicKey`s below) live in WASM
  // memory. wasm-bindgen registers each with a `FinalizationRegistry`, which
  // frees it once JavaScript drops it, so nothing here calls `free()`.
  const client = pubky.client
  return {
    fetch: (url, init) => client.fetch(url, init),
    resolvePubky,
    async getHomeserverOf(user) {
      const homeserver = await pubky.getHomeserverOf(PublicKey.from(user))
      return homeserver?.z32()
    },
  }
}
