// A circle admin nobody has ever published: a fresh key has no pkarr record,
// so the board's store asks the relay about it and never reaches a
// homeserver. The specs need no testnet data and write none.

import { Keypair } from '@synonymdev/pubky'

/** A new random Pubky key in raw z-base32, as `?circle=` takes it. */
export function randomCircle(): string {
  return Keypair.random().publicKey.z32()
}
