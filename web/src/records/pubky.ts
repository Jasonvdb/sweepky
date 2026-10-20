// Pubky public keys, ported from sweepky-core's `pubky.rs`.
//
// Records store a key as 52 characters of raw z-base32; the SDK prints it as
// `pubky<z32>`. Parsing takes either and gives the raw form. It accepts only
// the canonical spelling, so each key has exactly one string: comparing two
// `Pubky` values with `===` is comparing their key bytes, which is what 01's
// "compare by key bytes, never pubky strings" asks for, and a `Pubky` can key
// a `Map` or a `Set`.
//
// Like core, this checks the form only, not that the bytes are a valid
// Ed25519 point. That is left to the SDK, which parses the key again
// (`PublicKey.from`) before the key is used on the network.

/**
 * A key in raw, canonical z-base32. The brand (a property that exists only in
 * the type) stops a plain string from being passed where a checked key is
 * expected: the only way to get one is `parsePubky`.
 */
export type Pubky = string & { readonly __brand: 'Pubky' }

/** The length of a key in raw z-base32. */
const Z32_LEN = 52

/** The prefix the Pubky SDK prints before a key. */
const SDK_PREFIX = 'pubky'

/**
 * A canonical key: 52 characters of the z-base32 alphabet
 * (`ybndrfg8ejkmcpqxot1uwisza345h769`, in value order), the last one `y` or
 * `o`.
 *
 * Why the last one: 52 characters carry 260 bits for a 256-bit key, so the
 * last character holds one bit of the key and four padding bits that
 * decoding ignores. Only a character whose four low bits are zero is the
 * spelling an encoder writes, and in value order those are 0 (`y`) and 16
 * (`o`). So `...ewo` is canonical, and `...ewt` (17) is the same key spelt
 * with a padding bit set.
 *
 * `$` without the `m` flag matches only at the very end of the string, so a
 * trailing newline does not slip through.
 */
const CANONICAL_KEY = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{51}[yo]$/

/**
 * The key `text` names, in raw form, or `null` when it is not 52 characters
 * of lower-case z-base32 (with or without the `pubky` prefix) in canonical
 * form.
 */
export function parsePubky(text: string): Pubky | null {
  const raw = stripSdkPrefix(text)
  return CANONICAL_KEY.test(raw) ? (raw as Pubky) : null
}

/**
 * `text` without the SDK's `pubky` prefix, or `text` unchanged. The prefix is
 * stripped only when exactly 52 characters follow it, as the SDK does: a raw
 * key may itself begin with the letters "pubky" and must stay whole.
 */
function stripSdkPrefix(text: string): string {
  const rest = text.slice(SDK_PREFIX.length)
  return text.startsWith(SDK_PREFIX) && rest.length === Z32_LEN ? rest : text
}
