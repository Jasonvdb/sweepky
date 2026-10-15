# P2d — `sweepky-cli`: login through Pubky Ring

## Goal

`login` option A, the default: the Pubky Ring sign-in through a loopback page. This phase also completes the end-to-end test from [06](../06-verification-and-limits.md#verification) with its login-option parts, its check that two writers can share one saved Ring token, and its check that `logout` leaves the saved token unable to restore. It builds on [P2a](P2a-cli-identity.md) for the network config with the relay URL, the shared tail of `login`, `logout`, the config directories, the writers' lock and the capability constant, and on [P2c](P2c-cli-pull-done.md) for the end-to-end test.

## Build

- **`login` (option A, default):** `PubkyGrantAuthFlow::builder(caps, signin, "sweepky-cli").relay(cfg.relay).client(...)`, never the convenience constructor; capabilities exactly `/pub/sweepky/:rw` with the trailing slash; default grant format, no encryption scopes. A one-page loopback site (random port and path, one flow, timeout) with the QR, a copy-link button and live status, opened in the default browser; the same URL and a terminal QR as fallback. The page is a static HTML string with the QR rendered server-side as SVG by `qrcode`, no JS framework. After approval: check the granted capabilities include write on `/pub/sweepky/`, else sign out with a clear message; store the SDK's exported grant token in a 0600 file; show the expiry (two years) and warn within 30 days of it on later runs.

## Done when

- Both login options covered in the same test, as in [06](../06-verification-and-limits.md#verification): loopback page fetched (QR and link present, status "waiting"), relay host asserted local (the authorization URL's relay is the testnet relay), in-process approval (`PubkySigner::approve_auth`), status flip (to "approved"), the resulting grant writing a record (its `keys/<deviceId>.json`), a narrowed approval refused (read-only through `approve_auth_with_capabilities`, with the expected message), wrong loopback path 404.
- These parts run in the test that [P2c](P2c-cli-pull-done.md) landed, with A and A's second install switched to the default Ring flow; B and C stay on `--identity`.
- In A's first install, which holds one saved Ring token, two writer commands run concurrently and both succeed: `circle add` of a synthetic pubky the test uses nowhere else, and `keys revoke` of the key the test injected under A's `keys/`. The writers' lock runs them one at a time, so neither loses its bearer to the other's restore ([02](../02-encryption-and-safety.md#device-keys)). Afterwards `circle.json` lists the new member and the injected key has `revokedAt` set. Both commands run after the checks P2c landed and before `logout`, so they change no group, credit or label the test asserts.
- After `logout`, restoring the Ring token that A saved at login returns 401.
- `cargo clippy -- -D warnings`, `cargo deny check` and `cargo nextest run` clean.

## Resolved questions

- **Client id.** The SDK validates only non-empty and up to 253 characters; Ring shows it as the app name on the approval screen and in its grant list. It is `sweepky-cli`, and it never changes between releases because saved sessions are compared against it. The board uses a different id in E4 so the two grants are distinguishable in Ring.

## Notes

- The SDK's convenience constructor sets no relay, so a testnet login through it would post its approval through the production relay ([03](../03-cli-and-skill.md#two-ways-to-log-in)).
- The authorization URL carries the relay channel secret, so it is never logged or written to disk ([03](../03-cli-and-skill.md#two-ways-to-log-in)).
- The SDK hands the grant token back as a plain `String`; move it into a `SecretString` at once and write the 0600 file from that ([03](../03-cli-and-skill.md#rust-conventions-teaching-notes-keep-in-code-comments)).
