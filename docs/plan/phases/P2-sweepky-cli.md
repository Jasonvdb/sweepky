# P2 — `sweepky-cli`

## Goal

The `sweepky` binary, end to end against a local testnet, including open-bounty discovery and credits.

## Build

- **`login` (option A, default):** `PubkyGrantAuthFlow::builder(caps, signin, "sweepky-cli").relay(cfg.relay).client(...)`, never the convenience constructor; capabilities exactly `/pub/sweepky/:rw` with the trailing slash; default grant format, no encryption scopes. A one-page loopback site (random port and path, one flow, timeout) with the QR, a copy-link button and live status, opened in the default browser; the same URL and a terminal QR as fallback. The page is a static HTML string with the QR rendered server-side as SVG by `qrcode`, no JS framework. After approval: check the granted capabilities include write on `/pub/sweepky/`, else sign out with a clear message; store the SDK's exported grant token in a 0600 file; show the expiry (two years) and warn within 30 days of it on later runs.
- **`post --open`:** finds the starting cursor on the owner's homeserver (non-live event stream, `reverse`, `limit 1` after the bounty PUT) and on every other watched homeserver (exponential then binary search with `limit=1`), and writes `bounties/<id>.discovered.json`.
- **`pull`:** roster polling with reverse paged listings, 404 as empty, conditional re-GETs of open bounties and `running` sweeps, cached homeserver resolution; the `/events/` watcher over the watch list through the SDK's HTTP client, 1000 per page, URI dedupe, DEL handling, re-fetch through pkarr-resolved storage, cursor advanced after each batch and persisted; trust labels from roster plus credits; unknown-key alarm; decrypt to `~/.local/share/sweepky/<bounty>/`; group findings by location keeping `reportedBy`; untrusted content into `untrusted/`; append accepted strangers' sweeps to `bounties/<id>.discovered.json`.
- **`done <bounty> [--credit] [--no-credit]`:** proposes credits from the groups, never including the owner (`--credit <own pubky>` is refused with a one-line reason), confirms interactively unless flags settle it, rewrites the bounty with `status: "done"`, `doneAt`, `credits`, preserving unknown fields. Last writer wins, deliberately.

## Done when

- The end-to-end test in [06](../06-verification-and-limits.md#verification) passes: identities A (owner), B (circle sweeper), C (stranger); the open bounty with its `discovered.json`; B and C running `run <bounty>` and `submit`; C found through `/events/`, labelled `unknown`, attributed but kept in `untrusted/`, and appended to `discovered.json`; the shared location grouped with `reportedBy` {B, C} and the shared-id pair kept apart; the injected unknown key making `pull` alarm; `done --credit <A>` refused; `done` proposing {B, C}; C at `known: 1` afterwards; Cloudflare-format and common-format sweeps both grouping; the later device key unable to decrypt; the second install of A decrypting the third sweep; `logout` leaving the saved token unable to restore (401); the cursor surviving a restart.
- Both login options covered in the same test, as in [06](../06-verification-and-limits.md#verification): loopback page fetched, relay host asserted local, in-process approval, status flip, a narrowed approval refused, `--identity` for B and C, wrong loopback path 404.
- Clippy, deny, nextest clean.

## Resolved questions

- **Starting cursor.** `/events/` has no "latest" shortcut: `reverse` is parsed and ignored, a timestamp cursor must match a row exactly, `limit` caps at 1000, and there is no max-id endpoint, so paging from zero on production is not viable. Resolution above: the owner's own event stream gives the event id of the bounty PUT; other homeservers are binary-searched once with `limit=1`.
- **Client id.** The SDK validates only non-empty and up to 253 characters; Ring shows it as the app name on the approval screen and in its grant list. It is `sweepky-cli`, and it never changes between releases because saved sessions are compared against it. The board uses a different id in E4 so the two grants are distinguishable in Ring.

## Notes

- `done` is the only command that rewrites an existing bounty record; test that a bounty posted by a newer client with extra fields survives it intact. `pull` rewrites only `discovered.json`.
