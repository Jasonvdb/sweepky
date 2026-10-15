# 06 — Verification, known limits and references

## Verification

- **Rust:** `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run`, `cargo deny check`. Core unit tests: record (de)serialisation with unknown fields and kinds, path builders, target pinning, pad-to-bucket, manifest binding, feed parsing, trust labels.
- **Interop:** `web/` test decrypts `fixtures/rust.age`; a Rust test decrypts `fixtures/typage.age`; C2SP CCTV vectors on both sides.
- **End to end (local testnet, `#[pubky_testnet::test]`):** identities A (admin/owner), B (circle sweeper), C (stranger). Circle = {A, B}. A posts an `open` bounty with two targets. B submits a synthetic sweep; C submits another. A pulls: B's sweep is `circle` and merged; C's sweep is discovered via the testnet homeserver's `/events/` feed, labelled `unknown`, and lands in `untrusted/`. A confirms one of C's findings (local only, no public record yet), then resolves it, and C's label becomes `known: 1`. A second sweep submitted with a hand-written `findings.json` (no Cloudflare output) packages and decrypts identically. A device key added after a sweep cannot decrypt it. `logout` invalidates the grant. The events cursor survives a restart.
- **Board:** sign in on the testnet (approved with `sweepky dev approve`), key published at `keys/web-*.json`, decrypt the e2e sweep, trust badges correct; public view without a session shows a `running`→`done` transition within one poll and a stranger's sweep arriving via the feed.
- **Sweeper safety:** inside an `init` project, the agent cannot `curl` out, cannot read `~/.config/sweepky/`, and `sweepky submit` still succeeds.
- **Local demo acceptance (P5):** `scripts/demo-local.sh` reproduces the whole flow from a clean testnet; the board at `localhost:5173`, signed in as the dev identity, decrypts the demo sweep; the terminal `watch` shows the same. Jason approves before anything is deployed.
- **Hygiene after each session:** drop leaked `pubky_test_*` databases created during the session; confirm `git status` is clean and nothing from the local demo report is tracked.
- **Later (post-approval):** the production one-write check under `/pub/sweepky/`; `pubky/vibes` CI validates `vibe.json` and reaches `hosted.url`.

## Known limits (say them in the README)

- No age implementation has an independent audit; the underlying noble/RustCrypto libraries do.
- Metadata is public: paths, timing, padded sizes, recipient count (reveals circle size).
- No revocation or forward secrecy: removed members keep access to past ciphertext, which is public forever. Won't-fix findings stay out of the system.
- Production writes are permanent in practice (event history, backups).
- Static review only → many `needs_validation` findings until a sandboxed runner exists.
- Pro/Max 5-hour windows: a `standard` whole-repo sweep can die mid-phase and lose unvalidated candidates; scope with `paths` or use `quick`.
- Open-bounty discovery sees only homeservers on the watch list.
- Each developer runs their own unmodified Claude Code on their own plan. The tool never reads or proxies Claude credentials.

## Local environment (this machine)

- Testnet: `TEST_PUBKY_CONNECTION_STRING='postgres://jason@localhost:5432/postgres' cargo run -p pubky-testnet` from the `pubky-homeserver` checkout (brew `postgresql@18`; no Docker needed). Ports: pkarr relay `15411`, HTTP relay `15412`, homeserver `6286`; homeserver key `8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo`. Ephemeral DB per run.
- Rust: `Pubky::testnet()`. JS: `Pubky.testnet()`. Verify the grant-flow relay default under testnet in P4.
- Ring stand-in: `sweepky dev identity new <name>` (keypair + signup on the testnet homeserver) and `sweepky dev approve <pubkyauth-url> --as <name>` (wraps `PubkySigner::approve_auth`). The Pubky Ring Simulator (`simulator.pubkyring.app`, Shortcut mode) is a zero-code alternative.
- Toolchain: rustc/cargo 1.96, node 24, pnpm 10, psql 18.

## Key references

- Cloudflare skill (local install `~/.claude/skills/security-audit/`, upstream `c1c8a8c`): `SKILL.md` output dir (line 51), profiles and scoped runs (111–116), sandbox requirements (33–40), prior-run rules we deliberately don't use (92–105); `report-schema.json` (`fingerprint` is the dedupe key).
- Pubky: `pubky-homeserver/examples/rust/2-auth_flow/client.rs` (CLI grant auth); `pubky-sdk/src/actors/signer/auth.rs` (`approve_auth`); `pubky-sdk/bindings/js/src/pubky.rs` (`startGrantAuthFlow`, `Pubky.testnet`); `pubky-homeserver/src/client_server/routes/events.rs` (the `/events/` feed); `agent-skills/skills/pubky/references/{auth.md,sdk-rust.md,sdk-js.md,reference-apps.md}`.
- Frontend: `pubky/pubky-app-templates/basic-pubky-app`; `pubky-marketplace/src/hooks/useStepUpReauth/useStepUpReauth.ts` (QR/deeplink); `vibes/apps/web/src/app/globals.css`, `vibes/SKILL-vibe-self-host.md`, `vibes/packages/schema/src/vibe.ts`.
- Later: `paykit-rs/paykit-lib/src/{pubky_routing.rs,payment_reference.rs}`; `locks/docs/ADRs/{0001,0017}*.md`.
- External: c2sp.org/age · FiloSottile/typage · str4d/rage · code.claude.com/docs/en/sandboxing · code.claude.com/docs/en/legal-and-compliance.
