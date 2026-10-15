# 06 — Verification, known limits and references

## Verification

- **Rust:** `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run`, `cargo deny check`. Core unit tests: record (de)serialisation with unknown fields and kinds, bounty rewrite preserving unknown fields, path builders, target pinning, pad-to-bucket, manifest binding, feed parsing, trust labels from roster plus credits, C2SP CCTV age vectors.
- **End to end (local testnet, `#[pubky_testnet::test]`):** identities A (admin/owner), B (circle sweeper), C (stranger). Circle = {A, B}. A posts an `open` bounty with two targets. B submits a synthetic sweep; C submits another that shares one finding `id` with B's. A pulls: B's sweep is `circle` and merged; C's sweep is discovered via the testnet homeserver's `/events/` feed, labelled `unknown`, and lands in `untrusted/`; the merged finding lists both B and C as reporters. A runs `done`: the CLI proposes credits {B, C}, A accepts, the bounty record is rewritten with `status: "done"` and both credits, and C's label becomes `known: 1` on the next pull. One of the two sweeps uses Cloudflare-format output and the other a hand-written common-format `findings.json`, and both decrypt and merge. A device key published after a sweep cannot decrypt it. A second CLI install of A, logged in before a third sweep, can decrypt that third sweep. `logout` invalidates the grant. The events cursor survives a restart.
- **Board:** public view against the testnet shows a `running`→`done` sweep transition within one poll, a stranger's sweep arriving via the feed with the `unknown` badge, and the bounty flipping to done with both credits and C's badge becoming `known: 1`. No sign-in exists to test.
- **Sweeper safety:** inside an `init` project, the agent cannot `curl` out, cannot read `~/.config/sweepky/`, and `sweepky submit` still succeeds.
- **Local demo acceptance (P5):** `scripts/demo-local.sh` reproduces the whole flow from a clean testnet; `sweepky pull` as the owner prints every finding from the demo report; the board at `localhost:5173` shows the public state including the done bounty and its credits; the terminal `watch` shows the same. Jason approves before anything is deployed.
- **Hygiene after each session:** drop leaked `pubky_test_*` databases created during the session; confirm `git status` is clean and nothing from the local demo report is tracked.
- **Later (post-approval):** the production one-write check under `/pub/sweepky/`; `pubky/vibes` CI validates `vibe.json` and reaches `hosted.url`.

## Known limits (say them in the README)

- Only the owner can read findings. The circle, and everyone else, sees only that sweeps happened and who was credited.
- No age implementation has an independent audit; the underlying RustCrypto libraries do.
- Metadata is public: paths, timing, padded sizes, recipient count (reveals how many devices the owner has).
- No forward secrecy: the ciphertext is public forever, and whoever holds the owner's key file later can read every sweep encrypted to it. Won't-fix findings stay out of the system.
- Losing the owner's key file loses sweeps not yet pulled; pulled sweeps are on local disk.
- Production writes are permanent in practice (event history, backups).
- Static review only → many `needs_validation` findings until a sandboxed runner exists.
- Pro/Max 5-hour windows: a `standard` whole-repo sweep can die mid-phase and lose unvalidated candidates; scope with `paths` or use `quick`.
- Open-bounty discovery sees only homeservers on the watch list.
- Credits are per bounty, not per finding, so a sweeper's public record says how many bounties they helped on and nothing about severity.
- Each developer runs their own unmodified Claude Code on their own plan. The tool never reads or proxies Claude credentials.

## Local environment (this machine)

- Testnet: `TEST_PUBKY_CONNECTION_STRING='postgres://jason@localhost:5432/postgres' cargo run -p pubky-testnet` from the `pubky-homeserver` checkout (brew `postgresql@18`; no Docker needed). Ports: pkarr relay `15411`, HTTP relay `15412`, homeserver `6286`; homeserver key `8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo`. Ephemeral DB per run.
- Rust: `Pubky::testnet()`. JS: `Pubky.testnet()`.
- Ring stand-in: `sweepky login --signer <name>` (testnet only) makes a local keypair, signs up on the testnet homeserver (open signup mode) and holds the session directly via `PubkySigner`. The Ring QR flow itself is exercised only in the automated end-to-end test, which approves the printed auth URL in-process with `PubkySigner::approve_auth`, and manually against real Pubky Ring once a production homeserver is in play. The Ring repo has a simulator, but it is unverified against a local testnet and the plan does not depend on it.
- Several identities in one script: `SWEEPKY_HOME=<dir>` overrides `~/.config/sweepky/` and `~/.local/share/sweepky/`.
- Toolchain: rustc/cargo 1.96, node 24, pnpm 10, psql 18.

## Key references

- Cloudflare skill (local install `~/.claude/skills/security-audit/`, upstream `c1c8a8c`): `SKILL.md` output dir (line 51), profiles and scoped runs (111–116), sandbox requirements (33–40), prior-run rules we deliberately don't use (92–105); `report-schema.json` (`fingerprint` is the dedupe key).
- Pubky access model: `pubky-homeserver/pubky-homeserver/src/client_server/auth/authorization.rs` (`has_read_permission`: `/pub/` world-readable, `/priv/` owner-session only); `pubky-homeserver/examples/rust/2-auth_flow/client.rs` (CLI grant auth); `pubky-sdk/src/actors/signer/auth.rs` (`approve_auth`); `pubky-sdk/bindings/js/src/pubky.rs` (`Pubky.testnet`); `pubky-homeserver/src/client_server/routes/events.rs` (the `/events/` feed); `agent-skills/skills/pubky/references/{auth.md,sdk-rust.md,sdk-js.md,reference-apps.md}`.
- Why not Noise: `paykit-rs/paykit-lib/src/noise_key.rs` (Noise key derived from the identity secret, which Ring never hands to apps); `pubky-noise/README.md` (handshake-then-transport channel).
- Frontend: `pubky/pubky-app-templates/basic-pubky-app`; `vibes/apps/web/src/app/globals.css`, `vibes/SKILL-vibe-self-host.md`, `vibes/packages/schema/src/vibe.ts`. For E4 later: `pubky-marketplace/src/hooks/useStepUpReauth/useStepUpReauth.ts` (QR/deeplink).
- Later: `paykit-rs/paykit-lib/src/{pubky_routing.rs,payment_reference.rs}`; `locks/docs/ADRs/{0001,0017}*.md`.
- External: c2sp.org/age · str4d/rage · FiloSottile/typage (E4) · code.claude.com/docs/en/sandboxing · code.claude.com/docs/en/legal-and-compliance.
