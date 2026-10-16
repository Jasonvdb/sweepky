# Security audit report: t1 at 791991b

Synthetic report in Sweepky's Cloudflare-shaped run-directory fixture,
laid out the way Cloudflare's `security-audit` skill lays out its
`REPORT.md`. The target, the findings and this text are made up for the
tests.

## Run

- Profile `quick`, scoped to `src/auth/`. This is a partial pass: a quick,
  scoped run does not cover the rest of the repository.
- Source ref `791991b2e79a7fe8371635dc377b9cc620032465`, clean worktree.
- Execution: sandboxed, source and local only. No deployed service was
  contacted.
- No prior runs. `src/http.rs` was seen and recorded as out of scope.

## Posture

Session handling is small and readable. One boundary error in the expiry
check is confirmed; one timing lead needs a deployment to settle.

## Confirmed findings

| Severity | Title | Boundary | Observed result |
|---|---|---|---|
| info | Session expiry check accepts a token during its expiry second | `Session::validate` | `validate` returned `Ok` at the token's `expires_at` second |

### Session expiry check accepts a token during its expiry second

- **Location:** `src/auth/session.rs:88`, `fn is_expired`, reached from
  `handle_request` in `src/auth/handler.rs:18`.
- **Principal:** a client whose session token is about to expire.
- **Reproduction:** set the test clock to the token's `expires_at`, then call
  `Session::validate` with that token.
- **Conditions:** the request arrives within the token's last second.
- **Result:** `validate` returned `Ok`.
- **Impact:** none beyond one extra second of a token that was valid a second
  earlier.
- **Fix:** compare with `>=` in `is_expired`.

## Needs validation

| Title | Trace | Blocker | Local next step | Deployment check |
|---|---|---|---|---|
| Session token compared with `==` | `handle_request` → `from_header` → `validate` (`src/auth/session.rs:120`) | Whether the difference can be measured over the network | Time `validate` over tokens sharing a growing prefix with the stored one | Repeat the measurement from a host on the same network as a test deployment |

## Hardening notes

- `safe_redirect` keeps only paths with a single leading `/`, so the sign-in
  redirect cannot leave the site.

## Coverage

From `coverage-ledger.json`: 3 units with candidates, 0 covered without
one, 0 blocked, 0 deferred, and 1 out of scope (`src/http.rs`). The final
coverage critic found no gap inside `src/auth/`.
