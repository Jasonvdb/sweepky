# Careful review: t1 at 791991b

Synthetic report in Sweepky's common-format run-directory fixture. The
target, the findings and this text are made up for the tests.

## Scope

- Target `t1`, commit `791991b2e79a7fe8371635dc377b9cc620032465`.
- Read `src/auth/` and `src/http.rs`. Nothing was built or run: this is a
  static review.

## Findings

Both findings are `needs_validation`. Neither has a severity or a
confidence, because neither was shown with a local result.

| Id | Where | Summary |
|---|---|---|
| `session-expiry-off-by-one` | `src/auth/session.rs:88`, `fn is_expired` | A session still counts as valid during its expiry second |
| `auth-token-compare-timing` | `src/http.rs:12`, `fn header` | Header names looked up with a short-circuiting comparison |

## Not covered

- `src/lib.rs`, which only declares modules.
- Anything that needs the service running.
