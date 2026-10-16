# Triage notes

Synthetic notes in Sweepky's common-format run-directory fixture.

- Token path: `handle_request` → `from_header` → `validate`. `validate`
  checks expiry first, then compares the token.
- `is_expired` uses `>`; the doc comment above it asks for `>=`. Reported as
  `session-expiry-off-by-one`.
- `Request::header` compares header names with `==`. Header names are
  public, so this is probably harmless. Reported as
  `auth-token-compare-timing` so that someone measures it.
- `safe_redirect` refuses `//host` and anything without a leading `/`.
  Nothing to report.
