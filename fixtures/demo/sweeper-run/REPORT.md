# Security audit report: t1 at be535e6

**Made-up demo findings.** This is the synthetic stand-in for a real
`security-audit` run directory in Sweepky's local demo, laid out the way
Cloudflare's `security-audit` skill lays out its `REPORT.md`. No audit was
run. The findings and this text are made up; each points at a real line of
Sweepky's own plan documents, so the demo's links resolve, and none
describes a vulnerability.

## Run

- Profile `quick`, scoped to `docs/plan/`. This is a partial pass.
- Source ref `be535e6c056b864f2f93dc64218dd418c3fc5856`.
- Execution: none. Nothing was built, run or contacted.

## Posture

The plan documents are consistent. Three wording leads need a reader to
settle.

## Confirmed findings

None.

## Needs validation

| Title | Trace | Blocker | Local next step |
|---|---|---|---|
| Made-up demo finding: the reading-key decision does not say an owner may have several installs | `docs/plan/00-overview.md:16`, Decisions (locked) | Needs a first-time reader | Ask a new reader how many reading keys an owner with two laptops has |
| Made-up demo finding: the logout order reads as one step on a quick read | `docs/plan/02-encryption-and-safety.md:68`, Device keys | Needs a reader | Ask a reader to restate the logout order |
| Made-up demo finding: the metadata limit does not say the recipient count changes over time | `docs/plan/06-verification-and-limits.md:20`, Known limits (say them in the README) | The owner's call | Compare the bullet with the README's list |

## Coverage

`docs/plan/00-overview.md`, `docs/plan/02-encryption-and-safety.md` and
`docs/plan/06-verification-and-limits.md` were read. Nothing else was.
