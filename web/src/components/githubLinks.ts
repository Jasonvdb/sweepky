// Links from a bounty's targets to GitHub. A target's `repo`, revisions and
// number are whatever the bounty's owner wrote, and the owner may be a
// stranger, so a link is built only when every part has a shape that can
// name nothing but a GitHub page: an allowlist, never an escape. Anything
// else gets no link at all and is shown as text, so a `javascript:` string,
// another host or a path with a `?` in it never reaches an `href`.

/**
 * `github.com/<owner>/<name>` and nothing more. An owner is up to 39 letters,
 * digits and hyphens, not starting with a hyphen; a name is up to 100
 * letters, digits, `.`, `_` and `-` (`.` and `..` are refused below). No
 * other character, so the path needs no encoding and cannot reach a query, a
 * fragment or another directory. Lower-case `github.com` only: the host is
 * matched as written, never folded.
 */
const GITHUB_REPO = /^github\.com\/([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]{1,100})$/

/** A full SHA-1 object name in lower case, which GitHub serves; a SHA-256 name gets no link. */
const SHA1_HEX = /^[0-9a-f]{40}$/

/** The GitHub page a revision link opens: the tree at it, or the commit itself. */
export type RevPage = 'tree' | 'commit'

/** `https://github.com/<owner>/<name>/<page>/<sha>`, or `null` unless `repo` and `sha` are both safe. */
export function githubRevUrl(repo: string, sha: string, page: RevPage): string | null {
  const base = githubRepoUrl(repo)
  if (base === null || !SHA1_HEX.test(sha)) return null
  return `${base}/${page}/${sha}`
}

/**
 * `https://github.com/<owner>/<name>/pull/<number>`, or `null` unless `repo`
 * is safe and `number` a whole number from 1 that a double holds exactly.
 * `number` is `unknown` because it comes straight from a record's JSON.
 */
export function githubPullUrl(repo: string, number: unknown): string | null {
  const base = githubRepoUrl(repo)
  if (base === null || !isPullNumber(number)) return null
  return `${base}/pull/${number}`
}

/** Whether `value` is a pull request number: a safe integer of 1 or more. */
export function isPullNumber(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0
}

function githubRepoUrl(repo: string): string | null {
  const match = GITHUB_REPO.exec(repo)
  const name = match?.[2]
  if (match === null || name === undefined || name === '.' || name === '..') return null
  return `https://${repo}`
}
