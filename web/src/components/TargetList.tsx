// A bounty's targets, each at the revision it is pinned to (01, "Target
// kinds"), with a link to GitHub where githubLinks.ts can build a safe one
// and, under each, the sweeps whose records name it.
//
// The parser checks only a target's `id` and `kind` (records/parse.ts), so
// the rest is read here, as core's `Target::known` reads it: a kind this
// build does not know, or a known kind whose fields are missing or of the
// wrong shape, is a placeholder, never a guess. Every value shown is a
// stranger's text and goes through StrangerText.

import type { Target } from '../records/parse.ts'
import type { SweepView } from '../store/selectors.ts'
import { sweepKey } from '../store/state.ts'
import { githubPullUrl, githubRevUrl, isPullNumber } from './githubLinks.ts'
import { StrangerText } from './StrangerText.tsx'
import { SweepLink, SweepStatus } from './SweeperTimeline.tsx'
import { TrustBadge } from './TrustBadge.tsx'

/** One target as this page reads it. */
type TargetView =
  | {
      readonly kind: 'repo'
      readonly repo: string
      readonly rev: string
      readonly paths: readonly string[]
    }
  | { readonly kind: 'commit'; readonly repo: string; readonly rev: string }
  | {
      readonly kind: 'pr'
      readonly repo: string
      readonly number: number
      readonly head: string
      readonly base: string
      readonly mergeBase: string
    }
  /** A kind this build does not know. */
  | { readonly kind: 'unknown' }
  /** A known kind whose fields do not read. */
  | { readonly kind: 'unreadable' }

/** A git object name as core's `GitSha` takes it: 40 or 64 lower-case hex characters. */
const GIT_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/

function readTarget({ kind, fields }: Target): TargetView {
  const text = (key: string): string | null => {
    const value = fields.get(key)
    return typeof value === 'string' && value !== '' ? value : null
  }
  const sha = (key: string): string | null => {
    const value = text(key)
    return value !== null && GIT_SHA.test(value) ? value : null
  }
  const repo = text('repo')
  switch (kind) {
    case 'repo': {
      const rev = sha('rev')
      const paths = readPaths(fields.get('paths'))
      if (repo === null || rev === null || paths === null) break
      return { kind, repo, rev, paths }
    }
    case 'commit': {
      const rev = sha('rev')
      if (repo === null || rev === null) break
      return { kind, repo, rev }
    }
    case 'pr': {
      const number = fields.get('number')
      const [head, base, mergeBase] = [sha('head'), sha('base'), sha('mergeBase')]
      if (repo === null || !isPullNumber(number)) break
      if (head === null || base === null || mergeBase === null) break
      return { kind, repo, number, head, base, mergeBase }
    }
    default:
      return { kind: 'unknown' }
  }
  return { kind: 'unreadable' }
}

/** `paths` as a list of strings; absent is the whole tree, anything else does not read. */
function readPaths(value: unknown): readonly string[] | null {
  if (value === undefined) return []
  if (!Array.isArray(value) || !value.every((path) => typeof path === 'string')) return null
  return value
}

/** A sweep of the bounty with the target ids its record names. */
export interface TargetedSweep {
  readonly view: SweepView
  readonly targets: readonly string[]
}

interface TargetListProps {
  readonly targets: readonly Target[]
  /** The bounty's timeline, oldest start first. */
  readonly sweeps: readonly TargetedSweep[]
}

export function TargetList({ targets, sweeps }: TargetListProps) {
  return (
    <div className="target-list">
      {targets.map((target) => (
        <article key={target.id} className="card target">
          <h3 className="target__heading">
            <span className="mono">{target.id}</span> <StrangerText text={target.kind} />
          </h3>
          <TargetPin view={readTarget(target)} />
          <TargetSweeps sweeps={sweeps.filter((sweep) => sweep.targets.includes(target.id))} />
        </article>
      ))}
    </div>
  )
}

/** What the target is pinned to, and its GitHub link when one is safe. */
function TargetPin({ view }: { readonly view: TargetView }) {
  switch (view.kind) {
    case 'repo':
      return (
        <>
          <dl className="target__pin">
            <Field term="Repository" value={view.repo} />
            <Field term="Revision" value={view.rev} />
            <dt>Paths</dt>
            {view.paths.length === 0 ? (
              <dd>the whole repository</dd>
            ) : (
              view.paths.map((path, index) => (
                <dd key={index} className="mono">
                  <StrangerText text={path} />
                </dd>
              ))
            )}
          </dl>
          <GitHubLink href={githubRevUrl(view.repo, view.rev, 'tree')} />
        </>
      )
    case 'commit':
      return (
        <>
          <dl className="target__pin">
            <Field term="Repository" value={view.repo} />
            <Field term="Commit" value={view.rev} />
          </dl>
          <GitHubLink href={githubRevUrl(view.repo, view.rev, 'commit')} />
        </>
      )
    case 'pr':
      return (
        <>
          <dl className="target__pin">
            <Field term="Repository" value={view.repo} />
            <Field term="Pull request" value={`#${view.number}`} />
            <Field term="Head" value={view.head} />
            <Field term="Base" value={view.base} />
            <Field term="Merge base" value={view.mergeBase} />
          </dl>
          <GitHubLink href={githubPullUrl(view.repo, view.number)} />
        </>
      )
    case 'unknown':
      return <p className="details__none">A target of a kind this board does not show.</p>
    case 'unreadable':
      return <p className="details__none">This target's fields cannot be read.</p>
  }
}

function Field({ term, value }: { readonly term: string; readonly value: string }) {
  return (
    <>
      <dt>{term}</dt>
      <dd className="mono">
        <StrangerText text={value} />
      </dd>
    </>
  )
}

/**
 * "View on GitHub", or nothing when githubLinks.ts built no URL. A new tab:
 * GitHub refuses to be framed, and the board may itself sit in a frame on
 * Vibes. `noreferrer` also implies `noopener`, so GitHub's page gets no
 * handle on this one and no referrer naming the bounty.
 */
function GitHubLink({ href }: { readonly href: string | null }) {
  if (href === null) return null
  return (
    <p className="target__link">
      <a href={href} target="_blank" rel="noreferrer">
        View on GitHub
      </a>
    </p>
  )
}

function TargetSweeps({ sweeps }: { readonly sweeps: readonly TargetedSweep[] }) {
  if (sweeps.length === 0) return <p className="details__none">No sweeps yet.</p>
  return (
    <ul className="target__sweeps" aria-label="Sweeps of this target">
      {sweeps.map(({ view }) => (
        <li key={sweepKey(view.ref)} className="target-sweep">
          <SweepStatus signal={view.signal} />
          <TrustBadge trust={view.trust} />
          <SweepLink sweep={view.ref} />
        </li>
      ))}
    </ul>
  )
}
