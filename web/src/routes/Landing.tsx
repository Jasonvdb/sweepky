// `/`: the landing page (04, "Landing page"): the hero, The problem, How it
// works, Safe by design, Reputation and the final call to action with the
// setup block (`#setup`), in that order. Every word comes from
// landing/copy.ts, where each claim names its source. The hero's floor plan
// is the board's own, read from the same store, or the empty state: the page
// never draws a mock-up, and the store is the only thing on it that reads a
// homeserver.

import { useId, type ReactNode } from 'react'
import { useBoard } from '../App.tsx'
import { buttonClassName } from '../components/Button.tsx'
import { CircleLink } from '../components/CircleLink.tsx'
import { CopyButton, type CopyLabels } from '../components/CopyButton.tsx'
import { FloorPlan } from '../components/FloorPlan.tsx'
import { Section } from '../components/Section.tsx'
import { StrangerText } from '../components/StrangerText.tsx'
import { TrustBadge } from '../components/TrustBadge.tsx'
import { useClock } from '../components/useClock.ts'
import {
  KNOWN_LIMITS_URL,
  LANDING_COPY,
  README_URL,
  REPO_URL,
  type Step,
} from '../landing/copy.ts'
import { useScrollToHash } from '../landing/scrollToHash.ts'
import { boardStatus, floorPlan, floorPlanLoading } from '../store/selectors.ts'
import type { Trust, TrustLabel } from '../trust/trust.ts'
import { StatusNotice } from './Board.tsx'

const { hero, problem, howItWorks, safety, reputation, start } = LANDING_COPY

const COPY_LABELS: CopyLabels = {
  idle: start.copyButton.idle.label,
  copied: start.copyButton.copied.label,
  failed: start.copyButton.failed.label,
}

export function Landing() {
  useScrollToHash()
  return (
    <>
      <Hero />
      <Section eyebrow={problem.eyebrow} heading={problem.heading.text} subtitle={problem.subtitle.text}>
        <ul className="landing-problems">
          {problem.cards.map((card) => (
            <li key={card.title}>
              <h3 className="landing-card__title">{card.title}</h3>
              <p>{card.text}</p>
              {card.link !== undefined && <a href={card.link.href}>{card.link.label}</a>}
            </li>
          ))}
        </ul>
      </Section>
      <Section
        eyebrow={howItWorks.eyebrow}
        heading={howItWorks.heading.text}
        subtitle={howItWorks.subtitle.text}
      >
        <Loop />
        <p className="landing-note">{howItWorks.login.text}</p>
      </Section>
      <Section eyebrow={safety.eyebrow} heading={safety.heading.text} subtitle={safety.subtitle.text}>
        <ul className="card-grid landing-cards">
          {safety.cards.map((card) => (
            <li key={card.title} className="card">
              <h3 className="landing-card__title">{card.title}</h3>
              <p>{card.text}</p>
            </li>
          ))}
        </ul>
        <p className="landing-limits">
          {safety.limits.text} <a href={KNOWN_LIMITS_URL}>{safety.limitsLink.label}</a>
        </p>
      </Section>
      <Section
        eyebrow={reputation.eyebrow}
        heading={reputation.heading.text}
        subtitle={reputation.subtitle.text}
      >
        <ul className="landing-legend">
          {reputation.labels.map((entry) => (
            <li key={entry.label}>
              <TrustBadge trust={legendTrust(entry.label)} />
              <p>{entry.text}</p>
            </li>
          ))}
        </ul>
        <p className="landing-note">{reputation.footnote.text}</p>
      </Section>
      <Section id="setup" eyebrow={start.eyebrow} heading={start.heading.text}>
        <div className="landing-start">
          <div className="landing-setup">
            <AgentSetup />
            <Lane label={start.manual.label} steps={start.manual.steps} copyLabels={COPY_LABELS}>
              <p className="landing-install">
                <a href={README_URL}>{start.install.label}</a>
              </p>
            </Lane>
          </div>
          <p className="actions">
            <CircleLink to="/board" className={buttonClassName('primary')}>
              {start.board.label}
            </CircleLink>
            <a href={REPO_URL} className={buttonClassName('secondary')}>
              {start.repo.label}
            </a>
          </p>
        </div>
      </Section>
    </>
  )
}

/**
 * The most rooms the hero's plan sheet draws, the newest: one row beside the
 * text on a wide screen, so the sheet keeps one height from loading to
 * loaded. The count in its title block links to the board, which has them all.
 */
const HERO_ROOMS = 3

/**
 * The heading across the full width; under it the subtitle and actions on
 * the left and, on the right, the board's floor plan, compact and live, with
 * the board's notice when it cannot read the circle. From 56rem up the two
 * sit side by side (landing.css).
 */
function Hero() {
  const headingId = useId()
  const now = useClock()
  const status = useBoard(boardStatus)
  const rooms = useBoard((state) => floorPlan(state, now))
  const loading = useBoard(floorPlanLoading)
  // `null` until circle.json answers; '' for a circle with no name, or the
  // admin alone when there is no circle.json.
  const circleName = useBoard((state) => state.circle?.name ?? null)
  return (
    <section className="landing-hero" aria-labelledby={headingId}>
      <div className="container landing-hero__inner">
        <h1 id={headingId} className="landing-hero__title">
          {hero.heading.text}
        </h1>
        <div className="landing-hero__text">
          <p className="landing-hero__subtitle">{hero.subtitle.text}</p>
          <p className="actions">
            <CircleLink to="/#setup" className={buttonClassName('primary')}>
              {hero.actions.setup.label}
            </CircleLink>
            <CircleLink to="/board" className={buttonClassName('secondary')}>
              {hero.actions.board.label}
            </CircleLink>
          </p>
          <p className="landing-hero__jumps">
            <CircleLink to="/#sweep">{hero.actions.sweep.label}</CircleLink>
            <CircleLink to="/#post">{hero.actions.post.label}</CircleLink>
          </p>
        </div>
        {/* The plan sheet: the circle's name and room count as its title
            block, the live plan on a grid, then what the board shows. */}
        <div
          className={
            rooms.length === 0 && loading
              ? 'landing-hero__visual landing-hero__visual--loading'
              : 'landing-hero__visual'
          }
        >
          <p className="landing-hero__sheet">
            <span className="landing-hero__circle">
              {circleName === null && loading ? (
                <span className="landing-hero__name-bar" aria-hidden="true" />
              ) : circleName === null || circleName === '' ? (
                hero.visual.untitled.label
              ) : (
                <StrangerText text={circleName} />
              )}
            </span>
            {rooms.length > 0 && (
              <CircleLink to="/board" className="landing-hero__count">
                {rooms.length} {rooms.length === 1 ? hero.visual.room.label : hero.visual.rooms.label}
              </CircleLink>
            )}
          </p>
          <StatusNotice status={status} />
          <FloorPlan rooms={rooms.slice(0, HERO_ROOMS)} compact loading={loading} />
          <p className="landing-hero__caption">{hero.visual.text}</p>
        </div>
      </div>
    </section>
  )
}

/**
 * How it works as 00's loop, in the order it happens: the owner posts, the
 * sweeper runs, sweeps and submits, then the owner pulls and marks done. Each
 * step carries its lane's name; from 56rem up the owner's steps sit left of
 * the numbered spine and the sweeper's right of it (landing.css). `#post` and
 * `#sweep` are each lane's first step.
 */
function Loop() {
  const { owners, sweepers } = howItWorks
  const loop = [
    ...owners.steps.slice(0, 1).map((step) => ({ lane: owners, step })),
    ...sweepers.steps.map((step) => ({ lane: sweepers, step })),
    ...owners.steps.slice(1).map((step) => ({ lane: owners, step })),
  ]
  return (
    <ol className="landing-loop">
      {loop.map(({ lane, step }, at) => {
        const first = lane.steps[0] === step
        return (
          <li
            key={step.command}
            id={first ? lane.id : undefined}
            className={`landing-loop__step landing-loop__step--${lane.id}`}
          >
            <span className="landing-loop__node" aria-hidden="true">
              {at + 1}
            </span>
            <div className="landing-loop__body">
              <p className="landing-loop__lane">{lane.label}</p>
              <code className="landing-loop__command">{step.command}</code>
              <p>{step.text}</p>
            </div>
          </li>
        )
      })}
    </ol>
  )
}

/**
 * The prompt a visitor pastes into their coding agent, shown in full and
 * wrapped, so it never scrolls sideways, with a button that copies it.
 */
function AgentSetup() {
  const headingId = useId()
  return (
    <section className="card landing-setup__card" aria-labelledby={headingId}>
      <div className="landing-setup__header">
        <h3 id={headingId} className="landing-setup__title">
          {start.agent.label}
        </h3>
        <CopyButton
          text={start.agent.prompt.text}
          subject={start.agent.copySubject.label}
          labels={COPY_LABELS}
          variant="default"
        />
      </div>
      <p className="landing-setup__intro">{start.agent.intro.text}</p>
      <pre className="landing-setup__prompt">{start.agent.prompt.text}</pre>
    </section>
  )
}

interface LaneProps {
  readonly label: string
  readonly steps: readonly Step[]
  /** Each command's copy button, labelled with these. */
  readonly copyLabels: CopyLabels
  /** What follows the steps, such as a link. */
  readonly children?: ReactNode
}

/**
 * A card of commands, in order: the setup block's steps by hand, where each
 * command has its own copy button.
 */
function Lane({ label, steps, copyLabels, children }: LaneProps) {
  const headingId = useId()
  return (
    <section className="card landing-lane" aria-labelledby={headingId}>
      <h3 id={headingId} className="landing-lane__label">
        {label}
      </h3>
      <ol className="landing-lane__steps">
        {steps.map((step) => (
          <li key={step.command}>
            <div className="landing-lane__command">
              <code>{step.command}</code>
              <CopyButton text={step.command} subject={step.command} labels={copyLabels} variant="secondary" />
            </div>
            <p>{step.text}</p>
          </li>
        ))}
      </ol>
      {children}
    </section>
  )
}

/**
 * The trust the legend's badge draws for `label`: the board's own badge, so
 * it looks as it does on the board. `known` needs a count to show, and one is
 * the smallest a `known` sweeper can have.
 */
function legendTrust(label: TrustLabel): Trust {
  return label === 'known' ? { label, bounties: 1, owners: 1 } : { label, bounties: 0, owners: 0 }
}
