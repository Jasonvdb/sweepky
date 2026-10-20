// `/`: the landing page (04, "Landing page"): the hero, The problem, How it
// works, Safe by design, Reputation and the final call to action, in that
// order. Every word comes from landing/copy.ts, where each claim names its
// source. The hero's floor plan is the board's own, read from the same
// store, or the empty state: the page never draws a mock-up, and the store is
// the only thing on it that reads a homeserver.

import { useId } from 'react'
import { useBoard } from '../App.tsx'
import { buttonClassName } from '../components/Button.tsx'
import { CircleLink } from '../components/CircleLink.tsx'
import { FloorPlan } from '../components/FloorPlan.tsx'
import { Section } from '../components/Section.tsx'
import { TrustBadge } from '../components/TrustBadge.tsx'
import { useClock } from '../components/useClock.ts'
import {
  KNOWN_LIMITS_URL,
  LANDING_COPY,
  README_URL,
  REPO_URL,
  type Card,
  type Step,
} from '../landing/copy.ts'
import { useScrollToHash } from '../landing/scrollToHash.ts'
import { boardStatus, floorPlan } from '../store/selectors.ts'
import type { Trust, TrustLabel } from '../trust/trust.ts'
import { StatusNotice } from './Board.tsx'

const { hero, problem, howItWorks, safety, reputation, start } = LANDING_COPY

export function Landing() {
  useScrollToHash()
  return (
    <>
      <Hero />
      <Section eyebrow={problem.eyebrow} heading={problem.heading} subtitle={problem.subtitle.text}>
        <Cards cards={problem.cards} />
      </Section>
      <Section
        eyebrow={howItWorks.eyebrow}
        heading={howItWorks.heading}
        subtitle={howItWorks.subtitle.text}
      >
        <div className="landing-lanes">
          <Lane {...howItWorks.owners} />
          <Lane {...howItWorks.sweepers} />
        </div>
        <p className="landing-note">{howItWorks.login.text}</p>
      </Section>
      <Section eyebrow={safety.eyebrow} heading={safety.heading} subtitle={safety.subtitle.text}>
        <Cards cards={safety.cards} />
        <p className="landing-note">
          {safety.limits.text} <a href={KNOWN_LIMITS_URL}>{safety.limitsLink.label}</a>
        </p>
      </Section>
      <Section
        eyebrow={reputation.eyebrow}
        heading={reputation.heading}
        subtitle={reputation.subtitle.text}
      >
        <ul className="card-grid landing-labels">
          {reputation.labels.map((entry) => (
            <li key={entry.label} className="card">
              <TrustBadge trust={legendTrust(entry.label)} />
              <p>{entry.text}</p>
            </li>
          ))}
        </ul>
        <p className="landing-note">{reputation.footnote.text}</p>
      </Section>
      <Section heading={start.heading}>
        <div className="landing-start">
          <p className="card landing-install">
            <a href={README_URL}>{start.install.label}</a>
          </p>
          <p className="actions">
            <CircleLink to="/board" className={buttonClassName('primary')}>
              {start.board.label}
            </CircleLink>
            <a href={REPO_URL} className={buttonClassName('secondary')}>
              {start.repo.label}
            </a>
          </p>
          <p className="landing-credits">
            <a href="https://pubky.org">{start.pubky.label}</a>
            <span>{start.licence.label}</span>
          </p>
        </div>
      </Section>
    </>
  )
}

/**
 * Heading, subtitle and actions on the left; on the right the board's floor
 * plan, compact and live, with the board's notice when it cannot read the
 * circle. From 56rem up the two sit side by side (landing.css).
 */
function Hero() {
  const headingId = useId()
  const now = useClock()
  const status = useBoard(boardStatus)
  const rooms = useBoard((state) => floorPlan(state, now))
  return (
    <section className="landing-hero" aria-labelledby={headingId}>
      <div className="container landing-hero__inner">
        <div className="landing-hero__text">
          <h1 id={headingId} className="landing-hero__title">
            {hero.heading.lead}
            <span className="accent">{hero.heading.accent}</span>
            {hero.heading.tail}
          </h1>
          <p className="landing-hero__subtitle">{hero.subtitle.text}</p>
          <p className="actions">
            <CircleLink to="/board" className={buttonClassName('primary')}>
              {hero.actions.board.label}
            </CircleLink>
            <CircleLink to="/#sweep" className={buttonClassName('default')}>
              {hero.actions.sweep.label}
            </CircleLink>
            <CircleLink to="/#post" className={buttonClassName('secondary')}>
              {hero.actions.post.label}
            </CircleLink>
          </p>
        </div>
        <div className="landing-hero__visual">
          <StatusNotice status={status} />
          <FloorPlan rooms={rooms} compact />
          <p className="landing-hero__caption">{hero.visual.text}</p>
        </div>
      </div>
    </section>
  )
}

function Cards({ cards }: { readonly cards: readonly Card[] }) {
  return (
    <ul className="card-grid landing-cards">
      {cards.map((card) => (
        <li key={card.title} className="card">
          <h3 className="landing-card__title">{card.title}</h3>
          <p>{card.text}</p>
          {card.link !== undefined && <a href={card.link.href}>{card.link.label}</a>}
        </li>
      ))}
    </ul>
  )
}

interface LaneProps {
  /** The anchor `/#post` or `/#sweep` scrolls to. */
  readonly id: string
  readonly label: string
  readonly steps: readonly Step[]
}

/** One side of How it works: who it is for and the commands they run, in order. */
function Lane({ id, label, steps }: LaneProps) {
  const headingId = useId()
  return (
    <section id={id} className="card landing-lane" aria-labelledby={headingId}>
      <h3 id={headingId} className="landing-lane__label">
        {label}
      </h3>
      <ol className="landing-lane__steps">
        {steps.map((step) => (
          <li key={step.command}>
            <code>{step.command}</code>
            <p>{step.text}</p>
          </li>
        ))}
      </ol>
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
