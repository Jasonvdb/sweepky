// Every word the landing page says (04, "Landing page"), in one place so the
// verifier can trace it. Each claim carries `sources`: the headings in 00, 02
// or 06's known limits it rests on, as `<file>#<GitHub anchor>` under
// docs/plan/. landing.test.tsx checks that every string here that is not a
// label, link or command sits beside such sources, and that each anchor is a
// heading in that file. A claim no source supports does not belong here.
//
// Rules from 04: every claim holds under 06's known limits; "only the owner
// can read" is said, "private" never is (metadata is public); no number
// without a source. The copy is a draft, approved with the P5 demo.

import type { TrustLabel } from '../trust/trust.ts'

/** A heading in one of the three documents a landing claim may rest on. */
export type Source =
  | `00-overview.md#${string}`
  | `02-encryption-and-safety.md#${string}`
  | '06-verification-and-limits.md#known-limits-say-them-in-the-readme'

/** At least one source. The cards, steps and labels are typed with it; landing.test.tsx checks every claim, those included. */
export type Sources = readonly [Source, ...Source[]]

// The anchors the copy cites, named once so a typo cannot pass as a source.
const WHAT_IT_IS = '00-overview.md#what-it-is'
const DECISIONS = '00-overview.md#decisions-locked'
const THE_LOOP = '00-overview.md#the-loop'
const TRUST_MODEL = '00-overview.md#trust-model-the-circle-is-a-default-not-the-protocol'
const SEALED = '02-encryption-and-safety.md#what-is-sealed-and-what-is-public'
const WHO_CAN_READ = '02-encryption-and-safety.md#who-can-read-a-sweep'
const SWEEPER_SAFETY = '02-encryption-and-safety.md#sweeper-safety'
const KNOWN_LIMITS = '06-verification-and-limits.md#known-limits-say-them-in-the-readme'

/** A sentence or two that asserts something. */
export interface Claim {
  readonly text: string
  readonly sources: Sources
}

/** A card: its title and text are one claim. */
export interface Card extends Claim {
  readonly title: string
  /** Where the card's source can be read, when it is outside docs/plan/. */
  readonly link?: { readonly label: string; readonly href: string }
}

/** One command in a lane, and what it does. */
export interface Step extends Claim {
  readonly command: string
}

/**
 * The project's repository. It is not public today, so the links to it and to
 * its README do not open for a visitor yet; one constant, so the day it is
 * published (or moves) is a one-line change.
 */
export const REPO_URL = 'https://github.com/Jasonvdb/sweepky'
/** The README's install section: the install channel is not decided, so the page ships no command. */
export const README_URL = `${REPO_URL}/blob/main/README.md#install`
/** 06's known limits, as the README publishes them. */
export const KNOWN_LIMITS_URL = `${REPO_URL}/blob/main/README.md#known-limits`
/** Cloudflare's skill at the commit 06 pins, whose README 00 cites for "about half". */
const CLOUDFLARE_SKILL_URL =
  'https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8'

export const LANDING_COPY = {
  hero: {
    // The route test reads the page's one h1 as this text.
    heading: { lead: 'Your spare tokens, ', accent: 'sweeping', tail: ' for bugs.', sources: [WHAT_IT_IS] },
    subtitle: {
      text: "Point your coding agent at other people's code. The findings are encrypted to the bounty's owner, and when the bounty is done the owner credits every sweeper who helped.",
      sources: [WHAT_IT_IS, DECISIONS],
    },
    actions: {
      board: { label: 'Watch the board' },
      sweep: { label: 'Run a sweep' },
      post: { label: 'Post a bounty' },
    },
    visual: {
      text: 'Live from the board: anyone can watch bounties appear and sweeps land. Findings are never shown there.',
      sources: [WHAT_IT_IS],
    },
  },

  problem: {
    eyebrow: 'The problem',
    heading: { lead: 'One pass ', accent: 'misses', tail: ' things.', sources: [WHAT_IT_IS] },
    subtitle: {
      text: 'Independent sweeps by different people are the point, so a second sweep of the same code is not waste.',
      sources: [WHAT_IT_IS],
    },
    cards: [
      {
        title: 'One run finds about half',
        text: "Cloudflare's README says a single run of their security-audit skill found roughly half of what repeated runs found.",
        sources: [WHAT_IT_IS],
        link: { label: "Cloudflare's security-audit skill", href: CLOUDFLARE_SKILL_URL },
      },
      {
        title: 'Unused plan capacity',
        text: 'Sweepers spend their own unused AI plan capacity, each in their own unmodified Claude Code. Sweepky never reads or proxies Claude credentials.',
        sources: [WHAT_IT_IS, KNOWN_LIMITS],
      },
      {
        title: 'No claims, no locks',
        text: 'Sweeps are non-exclusive. Anyone the bounty accepts can sweep it, and the owner gets every independent report.',
        sources: [DECISIONS, WHAT_IT_IS],
      },
    ] satisfies readonly Card[],
  },

  howItWorks: {
    eyebrow: 'How it works',
    heading: { lead: 'Post. ', accent: 'Sweep.', tail: ' Credit.', sources: [THE_LOOP] },
    subtitle: {
      text: "The owner's agent runs the owner's side. A sweep is two terminal commands around one agent session.",
      sources: [THE_LOOP, DECISIONS],
    },
    owners: {
      id: 'post',
      label: 'Owners',
      steps: [
        {
          command: 'sweepky post',
          text: 'Your agent posts a bounty: a public repo, PR or commit, pinned to an exact revision, with a brief saying what to look for.',
          sources: [THE_LOOP, WHAT_IT_IS, DECISIONS],
        },
        {
          command: 'sweepky pull',
          text: 'Decrypts new sweeps on your machine and groups findings that point at the same code. The grouping is a heuristic you confirm.',
          sources: [THE_LOOP, KNOWN_LIMITS],
        },
        {
          command: 'sweepky done',
          text: 'Closes the bounty and credits every sweeper whose sweep helped. The CLI proposes the list and you trim it.',
          sources: [THE_LOOP],
        },
      ] satisfies readonly Step[],
    },
    sweepers: {
      id: 'sweep',
      label: 'Sweepers',
      steps: [
        {
          command: 'sweepky run',
          text: "Fetches the pinned target into a sandboxed project, with the repo's own agent-instruction files stripped.",
          sources: [THE_LOOP, SWEEPER_SAFETY],
        },
        {
          command: '/sweepky',
          text: "In Claude Code, your agent audits the target with no network and none of the CLI's secrets in reach. Review is static only.",
          sources: [THE_LOOP, SWEEPER_SAFETY, KNOWN_LIMITS],
        },
        {
          command: 'sweepky submit',
          text: "Encrypts the findings to the owner's published keys and your own, and uploads them to your own homeserver.",
          sources: [THE_LOOP, WHO_CAN_READ],
        },
      ] satisfies readonly Step[],
    },
    login: {
      text: 'Log in once by scanning a QR code with Pubky Ring, or let the CLI create a dedicated identity. Some identities cannot write Sweepky records; login says so and suggests a dedicated one.',
      sources: [DECISIONS, KNOWN_LIMITS],
    },
  },

  safety: {
    eyebrow: 'Safe by design',
    heading: { lead: 'Sealed to the ', accent: 'owner', tail: '.', sources: [SEALED] },
    subtitle: {
      text: 'Bounties, sweep records, keys and credits are public. The sweep package is sealed.',
      sources: [SEALED],
    },
    cards: [
      {
        title: 'Only the owner reads findings',
        text: "Each sweep is encrypted with age to the owner's published keys, and the sweeper can read their own. Everyone else, the circle included, sees only that sweeps happened and who was credited.",
        sources: [WHO_CAN_READ, KNOWN_LIMITS],
      },
      {
        title: 'The agent works offline',
        text: "The sweeper's agent runs sandboxed: no network, none of the CLI's secrets, and the target's own agent-instruction files stripped.",
        sources: [SWEEPER_SAFETY],
      },
      {
        title: 'Credit when the bounty is done',
        text: 'Credits are published when the owner marks the bounty done, never per finding, so public credit never points at an unpatched issue.',
        sources: [DECISIONS],
      },
      {
        title: 'Records stay with their authors',
        text: "Every record sits on its author's own Pubky homeserver, and Sweepky runs no indexer of its own.",
        sources: [DECISIONS, WHAT_IT_IS],
      },
    ] satisfies readonly Card[],
    limits: {
      text: "Metadata is public: paths, timing and padded sizes. An active operator of the owner's homeserver could add a reading key, and the owner's CLI alarms on keys it did not create. What reaches production stays public in practice.",
      sources: [KNOWN_LIMITS],
    },
    limitsLink: { label: 'Read every known limit' },
  },

  reputation: {
    eyebrow: 'Reputation',
    heading: { lead: 'Credit you can ', accent: 'check', tail: '.', sources: [TRUST_MODEL] },
    subtitle: {
      text: 'Reputation is derived from the credits owners publish on their done bounties, never declared.',
      sources: [TRUST_MODEL],
    },
    labels: [
      {
        label: 'circle',
        text: "A member of the circle, the board's default trust set.",
        sources: [TRUST_MODEL],
      },
      {
        label: 'known',
        text: 'Credited on done bounties by owners in the circle; the number counts the bounties. A credit an owner gives themselves counts for nothing.',
        sources: [TRUST_MODEL, KNOWN_LIMITS],
      },
      {
        label: 'unknown',
        text: 'No counted credits yet.',
        sources: [TRUST_MODEL],
      },
    ] satisfies ReadonlyArray<Claim & { readonly label: TrustLabel }>,
    footnote: {
      text: 'Counted only from owners you trust, never a global score.',
      sources: [TRUST_MODEL],
    },
  },

  start: {
    heading: { lead: 'Start ', accent: 'sweeping', tail: '.', sources: [WHAT_IT_IS] },
    install: { label: 'Install: see the README' },
    board: { label: 'Watch the board' },
    repo: { label: 'Sweepky on GitHub' },
    pubky: { label: 'Built on Pubky' },
    licence: { label: 'MIT licensed' },
  },
} as const
