import { useId, type ReactNode } from 'react'

/** A heading with one word in --brand: `lead`, then `accent`, then `tail`. */
export interface SectionHeading {
  readonly lead?: string
  readonly accent: string
  readonly tail?: string
}

interface SectionProps {
  /** The anchor a link can jump to, such as `post` for `/#post`. */
  readonly id?: string
  /** The small uppercase line above the heading, such as "The problem". */
  readonly eyebrow?: string
  readonly heading: SectionHeading
  /** One muted line under the heading. */
  readonly subtitle?: string
  /** The section's body, usually a `.card-grid` of `.card`s. */
  readonly children?: ReactNode
}

/**
 * pubky-app's landing section pattern (sections.css). The section is labelled
 * by its heading, so assistive technology lists it as a landmark by name.
 */
export function Section({ id, eyebrow, heading, subtitle, children }: SectionProps) {
  const headingId = useId()
  return (
    <section id={id} className="section" aria-labelledby={headingId}>
      <div className="container">
        <header className="section__header">
          {eyebrow !== undefined && <p className="section__eyebrow">{eyebrow}</p>}
          <h2 id={headingId} className="section__heading">
            {heading.lead}
            <span className="accent">{heading.accent}</span>
            {heading.tail}
          </h2>
          {subtitle !== undefined && <p className="section__subtitle">{subtitle}</p>}
        </header>
        {children}
      </div>
    </section>
  )
}
