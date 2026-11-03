import { useId, type ReactNode } from 'react'

interface SectionProps {
  /** The anchor a link can jump to, such as `setup` for `/#setup`. */
  readonly id?: string
  /** The section's name, beside its heading, such as "The problem". */
  readonly eyebrow?: string
  readonly heading: string
  /** One muted line under the heading. */
  readonly subtitle?: string
  /** The section's body. */
  readonly children?: ReactNode
}

/**
 * A landing section (sections.css): its name in the left rail, the heading
 * and subtitle beside it, then the body across the full width. The section is
 * labelled by its heading, so assistive technology lists it as a landmark by
 * name.
 */
export function Section({ id, eyebrow, heading, subtitle, children }: SectionProps) {
  const headingId = useId()
  return (
    <section id={id} className="section" aria-labelledby={headingId}>
      <div className="container">
        <header className="section__header">
          {eyebrow !== undefined && <p className="section__eyebrow">{eyebrow}</p>}
          <div className="section__intro">
            <h2 id={headingId} className="section__heading">
              {heading}
            </h2>
            {subtitle !== undefined && <p className="section__subtitle">{subtitle}</p>}
          </div>
        </header>
        {children}
      </div>
    </section>
  )
}
