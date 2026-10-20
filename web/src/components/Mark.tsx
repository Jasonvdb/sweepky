// Sweepky's own mark: a detector's sweep, a ring with a sweeping wedge and a
// dot at its centre. The same drawing is public/favicon.svg. Pubky's and
// Synonym's marks never ship (04, "Not taken").

/**
 * The mark in the text's colour (`currentColor`), so its CSS picks the
 * colour from the tokens. Decorative: it always sits beside the name
 * "Sweepky", so assistive technology skips it.
 */
export function Mark({ className }: { readonly className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 32 32"
      width="32"
      height="32"
      aria-hidden="true"
      focusable="false"
    >
      <circle cx="16" cy="16" r="13" fill="none" stroke="currentColor" strokeWidth="2.5" />
      <path d="M16 16 L16 5 A11 11 0 0 1 25.5 10.5 Z" fill="currentColor" />
      <circle cx="16" cy="16" r="2.5" fill="currentColor" />
    </svg>
  )
}
