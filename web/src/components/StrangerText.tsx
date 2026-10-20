// Text a stranger wrote: a bounty's title, a focus, a playbook, a label, a
// path. Core's checks let zero-width and default-ignorable characters through
// (P1a carry-forward), and a title may hold bidi controls, so the board never
// relies on those checks for display safety.

/**
 * `text` as a text node, which React escapes, so `<b>` shows as `<b>` and
 * never becomes markup. Inside a `<bdi>` (and `unicode-bidi: isolate` in
 * board.css, for browsers that treat `<bdi>` as a plain span): a U+202E in a
 * title reorders the title itself, never the label or link beside it.
 */
export function StrangerText({ text }: { readonly text: string }) {
  return <bdi className="stranger-text">{text}</bdi>
}
