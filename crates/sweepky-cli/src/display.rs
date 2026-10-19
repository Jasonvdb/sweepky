//! Showing text a stranger wrote in a terminal: [`sanitize`].
//!
//! Every string in a record is written by whoever owns that record, and the
//! homeserver serves whatever bytes it likes, so a key's `label`, a circle's
//! `name` and a member's `label` (and later a bounty's `title`, an open
//! `status` and the rest) are a stranger's text. Printed as they are, they
//! can drive the terminal: an ESC sequence can move the cursor, clear the
//! screen, retitle the window or write a link that opens somewhere else; a
//! newline can start a line that looks like Sweepky's own output; a
//! right-to-left override can show `txt.exe` as `exe.txt`; a zero-width
//! character can make two different labels look the same. So the CLI passes
//! every such string through [`sanitize`] before it goes into a
//! [`Report`](crate::Report) or onto standard error.
//!
//! `sanitize` keeps ordinary text, accents, other scripts and emoji as they
//! are, and writes each character in the list below as Rust's visible
//! `\u{..}` escape, so nothing is hidden and nothing is silently dropped:
//!
//! - controls (`Cc`): C0 `U+0000..=U+001F`, among them ESC, which starts
//!   every escape sequence, and newline and tab; DEL `U+007F`; and C1
//!   `U+0080..=U+009F`, among them the one-byte CSI `U+009B`;
//! - the line and paragraph separators `U+2028` and `U+2029`;
//! - format characters (`Cf`): the bidi controls (`U+061C`, `U+200E`,
//!   `U+200F`, `U+202A..=U+202E`, `U+2066..=U+2069`), the zero-width ones
//!   (`U+200B..=U+200D`, `U+2060..=U+2064`, `U+FEFF`), the soft hyphen
//!   `U+00AD`, the tag characters and the rest of Unicode's `Cf` list;
//! - every other default-ignorable code point (Unicode's
//!   `Default_Ignorable_Code_Point`, which renderers draw as nothing):
//!   variation selectors, Hangul fillers and the reserved ranges;
//! - noncharacters (`U+FDD0..=U+FDEF` and the last two code points of every
//!   plane).
//!
//! A backslash is written `\\`, so a stranger cannot spell out an escape
//! that reads as one `sanitize` wrote. And the result is bounded: a caller
//! names how many characters of the text to show, and anything longer is cut
//! there and marked with [`TRUNCATED`].
//!
//! The lists follow Unicode 16.0 (`DerivedCoreProperties.txt` for
//! `Default_Ignorable_Code_Point`, `UnicodeData.txt` for `Cf`). A later
//! Unicode version may add format characters; the tests pin every range the
//! threat above needs.

/// How many characters of a short name to show: a key's `label`, a circle's
/// `name`, a member's `label`. A label that needs more than this is not a
/// label; the rest is cut and marked.
pub(crate) const MAX_LABEL_CHARS: usize = 64;

/// What `sanitize` puts after text it cut short.
pub(crate) const TRUNCATED: &str = "\u{2026}(truncated)";

/// `text` made safe to print in a terminal: at most `max_chars` of its
/// characters, each one that could drive the terminal or hide in it written
/// as a visible `\u{..}` escape, and a backslash doubled; then
/// [`TRUNCATED`] if any were left out.
///
/// It counts the characters of `text`, not the bytes and not the escapes it
/// writes, so a cut never lands inside a character (which slicing a `&str`
/// there would panic on), and the result is at most ten bytes per character
/// shown, plus the marker: the longest escape, `\u{10ffff}`, is ten.
// Returns a new `String` rather than borrowing `text`: most of the time the
// text comes back unchanged, but the caller then owns one value either way,
// and a label is short.
pub(crate) fn sanitize(text: &str, max_chars: usize) -> String {
    let mut shown = String::with_capacity(text.len().min(max_chars.saturating_mul(4)));
    // `chars()` walks the string one Unicode scalar value at a time, decoding
    // the UTF-8 itself, so no index is ever computed here. `take` stops after
    // `max_chars` of them.
    let mut chars = text.chars();
    for c in chars.by_ref().take(max_chars) {
        if c == '\\' {
            shown.push_str("\\\\");
        } else if must_escape(c) {
            // `escape_unicode` yields `\u{1b}` for ESC: a backslash, `u`, and
            // the code point in lower-case hex between braces.
            shown.extend(c.escape_unicode());
        } else {
            shown.push(c);
        }
    }
    // `by_ref` above lent the iterator to `take` instead of giving it away,
    // so here it carries on where `take` stopped: anything left means the
    // text was longer than `max_chars`.
    if chars.next().is_some() {
        shown.push_str(TRUNCATED);
    }
    shown
}

/// Whether `c` is one of the characters [`sanitize`] escapes, by the list in
/// the module's docs.
fn must_escape(c: char) -> bool {
    let code = u32::from(c);
    // `char::is_control` is exactly Unicode's `Cc`: C0, DEL and C1.
    c.is_control() || is_noncharacter(code) || is_in_escaped_ranges(code)
}

/// Whether `code` is a noncharacter: U+FDD0..=U+FDEF, and U+FFFE and U+FFFF
/// in every plane, which are the code points whose low 16 bits are 0xFFFE or
/// 0xFFFF.
fn is_noncharacter(code: u32) -> bool {
    // The parentheses are for the reader: unlike C, Rust already applies `&`
    // before `==`.
    (0xFDD0..=0xFDEF).contains(&code) || (code & 0xFFFE) == 0xFFFE
}

/// Whether `code` is in one of [`ESCAPED_RANGES`].
fn is_in_escaped_ranges(code: u32) -> bool {
    // A sorted list of inclusive ranges, searched in order. It is short and
    // a label is short, so a linear scan is fine; `any` stops at the first
    // match.
    ESCAPED_RANGES
        .iter()
        .any(|&(first, last)| (first..=last).contains(&code))
}

/// The ranges [`must_escape`] checks besides `Cc` and the noncharacters: the
/// union of Unicode 16.0's `Cf` (format) characters, its
/// `Default_Ignorable_Code_Point` set, and the separators `Zl` and `Zp`.
const ESCAPED_RANGES: &[(u32, u32)] = &[
    // Soft hyphen (Cf, default-ignorable).
    (0x00AD, 0x00AD),
    // Combining grapheme joiner (default-ignorable).
    (0x034F, 0x034F),
    // Arabic number signs (Cf), which change how the digits after them show.
    (0x0600, 0x0605),
    // Arabic letter mark (Cf, bidi).
    (0x061C, 0x061C),
    // Arabic end of ayah (Cf).
    (0x06DD, 0x06DD),
    // Syriac abbreviation mark (Cf).
    (0x070F, 0x070F),
    // Arabic pound and piastre mark above (Cf).
    (0x0890, 0x0891),
    // Arabic disputed end of ayah (Cf).
    (0x08E2, 0x08E2),
    // Hangul choseong and jungseong fillers (default-ignorable).
    (0x115F, 0x1160),
    // Khmer inherent vowels (default-ignorable).
    (0x17B4, 0x17B5),
    // Mongolian free variation selectors and vowel separator.
    (0x180B, 0x180F),
    // Zero-width space, non-joiner and joiner; left-to-right and
    // right-to-left marks.
    (0x200B, 0x200F),
    // Line and paragraph separators (Zl, Zp); bidi embeddings, pops and
    // overrides.
    (0x2028, 0x202E),
    // Word joiner, invisible operators, the reserved U+2065, bidi isolates
    // and the deprecated shaping controls.
    (0x2060, 0x206F),
    // Hangul filler (default-ignorable).
    (0x3164, 0x3164),
    // Variation selectors 1 to 16 (default-ignorable).
    (0xFE00, 0xFE0F),
    // Zero-width no-break space, the byte-order mark (Cf).
    (0xFEFF, 0xFEFF),
    // Halfwidth Hangul filler (default-ignorable).
    (0xFFA0, 0xFFA0),
    // Reserved default-ignorables, then the interlinear annotation
    // characters (Cf), whose text a renderer may hide.
    (0xFFF0, 0xFFFB),
    // Kaithi number signs (Cf).
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    // Egyptian hieroglyph format controls (Cf).
    (0x13430, 0x1343F),
    // Shorthand format controls (Cf).
    (0x1BCA0, 0x1BCA3),
    // Musical symbol beam, tie, slur and phrase controls (Cf).
    (0x1D173, 0x1D17A),
    // Tags, variation selectors 17 to 256, and the reserved rest of the
    // block (all default-ignorable).
    (0xE0000, 0xE0FFF),
];

#[cfg(test)]
mod tests {
    use super::{MAX_LABEL_CHARS, TRUNCATED, sanitize};

    /// `c` as `sanitize` must show it: Rust's `\u{..}` escape, lower-case hex.
    fn escaped(c: char) -> String {
        c.escape_unicode().to_string()
    }

    #[test]
    fn sanitize_escapes_controls_and_reordering() {
        // Every range the sanitiser must escape, by its first and last
        // character and a few in between, named so a failure says which.
        let must_escape: [(&str, &[u32]); 7] = [
            (
                "C0 controls, NUL, BEL, BS, TAB, LF, CR and ESC among them",
                &[0x00, 0x07, 0x08, 0x09, 0x0A, 0x0D, 0x1B, 0x1F],
            ),
            ("DEL", &[0x7F]),
            (
                "C1 controls, NEL and the one-byte CSI among them",
                &[0x80, 0x85, 0x9B, 0x9F],
            ),
            (
                "bidi controls",
                &[
                    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067,
                    0x2068, 0x2069,
                ],
            ),
            (
                "zero-width and default-ignorable characters",
                &[
                    0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x00AD,
                ],
            ),
            ("the tag block", &[0xE0000, 0xE0001, 0xE0041, 0xE007F]),
            ("line and paragraph separators", &[0x2028, 0x2029]),
        ];
        for (group, codes) in must_escape {
            for &code in codes {
                let c = char::from_u32(code).expect("a valid char");
                let shown = sanitize(&format!("a{c}b"), MAX_LABEL_CHARS);
                assert_eq!(shown, format!("a{}b", escaped(c)), "{group}: U+{code:04X}");
                assert!(!shown.contains(c), "{group}: U+{code:04X} survived");
            }
        }

        // An ESC sequence, a one-byte CSI and an OSC 8 hyperlink: the
        // control characters that start them are escaped, so the terminal
        // sees plain text.
        assert_eq!(
            sanitize("\u{1b}[31mred\u{1b}[0m", MAX_LABEL_CHARS),
            "\\u{1b}[31mred\\u{1b}[0m"
        );
        assert_eq!(sanitize("\u{9b}2J", MAX_LABEL_CHARS), "\\u{9b}2J");
        assert_eq!(
            sanitize("\u{1b}]8;;http://x\u{7}y", MAX_LABEL_CHARS),
            "\\u{1b}]8;;http://x\\u{7}y"
        );
        // A right-to-left override that would show `exe.txt` as `txt.exe`.
        assert_eq!(
            sanitize("report\u{202e}txt.exe", MAX_LABEL_CHARS),
            "report\\u{202e}txt.exe"
        );
    }

    #[test]
    fn sanitize_doubles_backslashes() {
        // A backslash is doubled, so a stranger cannot write text that looks
        // like one of these escapes.
        assert_eq!(sanitize("a\\u{1b}b", MAX_LABEL_CHARS), "a\\\\u{1b}b");
    }

    #[test]
    fn sanitize_keeps_ordinary_text() {
        // Ordinary text, accents, other scripts, emoji and punctuation
        // included, is unchanged.
        for ordinary in [
            "",
            "laptop-1",
            "Jason's MacBook (work)",
            "caf\u{e9} \u{2013} na\u{ef}ve",
            "\u{65e5}\u{672c}\u{8a9e} \u{0627}\u{0644}\u{0639}\u{0631}\u{0628}\u{064a}\u{0629}",
            "\u{2713} \u{1f600}",
            "a b\u{a0}c",
        ] {
            assert_eq!(sanitize(ordinary, MAX_LABEL_CHARS), ordinary);
        }
    }

    #[test]
    fn sanitize_cuts_long_text_by_characters() {
        // Over-long text is cut to its first `max_chars` characters, counted
        // as characters, not bytes, and marked as cut.
        let long = "\u{e9}".repeat(MAX_LABEL_CHARS + 1);
        let shown = sanitize(&long, MAX_LABEL_CHARS);
        assert_eq!(
            shown,
            format!("{}{TRUNCATED}", "\u{e9}".repeat(MAX_LABEL_CHARS))
        );
        // Exactly `max_chars` is not cut.
        let exact = "x".repeat(MAX_LABEL_CHARS);
        assert_eq!(sanitize(&exact, MAX_LABEL_CHARS), exact);
        // The cut counts the original characters, so escapes cannot make
        // the output unbounded: here every character becomes 10.
        let tags = "\u{e007f}".repeat(1000);
        let shown = sanitize(&tags, 3);
        assert_eq!(
            shown,
            format!("{}{TRUNCATED}", escaped('\u{e007f}').repeat(3))
        );
    }
}
