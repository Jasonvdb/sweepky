//! The Pubky Ring sign-in page, and the QR code `login` prints in the
//! terminal as its fallback (03, "How the Ring sign-in looks").
//!
//! [`render_page`] writes the whole page as one HTML string, which the
//! loopback server serves at its random path. It holds:
//!
//! - the authorization URL's QR code, rendered here, on the server side, as
//!   an inline SVG, so the browser loads no image and runs no QR library;
//! - a copy button worded "paste into Ring on your phone", for a phone that
//!   shares the laptop's clipboard;
//! - the authorization URL itself as text (`id="auth-link"`), which the copy
//!   button copies;
//! - what Sweepky asks for: [`SWEEPKY_CAPABILITY`] and the client id
//!   [`CLIENT_ID`], which Ring shows as the app's name;
//! - a live status, which starts as waiting and which [`STATUS_SCRIPT`]
//!   keeps up to date from the status path.
//!
//! **The page and its CSP.** The page loads nothing: no script, stylesheet,
//! image or frame from anywhere, and it has no form. Its one `<script>` and
//! one `<style>` carry the nonce the server passes in, no element has an
//! inline event handler (`onclick=` and the like) or a `style=` attribute,
//! and the SVG's markup uses only presentation attributes (`fill`,
//! `shape-rendering`), which CSP does not count as styles. So the page needs
//! no more than `script-src 'nonce-N'; style-src 'nonce-N'; connect-src
//! 'self'`, and the server's policy can leave everything else at `'none'`.
//! Under it, an injected `<script>` without the nonce would not run.
//!
//! **The status path** answers with one word as its body, a
//! [`SignInStatus`] word: `waiting`, `approved`, `refused` or `expired`.
//! The script asks it about once a second and stops on any word but
//! `waiting`, or after five failed asks in a row.
//!
//! **The authorization URL is a secret** while the flow runs: it carries the
//! relay channel's secret, so whoever has it can listen for the approval
//! (03, "Two ways to log in"). It goes only into the page string returned
//! here and into the terminal's QR code; nothing here logs it or writes it
//! to disk, and every error is fixed text that quotes none of it. The
//! returned page holds it too, so the caller treats the page the same way.
//! (The page is not wiped on drop: the SDK hands the URL over as a plain
//! `Url`, unwiped, so a wiped copy here would buy nothing.)

use anyhow::{anyhow, bail};
use qrcode::render::svg;
use qrcode::render::unicode::Dense1x2;
use qrcode::{EcLevel, QrCode};

use crate::network::{CLIENT_ID, SWEEPKY_CAPABILITY};

/// What the sign-in page's status path answers, one word as the whole body,
/// and the words [`STATUS_SCRIPT`] understands.
///
/// Public words only, so the type derives `Debug` and compares freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignInStatus {
    /// Nobody has approved the grant yet.
    Waiting,
    /// Ring approved the grant. The login is not finished: the terminal
    /// still checks what was granted and writes this install's key record,
    /// which the homeserver can refuse (a 403 or a 507), so the page says
    /// approved and leaves the outcome to the terminal.
    Approved,
    /// Sweepky refused what was approved, such as a grant narrowed below
    /// `/pub/sweepky/:rw`; the terminal says why.
    Refused,
    /// The flow timed out before anyone approved it.
    Expired,
}

impl SignInStatus {
    /// The word the status path answers with for this status.
    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Approved => "approved",
            Self::Refused => "refused",
            Self::Expired => "expired",
        }
    }
}

/// The error for a link no QR code can hold, in fixed text: it quotes none
/// of the link, which carries the relay channel's secret.
const QR_DOES_NOT_FIT: &str = "the Pubky Ring sign-in link is too long for a QR code";

/// What qrcode's SVG renderer starts every image with (qrcode 0.14.1's
/// `render/svg.rs`). An XML declaration belongs at the top of an XML file,
/// not inside an HTML page, so [`qr_svg`] strips it.
const XML_PROLOG: &str = r#"<?xml version="1.0" standalone="yes"?>"#;

/// The page's one script: it keeps the status line up to date and makes the
/// copy button work.
///
/// It is a constant, the same for every flow. Nothing from the flow is
/// written into it: the status path comes from the `data-status` attribute
/// and the link from the `auth-link` element, both escaped as HTML when the
/// page is written. Putting a value into script text instead would need
/// JavaScript escaping, a different and easier-to-get-wrong problem.
///
/// It sets text with `textContent`, never `innerHTML`, so even a word the
/// script did not expect could not become markup; it fetches exactly the
/// path the attribute holds, which [`render_page`] checks is absolute, so
/// it never builds a URL of its own.
const STATUS_SCRIPT: &str = r#"
"use strict";
(() => {
  const status = document.getElementById("status");
  const path = status.getAttribute("data-status");
  const text = {
    waiting: status.textContent,
    approved: "approved in Pubky Ring; the terminal finishes the login, so you can close this tab",
    refused: "Sweepky refused this approval; the terminal says why",
    expired: "this sign-in page expired; run sweepky login again",
  };
  const pollMs = 1000;
  const maxFailures = 5;
  let failures = 0;
  const poll = async () => {
    try {
      const response = await fetch(path, { cache: "no-store" });
      const word = response.ok ? (await response.text()).trim() : "";
      if (!Object.hasOwn(text, word)) throw new Error("not a status");
      failures = 0;
      status.textContent = text[word];
      if (word !== "waiting") return;
    } catch {
      failures += 1;
      if (failures >= maxFailures) {
        status.textContent = "the terminal stopped answering; it shows how the login ended";
        return;
      }
    }
    setTimeout(poll, pollMs);
  };
  setTimeout(poll, pollMs);

  const copy = document.getElementById("copy");
  const link = document.getElementById("auth-link").textContent;
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(link);
      copy.textContent = "Copied: now paste it into Ring on your phone";
    } catch {
      copy.textContent = "Copying failed: select the link below and copy it";
    }
  });
})();
"#;

/// The page's one stylesheet. The QR code keeps its own white background
/// and black modules in a dark theme too, so a phone can always read it.
const STYLE: &str = r#"
:root { color-scheme: light dark; font-family: system-ui, sans-serif; line-height: 1.5; }
body { margin: 0; padding: 16px; }
main { max-width: 34rem; margin: 0 auto; }
#qr svg { display: block; width: 100%; max-width: 360px; height: auto; }
#auth-link { display: block; word-break: break-all; font-size: 0.85rem; }
button { font: inherit; padding: 0.5rem 1rem; }
#status { font-weight: 600; }
"#;

/// The sign-in page for the authorization URL `link`, whose status line
/// asks `status_path` and whose script and style carry `nonce`.
///
/// `status_path` must be an absolute path on this server: it starts with
/// one `/` and holds only letters, digits and `/-_.~`, so a browser cannot
/// read it as another host (`//host` or `/\host`) or as relative to the
/// page. `nonce` must be one a CSP header can carry, base64 as CSP defines
/// it. The server makes both; either one wrong is a bug there, refused in
/// fixed text. A link too long for a QR code is refused in fixed text too.
pub(crate) fn render_page(link: &str, status_path: &str, nonce: &str) -> anyhow::Result<String> {
    if !is_status_path(status_path) {
        bail!("the sign-in page's status path is not an absolute path on this server");
    }
    if !is_csp_nonce(nonce) {
        bail!("the sign-in page's nonce is not one a Content-Security-Policy can carry");
    }
    let qr = qr_svg(link)?;
    // Each value is escaped as it goes in, whether or not it could hold a
    // character that needs it: what reaches the page is then never a
    // question of where the value came from. The SVG is the one exception,
    // because it is markup: qrcode writes it from numbers and the two fixed
    // colours alone, so it holds nothing from the link but the shape of its
    // QR code.
    //
    // The style and the script go in as arguments (`{style}`, `{script}`)
    // rather than as part of the template, so their own `{` and `}` need
    // no doubling: `format!` reads braces only in its template.
    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sweepky: sign in with Pubky Ring</title>
<style nonce="{nonce}">{style}</style>
</head>
<body>
<main>
<h1>Sign in to Sweepky with Pubky Ring</h1>
<p>Scan this code with Pubky Ring on your phone.</p>
<div id="qr" role="img" aria-label="QR code of the sign-in link">{qr}</div>
<p>Or copy the link and paste it into Ring:</p>
<p><button id="copy" type="button">Copy the link to paste into Ring on your phone</button></p>
<p><code id="auth-link">{link}</code></p>
<h2>What Sweepky asks for</h2>
<dl>
<dt>Access</dt>
<dd><code>{capability}</code>: read and write under <code>/pub/sweepky/</code>, where Sweepky keeps its records, and nothing else in your account</dd>
<dt>App</dt>
<dd><code>{client_id}</code>, the name Ring shows for it</dd>
</dl>
<p id="status" role="status" data-status="{status_path}">waiting for approval in Pubky Ring</p>
</main>
<script nonce="{nonce}">{script}</script>
</body>
</html>
"#,
        nonce = html_escape(nonce),
        style = STYLE,
        qr = qr,
        link = html_escape(link),
        capability = html_escape(SWEEPKY_CAPABILITY),
        client_id = html_escape(CLIENT_ID),
        status_path = html_escape(status_path),
        script = STATUS_SCRIPT,
    ))
}

/// `link` as a QR code drawn in block characters, two rows of modules per
/// line of text, for the terminal: the fallback for an SSH session or a
/// machine with no browser.
///
/// The lowest error correction keeps it small: a 400-character link fits
/// an 80-column terminal. The terminal is not a printed code that can get
/// scratched, so the extra redundancy would only make it bigger. Light
/// modules (and the quiet zone around the code) are drawn as blocks and
/// dark ones left blank, as `qrencode -t UTF8` draws them: on the usual
/// light-on-dark terminal that shows dark modules on a light ground, the
/// way a scanner expects. The link printed beside it is the fallback for a
/// terminal where that does not hold.
pub(crate) fn terminal_qr(link: &str) -> anyhow::Result<String> {
    let code = qr_code(link, EcLevel::L)?;
    // `render` returns a builder. Each setter takes it as `&mut` and returns
    // that same `&mut`, so the calls chain on one temporary builder, which
    // lives to the end of this statement; `build` returns an owned `String`
    // that outlives it.
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .build())
}

/// `text` escaped for HTML, as element text or inside a quoted attribute:
/// `&`, `<`, `>`, `"` and `'` become entities, and everything else stays as
/// it is.
///
/// Those five are all HTML needs: `<` and `&` start markup and entities in
/// text, and a quote would end a quoted attribute value.
fn html_escape(text: &str) -> String {
    // Most text needs no escape, so its own length is the right start; the
    // `String` grows if it has to.
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// `link`'s QR code as an SVG element for the page, at qrcode's default
/// (medium) error correction, which a phone reads easily from a screen.
fn qr_svg(link: &str) -> anyhow::Result<String> {
    let image = qr_code(link, EcLevel::M)?
        .render::<svg::Color<'_>>()
        .build();
    // `strip_prefix` returns the text after the prolog, or `None` when the
    // text does not start with it, without indexing into the string (an
    // index off a character boundary would panic). A qrcode release that
    // changed its prolog would land in the `None` arm: refused in fixed
    // text, never a panic and never a page with the prolog left in.
    image
        .strip_prefix(XML_PROLOG)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("the QR code library wrote an SVG this build does not expect"))
}

/// `link` as a QR code at error correction `level`, or [`QR_DOES_NOT_FIT`].
///
/// qrcode picks the smallest version that holds the link. In practice its
/// one error for an automatic version is that the data does not fit even
/// the largest (2953 bytes at the lowest level). Any error is replaced, not
/// wrapped, so the message is always the fixed text.
fn qr_code(link: &str, level: EcLevel) -> anyhow::Result<QrCode> {
    QrCode::with_error_correction_level(link, level).map_err(|_| anyhow!(QR_DOES_NOT_FIT))
}

/// Whether `path` is an absolute path on this server and nothing else: one
/// leading `/`, then only ASCII letters, digits and `/-_.~`.
///
/// `//host/...` is a URL to another host (a "protocol-relative" URL), and
/// browsers read `\` as `/` in an http URL, so `/\host/...` is too; the
/// character list keeps out both, and every character that would need
/// escaping in a URL.
fn is_status_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~'))
}

/// Whether `nonce` is a CSP nonce: CSP's `base64-value`, one or more of
/// `A-Z a-z 0-9 + / - _`, then at most two `=`.
fn is_csp_nonce(nonce: &str) -> bool {
    // Up to two `=` come off the end. A third, or one anywhere else, is
    // left in `body`, where the character check refuses it. `strip_suffix`
    // returns `None` when the text does not end that way, and `unwrap_or`
    // then keeps the whole nonce: no index, so nothing can panic.
    let body = nonce
        .strip_suffix("==")
        .or_else(|| nonce.strip_suffix('='))
        .unwrap_or(nonce);
    !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::{
        QR_DOES_NOT_FIT, STATUS_SCRIPT, SignInStatus, html_escape, render_page, terminal_qr,
    };

    /// A synthetic grant link shaped like the SDK's, with made-up values:
    /// `&` in its query, and a relay URL with `http://` in it.
    const LINK: &str = "pubkyauth://signin_grant?caps=/pub/sweepky/:rw\
        &relay=http://localhost:15412/inbox&cid=sweepky-cli\
        &cpk=yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\
        &secret=c3ludGhldGljLXJlbGF5LWNoYW5uZWwtc2VjcmV0LTAx";

    /// A synthetic status path, as the loopback server would make one.
    const STATUS_PATH: &str = "/c3ludGhldGljLWZsb3ctcGF0aA/status";

    /// A synthetic nonce, base64 as CSP nonces are.
    const NONCE: &str = "c3ludGhldGljLW5vbmNl";

    fn page() -> String {
        render_page(LINK, STATUS_PATH, NONCE).expect("a page")
    }

    /// The text between `open` and the first `close` after it, where
    /// `open` occurs exactly once in `page`.
    fn between<'a>(page: &'a str, open: &str, close: &str) -> &'a str {
        assert_eq!(page.matches(open).count(), 1, "{open}");
        let (_, rest) = page.split_once(open).expect("the opening");
        let (inside, _) = rest.split_once(close).expect("the closing");
        inside
    }

    #[test]
    fn the_page_holds_the_qr_the_link_what_is_asked_and_waiting() {
        let page = page();
        // One inline SVG, with qrcode's XML prolog stripped: a prolog
        // inside HTML is not markup the browser expects.
        assert_eq!(page.matches("<svg").count(), 1, "{page}");
        assert!(!page.contains("<?xml"), "{page}");
        // The link, escaped, in the element the copy button reads.
        let shown = between(&page, r#"<code id="auth-link">"#, "</code>");
        assert_eq!(shown, LINK.replace('&', "&amp;"));
        let button = between(&page, r#"<button id="copy" type="button">"#, "</button>");
        assert!(button.contains("paste into Ring on your phone"), "{button}");
        // What is asked for.
        assert!(page.contains("<code>/pub/sweepky/:rw</code>"), "{page}");
        assert!(page.contains("<code>sweepky-cli</code>"), "{page}");
        // The status starts as waiting, and names its absolute path.
        let status = between(
            &page,
            &format!(r#"<p id="status" role="status" data-status="{STATUS_PATH}">"#),
            "</p>",
        );
        assert!(status.contains("waiting"), "{status}");
    }

    #[test]
    fn render_page_refuses_a_status_path_or_nonce_it_cannot_place_safely() {
        // Not absolute, or read by a browser as another host (`//host`,
        // `/\host`): the script would fetch somewhere other than this
        // server's status path.
        for path in [
            "status",
            "",
            "//example.test/status",
            "/\\example.test/status",
        ] {
            assert!(render_page(LINK, path, NONCE).is_err(), "{path}");
        }
        // Not base64 as CSP defines it, so no CSP header could name it.
        for nonce in ["", "==", "a\"b", "a b", "abc==="] {
            assert!(render_page(LINK, STATUS_PATH, nonce).is_err(), "{nonce}");
        }
    }

    #[test]
    fn one_nonced_script_and_style_and_no_inline_handler_or_style() {
        let page = page();
        assert_eq!(page.matches("<script").count(), 1, "{page}");
        assert_eq!(page.matches("<style").count(), 1, "{page}");
        between(&page, &format!(r#"<script nonce="{NONCE}">"#), "</script>");
        between(&page, &format!(r#"<style nonce="{NONCE}">"#), "</style>");
        // A strict nonce CSP blocks both, and the page needs neither.
        assert!(!has_event_handler_attribute(&page), "{page}");
        assert!(!page.contains("style="), "{page}");
    }

    /// Whether `page` has an `on...=` attribute anywhere: `on` after
    /// whitespace, then letters, then `=`.
    fn has_event_handler_attribute(page: &str) -> bool {
        page.match_indices("on").any(|(at, _)| {
            let before = page.get(..at).and_then(|text| text.chars().last());
            let name_end = page
                .get(at..)
                .and_then(|text| text.find(|c: char| !c.is_ascii_alphabetic()));
            let after = name_end
                .and_then(|end| page.get(at + end..))
                .and_then(|text| text.chars().next());
            before.is_some_and(char::is_whitespace) && after == Some('=')
        })
    }

    #[test]
    fn the_script_is_a_constant_that_fetches_the_attribute_path() {
        // Whatever the flow, the page carries the same script.
        for (link, path, nonce) in [
            (LINK, STATUS_PATH, NONCE),
            (
                "pubkyauth://signin_grant?other=1",
                "/other/status",
                "b3RoZXI=",
            ),
        ] {
            let page = render_page(link, path, nonce).expect("a page");
            let script = between(&page, &format!(r#"<script nonce="{nonce}">"#), "</script>");
            assert_eq!(script, STATUS_SCRIPT);
        }
        // It fetches the path the attribute holds as it is, and never
        // builds a URL of its own.
        assert!(STATUS_SCRIPT.contains(r#"getAttribute("data-status")"#));
        assert!(STATUS_SCRIPT.contains(r#"fetch(path, { cache: "no-store" })"#));
        for never in ["location", "URL(", "./", "innerHTML", "+ path", "path +"] {
            assert!(!STATUS_SCRIPT.contains(never), "{never}");
        }
        // It knows every word the status path answers with.
        for status in [
            SignInStatus::Waiting,
            SignInStatus::Approved,
            SignInStatus::Refused,
            SignInStatus::Expired,
        ] {
            assert!(
                STATUS_SCRIPT.contains(&format!("{}: ", status.word())),
                "{status:?}"
            );
        }
    }

    #[test]
    fn the_page_loads_nothing_and_holds_no_web_address_but_two() {
        let page = page();
        for tag in ["<script src", "<link", "<img", "<iframe", "<form"] {
            assert!(!page.contains(tag), "{tag}");
        }
        // Take out the two web addresses the page may hold, each once: the
        // SVG namespace on the svg element, and the escaped link, whose
        // relay URL is one. None may be left.
        let namespace = r#"<svg xmlns="http://www.w3.org/2000/svg""#;
        let link = LINK.replace('&', "&amp;");
        assert_eq!(page.matches(namespace).count(), 1, "{page}");
        assert_eq!(page.matches(&link).count(), 1, "{page}");
        let rest = page.replace(namespace, "").replace(&link, "");
        assert!(!rest.contains("http://"), "{rest}");
        assert!(!rest.contains("https://"), "{rest}");
    }

    #[test]
    fn html_escape_escapes_the_five_and_nothing_else() {
        assert_eq!(html_escape(r#"&<>"'"#), "&amp;&lt;&gt;&quot;&#39;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        for plain in ["", "plain text, /pub/sweepky/:rw = ok", "é 漢字 🙂"] {
            assert_eq!(html_escape(plain), plain);
        }
    }

    #[test]
    fn terminal_qr_draws_a_400_character_link_in_blocks_for_80_columns() {
        let long = format!("{LINK}&pad={}", "x".repeat(400 - LINK.len() - 5));
        assert_eq!(long.len(), 400);
        let qr = terminal_qr(&long).expect("a QR code");
        assert!(qr.contains('█'), "{qr}");
        assert!(
            qr.chars()
                .all(|c| matches!(c, ' ' | '▀' | '▄' | '█' | '\n')),
            "{qr}"
        );
        // Every line as wide, and no wider than an 80-column terminal.
        let widths: Vec<usize> = qr.lines().map(|line| line.chars().count()).collect();
        assert!(
            widths
                .iter()
                .all(|width| *width == widths[0] && *width <= 80),
            "{widths:?}"
        );
    }

    #[test]
    fn a_link_too_long_for_any_qr_code_is_refused_in_fixed_text() {
        // Past the largest QR code even at the lowest error correction
        // (2953 bytes), with a marker the error must not repeat.
        let marker = "syntheticmarker";
        let too_long = format!("pubkyauth://signin_grant?pad={}{marker}", "x".repeat(3000));
        for err in [
            terminal_qr(&too_long).expect_err("too long"),
            render_page(&too_long, STATUS_PATH, NONCE).expect_err("too long"),
        ] {
            let text = format!("{err:#}");
            assert_eq!(text, QR_DOES_NOT_FIT);
            assert!(
                !text.contains(marker) && !text.contains("pubkyauth"),
                "{text}"
            );
        }
    }
}
