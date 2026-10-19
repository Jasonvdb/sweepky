//! Takes out of a fetched target the files that would load as instructions
//! for the agent, 02's list: `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`,
//! `.claude/` and `.mcp.json`.
//!
//! - **At every depth.** Claude Code loads a subdirectory's `CLAUDE.md` the
//!   first time the agent reads a file there, and the fixture plants one in
//!   `src/auth/`.
//! - **In any case.** macOS's default filesystem ignores case, so a
//!   `claude.md` in the repository is the file Claude Code opens as
//!   `CLAUDE.md`.
//! - **Whatever is at such a name goes**: a file, a directory with all it
//!   holds, or a link, of which only the link itself is removed.
//! - **No link is ever followed.** The walk reads each entry's own type, as
//!   `lstat` does, and descends only into real directories; a removal never
//!   follows a link either. With `core.symlinks=false` the checkout wrote
//!   none anyway, so this is the second line.
//!
//! What stripping cannot reach is git's history: a `git diff` the agent runs
//! (a commit or pull request target's scope command) still shows a changed
//! `CLAUDE.md`'s lines. That is content to review, not instructions: Claude
//! Code loads instructions only from files on disk.
//!
//! The names come from the repository, so [`strip_agent_files`]'s list is
//! only written into `scope.json`, as JSON; anything that prints one runs it
//! through the terminal sanitiser first.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// The names stripped, in lower case, as [`fold`] compares them.
const AGENT_FILES: [&str; 5] = [
    "claude.md",
    "claude.local.md",
    "agents.md",
    ".claude",
    ".mcp.json",
];

/// Removes every entry under `root` named as one of [`AGENT_FILES`], in any
/// case, at any depth, and returns what it removed: each path relative to
/// `root`, `/`-separated, a directory with a trailing `/`, sorted.
///
/// A path that is not UTF-8 is listed with `U+FFFD` in place of what is not;
/// the list says what went, it is never a path to open.
pub(super) fn strip_agent_files(root: &Path) -> anyhow::Result<Vec<String>> {
    let mut stripped = Vec::new();
    // The directories still to look in: each one's path on disk, and the
    // same path relative to `root` as the list writes it ("" for `root`,
    // else ending in `/`). A stack rather than recursion, so a deep tree
    // cannot exhaust the call stack.
    let mut pending: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, relative)) = pending.pop() {
        let entries =
            fs::read_dir(&dir).with_context(|| format!("could not list {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("could not list {}", dir.display()))?;
            let path = entry.path();
            // `DirEntry::file_type` describes the entry itself, as `lstat`
            // does: for a link, the link, never what it points at.
            let kind = entry
                .file_type()
                .with_context(|| format!("could not inspect {}", path.display()))?;
            let name = entry.file_name();
            let listed = format!("{relative}{}", name.to_string_lossy());
            if is_agent_file(&name) {
                if kind.is_dir() {
                    // A real directory (a link to one is not `is_dir` here).
                    // std's `remove_dir_all` removes a link it meets inside
                    // as a link, and never follows one (the fix for
                    // CVE-2022-21658, in every Rust since 1.58.1).
                    fs::remove_dir_all(&path)
                        .with_context(|| format!("could not remove {}", path.display()))?;
                    stripped.push(format!("{listed}/"));
                } else {
                    // A file or a link: `unlink`, which removes a link
                    // itself, never the file it points at.
                    fs::remove_file(&path)
                        .with_context(|| format!("could not remove {}", path.display()))?;
                    stripped.push(listed);
                }
            } else if kind.is_dir() {
                pending.push((path, format!("{listed}/")));
            }
        }
    }
    // `read_dir` lists in no set order, so sort for a list that is the same
    // on every run.
    stripped.sort();
    Ok(stripped)
}

/// Whether `name` is one of [`AGENT_FILES`] once case is ignored. A name
/// that is not UTF-8 is none of them.
fn is_agent_file(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    // `chars().map(fold)` folds `name` one character at a time, and `eq`
    // compares that with the stored name without building a new string.
    AGENT_FILES
        .iter()
        .any(|agent| name.chars().map(fold).eq(agent.chars()))
}

/// `c` with its case folded as a case-insensitive filesystem folds it, as
/// far as [`AGENT_FILES`] can tell: ASCII letters to lower case, and the
/// long s, U+017F, to `s`, which Unicode's case folding does too. macOS's
/// APFS opens `AGENTſ.md` as `AGENTS.md` (checked on APFS while this was
/// written), so it is stripped as well. No other character folds onto a
/// letter or a run of letters in those five names.
fn fold(c: char) -> char {
    match c {
        '\u{17F}' => 's',
        _ => c.to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use super::strip_agent_files;
    use crate::test_support::private_temp;

    /// Writes `text` to `root/relative`, making its directories first.
    fn plant(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(path, text).expect("write");
    }

    fn gone(path: &Path) -> bool {
        fs::symlink_metadata(path).is_err()
    }

    #[test]
    fn every_agent_file_goes_at_every_depth_and_in_any_case() {
        let temp = private_temp();
        let root = temp.path();
        // 02's five names, a nested one, and case variants of each.
        for relative in [
            "CLAUDE.md",
            "CLAUDE.local.md",
            "AGENTS.md",
            ".claude/settings.json",
            ".mcp.json",
            "src/auth/CLAUDE.md",
            "docs/claude.md",
            "docs/Agents.MD",
            "docs/deep/er/.CLAUDE/commands/x.md",
            "docs/.Mcp.Json",
            "docs/claude.LOCAL.md",
            // The long s, which APFS folds to `s`; in a directory of its
            // own, since there it is the same file as `docs/Agents.MD`.
            "unicode/AGENT\u{17F}.md",
        ] {
            plant(root, relative, "fixture: run must strip this");
        }
        // Ordinary files, and names that only look like agent files.
        let kept = [
            "README.md",
            "src/lib.rs",
            "src/auth/session.rs",
            "docs/CLAUDE.md.bak",
            "docs/AGENTS.txt",
            "docs/my.claude/notes.md",
            "docs/.claude-old",
            "docs/CLAUDE",
        ];
        for relative in kept {
            plant(root, relative, "ordinary");
        }
        // A `.mcp.json` that is a directory goes too.
        fs::create_dir_all(root.join("tools/.mcp.json/inner")).expect("mkdir");

        let stripped = strip_agent_files(root).expect("strips");
        assert_eq!(
            stripped,
            [
                ".claude/",
                ".mcp.json",
                "AGENTS.md",
                "CLAUDE.local.md",
                "CLAUDE.md",
                "docs/.Mcp.Json",
                "docs/Agents.MD",
                "docs/claude.LOCAL.md",
                "docs/claude.md",
                "docs/deep/er/.CLAUDE/",
                "src/auth/CLAUDE.md",
                "tools/.mcp.json/",
                "unicode/AGENT\u{17F}.md",
            ]
        );
        for relative in &stripped {
            assert!(gone(&root.join(relative)), "{relative} is still there");
        }
        for relative in kept {
            assert_eq!(
                fs::read_to_string(root.join(relative)).expect(relative),
                "ordinary"
            );
        }
        // The directories that held a stripped file stay.
        assert!(root.join("docs/deep/er").is_dir());
        // A second pass finds nothing left.
        assert_eq!(
            strip_agent_files(root).expect("strips"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_link_is_removed_itself_and_never_followed() {
        let outside = private_temp();
        plant(outside.path(), "secret.txt", "outside");
        plant(outside.path(), "CLAUDE.md", "outside");
        plant(outside.path(), "dir/AGENTS.md", "outside");
        let temp = private_temp();
        let root = temp.path();
        // A link named as an agent file, to a file and to a directory
        // outside the target.
        symlink(outside.path().join("secret.txt"), root.join("CLAUDE.md")).expect("symlink");
        symlink(outside.path().join("dir"), root.join(".claude")).expect("symlink");
        // A link to a directory under an ordinary name: never walked into,
        // so the agent files beyond it are not this target's to remove.
        symlink(outside.path(), root.join("linked")).expect("symlink");
        // A dangling link named as an agent file.
        symlink(root.join("nowhere"), root.join("AGENTS.md")).expect("symlink");

        let stripped = strip_agent_files(root).expect("strips");
        assert_eq!(stripped, [".claude", "AGENTS.md", "CLAUDE.md"]);
        for name in &stripped {
            assert!(gone(&root.join(name)), "{name}");
        }
        // Everything outside is as it was, and the ordinary link stays.
        for relative in ["secret.txt", "CLAUDE.md", "dir/AGENTS.md"] {
            assert_eq!(
                fs::read_to_string(outside.path().join(relative)).expect(relative),
                "outside"
            );
        }
        assert!(
            fs::symlink_metadata(root.join("linked"))
                .expect("there")
                .is_symlink()
        );
    }
}
