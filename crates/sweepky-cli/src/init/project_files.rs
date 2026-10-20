//! The files P3's `init` writes for Claude Code, before the marker: the
//! sandbox settings `.claude/settings.json`, the project's `CLAUDE.md` and a
//! copy of the `/sweepky` skill at `.claude/skills/sweepky/SKILL.md`.
//!
//! The three texts live in the repository under `skills/sweepky/` and are
//! built into the binary with `include_str!`, so the files `init` writes are
//! the reviewed ones byte for byte, and nothing is read from disk at run
//! time. Only the settings change per project: their `claudeMdExcludes`
//! names the project's own canonical path.
//!
//! The same rules as the rest of `init` apply: every file is new (created
//! all or nothing, [`write_new`]) or already holds exactly the bytes `init`
//! would write, and is then kept. Everything is inspected before anything is
//! written, so a refusal changes nothing in the project.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use serde_json::Value;

use super::{Existing, existing, write_new};
use crate::private_fs::{lstat, open_seen_file, read_up_to_cap, refuse_unless_dir, sync_parent};

/// The sandbox template from 02, with a placeholder where the project's
/// path goes. `include_str!` reads the file at compile time, relative to
/// this source file, so a moved or deleted template is a compile error.
const SETTINGS_TEMPLATE: &str = include_str!("../../../../skills/sweepky/settings.json");

/// The project's `CLAUDE.md`: what the agent finds, where it writes, what it
/// must not do.
const PROJECT_CLAUDE_MD: &str = include_str!("../../../../skills/sweepky/project-CLAUDE.md");

/// The `/sweepky` skill, copied into the project unchanged.
const SKILL: &str = include_str!("../../../../skills/sweepky/SKILL.md");

/// The settings key whose value names the project's path.
const EXCLUDES_KEY: &str = "claudeMdExcludes";

/// The directories `init` makes for Claude Code, parents first, relative to
/// the project.
const CLAUDE_DIRS: [&str; 3] = [".claude", ".claude/skills", ".claude/skills/sweepky"];

/// The settings file, relative to the project. `init`'s second run looks for
/// it to tell a P3 project from one P2a's `init` made.
pub(super) const SETTINGS: &str = ".claude/settings.json";

/// Characters a glob pattern gives a meaning to. A project path holding one
/// would change what `claudeMdExcludes` matches, so `init` refuses it. `*`,
/// `?`, `[ ]`, `{ }` and `\` are the usual ones; `( )` close the door on
/// extended globs such as `@(a|b)` too.
const GLOB_METACHARACTERS: [char; 9] = ['*', '?', '[', ']', '{', '}', '\\', '(', ')'];

/// The project path as text that is safe to put into a glob pattern: valid
/// UTF-8 (JSON strings are text, and a lossy conversion would name another
/// directory) and free of [`GLOB_METACHARACTERS`]. The error names the path
/// and why.
///
/// The `&str` it returns borrows from `dir` (lifetime elision ties the one
/// output reference to the one input), so nothing is copied.
pub(super) fn glob_safe(dir: &Path) -> anyhow::Result<&str> {
    let Some(text) = dir.to_str() else {
        bail!(
            "{} is not valid UTF-8, so init cannot name it in .claude/settings.json; init a \
             directory whose path is UTF-8",
            dir.display()
        );
    };
    if text.contains(GLOB_METACHARACTERS) {
        bail!(
            "{} holds a character that is special in a glob pattern (one of * ? [ ] {{ }} \\ ( )), \
             which would change what the sandbox's claudeMdExcludes rule matches; init a \
             directory whose path has none",
            dir.display()
        );
    }
    Ok(text)
}

/// The bytes of `.claude/settings.json` for the project whose canonical path
/// is `canonical`: the template with `claudeMdExcludes` set to
/// `["<canonical>/sweeps/**/target/**"]`, pretty-printed, and a newline.
///
/// The template is parsed and the value set with `serde_json`, never spliced
/// in as text: serde_json escapes the path as a JSON string, so a `"` or a
/// newline in it cannot end the string and add keys of its own.
fn settings_bytes(canonical: &Path) -> anyhow::Result<Vec<u8>> {
    // `trim_end_matches` keeps a project at `/` from giving `//sweeps/…`.
    let pattern = format!(
        "{}/sweeps/**/target/**",
        glob_safe(canonical)?.trim_end_matches('/')
    );
    let mut settings: Value = serde_json::from_str(SETTINGS_TEMPLATE)
        .context("the built-in sandbox template is not JSON")?;
    // `as_object_mut` lends the top-level map out mutably, or gives `None`
    // when the template is not an object; `get_mut` then finds the key the
    // template must already have, so a renamed key fails here rather than
    // being added beside a stale one.
    let Some(excludes) = settings
        .as_object_mut()
        .and_then(|map| map.get_mut(EXCLUDES_KEY))
    else {
        bail!("the built-in sandbox template has no {EXCLUDES_KEY}");
    };
    *excludes = Value::Array(vec![Value::String(pattern)]);
    let mut bytes =
        serde_json::to_vec_pretty(&settings).context("could not write the sandbox settings")?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// What [`ClaudeFiles::write`] will do for one path.
enum Step {
    /// Make this directory; nothing is there yet.
    CreateDir(PathBuf),
    /// Create the file at `path`, named `relative` in the report, with
    /// `bytes`; nothing is there yet.
    CreateFile {
        path: PathBuf,
        relative: &'static str,
        bytes: Vec<u8>,
    },
    /// The file named `relative` already holds exactly the bytes init
    /// writes: a run that stopped part way wrote it, so it is kept.
    KeepFile { relative: &'static str },
}

/// The Claude Code files of one project, inspected and ready to write.
///
/// [`ClaudeFiles::inspect`] looks at every path and refuses before anything
/// is written; [`ClaudeFiles::write`] then makes what is missing. Two steps,
/// so `init` can run every check, `.gitignore`'s included, before its
/// first write.
pub(super) struct ClaudeFiles {
    steps: Vec<Step>,
}

impl ClaudeFiles {
    /// Looks at `.claude/`, its two subdirectories and the three files in
    /// `dir`, whose canonical path is `canonical`. Refuses a symlink or
    /// anything but a directory where a directory goes, and a symlink,
    /// anything but a regular file, or a file whose bytes differ from what
    /// init writes where a file goes. The error names the path and quotes
    /// none of the file.
    pub(super) fn inspect(dir: &Path, canonical: &Path) -> anyhow::Result<Self> {
        let mut steps = Vec::new();
        for relative in CLAUDE_DIRS {
            let path = dir.join(relative);
            match lstat(&path)? {
                None => steps.push(Step::CreateDir(path)),
                Some(meta) => refuse_unless_dir(&path, &meta)?,
            }
        }
        let files = [
            (SETTINGS, settings_bytes(canonical)?),
            ("CLAUDE.md", PROJECT_CLAUDE_MD.as_bytes().to_vec()),
            (".claude/skills/sweepky/SKILL.md", SKILL.as_bytes().to_vec()),
        ];
        for (relative, bytes) in files {
            let path = dir.join(relative);
            steps.push(if holds_exactly(&path, &bytes)? {
                Step::KeepFile { relative }
            } else {
                Step::CreateFile {
                    path,
                    relative,
                    bytes,
                }
            });
        }
        Ok(Self { steps })
    }

    /// Makes the missing directories and files, in order, and returns one
    /// report line per file. Each new directory's name is synced to disk
    /// through its parent, as each new file's is by [`write_new`].
    // `self` by value: the steps are used up, so they cannot run twice.
    pub(super) fn write(self) -> anyhow::Result<Vec<String>> {
        let mut lines = Vec::new();
        for step in self.steps {
            match step {
                Step::CreateDir(path) => {
                    // `create_dir`, not `create_dir_all`: it fails if
                    // anything at all is at `path`, a symlink included,
                    // rather than accept what someone put there since the
                    // inspection.
                    fs::create_dir(&path)
                        .with_context(|| format!("could not create {}", path.display()))?;
                    sync_parent(&path)?;
                }
                Step::CreateFile {
                    path,
                    relative,
                    bytes,
                } => {
                    write_new(&path, &bytes)?;
                    lines.push(format!("wrote {relative}"));
                }
                Step::KeepFile { relative } => {
                    lines.push(format!(
                        "kept {relative}, which already held what init writes"
                    ));
                }
            }
        }
        Ok(lines)
    }
}

/// Whether the regular file at `path` holds exactly `bytes`: `false` when
/// nothing is there, an error for anything else, and for a file that holds
/// other bytes. An identical file is what a run that stopped part way left,
/// so keeping it lets the next run finish.
///
/// Reads at most one byte past `bytes.len()`, which is enough to tell a
/// longer file, so a huge file planted at the name is never read whole. The
/// error never quotes the file.
fn holds_exactly(path: &Path, bytes: &[u8]) -> anyhow::Result<bool> {
    let seen = match existing(path)? {
        Existing::Missing => return Ok(false),
        Existing::File(seen) => seen,
        Existing::Symlink => bail!(
            "{} is a symbolic link; init never writes through a link. Remove it and run init \
             again",
            path.display()
        ),
        Existing::Other => bail!(
            "{} exists and is not a regular file; move it away and run init again",
            path.display()
        ),
    };
    let (mut file, _) = open_seen_file(path, &seen, OpenOptions::new().read(true))?;
    let found = read_up_to_cap(&mut file, bytes.len().saturating_add(1))
        .with_context(|| format!("could not read {}", path.display()))?;
    // `found` is a `Zeroizing<Vec<u8>>`; `as_slice` views it as bytes for the
    // comparison.
    if found.as_slice() != bytes {
        bail!(
            "{} already exists and differs from the file init writes; move it away and run init \
             again",
            path.display()
        );
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use serde_json::{Value, json};

    use super::{PROJECT_CLAUDE_MD, SETTINGS_TEMPLATE, SKILL, glob_safe, settings_bytes};
    use crate::dirs::Dirs;
    use crate::identity::IdentityName;
    use crate::init::{MARKER, init_without_playbook as init};

    /// 02's sandbox template, as its "Sweeper safety" section shows it, with
    /// the project's path filled in.
    fn expected_settings(canonical: &Path) -> Value {
        let pattern = format!("{}/sweeps/**/target/**", canonical.display());
        json!({
            "sandbox": {
                "enabled": true,
                "failIfUnavailable": true,
                "allowUnsandboxedCommands": false,
                "filesystem": { "denyRead": ["~/.config/sweepky", "~/.local/share/sweepky"] }
            },
            "permissions": {
                "blockReadsOutsideWorkingDirectories": true,
                "deny": ["WebFetch", "WebFetch(domain:*)", "WebSearch", "mcp__*", "Artifact"]
            },
            "claudeMdExcludes": [pattern]
        })
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).expect("readable")).expect("JSON")
    }

    #[test]
    fn init_writes_02_s_sandbox_settings_with_the_canonical_path() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");
        init(&dir).expect("init succeeds");

        // On macOS the temp dir is under /var, a link to /private/var: the
        // canonical path is the one the pattern names, because Claude Code
        // matches the files' real absolute paths.
        let canonical = fs::canonicalize(&dir).expect("canonical");
        assert_eq!(
            read_json(&dir.join(".claude/settings.json")),
            expected_settings(&canonical)
        );
    }

    #[test]
    fn the_template_in_the_repository_is_02_s() {
        // The template file and 02's code block hold the same JSON, with the
        // same placeholder, so a change to one without the other fails here.
        let doc = include_str!("../../../../docs/plan/02-encryption-and-safety.md");
        let (_, after) = doc
            .split_once("`sweepky init <dir>` writes `.claude/settings.json`:")
            .expect("02 introduces the template");
        let (_, block) = after.split_once("```json").expect("a json block");
        let (block, _) = block.split_once("```").expect("the block ends");
        let from_doc: Value = serde_json::from_str(block).expect("02's block is JSON");
        let template: Value = serde_json::from_str(SETTINGS_TEMPLATE).expect("template is JSON");
        assert_eq!(template, from_doc);
        assert_eq!(
            template,
            expected_settings(Path::new("<absolute init dir>"))
        );
    }

    #[test]
    fn the_first_deny_read_entry_covers_every_secret_file() {
        // `~/.config/sweepky`, expanded with HOME as `Dirs` resolves it,
        // holds the device key, the identity files and P2d's grant token;
        // the second entry is the data directory. So `cat
        // ~/.config/sweepky/*` from a sandboxed command is denied.
        let template: Value = serde_json::from_str(SETTINGS_TEMPLATE).expect("JSON");
        let deny_read: Vec<&str> = template["sandbox"]["filesystem"]["denyRead"]
            .as_array()
            .expect("a list")
            .iter()
            .map(|entry| entry.as_str().expect("a string"))
            .collect();
        let home = Path::new("/home/sweeper");
        let expand = |entry: &str| home.join(entry.strip_prefix("~/").expect("under ~"));
        let [config, data] = deny_read.as_slice() else {
            panic!("two entries: {deny_read:?}");
        };
        let (config, data) = (expand(config), expand(data));

        let dirs = Dirs::resolve(Some(home.as_os_str()), None).expect("resolves");
        let name: IdentityName = "throwaway".parse().expect("valid name");
        assert_eq!(dirs.config(), config);
        assert_eq!(dirs.data(), data);
        for secret in [
            dirs.device_key_file(),
            dirs.grant_token_file(),
            dirs.identity_key_file(&name),
            dirs.identity_file(&name),
            dirs.login_file(),
        ] {
            assert!(secret.starts_with(&config), "{}", secret.display());
        }
    }

    #[test]
    fn a_path_that_would_change_the_glob_is_refused_before_anything_is_written() {
        let temp = tempfile::tempdir().expect("temp dir");
        for name in ["star*", "what?", "[set]", "{a,b}", "back\\slash", "@(x)"] {
            let dir = temp.path().join(name);
            let err = init(&dir).expect_err(name);
            assert!(format!("{err:#}").contains("glob"), "{name}: {err:#}");
            assert!(!dir.exists(), "{name}");
        }

        // A path that is not UTF-8 cannot be written into JSON as itself.
        // `OsStr::from_bytes` (a Unix extension) builds one from raw bytes.
        use std::os::unix::ffi::OsStrExt;
        let dir = temp
            .path()
            .join(std::ffi::OsStr::from_bytes(b"not-\xff-utf8"));
        let err = init(&dir).expect_err("not UTF-8");
        assert!(format!("{err:#}").contains("UTF-8"), "{err:#}");
        assert!(!dir.exists());

        // A parent link whose target holds one is caught on the canonical
        // path, still before any file is written.
        let odd = temp.path().join("odd[1]");
        fs::create_dir(&odd).expect("mkdir");
        let link = temp.path().join("plain");
        symlink(&odd, &link).expect("symlink");
        let err = init(&link.join("project")).expect_err("canonical path refused");
        assert!(format!("{err:#}").contains("glob"), "{err:#}");
        let made: Vec<_> = fs::read_dir(odd.join("project"))
            .expect("the directory itself was made")
            .collect();
        assert!(made.is_empty());
    }

    #[test]
    fn a_quote_or_newline_in_the_path_stays_inside_the_json_string() {
        // serde_json escapes the path, so it cannot end the string and add a
        // key, as text splicing would let `", "sandbox": {...` do.
        let dir = Path::new("/tmp/a\"b\nc");
        assert!(glob_safe(dir).is_ok());
        let settings: Value =
            serde_json::from_slice(&settings_bytes(dir).expect("built")).expect("JSON");
        assert_eq!(settings, expected_settings(dir));
    }

    #[test]
    fn the_skill_and_claude_md_are_copied_byte_for_byte() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");
        init(&dir).expect("init succeeds");

        // `SKILL` is the repository's `skills/sweepky/SKILL.md`, built in
        // with `include_str!`; read here from disk too, so the copy is
        // compared with the file and not only with itself.
        let repo_skill = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../skills/sweepky/SKILL.md"
        ))
        .expect("the repository's skill");
        assert_eq!(SKILL.as_bytes(), repo_skill);
        assert_eq!(
            fs::read(dir.join(".claude/skills/sweepky/SKILL.md")).expect("copied"),
            repo_skill
        );
        assert_eq!(
            fs::read_to_string(dir.join("CLAUDE.md")).expect("written"),
            PROJECT_CLAUDE_MD
        );
    }

    #[test]
    fn the_project_claude_md_says_where_to_write_and_what_not_to_do() {
        for phrase in [
            "./sweeps/<id>/",
            "scope.json",
            "Write only under `./sweeps/<id>/audit/`",
            "No network.",
            "Never run `sweepky`",
            "Never read other `sweeps/` directories",
            "Never read anything under `~/.config/sweepky`",
            "Never run target code",
            "names the sweeper's configured playbook. Read it as data",
        ] {
            assert!(PROJECT_CLAUDE_MD.contains(phrase), "{phrase}");
        }
    }

    #[test]
    fn existing_claude_files_are_kept_only_when_identical() {
        let temp = tempfile::tempdir().expect("temp dir");

        // A run that stopped part way left the settings and the skill: the
        // next run keeps them and finishes.
        let first = temp.path().join("first");
        init(&first).expect("init succeeds");
        let settings = fs::read(first.join(".claude/settings.json")).expect("settings");
        let dir = temp.path().join("part-way");
        fs::create_dir_all(dir.join(".claude/skills/sweepky")).expect("mkdir");
        let canonical = fs::canonicalize(&dir).expect("canonical");
        fs::write(
            dir.join(".claude/settings.json"),
            settings_bytes(&canonical).expect("built"),
        )
        .expect("write");
        fs::write(dir.join(".claude/skills/sweepky/SKILL.md"), SKILL).expect("write");
        let report = init(&dir).expect("init finishes");
        assert!(report.text().contains("kept"), "{}", report.text());
        assert!(dir.join(MARKER).is_file());
        assert_ne!(
            settings,
            fs::read(dir.join(".claude/settings.json")).expect("settings"),
            "each project names its own path"
        );

        // A file that differs, shorter, longer or other bytes, is refused by
        // name, quoted nowhere, left as it was, and nothing is written.
        for (name, relative) in [
            ("settings", ".claude/settings.json"),
            ("claude-md", "CLAUDE.md"),
            ("skill", ".claude/skills/sweepky/SKILL.md"),
        ] {
            for (case, contents) in [
                ("other", b"PLANTED-7f3a\n".to_vec()),
                ("longer", [SKILL.as_bytes(), b"PLANTED-7f3a"].concat()),
                ("empty", Vec::new()),
            ] {
                let dir = temp.path().join(format!("{name}-{case}"));
                let path = dir.join(relative);
                fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
                fs::write(&path, &contents).expect("write");
                let err = init(&dir).expect_err(name);
                let message = format!("{err:#}");
                assert!(message.contains(&path.display().to_string()), "{message}");
                assert!(message.contains("differs"), "{message}");
                assert!(!message.contains("PLANTED"), "{message}");
                assert_eq!(fs::read(&path).expect("read"), contents);
                assert!(!dir.join(MARKER).exists());
                assert!(!dir.join(".gitignore").exists());
            }
        }
    }

    #[test]
    fn a_symlinked_claude_dir_or_file_is_refused_before_any_write() {
        let temp = tempfile::tempdir().expect("temp dir");
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).expect("mkdir");

        // `.claude` a link to a directory elsewhere: nothing appears there,
        // and no `.gitignore` or marker in the project.
        let dir = temp.path().join("claude-link");
        fs::create_dir(&dir).expect("mkdir");
        symlink(&outside, dir.join(".claude")).expect("symlink");
        let err = init(&dir).expect_err("linked .claude refused");
        assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
        assert_eq!(fs::read_dir(&outside).expect("readable").count(), 0);
        assert!(!dir.join(".gitignore").exists());
        assert!(!dir.join(MARKER).exists());

        // A dangling link where `CLAUDE.md` or the settings go: refused,
        // and nothing is created where it points.
        for relative in ["CLAUDE.md", ".claude/settings.json"] {
            let dir = temp
                .path()
                .join(format!("link-{}", relative.replace('/', "-")));
            let path = dir.join(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            let nowhere = temp
                .path()
                .join(format!("nowhere-{}", relative.replace('/', "-")));
            symlink(&nowhere, &path).expect("symlink");
            let err = init(&dir).expect_err(relative);
            assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
            assert!(!nowhere.exists());
            assert!(!dir.join(".gitignore").exists());
        }

        // `.claude` a regular file: refused too.
        let dir = temp.path().join("claude-file");
        fs::create_dir(&dir).expect("mkdir");
        fs::write(dir.join(".claude"), "x").expect("write");
        assert!(init(&dir).is_err());
        assert!(!dir.join(".gitignore").exists());
    }
}
