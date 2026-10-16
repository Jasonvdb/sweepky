//! Checks the bare git repository at `fixtures/target-repo.git`, which the
//! CLI's target tests (P2b, P3) pin targets in and fetch from instead of a
//! real repository host.
//!
//! The fixture is committed as plain files, so a careless regeneration could
//! slip something into it. These tests guard three things:
//!
//! 1. **It holds nothing git would run or obey.** A bare repository's
//!    `hooks/` and `config` can make git run programs (a hook, or a config key
//!    such as `core.fsmonitor`), and every later test that fetches from the
//!    fixture would run them. So [`inert_fixture`] reads the files first, with
//!    no git involved, and only then hands the path to a test that runs git.
//! 2. **It is synthetic and anonymous.** Every commit and the tag carry the
//!    fixed fixture identity and an August 2026 date, and no signature, so
//!    nobody's real name, email or key is in the objects.
//! 3. **Its history is the one `fixtures/README.md` records**, SHA for SHA, so
//!    the later tests can rely on the README's commit names (R, A, B, M, …).
//!
//! Every git command here is read-only and runs with the system's and the
//! user's git config switched off, so the result does not depend on whose
//! machine runs it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The fixture's `config`, byte for byte: format version 0, file modes
/// tracked, bare. `make-target-repo.sh` writes exactly this. Anything more
/// is refused, because a repository's own config can name programs for git
/// to run, and macOS's `git init` adds `ignorecase` and `precomposeunicode`,
/// which would make the fixture behave differently on Linux.
const EXPECTED_CONFIG: &str =
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n";

/// `HEAD` names `main`, as a bare repository made with
/// `--initial-branch=main` writes it.
const EXPECTED_HEAD: &str = "ref: refs/heads/main\n";

/// Every file the fixture may hold outside `objects/pack/`. The refs stay
/// loose (no `packed-refs`), because git only accepts a directory as a
/// repository when `refs/` exists, and git cannot commit an empty directory.
const EXPECTED_FILES: [&str; 6] = [
    "HEAD",
    "config",
    "refs/heads/main",
    "refs/heads/topic",
    "refs/pull/1/head",
    "refs/tags/v0.1.0",
];

/// The fixture's commits and their parents, in order, as the graph in
/// `fixtures/README.md` draws it. The SHAs come from the README itself.
const COMMITS: [(&str, &[&str]); 7] = [
    ("R", &[]),
    ("A", &["R"]),
    ("T1", &["A"]),
    ("B", &["A"]),
    ("F1", &["B"]),
    ("F2", &["F1"]),
    ("M", &["B", "T1"]),
];

/// The refs that point straight at a commit, and the commit each must name.
/// `refs/pull/1/head` is one of them, though it is not a branch.
const COMMIT_REFS: [(&str, &str); 3] = [
    ("refs/heads/main", "M"),
    ("refs/heads/topic", "T1"),
    ("refs/pull/1/head", "F2"),
];

/// The one tag's name, as the README's tag table writes it.
const TAG_NAME: &str = "v0.1.0";

/// The one tag's ref. It points at the tag object, not straight at a commit.
const TAG_REF: &str = "refs/tags/v0.1.0";

/// The agent-instruction files planted in the root commit, which `run` must
/// strip from a target copy (02's sweeper-safety rules).
const PLANTED_FILES: [&str; 6] = [
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    ".claude/settings.json",
    ".mcp.json",
    "src/auth/CLAUDE.md",
];

/// The one identity every commit and the tag carry.
const FIXTURE_IDENTITY: &str = "Sweepky Fixture <fixture@example.invalid>";

/// August 2026 in Unix seconds: from 2026-08-01T00:00:00Z up to, but not
/// including, 2026-09-01T00:00:00Z. Every commit and tag time is in it.
const AUGUST_2026: Range<u64> = 1_785_542_400..1_788_220_800;

#[test]
fn fixture_holds_only_inert_files() {
    // `inert_fixture` runs the whole check; this test makes sure it runs even
    // if every git test is filtered out.
    inert_fixture();
}

#[test]
fn fixture_passes_fsck_strict() {
    let dir = inert_fixture();
    // `--strict` also checks file modes and the shape of every object. Any
    // line on stdout is a problem or an object nothing points at.
    let report = git(&dir, &["fsck", "--strict", "--no-progress"]);
    assert_eq!(report, "", "fsck reported problems");
}

#[test]
fn history_is_the_one_the_readme_records() {
    let dir = inert_fixture();
    let shas = recorded_shas();
    for (name, parents) in COMMITS {
        let sha = sha_of(&shas, name);
        assert_eq!(
            git(&dir, &["cat-file", "-t", sha]),
            "commit",
            "{name} is a commit"
        );
        let expected: Vec<&str> = parents.iter().map(|parent| sha_of(&shas, parent)).collect();
        assert_eq!(
            parents_of(&dir, sha),
            expected,
            "{name}'s parents are {parents:?}"
        );
    }

    // No commit beyond the seven the README names.
    let rev_list = git(&dir, &["rev-list", "--all"]);
    let all: BTreeSet<&str> = rev_list.lines().collect();
    let named: BTreeSet<&str> = COMMITS
        .iter()
        .map(|(name, _)| sha_of(&shas, name))
        .collect();
    assert_eq!(all, named, "the fixture holds exactly the README's commits");
}

#[test]
fn refs_resolve_to_the_recorded_shas() {
    let dir = inert_fixture();
    let shas = recorded_shas();

    let listing = git(&dir, &["for-each-ref", "--format=%(refname)"]);
    let refs: BTreeSet<&str> = listing.lines().collect();
    let expected: BTreeSet<&str> = COMMIT_REFS
        .iter()
        .map(|(name, _)| *name)
        .chain([TAG_REF])
        .collect();
    assert_eq!(refs, expected, "the fixture has exactly these refs");
    assert_eq!(git(&dir, &["symbolic-ref", "HEAD"]), "refs/heads/main");

    for (name, commit) in COMMIT_REFS {
        assert_eq!(
            git(&dir, &["rev-parse", "--verify", name]),
            sha_of(&shas, commit),
            "{name} points at {commit}"
        );
    }
    // `{{` and `}}` are a literal brace in `format!`, so this is
    // `refs/tags/v0.1.0^{commit}`: the tag peeled to the commit it names.
    let peeled = format!("{TAG_REF}^{{commit}}");
    assert_eq!(
        git(&dir, &["rev-parse", "--verify", &peeled]),
        sha_of(&shas, "A"),
        "{TAG_NAME} peels to A"
    );
}

#[test]
fn v0_1_0_is_an_annotated_tag() {
    let dir = inert_fixture();
    let shas = recorded_shas();
    // A lightweight tag is a ref straight to the commit; an annotated one
    // points at a tag object, the one `post` has to peel to reach the commit.
    let tag = git(&dir, &["rev-parse", "--verify", TAG_REF]);
    assert_eq!(
        tag,
        sha_of(&shas, TAG_NAME),
        "the tag object is the recorded one"
    );
    assert_eq!(git(&dir, &["cat-file", "-t", &tag]), "tag");
}

#[test]
fn main_tip_is_a_merge_commit() {
    let dir = inert_fixture();
    assert_eq!(
        parents_of(&dir, "refs/heads/main").len(),
        2,
        "main's tip has two parents"
    );
}

#[test]
fn pr_merge_base_is_b_not_the_base_tip() {
    let dir = inert_fixture();
    let shas = recorded_shas();
    // `--all` lists every best common ancestor. Exactly one means the
    // three-dot diff `main...refs/pull/1/head` has one clear starting point.
    let merge_base = git(
        &dir,
        &["merge-base", "--all", "refs/heads/main", "refs/pull/1/head"],
    );
    assert_eq!(merge_base, sha_of(&shas, "B"), "the PR's merge base is B");
    // The case the PR target exists for: the base moved on after the PR
    // branched, so the three-dot and two-dot diffs differ.
    assert_ne!(
        merge_base,
        sha_of(&shas, "M"),
        "the merge base must differ from the base tip"
    );
}

#[test]
fn planted_agent_files_are_in_the_root_commit() {
    let dir = inert_fixture();
    let shas = recorded_shas();
    let listing = git(&dir, &["ls-tree", "-r", "--full-tree", sha_of(&shas, "R")]);
    let mut paths = BTreeSet::new();
    for line in listing.lines() {
        // Each line is "<mode> <type> <sha>\t<path>".
        let (meta, path) = line.split_once('\t').expect("ls-tree prints a tab");
        // Only plain, non-executable files: no executable bit (100755), no
        // symlink (120000) and no submodule (160000) for `run` to check out.
        assert!(
            meta.starts_with("100644 blob "),
            "{path} is not a plain file: {meta}"
        );
        paths.insert(path);
    }
    for planted in PLANTED_FILES {
        assert!(paths.contains(planted), "the root commit has {planted}");
    }
}

#[test]
fn objects_carry_only_the_fixture_identity_and_no_signature() {
    let dir = inert_fixture();
    let shas = recorded_shas();
    let commits = git(&dir, &["rev-list", "--all"]);
    for sha in commits.lines() {
        // The raw object, header lines first: `author <name> <email> <time>
        // <zone>`, `committer …`, and `gpgsig …` if the commit was signed.
        let object = git(&dir, &["cat-file", "commit", sha]);
        assert_header_identity(&object, "author", sha);
        assert_header_identity(&object, "committer", sha);
        assert!(!object.contains("gpgsig"), "{sha} is signed");
    }
    let tag = git(&dir, &["cat-file", "tag", sha_of(&shas, TAG_NAME)]);
    assert_header_identity(&tag, "tagger", TAG_NAME);
    // A signed tag carries its signature at the end of the message.
    assert!(!tag.contains("-----BEGIN"), "{TAG_NAME} is signed");
}

/// The fixture's path, after checking its files are inert.
///
/// Every test that runs git gets the path from here, so the check always
/// comes first. It is not enough to check once in a separate test: tests run
/// in parallel and in no fixed order (nextest even runs each in its own
/// process), so one test cannot guard another.
fn inert_fixture() -> PathBuf {
    let dir = repo_root().join("fixtures/target-repo.git");
    assert_inert(&dir);
    dir
}

/// The repository root, two levels above this crate.
///
/// `env!` reads a variable when the test is *compiled*, and Cargo always sets
/// `CARGO_MANIFEST_DIR` to the crate's directory, so this works whatever
/// directory the test binary is later run from.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Reads the fixture's files, without git, and panics unless they are
/// exactly the inert set: the minimal `config`, no `hooks/`, `HEAD` naming
/// `main`, and besides those only the four loose refs and one pack.
fn assert_inert(dir: &Path) {
    assert_eq!(
        read_text(&dir.join("config")),
        EXPECTED_CONFIG,
        "the fixture's config must be exactly the minimal one"
    );
    assert_no_hooks(dir);
    assert_eq!(
        read_text(&dir.join("HEAD")),
        EXPECTED_HEAD,
        "HEAD must name refs/heads/main"
    );
    assert_only_expected_files(dir);
}

/// The file at `path` as UTF-8 text. Panics, naming the path, if it cannot
/// be read.
fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// Panics if the fixture has a `hooks` entry of any kind.
fn assert_no_hooks(dir: &Path) {
    // `symlink_metadata` looks at the path itself and does not follow a
    // symlink, so a `hooks` that is a dangling link is caught as well as a
    // real directory. `Path::exists` follows links and would miss it.
    match fs::symlink_metadata(dir.join("hooks")) {
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => panic!("cannot check for hooks/: {err}"),
        Ok(_) => panic!("the fixture must not have a hooks/ directory"),
    }
}

/// Panics unless the fixture holds exactly [`EXPECTED_FILES`] outside
/// `objects/pack/` and exactly one pack inside it.
fn assert_only_expected_files(dir: &Path) {
    // `partition` splits the paths in two by the closure's answer. It can
    // collect into any type with `Default` and `Extend`, so two sets here.
    let (packs, others): (BTreeSet<String>, BTreeSet<String>) = files_under(dir)
        .into_iter()
        .partition(|path| path.starts_with("objects/pack/"));
    assert_eq!(
        others,
        BTreeSet::from(EXPECTED_FILES.map(String::from)),
        "the fixture holds exactly HEAD, config and the four loose refs outside objects/pack/ \
         (no hooks/, info/, description, packed-refs or loose objects)"
    );
    assert_one_pack(&packs);
}

/// Every regular file under `dir`, as a `/`-separated path relative to it,
/// the way git and the README write paths. Panics on a symlink or anything
/// else that is not a plain file or directory, because git would follow a
/// link out of the fixture.
fn files_under(dir: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    // An explicit stack instead of recursion: a plain loop needs no helper
    // function with a growing set passed down by `&mut`. Each entry is a
    // directory to list, relative to `dir`; the empty string is `dir` itself.
    let mut pending = vec![String::new()];
    while let Some(relative) = pending.pop() {
        let listed = dir.join(&relative);
        let entries = fs::read_dir(&listed)
            .unwrap_or_else(|err| panic!("cannot list {}: {err}", listed.display()));
        for entry in entries {
            let entry = entry.expect("a readable directory entry");
            // A file name is an `OsString`, which need not be UTF-8.
            // `into_string` hands it back unchanged as the `Err` if it is not.
            let name = entry
                .file_name()
                .into_string()
                .unwrap_or_else(|name| panic!("non-UTF-8 name {name:?} in {}", listed.display()));
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            // `DirEntry::file_type` does not follow symlinks either.
            let kind = entry.file_type().expect("a readable file type");
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                found.insert(path);
            } else {
                panic!("{path} is neither a file nor a directory");
            }
        }
    }
    found
}

/// Panics unless `packs` is one `pack-<sha>.pack` and its `.idx`, with no
/// bitmap, reverse index or second pack.
fn assert_one_pack(packs: &BTreeSet<String>) {
    let pack = packs
        .iter()
        .find_map(|path| {
            path.strip_prefix("objects/pack/pack-")?
                .strip_suffix(".pack")
        })
        .unwrap_or_else(|| panic!("no pack in objects/pack/: {packs:?}"));
    assert!(is_sha(pack), "pack name {pack:?} is not a SHA-1");
    let expected = BTreeSet::from([
        format!("objects/pack/pack-{pack}.idx"),
        format!("objects/pack/pack-{pack}.pack"),
    ]);
    assert_eq!(
        packs, &expected,
        "objects/pack/ holds exactly one .pack and its .idx"
    );
}

/// Whether `text` is a full lower-case hex SHA-1.
fn is_sha(text: &str) -> bool {
    text.len() == 40
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Runs a read-only `git --git-dir <fixture> <args>` and returns its standard
/// output with the trailing newline removed. Panics if git fails.
fn git(fixture: &Path, args: &[&str]) -> String {
    let output = isolated_git(fixture)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("cannot run git (is it on PATH?): {err}"));
    assert!(
        output.status.success(),
        "git {args:?} failed with {}:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("git printed UTF-8");
    stdout.trim_end_matches('\n').to_string()
}

/// A `git --git-dir <fixture>` command that nothing in this process's
/// environment or this machine's git config can redirect or reconfigure.
/// The caller adds the subcommand.
fn isolated_git(fixture: &Path) -> Command {
    let mut command = Command::new("git");
    // A git run from inside a git hook inherits variables such as GIT_DIR
    // and GIT_OBJECT_DIRECTORY, which would point these commands at another
    // repository, and GIT_CONFIG_PARAMETERS can inject config. So every
    // GIT_* variable this process was given is dropped first. `vars_os`
    // rather than `vars`, because `vars` panics on a variable whose value is
    // not valid Unicode.
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GIT_") {
            command.env_remove(&key);
        }
    }
    // `Command`'s builder methods borrow it mutably and hand the borrow back,
    // so the chain ends in `;` and the owned `command` is returned after it.
    command
        // No system-wide or user config: nothing from this machine (a
        // signing setup, an alias, a hooks path) changes what git does here.
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        // Never stop to ask for a password.
        .env("GIT_TERMINAL_PROMPT", "0")
        // An explicit --git-dir rather than running inside the directory, so
        // git never goes looking for a repository, and a
        // `safe.bareRepository = explicit` setting would still allow it.
        .arg("--git-dir")
        .arg(fixture);
    command
}

/// The SHAs of `rev`'s parents, in order: none for a root commit, two for a
/// merge.
fn parents_of(fixture: &Path, rev: &str) -> Vec<String> {
    git(fixture, &["show", "-s", "--format=%P", rev])
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// The SHAs `fixtures/README.md` records in its `target-repo.git` section,
/// by name: the commits R, A, T1, B, F1, F2 and M, and the tag object
/// `v0.1.0`.
///
/// It reads every table row of the form ``| name | `<sha>` | …``, so the
/// README stays the one place the SHAs are written and this test cannot
/// drift from it.
fn recorded_shas() -> BTreeMap<String, String> {
    let readme = read_text(&repo_root().join("fixtures/README.md"));
    let section = readme
        .split("\n## ")
        .find(|section| section.starts_with("`target-repo.git`"))
        .expect("fixtures/README.md has a `target-repo.git` section");
    let mut shas = BTreeMap::new();
    for (name, sha) in section.lines().filter_map(sha_row) {
        let previous = shas.insert(name.to_string(), sha.to_string());
        assert!(previous.is_none(), "README records {name} twice");
    }
    shas
}

/// The name and SHA in a table row of the form ``| name | `<sha>` | …``, or
/// `None` for any other line. A name in backticks (`` `v0.1.0` ``) loses
/// them.
fn sha_row(line: &str) -> Option<(&str, &str)> {
    // "| R | `abc…` | none | …" splits on '|' into
    // ["", " R ", " `abc…` ", " none ", …], and `trim` drops the spaces.
    let cells: Vec<&str> = line.split('|').map(str::trim).collect();
    // A slice pattern: match only when there are at least three cells,
    // binding the second and third and ignoring the rest (`..`). The leading
    // `&` copies those two `&str`s out of the slice, so they borrow from
    // `line`, which outlives this function, and not from `cells`, which does
    // not.
    let &[_, name, sha, ..] = cells.as_slice() else {
        return None;
    };
    let sha = sha.strip_prefix('`')?.strip_suffix('`')?;
    is_sha(sha).then_some((name.trim_matches('`'), sha))
}

/// The SHA the README records for `name`.
fn sha_of<'a>(shas: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    // The returned `&str` borrows from the map, which the `'a` lifetime
    // spells out: the caller keeps the map alive while it uses the SHA.
    shas.get(name)
        .unwrap_or_else(|| panic!("fixtures/README.md records no SHA for {name}"))
}

/// Panics unless the object's `<field>` header line names the fixture
/// identity and a time in August 2026 (UTC).
fn assert_header_identity(object: &str, field: &str, what: &str) {
    let prefix = format!("{field} ");
    let value = object
        .lines()
        // The header ends at the first empty line; the message follows it.
        .take_while(|line| !line.is_empty())
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("{what} has no {field} line"));
    let (identity, time, zone) =
        identity_time_zone(value).unwrap_or_else(|| panic!("{what}: malformed {field} line"));
    assert_eq!(
        identity, FIXTURE_IDENTITY,
        "{what}: {field} is not the fixture identity"
    );
    assert_eq!(zone, "+0000", "{what}: {field} time is not in UTC");
    assert!(
        AUGUST_2026.contains(&time),
        "{what}: {field} time {time} is not in August 2026"
    );
}

/// Splits a header value, `<name> <<email>> <unix time> <zone>`, into the
/// identity, the time and the zone, or `None` if a part is missing.
fn identity_time_zone(value: &str) -> Option<(&str, u64, &str)> {
    // `rsplitn(3, ' ')` splits from the right at most twice, giving the zone,
    // the Unix time, then everything before them (the name and email).
    let mut parts = value.rsplitn(3, ' ');
    let zone = parts.next()?;
    let time = parts.next()?.parse().ok()?;
    let identity = parts.next()?;
    Some((identity, time, zone))
}
