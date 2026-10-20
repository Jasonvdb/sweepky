//! The Cloudflare playbook, installed into the project when the sweeper
//! agrees: `init --install-playbook`, or a `y` to the one question `init`
//! asks when neither `--install-playbook` nor `--no-playbook` is given.
//!
//! The install is 03's pinned line, run in the project:
//!
//! ```text
//! npx skills@1.7.2 add https://github.com/cloudflare/security-audit-skill#c1c8a8c1471069fb0e188eeaff69b8e8db6564a8 \
//!     --skill security-audit --agent claude-code --copy -y
//! ```
//!
//! skills@1.7.2 clones the repository at exactly that commit (`git fetch
//! --depth 1 origin <sha>` once `--branch <sha>` fails), copies
//! `skills/security-audit/` to `.claude/skills/security-audit/` as real
//! files (`--copy`; the default would symlink it to `.agents/skills/`), and
//! writes `skills-lock.json` in the project. A second run removes that
//! directory and copies it again, so an `init` that stopped after the
//! install finishes on the next run. Read from the package's source and
//! checked with one real install on 2026-10-20 (the P3 phase doc has the
//! record).
//!
//! The rules the child is run under:
//!
//! - **An argv, never a shell.** [`install_command`] is fixed text and the
//!   project's path is the working directory, not an argument, so nothing
//!   of the user's is ever split or expanded.
//! - **Pinned twice.** The npm package by its exact version and the
//!   playbook by its full 40-hex commit; never HEAD, never `--global`
//!   (which would land under `~/.agents`, where the sandbox cannot read).
//! - **Bounded and timed.** The child runs through git's
//!   [`run_bounded`]: standard input `/dev/null`, standard output and
//!   standard error each capped, a timeout, and the child killed past any
//!   of them. Its output is never shown: npm and the skills CLI print what
//!   a registry or a repository sent, so an error says only what failed.
//! - **The inherited environment, on purpose.** Unlike git, whose child
//!   gets an allowlist (`git::child_env`), npx keeps this process's
//!   environment, because npm needs `HOME` (its cache and `~/.npmrc`),
//!   `PATH` and the proxy variables, and has no switch that turns its
//!   config off. `DISABLE_TELEMETRY=1` is added, which turns off the skills
//!   CLI's usage pings. What a project directory could add is refused
//!   before npx runs ([`check_before_install`]): npm reads `.npmrc`,
//!   `package.json` and `node_modules` from it.
//! - **Checked after.** [`verify_installed`] looks at every entry the
//!   install made, with `lstat` and never following a link: real
//!   directories and regular files with one link only, and a `SKILL.md`.
//!   Only then does `init` write the marker that names the playbook.

use std::ffi::OsString;
use std::fs::{self, Metadata};
// `MetadataExt` adds `nlink()`, the number of names a file has.
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use sweepky_core::Playbook;

use crate::git::{Limits, run_bounded};
use crate::private_fs::{lstat, refuse_unless_dir};
use crate::prompt::Terminal;

/// The playbook's commit: Cloudflare's `security-audit-skill` at the
/// revision 03 pins, which `submit` names through the marker.
pub(crate) const PLAYBOOK_COMMIT: &str = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8";

/// The repository the playbook comes from.
const PLAYBOOK_REPO: &str = "https://github.com/cloudflare/security-audit-skill";

/// The npm package that installs it, at its exact version.
const SKILLS_PACKAGE: &str = "skills@1.7.2";

/// Where the install puts the playbook, relative to the project: Claude
/// Code's project skills directory, named after the skill.
pub(super) const SKILL_DIR: &str = ".claude/skills/security-audit";

/// The lock file skills@1.7.2 writes in the project. It writes it with a
/// plain `writeFile`, which follows a link, so a link there is refused.
const SKILLS_LOCK: &str = "skills-lock.json";

/// What npm reads from the directory it runs in: project config, the
/// project's manifest and its installed packages. Any of them could change
/// what `npx` runs, so `init` refuses a project that has one.
const NPM_PROJECT_FILES: [&str; 3] = [".npmrc", "package.json", "node_modules"];

/// The only variable `init` adds to npx's environment.
const NPX_ENV: [(&str, &str); 1] = [("DISABLE_TELEMETRY", "1")];

/// How the install is named in errors.
const WHAT: &str = "npx skills@1.7.2 add";

/// npx's limits: 5 minutes, for npm's download and the clone on a slow
/// link, and 1 MiB of each output. A real install writes about 2 KiB of
/// progress to standard output and a few npm notices to standard error.
const NPX_LIMITS: Limits = Limits {
    timeout: Duration::from_secs(5 * 60),
    stdout_cap: 1024 * 1024,
    stderr_cap: 1024 * 1024,
};

/// The most entries [`verify_installed`] looks at: the playbook has about
/// twenty files, so a thousand is room to grow and still a bound.
const MAX_INSTALLED_ENTRIES: usize = 1024;

/// The deepest directory [`verify_installed`] goes into below the skill's
/// own; the playbook is flat today.
const MAX_INSTALLED_DEPTH: usize = 8;

/// Whether `init` installs the playbook, from its two flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlaybookChoice {
    /// `--install-playbook`: install it without asking.
    Install,
    /// `--no-playbook`: install nothing and never run npx.
    Skip,
    /// Neither flag: ask once on standard error.
    Ask,
}

impl PlaybookChoice {
    /// The choice `--install-playbook` and `--no-playbook` make. clap
    /// refuses the two together; were both set anyway, nothing is
    /// installed, since only a clear yes runs npx.
    pub(crate) fn from_flags(install_playbook: bool, no_playbook: bool) -> Self {
        match (install_playbook, no_playbook) {
            (_, true) => Self::Skip,
            (true, false) => Self::Install,
            (false, false) => Self::Ask,
        }
    }
}

/// Whether to install, asking on `terminal` for [`PlaybookChoice::Ask`].
/// The question names both flags, so under `--no-input`, where
/// [`Terminal::confirm`] fails at once with the question in its message,
/// the error says how to answer it.
pub(super) fn wants_install(
    choice: PlaybookChoice,
    terminal: Terminal<'_>,
) -> anyhow::Result<bool> {
    match choice {
        PlaybookChoice::Install => Ok(true),
        PlaybookChoice::Skip => Ok(false),
        PlaybookChoice::Ask => terminal.confirm(&format!(
            "Install Cloudflare's security-audit playbook into this project at commit \
             {PLAYBOOK_COMMIT}, with `npx {SKILLS_PACKAGE}` (Node and network needed)? \
             --install-playbook or --no-playbook answers this without asking"
        )),
    }
}

/// The playbook value the marker records: `cloudflare/security-audit@`
/// and the full commit, parsed through core's [`Playbook`] so it passes
/// 01's pattern like any value read back.
fn installed_playbook() -> anyhow::Result<Playbook> {
    format!("cloudflare/security-audit@{PLAYBOOK_COMMIT}")
        .parse()
        .context("the pinned playbook does not pass 01's pattern; this is a bug")
}

/// Refuses a project npm would take configuration from, or whose install
/// targets are not what [`install`] can safely replace. Runs before
/// anything is written:
///
/// - `.npmrc`, `package.json` or `node_modules`, of any kind, is refused;
/// - `skills-lock.json` must be absent or a regular file with one link,
///   since npx rewrites it in place;
/// - `.claude/skills/security-audit` must be absent or a real directory,
///   which npx removes and copies again. Only a run that stopped before its
///   marker leaves one, because a finished `init` never gets here.
pub(super) fn check_before_install(dir: &Path) -> anyhow::Result<()> {
    for name in NPM_PROJECT_FILES {
        let path = dir.join(name);
        if lstat(&path)?.is_some() {
            bail!(
                "{} exists, and npm would read it as this project's own configuration, so init \
                 does not run npx here. Move it away, or run init with --no-playbook",
                path.display()
            );
        }
    }
    let lock = dir.join(SKILLS_LOCK);
    if let Some(meta) = lstat(&lock)? {
        refuse_unless_single_file(&lock, &meta)?;
    }
    let skill = dir.join(SKILL_DIR);
    if let Some(meta) = lstat(&skill)? {
        refuse_unless_dir(&skill, &meta)?;
    }
    Ok(())
}

/// Installs the playbook into `dir` with `npx`, checks what it made, and
/// returns the playbook the marker records.
pub(super) fn install(dir: &Path, npx: &impl RunNpx) -> anyhow::Result<Playbook> {
    npx.run(&install_command(dir))?;
    verify_installed(&dir.join(SKILL_DIR))?;
    installed_playbook()
}

/// One report line for a finished install.
pub(super) fn installed_line() -> String {
    format!(
        "installed Cloudflare's security-audit playbook at commit {PLAYBOOK_COMMIT} into \
         {SKILL_DIR} with npx {SKILLS_PACKAGE}, which also wrote {SKILLS_LOCK}"
    )
}

/// One npx run: its arguments after `npx`, the directory it runs in, and
/// the variables added to the environment it inherits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpxCommand {
    pub(super) args: Vec<String>,
    pub(super) dir: PathBuf,
    pub(super) env: &'static [(&'static str, &'static str)],
}

/// 03's pinned install line, run in `dir`.
pub(super) fn install_command(dir: &Path) -> NpxCommand {
    let source = format!("{PLAYBOOK_REPO}#{PLAYBOOK_COMMIT}");
    let args = [
        SKILLS_PACKAGE,
        "add",
        &source,
        "--skill",
        "security-audit",
        "--agent",
        "claude-code",
        "--copy",
        "-y",
    ];
    NpxCommand {
        args: args.into_iter().map(str::to_owned).collect(),
        dir: dir.to_owned(),
        env: &NPX_ENV,
    }
}

/// Where `init` runs npx: the seam between `init` and the npx binary, so
/// a test can record the command and stand in for the install.
///
/// Not `async`, unlike `git::RunGit`: `init` is a plain function, which the
/// binary calls before it builds a context, so the real runner drives its
/// child on a runtime of its own ([`NpxRunner`]).
pub(crate) trait RunNpx {
    /// Runs `command`, and fails on a failure status, a timeout or an
    /// output past its cap, saying none of what npx wrote.
    fn run(&self, command: &NpxCommand) -> anyhow::Result<()>;
}

/// The real [`RunNpx`]: `program`, which is `npx` found on `PATH` in the
/// binary, under `limits`.
pub(crate) struct NpxRunner {
    program: OsString,
    limits: Limits,
}

impl NpxRunner {
    /// `npx` from `PATH`, under [`NPX_LIMITS`].
    pub(crate) fn system() -> Self {
        Self {
            program: OsString::from("npx"),
            limits: NPX_LIMITS,
        }
    }

    /// `program` in npx's place, under `limits`: a test's script.
    #[cfg(test)]
    pub(crate) fn for_tests(program: &Path, limits: Limits) -> Self {
        Self {
            program: program.as_os_str().to_owned(),
            limits,
        }
    }
}

impl RunNpx for NpxRunner {
    fn run(&self, command: &NpxCommand) -> anyhow::Result<()> {
        let mut process = tokio::process::Command::new(&self.program);
        // `envs` adds to the inherited environment; there is no
        // `env_clear` here (see the module comment).
        process
            .args(&command.args)
            .envs(command.env.iter().copied())
            .current_dir(&command.dir);
        let limits = self.limits;
        // `init` may be called from inside tokio's runtime (the binary's
        // `main` is async), where blocking on a second future of that
        // runtime would panic. So the child runs on a small runtime of its
        // own, on a thread of its own, and this thread waits for it.
        // `move` hands `process` and `limits` to that thread, which then
        // owns them. `join` is `Err` only if the thread panicked.
        let finished = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("could not start a runtime to run npx")?
                .block_on(run_bounded(process, WHAT, &limits))
        })
        .join()
        .map_err(|_| anyhow!("the thread that ran {WHAT} stopped unexpectedly"))??;
        if !finished.status.success() {
            // Fixed text and the exit status only: npm's and the skills
            // CLI's own words carry what a registry or repository sent.
            let how = match finished.status.code() {
                Some(code) => format!("failed with exit status {code}"),
                None => "was stopped by a signal".to_owned(),
            };
            bail!(
                "{WHAT} {how}, so init installed no playbook and wrote no marker. Its output is \
                 not shown; run init again, or run it with --no-playbook"
            );
        }
        Ok(())
    }
}

/// Checks the playbook npx installed at `skill_dir`: a real directory with
/// a `SKILL.md`, and below it only real directories and regular files with
/// one link each, at most [`MAX_INSTALLED_ENTRIES`] entries and
/// [`MAX_INSTALLED_DEPTH`] levels. Nothing is followed: `lstat` and
/// `DirEntry::metadata` describe a link itself. An error names `skill_dir`
/// and what was wrong, not the entry, whose name came from the download.
pub(super) fn verify_installed(skill_dir: &Path) -> anyhow::Result<()> {
    let Some(meta) = lstat(skill_dir)? else {
        bail!(
            "{WHAT} finished but made no {}; init wrote no marker",
            skill_dir.display()
        );
    };
    refuse_unless_dir(skill_dir, &meta)?;
    let skill_md = skill_dir.join("SKILL.md");
    match lstat(&skill_md)? {
        Some(meta) => refuse_unless_single_file(&skill_md, &meta)?,
        None => bail!(
            "{WHAT} finished but {} has no SKILL.md; init wrote no marker",
            skill_dir.display()
        ),
    }
    refuse_anything_but_plain_files_below(skill_dir)
}

/// The walk of [`verify_installed`]: every entry below `skill_dir`, a real
/// directory or a regular file with one link, within the entry and depth
/// bounds.
fn refuse_anything_but_plain_files_below(skill_dir: &Path) -> anyhow::Result<()> {
    // A walk with a stack rather than recursion, so the depth bound is a
    // number checked here rather than the call stack's.
    let mut pending = vec![(skill_dir.to_owned(), 0_usize)];
    let mut seen = 0_usize;
    while let Some((dir, depth)) = pending.pop() {
        let entries =
            fs::read_dir(&dir).with_context(|| format!("could not read {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("could not read {}", dir.display()))?;
            seen += 1;
            if seen > MAX_INSTALLED_ENTRIES {
                bail!(
                    "{} holds more than {MAX_INSTALLED_ENTRIES} entries; init wrote no marker",
                    skill_dir.display()
                );
            }
            // On Unix `DirEntry::metadata` does not follow a link, unlike
            // `fs::metadata`, so a link shows up as a link.
            let meta = entry
                .metadata()
                .with_context(|| format!("could not inspect an entry of {}", dir.display()))?;
            let kind = meta.file_type();
            if kind.is_dir() {
                if depth >= MAX_INSTALLED_DEPTH {
                    bail!(
                        "{} is nested more than {MAX_INSTALLED_DEPTH} levels deep; init wrote no \
                         marker",
                        skill_dir.display()
                    );
                }
                pending.push((entry.path(), depth + 1));
            } else if !kind.is_file() || meta.nlink() != 1 {
                bail!(
                    "{} holds a symbolic link, a special file or a file with other hard links; \
                     the playbook must be plain files, so init refused it and wrote no marker. \
                     Remove {} and run init again",
                    skill_dir.display(),
                    skill_dir.display()
                );
            }
        }
    }
    Ok(())
}

/// Refuses `path` unless `meta`, its `lstat`, is a regular file with one
/// link: no symlink, no special file, and no second name that could share
/// its contents with a file elsewhere.
fn refuse_unless_single_file(path: &Path, meta: &Metadata) -> anyhow::Result<()> {
    if !meta.file_type().is_file() || meta.nlink() != 1 {
        bail!(
            "{} is not a regular file with one link; init never writes through a link. Move it \
             away and run init again",
            path.display()
        );
    }
    Ok(())
}

/// What a [`FakeNpx`] does in the project directory in npx's place.
#[cfg(test)]
type FakeInstall = Box<dyn Fn(&Path) -> anyhow::Result<()>>;

/// A stand-in for npx in the tests: it records each command and runs
/// `install` in npx's place.
#[cfg(test)]
pub(super) struct FakeNpx {
    install: FakeInstall,
    calls: std::cell::RefCell<Vec<NpxCommand>>,
}

#[cfg(test)]
impl FakeNpx {
    /// npx doing what skills@1.7.2 does: the skill's files copied into
    /// `.claude/skills/security-audit/` and the lock file written.
    pub(super) fn installing() -> Self {
        Self::doing(|dir| {
            let skill = dir.join(SKILL_DIR);
            fs::create_dir_all(skill.join("sub"))?;
            fs::write(skill.join("SKILL.md"), "---\nname: security-audit\n---\n")?;
            fs::write(skill.join("sub/HUNTING.md"), "synthetic\n")?;
            fs::write(dir.join(SKILLS_LOCK), "{\"version\":1}\n")?;
            Ok(())
        })
    }

    /// npx failing with `error`, as the real runner does on a failure
    /// status, a timeout or an output past its cap.
    pub(super) fn failing() -> Self {
        Self::doing(|_| Err(anyhow!("{WHAT} failed with exit status 1")))
    }

    /// npx running `install` in the project directory.
    pub(super) fn doing(install: impl Fn(&Path) -> anyhow::Result<()> + 'static) -> Self {
        Self {
            install: Box::new(install),
            calls: std::cell::RefCell::default(),
        }
    }

    /// Every command run so far.
    pub(super) fn calls(&self) -> Vec<NpxCommand> {
        self.calls.borrow().clone()
    }
}

#[cfg(test)]
impl RunNpx for FakeNpx {
    fn run(&self, command: &NpxCommand) -> anyhow::Result<()> {
        self.calls.borrow_mut().push(command.clone());
        (self.install)(&command.dir)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use std::time::Duration;

    use super::{
        NPX_ENV, NpxRunner, PLAYBOOK_COMMIT, PlaybookChoice, RunNpx, SKILL_DIR, install_command,
        installed_playbook, verify_installed,
    };
    use crate::git::Limits;

    #[test]
    fn the_install_line_is_03_s_pinned_one() {
        let command = install_command(Path::new("/abs/project"));
        assert_eq!(
            command.args,
            [
                "skills@1.7.2",
                "add",
                "https://github.com/cloudflare/security-audit-skill#\
                 c1c8a8c1471069fb0e188eeaff69b8e8db6564a8",
                "--skill",
                "security-audit",
                "--agent",
                "claude-code",
                "--copy",
                "-y",
            ]
        );
        // Never the global form, which installs elsewhere and pins nothing.
        assert!(!command.args.iter().any(|arg| arg.starts_with("--global")));
        assert_eq!(command.dir, Path::new("/abs/project"));
        assert_eq!(command.env, [("DISABLE_TELEMETRY", "1")]);
        assert_eq!(
            installed_playbook().expect("passes").as_str(),
            format!("cloudflare/security-audit@{PLAYBOOK_COMMIT}")
        );
    }

    #[test]
    fn the_flags_choose_and_only_install_runs_npx_without_asking() {
        assert_eq!(
            PlaybookChoice::from_flags(true, false),
            PlaybookChoice::Install
        );
        assert_eq!(
            PlaybookChoice::from_flags(false, true),
            PlaybookChoice::Skip
        );
        assert_eq!(
            PlaybookChoice::from_flags(false, false),
            PlaybookChoice::Ask
        );
        assert_eq!(PlaybookChoice::from_flags(true, true), PlaybookChoice::Skip);
    }

    /// A script at `dir/fake-npx` with `body`, made executable.
    fn script(dir: &Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("fake-npx");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    /// A test's way of making one case: given the directory and a file
    /// outside it.
    type Plant = fn(&Path, &Path);

    const QUICK: Limits = Limits {
        timeout: Duration::from_secs(10),
        stdout_cap: 1024,
        stderr_cap: 1024,
    };

    #[test]
    fn the_real_runner_passes_the_argv_in_the_project_with_stdin_null() {
        let temp = tempfile::tempdir().expect("temp dir");
        let project = temp.path().join("project");
        fs::create_dir(&project).expect("mkdir");
        // Each argument on a line of its own, the working directory, the
        // added variable, and standard input, which `cat` reads to its end
        // at once because it is /dev/null.
        let program = script(
            temp.path(),
            "printf '%s\\n' \"$@\" > args.txt; pwd -P > cwd.txt; \
             printf '%s' \"$DISABLE_TELEMETRY\" > env.txt; cat > stdin.txt",
        );
        let command = install_command(&project);

        NpxRunner::for_tests(&program, QUICK)
            .run(&command)
            .expect("the script succeeds");

        let args = fs::read_to_string(project.join("args.txt")).expect("args");
        assert_eq!(args.lines().collect::<Vec<_>>(), command.args);
        let cwd = fs::read_to_string(project.join("cwd.txt")).expect("cwd");
        assert_eq!(
            Path::new(cwd.trim_end()),
            fs::canonicalize(&project).expect("canonical")
        );
        assert_eq!(
            fs::read_to_string(project.join("env.txt")).expect("env"),
            NPX_ENV[0].1
        );
        assert_eq!(fs::read(project.join("stdin.txt")).expect("stdin"), b"");
    }

    #[test]
    fn a_failing_slow_or_loud_npx_is_an_error_that_quotes_none_of_it() {
        let temp = tempfile::tempdir().expect("temp dir");
        let project = temp.path().join("project");
        fs::create_dir(&project).expect("mkdir");
        let quick_timeout = Limits {
            timeout: Duration::from_millis(300),
            ..QUICK
        };
        let cases = [
            (
                "echo PLANTED-out; echo PLANTED-err >&2; exit 3",
                QUICK,
                "exit status 3",
            ),
            (
                "echo PLANTED-out; exec sleep 30",
                quick_timeout,
                "did not finish",
            ),
            ("yes PLANTED-out", QUICK, "standard output"),
            ("yes PLANTED-err >&2", QUICK, "standard error"),
        ];
        for (body, limits, expected) in cases {
            let program = script(temp.path(), body);
            let error = NpxRunner::for_tests(&program, limits)
                .run(&install_command(&project))
                .expect_err(body);
            let message = format!("{error:#}");
            assert!(message.contains(expected), "{body}: {message}");
            assert!(!message.contains("PLANTED"), "{body}: {message}");
        }
    }

    #[test]
    fn a_missing_npx_is_an_error() {
        let temp = tempfile::tempdir().expect("temp dir");
        let error = NpxRunner::for_tests(&temp.path().join("no-npx"), QUICK)
            .run(&install_command(temp.path()))
            .expect_err("no program");
        assert!(
            format!("{error:#}").contains("could not start"),
            "{error:#}"
        );
    }

    #[test]
    fn an_install_is_plain_files_and_directories_only() {
        let temp = tempfile::tempdir().expect("temp dir");
        let outside = temp.path().join("outside.md");
        fs::write(&outside, "not the playbook\n").expect("write");

        // What a good install looks like passes.
        let good = temp.path().join("good");
        fs::create_dir_all(good.join("sub")).expect("mkdir");
        fs::write(good.join("SKILL.md"), "skill\n").expect("write");
        fs::write(good.join("sub/x.md"), "x\n").expect("write");
        verify_installed(&good).expect("plain files pass");

        // Each way of not being plain files is refused.
        let cases: [(&str, Plant); 6] = [
            ("no-skill-md", |dir, _| {
                fs::create_dir(dir).expect("mkdir");
            }),
            ("linked-skill-md", |dir, outside| {
                fs::create_dir(dir).expect("mkdir");
                symlink(outside, dir.join("SKILL.md")).expect("symlink");
            }),
            ("hard-linked-skill-md", |dir, outside| {
                fs::create_dir(dir).expect("mkdir");
                fs::hard_link(outside, dir.join("SKILL.md")).expect("link");
            }),
            ("nested-link", |dir, outside| {
                fs::create_dir_all(dir.join("sub")).expect("mkdir");
                fs::write(dir.join("SKILL.md"), "skill\n").expect("write");
                symlink(outside, dir.join("sub/x.md")).expect("symlink");
            }),
            ("linked-dir", |dir, outside| {
                fs::create_dir(dir).expect("mkdir");
                fs::write(dir.join("SKILL.md"), "skill\n").expect("write");
                let parent = outside.parent().expect("a parent");
                symlink(parent, dir.join("sub")).expect("symlink");
            }),
            ("dir-is-a-link", |dir, outside| {
                let real = outside.with_extension("real");
                fs::create_dir(&real).expect("mkdir");
                fs::write(real.join("SKILL.md"), "skill\n").expect("write");
                symlink(&real, dir).expect("symlink");
            }),
        ];
        for (name, make) in cases {
            let dir = temp.path().join(name);
            make(&dir, &outside);
            assert!(verify_installed(&dir).is_err(), "{name}");
        }
        // Too deep is refused too.
        let deep = temp.path().join("deep");
        let mut nested = deep.clone();
        for _ in 0..=super::MAX_INSTALLED_DEPTH + 1 {
            nested = nested.join("d");
        }
        fs::create_dir_all(&nested).expect("mkdir");
        fs::write(deep.join("SKILL.md"), "skill\n").expect("write");
        assert!(verify_installed(&deep).is_err());
        assert_eq!(SKILL_DIR, ".claude/skills/security-audit");
    }
}
