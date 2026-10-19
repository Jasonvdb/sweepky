//! `run`, the terminal command a sweeper runs before the agent: it checks
//! a bounty, publishes the sweep as `running`, fetches the bounty's targets
//! into the project and writes what the agent and `submit` need beside
//! them.
//!
//! [`run`](fn@run), in the order 00's loop (step 2) and 03's `run` row give:
//!
//! 1. **Check, writing nothing.** The working directory must be an `init`
//!    project ([`require_project`]), whose marker may name a playbook. The
//!    argument, if any, must be a bounty's `pubky://` URL
//!    ([`parse_bounty_url`]); `--target` needs one. `--circle` must be a
//!    pubky, and this install must be logged in: the pubky `login.json`
//!    names is the sweeper. Without a URL, `pick` picks the bounty and the
//!    target, from the circle `--circle` names or else the sweeper's own,
//!    with no session, and its pick and warnings go to standard error.
//!    [`check_bounty`] reads the bounty and the one circle that decides,
//!    with no session, and chooses the targets, a picked target as if
//!    `--target` named it; [`CheckedBounty::summary`] goes to standard
//!    error. The git runner is made, and the sweep's id, and
//!    `fetch::check_sweep_dir` checks that `./sweeps/<id>/` can be made.
//! 2. **Publish `running`.** `sweeps/<id>.json`, under the writers' lock
//!    with a fresh session, signed out again at once
//!    ([`LockedSessionPublisher`]). A refused write ends the run here: no
//!    git has run and no directory was made.
//! 3. **Fetch, outside the lock.** `fetch::fetch_sweep` fetches each
//!    target, strips it and writes `scope.json` and `brief.md`; then the
//!    per-sweep marker `sweeps/<id>/.sweepky/sweep.json` (`marker`) is
//!    written, last.
//! 4. **Or abort.** If any step of 3 fails, an unserved SHA among them,
//!    the sweep directory is gone (the fetch's own guard, or a removal
//!    here when only the marker failed) and the record is flipped to
//!    `aborted`, with `finishedAt`, under the lock once more. `aborted` is
//!    final: `pull` re-fetches only `running` sweeps and the board shows an
//!    aborted one struck. A flip that fails too is said in the error, in
//!    fixed text.
//! 5. **Report** the sweep, what was stripped from each target, and what
//!    to run next: Claude Code with the project's settings alone,
//!    `/sweepky`, then `sweepky submit --run-dir sweeps/<id>`.
//!
//! So the lock is held twice at most, for the running write and for the
//! flip, each time around a sign-in, one PUT and a sign-out, and never
//! while git runs or the bounty is read.
//!
//! **The playbook.** The record's `playbook` is the one the project's
//! `init` recorded or, when there is none, as with every P2a `init`, the
//! placeholder [`UNSPECIFIED_PLAYBOOK`]: core's `Sweep` needs one, and
//! `submit --playbook` replaces it.
//!
//! The parts:
//!
//! - [`require_project`], [`parse_bounty_url`], [`check_bounty`] and
//!   [`CheckedBounty::summary`]: the checking half (above), with `select`,
//!   which decides from the records alone, and `pick`, which picks the
//!   bounty and target without a URL through `select`'s own rules.
//! - `fetch`: the check that `./sweeps/<id>/` can be made, and the fetch:
//!   each chosen target by its exact SHA, at depth 2, from its one checked
//!   remote, into `./sweeps/<id>/target/<tid>/`, checked out with every
//!   link written as a plain file; `strip` takes the agent-instruction
//!   files out of each copy at every depth and in any case; `scope_file`
//!   writes `scope.json`, rebuilt from the bounty's checked targets, and
//!   `brief.md`. A failure removes the half-made sweep directory.
//! - `marker`: the per-sweep marker, written last, all at once and never
//!   through a link.
//! - [`PublishRecord`], the seam the sweep record is written through, so
//!   the order above is tested with a fake storage and the fixture source.
//!
//! **Which circle, and why** (00's trust row: whose bounties a sweeper
//! works on is "the sweeper's own allowlist (circle by default) + the
//! sandbox"). Without `--circle`, a closed bounty is checked against its
//! owner's own `circle.json`: that is the roster the owner's `pull` reads
//! closed-bounty sweeps from, so a sweep from anyone outside it would never
//! be read. Being listed there is the owner's side, and it is unilateral:
//! anyone can list anyone in their circle. The sweeper's side is the human
//! who pastes the URL, which is the consent, and the sandbox bounds what a
//! hostile bounty's targets can do. `--circle <admin>` is the stricter
//! check, for any bounty, open or closed: both the owner and the sweeper
//! must be in that circle. Picking without a URL picks from this install's
//! own circle by default, and from the one `--circle` names when given.

mod fetch;
mod marker;
mod pick;
mod scope_file;
mod select;
mod strip;

use std::fs;
use std::path::Path;

use anyhow::{Context as _, bail};
use sweepky_core::paths;
use sweepky_core::{
    Bounty, BountyRef, KnownSweepStatus, KnownTarget, Playbook, Pubky, PubkyUrl, RecordTime,
    RepoName, SchemaVersion, Sweep, SweepRef, TargetId, UnknownFields,
};

use self::fetch::{FetchedSweep, check_sweep_dir, fetch_sweep};
use self::marker::SweepMarker;
use self::pick::{NOTHING_OPEN, pick_target};
use self::select::{Acceptance, ChosenTarget, ChosenTargets};
use crate::circle::parse_pubky;
use crate::display::sanitize;
use crate::git::RunGit;
use crate::identity::refuse_secret_material;
use crate::init::{ProjectMarker, read_project_marker};
use crate::own_storage::{OwnStorage, SessionStorage};
use crate::post::draft::{MAX_FOCUS_CHARS, MAX_TITLE_CHARS};
use crate::records::{PublicRecordReader, PublicRecords};
use crate::remote::{public_key_of, write_error};
use crate::session::{NOT_LOGGED_IN, with_writer_session};
use crate::state::read_login_state;
use crate::targets::TargetResolver;
use crate::{Context, Dirs, Report, clock};

/// What `run` says when it is given `--target` and no bounty URL.
const TARGET_NEEDS_URL: &str = "--target names a target of one bounty, so it needs that \
                                bounty's URL; without a URL, run picks the target itself";

/// The playbook a sweep record names when the project's `init` recorded
/// none, as P2a's `init` never does: core's `Sweep` needs one, this passes
/// 01's pattern, and `submit --playbook` replaces it (`submit` refuses a
/// record that still names it without the flag).
pub(crate) const UNSPECIFIED_PLAYBOOK: &str = "unspecified";

/// What the error says, in front of the failure, once the record says
/// `aborted`.
const ABORTED: &str = "run stopped, and the sweep's public record now says aborted";

/// What the error says, in front of the failure, when the record could not
/// be flipped to `aborted` either.
const NOT_ABORTED: &str = "run stopped, but the sweep's public record could not be changed \
                           to aborted and still says running";

/// What the write under the lock refuses when `login.json` names another
/// pubky than the one `run` checked the bounty for.
const LOGIN_CHANGED: &str = "this install was logged in as another identity while run checked the \
                             bounty, so nothing was published; run it again";

/// Runs `sweepky run [<bounty-url>] [--target <tid>] [--circle <admin>]`
/// in `ctx.cwd`, which must be an `init` project: see the module docs for
/// the order and why.
pub(crate) async fn run(
    ctx: &Context,
    bounty_url: Option<&str>,
    target: Option<&str>,
    circle: Option<&str>,
) -> anyhow::Result<Report> {
    let project_marker = require_project(&ctx.cwd)?;
    // `map` parses only a `Some`, and `transpose` turns the
    // `Option<Result<..>>` into the `Result<Option<..>>` that `?` takes.
    let bounty = bounty_url.map(parse_bounty_url).transpose()?;
    if bounty.is_none() && target.is_some() {
        bail!(TARGET_NEEDS_URL);
    }
    let circle = circle
        .map(|admin| parse_pubky(admin, "run --circle"))
        .transpose()?;
    let sweeper = logged_in_sweeper(&ctx.dirs)?;
    let records = PublicRecordReader::new(ctx.network.pubky());
    // Declared here and given a value only when there is no URL: the
    // request borrows the picked target's id from it, so it must live as
    // long as the request does, past the `match` that fills it.
    let picked;
    let request = match bounty {
        Some(bounty) => RunRequest {
            bounty,
            sweeper,
            circle,
            target,
        },
        None => {
            let pick = pick_target(&records, &ctx.targets, sweeper, circle).await?;
            ctx.stderr.write_flushed(&pick.summary())?;
            // anyhow's `context` works on an `Option` too: `None` becomes
            // this error.
            picked = pick.choice.context(NOTHING_OPEN)?;
            // Checked from here on exactly as for its URL and `--target`,
            // the bounty read again.
            RunRequest {
                bounty: picked.bounty,
                sweeper,
                circle,
                target: Some(picked.target.as_str()),
            }
        }
    };
    let checked = check_bounty(&records, &ctx.targets, &request).await?;
    ctx.stderr.write_flushed(&checked.summary())?;
    // Made before anything is published, so a machine where git cannot run
    // stops here with nothing to undo.
    let git = ctx.targets.git_runner(&ctx.dirs, &ctx.git_env)?;
    let new = NewSweep {
        project: &ctx.cwd,
        sweep: SweepRef {
            sweeper: request.sweeper,
            id: clock::new_record_id()?,
        },
        checked: &checked,
        playbook: project_marker.playbook(),
    };
    let publisher = LockedSessionPublisher {
        ctx,
        sweeper: request.sweeper,
    };
    let fetched = start_sweep(&publisher, &git, &ctx.targets, &new).await?;
    Ok(Report::new(started_report(&new, &fetched)))
}

/// The pubky this install is logged in as, from `login.json`: the sweeper,
/// whom the bounty is checked for and whose storage the sweep goes in.
/// `submit` asks it the same.
pub(crate) fn logged_in_sweeper(dirs: &Dirs) -> anyhow::Result<Pubky> {
    let Some(login) = read_login_state(dirs)? else {
        bail!(NOT_LOGGED_IN);
    };
    Ok(login.pubky)
}

/// One sweep `run` starts: the project it goes in, its record's address
/// (the sweeper and a new id), the bounty it sweeps, and the playbook the
/// project's `init` recorded, if any. It borrows all but the address (the
/// lifetime `'a`) from `run`, which keeps them.
struct NewSweep<'a> {
    project: &'a Path,
    sweep: SweepRef,
    checked: &'a CheckedBounty,
    playbook: Option<&'a Playbook>,
}

/// Where `run` publishes its sweep record, `sweeps/<id>.json`: the running
/// record, then, if the run fails, the aborted one.
///
/// A trait so that the order of the writes and the git runs can be tested
/// without a homeserver: the tests implement it for
/// `test_support::FakeOwnStorage`. Its method is an `async fn`, so callers
/// take `&impl PublishRecord`, as with `RunGit`.
trait PublishRecord {
    /// Writes `record` at `path` of the sweeper's own storage. A refusal is
    /// fixed text and the status, never the server's words.
    async fn publish(&self, path: &str, record: Vec<u8>) -> anyhow::Result<()>;
}

/// The real [`PublishRecord`]: each write under the writers' lock, with a
/// session signed in for it alone and signed out at once, so the lock is
/// held around a sign-in, one PUT and a sign-out, and never while git runs.
struct LockedSessionPublisher<'a> {
    ctx: &'a Context,
    /// The pubky `run` checked the bounty for, which the session must be.
    sweeper: Pubky,
}

impl PublishRecord for LockedSessionPublisher<'_> {
    async fn publish(&self, path: &str, record: Vec<u8>) -> anyhow::Result<()> {
        // `async move` moves `record` into the body, and copies `self` and
        // `path`, which are references. The body only borrows the session,
        // so `with_writer_session` signs it out whatever the body returns.
        with_writer_session(self.ctx, async move |signed| {
            // `login.json` is read again under the lock. A `login` as
            // another identity since `run` read it would publish this sweep
            // under a pubky the bounty was not checked for.
            if signed.login().pubky != self.sweeper {
                bail!(LOGIN_CHANGED);
            }
            put_record(&SessionStorage::new(signed), path, record).await
        })
        .await
    }
}

/// Writes `record` at `path` through `storage`, a refusal mapped by
/// `write_error`: 403 and 507 to their messages, anything else to fixed
/// text and the status, never the server's words. `submit` writes its
/// flip of the record through it too.
pub(crate) async fn put_record(
    storage: &impl OwnStorage,
    path: &str,
    record: Vec<u8>,
) -> anyhow::Result<()> {
    storage
        .put(path, record)
        .await
        .map_err(|error| write_error(&error).context(format!("could not write {path}")))
}

/// Starts `new`: checks that its directory can be made, publishes it as
/// `running` through `publisher`, then, outside any lock, fetches its
/// targets through `git` and `source` and writes its marker, last. If a
/// step after the running write fails, the sweep directory is gone and the
/// record is flipped to `aborted` ([`abort`]).
async fn start_sweep(
    publisher: &impl PublishRecord,
    git: &impl RunGit,
    source: &impl TargetResolver,
    new: &NewSweep<'_>,
) -> anyhow::Result<FetchedSweep> {
    check_sweep_dir(new.project, new.sweep.id)?;
    let running = running_record(new, clock::now()?)?;
    let path = paths::sweep_record(new.sweep.id);
    publisher
        .publish(&path, record_bytes(&running)?)
        .await
        .context("could not publish the sweep as running, so run fetched nothing")?;
    match fetch_and_mark(git, source, new, &running).await {
        Ok(fetched) => Ok(fetched),
        // `running` is moved into `abort`: the borrow `fetch_and_mark` took
        // ended with it.
        Err(failure) => Err(abort(publisher, &path, running, failure).await),
    }
}

/// The record `run` publishes for `new` before it fetches anything:
/// `running`, from `started_at`, with no `finishedAt`.
fn running_record(new: &NewSweep<'_>, started_at: RecordTime) -> anyhow::Result<Sweep> {
    let playbook = match new.playbook {
        Some(playbook) => playbook.clone(),
        None => UNSPECIFIED_PLAYBOOK
            .parse()
            .context("the placeholder playbook does not pass 01's pattern; this is a bug")?,
    };
    Ok(Sweep {
        schema_version: SchemaVersion::CURRENT,
        bounty: new.checked.bounty_ref,
        targets: new
            .checked
            .targets
            .iter()
            .map(|chosen| chosen.id.clone())
            .collect(),
        playbook,
        status: KnownSweepStatus::Running.into(),
        started_at,
        finished_at: None,
        sha256: None,
        extra: UnknownFields::new(),
    })
}

/// `record` as it is published: compact JSON, as `post` writes a bounty.
/// At most `MAX_TARGETS` ids of at most 32 characters, a URL and a short
/// playbook keep it far under `MAX_RECORD_BYTES`.
pub(crate) fn record_bytes(record: &Sweep) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(record).context("could not write the sweep record")
}

/// Fetches `new`'s targets into its sweep directory, then writes the
/// marker of `running`, last. A marker that cannot be written takes the
/// directory with it, as a failed fetch does, so no sweep is left without
/// one.
async fn fetch_and_mark(
    git: &impl RunGit,
    source: &impl TargetResolver,
    new: &NewSweep<'_>,
    running: &Sweep,
) -> anyhow::Result<FetchedSweep> {
    let fetched = fetch_sweep(git, source, new.project, new.sweep, new.checked).await?;
    let marker = SweepMarker::new(new.sweep, running, new.playbook);
    if let Err(error) = marker.write_into(&fetched.dir) {
        // Best effort, as the fetch's own guard is: a directory left behind
        // has no marker, so `submit` refuses it. `remove_dir_all` never
        // follows a link inside it.
        let _ = fs::remove_dir_all(&fetched.dir);
        return Err(error);
    }
    Ok(fetched)
}

/// The error `run` stops with when a step after the running write failed
/// with `failure`: `failure` itself, behind [`ABORTED`] once the record at
/// `path` is flipped to `aborted`, or behind [`NOT_ABORTED`] and the
/// flip's own error, which is fixed text too, when it could not be.
async fn abort(
    publisher: &impl PublishRecord,
    path: &str,
    running: Sweep,
    failure: anyhow::Error,
) -> anyhow::Error {
    match publish_aborted(publisher, path, running).await {
        Ok(()) => failure.context(ABORTED),
        // `{:#}` writes the flip's whole chain of context on one line.
        Err(flip) => failure.context(format!("{NOT_ABORTED} ({flip:#})")),
    }
}

/// Publishes `record`, the running one, at `path` as `aborted`, finished
/// now. Everything else stays as it was.
// `mut record`: this function owns the record it was given, so it may
// change it before writing it.
async fn publish_aborted(
    publisher: &impl PublishRecord,
    path: &str,
    mut record: Sweep,
) -> anyhow::Result<()> {
    record.status = KnownSweepStatus::Aborted.into();
    record.finished_at = Some(clock::now()?);
    publisher.publish(path, record_bytes(&record)?).await
}

/// What `run` reports once the sweep is whole: the sweep's URL, what was
/// stripped from each target, and what to run next. The ids and counts
/// are checked values and the project's path is the user's own, so
/// nothing here needs the sanitiser; the stripped names, which are the
/// repository's, are left to `scope.json`.
fn started_report(new: &NewSweep<'_>, fetched: &FetchedSweep) -> String {
    let id = new.sweep.id;
    let mut text = format!(
        "Started the sweep {}, published as running.\nIts targets are in sweeps/{id}/target/, \
         with scope.json and brief.md beside them:\n",
        new.sweep
    );
    for target in &fetched.targets {
        text.push_str(&format!(
            "  {}: agent-instruction files stripped: {} (scope.json lists them)\n",
            target.id,
            target.stripped.len()
        ));
    }
    text.push_str(&format!(
        "Next, in {}:\n  1. claude --setting-sources project,local\n  2. /sweepky, and let the \
         agent work until it exits\n  3. sweepky submit --run-dir sweeps/{id}\n",
        new.project.display()
    ));
    text
}

/// The marker of the `init` project `cwd` is, the directory `run` was run
/// in, or why it is not one. Only `cwd` itself is looked at, never a parent
/// (see `init::read_project_marker`).
pub(crate) fn require_project(cwd: &Path) -> anyhow::Result<ProjectMarker> {
    read_project_marker(cwd)
        .context("run must be run inside an init project, in the directory `sweepky init` made")
}

/// What `run` takes as its bounty, said by every refusal of another.
const BOUNTY_URL: &str = "run takes a bounty's URL, pubky://<owner>/pub/sweepky/bounties/<id>.json, \
                          as `sweepky post` printed it";

/// The bounty `text`, `run`'s argument, points at: a bounty record's
/// `pubky://` URL, its owner in either spelling. Every refusal is fixed
/// text, so a key pasted in the wrong place is never printed back.
pub(crate) fn parse_bounty_url(text: &str) -> anyhow::Result<BountyRef> {
    // The exact scheme `PubkyUrl` reads, first: a bounty URL holds a
    // 52-character key, which the classifier below would take for a raw
    // secret key.
    if text.starts_with("pubky://") {
        return bounty_of_url(text);
    }
    if text.starts_with("https://") || text.starts_with("http://") {
        bail!("that is a web address; {BOUNTY_URL}");
    }
    if let Some(refusal) = refuse_secret_material(text.as_bytes()) {
        // `into` makes the `Refusal` the error itself, which says what the
        // text looks like and why Sweepky never takes one.
        return Err(refusal.into());
    }
    bail!(BOUNTY_URL)
}

/// The bounty `text`, a `pubky://` URL, points at.
fn bounty_of_url(text: &str) -> anyhow::Result<BountyRef> {
    // Core's error says what is wrong with the URL in fixed text.
    let url: PubkyUrl = text.parse().context(BOUNTY_URL)?;
    if let Some(bounty) = BountyRef::from_url(&url) {
        // The SDK reads a key only when it is a point on Ed25519, so a key
        // that is not one is refused here, in fixed text, rather than later
        // in a message that names it.
        if public_key_of(&bounty.owner).is_err() {
            bail!("the owner in that URL is not an Ed25519 public key; {BOUNTY_URL}");
        }
        return Ok(bounty);
    }
    if SweepRef::from_url(&url).is_some() {
        bail!("that is a sweep record's URL, not its bounty's; {BOUNTY_URL}");
    }
    bail!("that pubky:// URL names another file than a bounty record; {BOUNTY_URL}")
}

/// What `run` was asked to check: the bounty, who sweeps it, and the two
/// flags that narrow it. Without a URL, the bounty and the target are the
/// ones `pick` picked.
#[derive(Debug)]
pub(crate) struct RunRequest<'a> {
    /// The bounty, from [`parse_bounty_url`].
    pub(crate) bounty: BountyRef,
    /// The sweeper: the pubky this install is logged in as.
    pub(crate) sweeper: Pubky,
    /// `--circle <admin>`: the circle to check the bounty against instead
    /// of its owner's own.
    pub(crate) circle: Option<Pubky>,
    /// `--target <tid>`, as typed: the one target to sweep instead of every
    /// one this build can.
    // A `&str` borrowed from the parsed command line, which `'a` says
    // outlives the request; it is checked as a `TargetId` in `select`.
    pub(crate) target: Option<&'a str>,
}

/// A bounty this sweeper may run, and what it sweeps of it: what
/// [`check_bounty`] found.
#[derive(Debug)]
pub(crate) struct CheckedBounty {
    /// Where the bounty was read from.
    pub(crate) bounty_ref: BountyRef,
    /// The bounty as its owner's storage served it.
    pub(crate) bounty: Bounty,
    /// Why this sweeper may run it.
    pub(crate) acceptance: Acceptance,
    /// The targets to sweep, in the bounty's order.
    pub(crate) targets: Vec<ChosenTarget>,
    /// One line for each target skipped, naming it by its id alone.
    pub(crate) warnings: Vec<String>,
}

/// Reads the bounty `request` names from its owner's storage through
/// `records` and checks it: whether its sweeper may run it (reading the
/// one circle that decides, if any) and which targets, through `source`'s
/// policy. No network but `records`' reads, and nothing written.
pub(crate) async fn check_bounty(
    records: &impl PublicRecords,
    source: &impl TargetResolver,
    request: &RunRequest<'_>,
) -> anyhow::Result<CheckedBounty> {
    let Some(bounty) = records.get_bounty(request.bounty).await? else {
        bail!("there is no such bounty: its owner's storage holds no record at that URL");
    };
    let circle = match select::circle_to_read(request, &bounty) {
        Some(holder) => records.get_circle(holder).await?,
        None => None,
    };
    let acceptance = select::accept(request, &bounty, circle.as_ref())?;
    // Taking the struct apart moves its two fields into the result.
    let ChosenTargets { targets, warnings } =
        select::choose_targets(&bounty, request.target, source)?;
    Ok(CheckedBounty {
        bounty_ref: request.bounty,
        bounty,
        acceptance,
        targets,
        warnings,
    })
}

impl CheckedBounty {
    /// What `run` shows of the bounty before it fetches anything: each
    /// warning, then the bounty's URL, its title and focus, why this
    /// sweeper may run it, and each target it sweeps with the commit it
    /// reviews.
    ///
    /// The title and focus are a stranger's text, so they go through the
    /// terminal sanitiser, with room for the longest `post` writes; so do
    /// repository names, as everywhere. The brief is never shown: it is a
    /// stranger's markdown of any length, and the agent reads it from the
    /// file `run` writes.
    pub(crate) fn summary(&self) -> String {
        // Taking the struct apart names every field, so one added later does
        // not compile until it is shown here or left out on purpose.
        let Self {
            bounty_ref,
            bounty,
            acceptance,
            targets,
            warnings,
        } = self;
        let mut text: String = warnings
            .iter()
            .map(|warning| format!("warning: {warning}\n"))
            .collect();
        text.push_str(&format!(
            "Bounty {bounty_ref}\n  Title: {}\n  Focus: {}\n  {}\n  Targets to sweep ({}):\n",
            sanitize(&bounty.title, MAX_TITLE_CHARS),
            sanitize(bounty.focus.as_str(), MAX_FOCUS_CHARS),
            acceptance_line(*acceptance),
            targets.len()
        ));
        for target in targets {
            text.push_str(&target_line(&target.id, &target.target));
        }
        text
    }
}

/// Why the sweeper may run the bounty, as the summary says it.
fn acceptance_line(acceptance: Acceptance) -> &'static str {
    match acceptance {
        Acceptance::Open => "Open: its owner reads sweeps from anyone, labelled untrusted",
        Acceptance::OwnersCircle => "Closed: you are in its owner's circle",
        Acceptance::NamedCircle => "You and its owner are both in the circle --circle names",
    }
}

/// The summary's line for target `id`: its kind, its repository and the
/// commit the sweep reviews. The id and the SHAs are checked values.
fn target_line(id: &TargetId, target: &KnownTarget) -> String {
    let shown = match target {
        KnownTarget::Repo(repo) => format!("repo {} at {}", shown_repo(repo.repo()), repo.rev()),
        KnownTarget::Commit(commit) => {
            format!("commit {} in {}", commit.rev(), shown_repo(commit.repo()))
        }
        KnownTarget::Pr(pr) => format!(
            "pull request {} of {}, head {}",
            pr.number(),
            shown_repo(pr.repo()),
            pr.head()
        ),
    };
    format!("    {id}: {shown}\n")
}

/// `repo` through the sanitiser, as every repository name is shown.
fn shown_repo(repo: &RepoName) -> String {
    sanitize(repo.as_str(), RepoName::MAX_LEN)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use anyhow::anyhow;
    use pubky::{Keypair, StatusCode};
    use serde_json::{Value, json};
    use sweepky_core::paths;
    use sweepky_core::{
        BountyRef, KnownSweepStatus, MAX_RECORD_BYTES, Playbook, Pubky, Sweep, SweepRef,
    };

    use super::pick::pick_target;
    use super::select::Acceptance;
    use super::{
        ABORTED, CheckedBounty, NOT_ABORTED, NewSweep, PublishRecord, RunRequest, TARGET_NEEDS_URL,
        abort, check_bounty, parse_bounty_url, put_record, record_bytes, require_project, run,
        running_record, start_sweep,
    };
    use crate::git::{GitCommand, GitRunner, RunGit};
    use crate::identity::Refusal;
    use crate::init::{self, MARKER};
    use crate::own_storage::OwnStorage;
    use crate::remote::{QUOTA_FULL, WRITE_FORBIDDEN};
    use crate::targets::{TargetResolver, TargetSource};
    use crate::test_support::{
        FakeOwnStorage, FakePublicRecords, PLANTED, RecordingGit, SYNTHETIC_SHA, bounty_id,
        bounty_json, circle_json, dirs_in, fixture_repo, fixture_targets, json_bytes,
        offline_network, private_temp, random_pubky, recorded_fixture_shas, repo_target_json,
        sweep_json, test_context, test_git_env,
    };

    #[test]
    fn run_needs_an_init_project_in_the_working_directory() {
        let temp = tempfile::tempdir().expect("temp dir");

        // A P2a project passes, read through init's own reader.
        let project = temp.path().join("project");
        init::init(&project).expect("init");
        let marker = require_project(&project).expect("an init project");
        assert_eq!(marker.playbook(), None);

        // Every other working directory is refused, by its path.
        let no_marker = temp.path().join("plain");
        fs::create_dir(&no_marker).expect("mkdir");
        // Only the working directory is checked: inside a project is not in
        // it.
        let inside = project.join("sub");
        fs::create_dir(&inside).expect("mkdir");
        // A marker that is a link, here to init's own valid marker.
        let linked = temp.path().join("linked");
        fs::create_dir(&linked).expect("mkdir");
        symlink(project.join(MARKER), linked.join(MARKER)).expect("symlink");
        // A file at that name that is not a marker.
        let foreign = temp.path().join("foreign");
        fs::create_dir(&foreign).expect("mkdir");
        fs::write(foreign.join(MARKER), format!("{PLANTED}\n")).expect("write");
        // A directory at that name.
        let directory = temp.path().join("directory");
        fs::create_dir_all(directory.join(MARKER)).expect("mkdir");

        for dir in [no_marker, inside, linked, foreign, directory] {
            let err = require_project(&dir).expect_err("refused");
            let message = format!("{err:#}");
            assert!(
                message.contains(&dir.display().to_string()),
                "{}: {message}",
                dir.display()
            );
            assert!(message.contains("init project"), "{message}");
            assert!(!message.contains(PLANTED), "{message}");
        }
    }

    #[test]
    fn the_bounty_url_is_a_bounty_record_s_pubky_url() {
        let owner = random_pubky();
        let id = bounty_id();
        let expected = BountyRef { owner, id };
        // Raw, as `post` prints it, and with the SDK's `pubky` prefix.
        for url in [
            format!("pubky://{owner}/pub/sweepky/bounties/{id}.json"),
            format!("pubky://pubky{owner}/pub/sweepky/bounties/{id}.json"),
        ] {
            assert_eq!(parse_bounty_url(&url).expect(&url), expected);
        }
    }

    #[test]
    fn any_other_argument_is_refused_unquoted() {
        let owner = random_pubky();
        let id = bounty_id();
        let secret = Keypair::random().secret();
        // A test may hold a secret in a plain array; it spells its bytes in
        // z-base32 and hex here, the shapes a pasted key comes in.
        let z32_secret = Pubky::from_bytes(secret).to_string();
        let hex_secret: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();

        let cases = [
            (
                format!("pubky://{owner}/pub/sweepky/sweeps/{id}.json"),
                "a sweep record's URL",
            ),
            (
                format!("https://{owner}/pub/sweepky/bounties/{id}.json"),
                "web address",
            ),
            (
                format!("pubky://{PLANTED}/pub/sweepky/bounties/{id}.json"),
                "not a pubky",
            ),
            (
                format!("pubky://{owner}/pub/sweepky/bounties/{PLANTED}.json"),
                "another file",
            ),
            (format!("{PLANTED} or so"), "takes a bounty's URL"),
        ];
        for (argument, expected) in &cases {
            let err = parse_bounty_url(argument).expect_err(argument);
            let message = format!("{err:#}");
            assert!(message.contains(expected), "{argument}: {message}");
            assert_unquoted(&message, &[argument, &owner.to_string(), PLANTED]);
        }

        // A pasted key is refused by the same classifier `login` uses.
        for argument in [&z32_secret, &hex_secret] {
            let err = parse_bounty_url(argument).expect_err("refused");
            assert_eq!(err.downcast_ref::<Refusal>(), Some(&Refusal::RawKey));
            assert_unquoted(&format!("{err:#}"), &[argument]);
        }
    }

    /// `message` contains none of `texts`.
    fn assert_unquoted(message: &str, texts: &[&str]) {
        for text in texts {
            assert!(!message.contains(text), "{message} quotes {text}");
        }
    }

    // -----------------------------------------------------------------------
    // Fetching and checking.

    fn request(owner: Pubky, sweeper: Pubky) -> RunRequest<'static> {
        RunRequest {
            bounty: BountyRef {
                owner,
                id: bounty_id(),
            },
            sweeper,
            circle: None,
            target: None,
        }
    }

    /// A fake holding `bounty` as `request`'s bounty and, if given, the
    /// owner's circle with `members`.
    fn records(
        request: &RunRequest<'_>,
        bounty: &Value,
        members: Option<&[Pubky]>,
    ) -> FakePublicRecords {
        let owner = request.bounty.owner;
        let records = FakePublicRecords::default().with_file(
            owner,
            &paths::bounty(request.bounty.id),
            json_bytes(bounty),
        );
        match members {
            Some(members) => records.with_file(
                owner,
                paths::circle(),
                json_bytes(&circle_json(owner, members)),
            ),
            None => records,
        }
    }

    #[tokio::test]
    async fn a_closed_bounty_is_read_with_its_owner_s_circle() {
        let (owner, sweeper) = (random_pubky(), random_pubky());
        let request = request(owner, sweeper);
        let records = records(
            &request,
            &bounty_json(json!([repo_target_json("t1")])),
            Some(&[owner, sweeper]),
        );

        let checked = check_bounty(&records, &TargetSource::Real, &request)
            .await
            .expect("accepted");
        assert_eq!(checked.acceptance, Acceptance::OwnersCircle);
        assert_eq!(checked.targets.len(), 1);
        // The bounty from its owner's storage, then the owner's circle.
        assert_eq!(
            records.asked(),
            [
                (owner, paths::bounty(bounty_id())),
                (owner, paths::circle().to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn an_open_bounty_is_read_alone() {
        let request = request(random_pubky(), random_pubky());
        let mut bounty = bounty_json(json!([repo_target_json("t1")]));
        bounty["open"] = json!(true);
        let records = records(&request, &bounty, None);

        let checked = check_bounty(&records, &TargetSource::Real, &request)
            .await
            .expect("accepted");
        assert_eq!(checked.acceptance, Acceptance::Open);
        assert_eq!(records.asked().len(), 1);
    }

    #[tokio::test]
    async fn the_circle_flag_s_circle_is_read_instead() {
        let (owner, sweeper, admin) = (random_pubky(), random_pubky(), random_pubky());
        let request = RunRequest {
            circle: Some(admin),
            ..request(owner, sweeper)
        };
        let records = records(
            &request,
            &bounty_json(json!([repo_target_json("t1")])),
            // The owner's own circle lists the sweeper, but is not the one
            // asked for.
            Some(&[owner, sweeper]),
        )
        .with_file(
            admin,
            paths::circle(),
            json_bytes(&circle_json(admin, &[owner, sweeper])),
        );

        let checked = check_bounty(&records, &TargetSource::Real, &request)
            .await
            .expect("accepted");
        assert_eq!(checked.acceptance, Acceptance::NamedCircle);
        assert_eq!(
            records.asked().last(),
            Some(&(admin, paths::circle().to_owned()))
        );
    }

    #[tokio::test]
    async fn a_missing_bounty_is_refused_unquoted() {
        let request = request(random_pubky(), random_pubky());
        let err = check_bounty(&FakePublicRecords::default(), &TargetSource::Real, &request)
            .await
            .expect_err("refused");
        let message = format!("{err:#}");
        assert!(message.contains("no such bounty"), "{message}");
        assert_unquoted(&message, &[&request.bounty.owner.to_string()]);
    }

    #[tokio::test]
    async fn the_summary_sanitises_the_title_and_focus_and_never_shows_the_brief() {
        let (owner, sweeper) = (random_pubky(), random_pubky());
        let request = request(owner, sweeper);
        let mut bounty = bounty_json(json!([repo_target_json("t1")]));
        // An escape that would clear the screen and a right-to-left
        // override, in both one-line fields, and a brief to look for.
        bounty["title"] = json!("Auth\u{1b}[2J review\u{202e}gpj.exe");
        bounty["focus"] = json!("sec\u{7}urity");
        bounty["brief"] = json!(format!("{PLANTED} brief text"));
        let records = records(&request, &bounty, Some(&[owner, sweeper]));

        let summary = check_bounty(&records, &TargetSource::Real, &request)
            .await
            .expect("accepted")
            .summary();
        assert!(
            summary.contains("Title: Auth\\u{1b}[2J review\\u{202e}gpj.exe"),
            "{summary}"
        );
        assert!(summary.contains("Focus: sec\\u{7}urity"), "{summary}");
        assert!(
            !summary.contains(['\u{1b}', '\u{202e}', '\u{7}']),
            "{summary}"
        );
        assert!(!summary.contains(PLANTED), "{summary}");
        // The bounty, the target and its commit, which are checked values.
        assert!(summary.contains(&request.bounty.to_string()), "{summary}");
        assert!(summary.contains("t1: repo"), "{summary}");
    }

    // -----------------------------------------------------------------------
    // The command: the running record, the fetch, the marker, the abort.

    /// What the fake storage answers a refused write with: no message may
    /// repeat it.
    const SERVER_TEXT: &str = "MARKER-9q2w: tenant over quota, path policy says no";

    const PLAYBOOK: &str = "cloudflare/security-audit@c1c8a8c";

    const STARTED_AT: &str = "2026-10-19T12:00:00Z";

    /// In the tests, the fake storage stands for the sweeper's storage
    /// under the lock: each write goes straight to it, mapped as the real
    /// publisher maps one.
    impl PublishRecord for FakeOwnStorage {
        async fn publish(&self, path: &str, record: Vec<u8>) -> anyhow::Result<()> {
            put_record(self, path, record).await
        }
    }

    /// The real runner, watched: before each git run it notes how many
    /// writes `storage` had been asked for and whether the sweep's marker
    /// was there, so a test can tell what came before git and what after.
    struct WatchedGit<'a> {
        git: GitRunner,
        storage: &'a FakeOwnStorage,
        marker: PathBuf,
        seen: Mutex<Vec<(usize, bool)>>,
    }

    impl RunGit for WatchedGit<'_> {
        async fn run(&self, command: &GitCommand) -> anyhow::Result<Vec<u8>> {
            let marker_there = fs::symlink_metadata(&self.marker).is_ok();
            self.seen
                .lock()
                .expect("lock")
                .push((self.storage.puts().len(), marker_there));
            self.git.run(command).await
        }
    }

    /// An open bounty of `targets`, as `run` checks it with the fixture
    /// source, read through a fake.
    async fn fixture_bounty(targets: Value) -> CheckedBounty {
        let request = request(random_pubky(), random_pubky());
        let mut bounty = bounty_json(targets);
        bounty["open"] = json!(true);
        let records = records(&request, &bounty, None);
        check_bounty(
            &records,
            &TargetSource::Fixture(fixture_targets()),
            &request,
        )
        .await
        .expect("accepted")
    }

    /// Target t1, commit `rev` of the fixture repository: M, which it
    /// serves, or [`SYNTHETIC_SHA`], which it never had.
    fn commit_target(rev: &str) -> Value {
        json!({ "id": "t1", "kind": "commit", "repo": fixture_repo().to_string(), "rev": rev })
    }

    /// A new sweep of `checked` in `project`, by a random sweeper.
    fn new_sweep<'a>(
        project: &'a Path,
        checked: &'a CheckedBounty,
        playbook: Option<&'a Playbook>,
    ) -> NewSweep<'a> {
        NewSweep {
            project,
            sweep: SweepRef {
                sweeper: random_pubky(),
                id: bounty_id(),
            },
            checked,
            playbook,
        }
    }

    #[tokio::test]
    async fn the_running_record_names_the_bounty_the_targets_and_the_playbook() {
        let (owner, sweeper) = (random_pubky(), random_pubky());
        let request = request(owner, sweeper);
        let records = records(
            &request,
            &bounty_json(json!([repo_target_json("t1"), repo_target_json("t2")])),
            Some(&[owner, sweeper]),
        );
        let checked = check_bounty(&records, &TargetSource::Real, &request)
            .await
            .expect("accepted");
        let project = Path::new("/abs/project");
        let started_at = STARTED_AT.parse().expect("a time");

        // No playbook recorded by `init`: the placeholder.
        let record =
            running_record(&new_sweep(project, &checked, None), started_at).expect("a record");
        let bytes = record_bytes(&record).expect("written");
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).expect("JSON"),
            json!({
                "schemaVersion": 1,
                "bounty": request.bounty.to_string(),
                "targets": ["t1", "t2"],
                "playbook": "unspecified",
                "status": "running",
                "startedAt": STARTED_AT,
            })
        );
        // Compact, within the cap, and read back equal by core.
        assert!(!bytes.contains(&b'\n'));
        assert!(bytes.len() <= MAX_RECORD_BYTES);
        assert_eq!(Sweep::from_json(&bytes).expect("core reads it"), record);

        // The playbook `init` recorded, when there is one.
        let playbook: Playbook = PLAYBOOK.parse().expect("a playbook");
        let started_at = STARTED_AT.parse().expect("a time");
        let record = running_record(&new_sweep(project, &checked, Some(&playbook)), started_at)
            .expect("a record");
        assert_eq!(record.playbook, playbook);
    }

    #[tokio::test]
    async fn running_is_published_before_git_runs_and_the_marker_written_after_the_fetch() {
        let shas = recorded_fixture_shas();
        let checked = fixture_bounty(json!([commit_target(shas["M"].as_str())])).await;
        let playbook: Playbook = PLAYBOOK.parse().expect("a playbook");
        let project = private_temp();
        let new = new_sweep(project.path(), &checked, Some(&playbook));
        let path = paths::sweep_record(new.sweep.id);
        let sweep_dir = project.path().join("sweeps").join(new.sweep.id.to_string());
        let source = TargetSource::Fixture(fixture_targets());
        // Declared before the runner, so the runner, whose private HOME is
        // under it, is dropped first.
        let home = private_temp();
        let storage = FakeOwnStorage::default();
        let git = WatchedGit {
            git: source
                .git_runner(&dirs_in(&home), &test_git_env())
                .expect("a runner"),
            storage: &storage,
            marker: sweep_dir.join(".sweepky/sweep.json"),
            seen: Mutex::default(),
        };

        let fetched = start_sweep(&storage, &git, &source, &new)
            .await
            .unwrap_or_else(|error| panic!("{error:#}"));

        // Every git run came after the one running write, and before the
        // marker.
        let seen = git.seen.into_inner().expect("lock");
        assert!(!seen.is_empty());
        assert!(seen.iter().all(|&run| run == (1, false)), "{seen:?}");
        assert_eq!(storage.puts(), [path.as_str()]);
        let stored = storage.get_own(&path).await.expect("reads").expect("there");
        let record = Sweep::from_json(&stored).expect("a sweep record");
        assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Running));
        assert_eq!(record.bounty, checked.bounty_ref);
        assert_eq!(record.playbook, playbook);
        // The marker, after the fetch, names the sweep and the record's
        // bounty and targets.
        let marker: Value =
            serde_json::from_slice(&fs::read(sweep_dir.join(".sweepky/sweep.json")).expect("read"))
                .expect("JSON");
        assert_eq!(marker["sweep"], new.sweep.to_string());
        assert_eq!(marker["bounty"], checked.bounty_ref.to_string());
        assert_eq!(marker["targets"], json!(["t1"]));
        assert_eq!(marker["playbook"], PLAYBOOK);
        assert_eq!(fetched.dir, sweep_dir);
    }

    #[tokio::test]
    async fn a_refused_running_write_runs_no_git_and_makes_no_sweep_directory() {
        let checked = fixture_bounty(json!([commit_target(SYNTHETIC_SHA)])).await;
        let project = private_temp();
        let new = new_sweep(project.path(), &checked, None);
        let path = paths::sweep_record(new.sweep.id);
        let source = TargetSource::Fixture(fixture_targets());
        let storage = FakeOwnStorage::refusing(&path, StatusCode::FORBIDDEN, SERVER_TEXT);
        let git = RecordingGit::succeeding(source.protocols(), b"");

        let error = start_sweep(&storage, &git, &source, &new)
            .await
            .expect_err("refused");

        let message = format!("{error:#}");
        assert!(message.contains(WRITE_FORBIDDEN), "{message}");
        assert!(!message.contains("MARKER-9q2w"), "{message}");
        // Nothing was written, so there is nothing to flip.
        assert_eq!(storage.puts(), [path.as_str()]);
        assert_eq!(git.argv(), Vec::<Vec<String>>::new());
        assert!(fs::symlink_metadata(project.path().join("sweeps")).is_err());
    }

    #[tokio::test]
    async fn an_unserved_sha_flips_the_record_to_aborted_and_removes_the_sweep() {
        let checked = fixture_bounty(json!([commit_target(SYNTHETIC_SHA)])).await;
        let project = private_temp();
        let new = new_sweep(project.path(), &checked, None);
        let path = paths::sweep_record(new.sweep.id);
        let source = TargetSource::Fixture(fixture_targets());
        let home = private_temp();
        let git = source
            .git_runner(&dirs_in(&home), &test_git_env())
            .expect("a runner");
        let storage = FakeOwnStorage::default();

        let error = start_sweep(&storage, &git, &source, &new)
            .await
            .expect_err("not served");

        let message = format!("{error:#}");
        assert!(message.starts_with(ABORTED), "{message}");
        assert!(
            message.contains(&format!(
                "the pinned commit {SYNTHETIC_SHA} is no longer served"
            )),
            "{message}"
        );
        // Running, then the same record as aborted, finished.
        assert_eq!(storage.puts(), [path.as_str(), path.as_str()]);
        let stored = storage.get_own(&path).await.expect("reads").expect("there");
        let aborted = Sweep::from_json(&stored).expect("a sweep record");
        let mut expected =
            running_record(&new, aborted.started_at.clone()).expect("the running record");
        expected.status = KnownSweepStatus::Aborted.into();
        expected.finished_at = Some(aborted.finished_at.clone().expect("finishedAt is set"));
        assert_eq!(aborted, expected);
        // No sweep directory, so no marker either.
        let sweep_dir = project.path().join("sweeps").join(new.sweep.id.to_string());
        assert!(fs::symlink_metadata(&sweep_dir).is_err());
    }

    #[tokio::test]
    async fn a_refused_flip_to_aborted_is_reported_with_the_failure_in_fixed_text() {
        let checked = fixture_bounty(json!([commit_target(SYNTHETIC_SHA)])).await;
        let new = new_sweep(Path::new("/abs/project"), &checked, None);
        let path = paths::sweep_record(new.sweep.id);
        let running = running_record(&new, STARTED_AT.parse().expect("a time")).expect("a record");
        let storage =
            FakeOwnStorage::refusing(&path, StatusCode::INSUFFICIENT_STORAGE, SERVER_TEXT);

        let error = abort(&storage, &path, running, anyhow!("the fetch failed")).await;

        let message = format!("{error:#}");
        assert!(message.starts_with(NOT_ABORTED), "{message}");
        assert!(message.contains(QUOTA_FULL), "{message}");
        assert!(message.ends_with("the fetch failed"), "{message}");
        assert!(!message.contains("MARKER-9q2w"), "{message}");
        assert_eq!(storage.puts(), [path.as_str()]);
    }

    // -----------------------------------------------------------------------
    // No URL: picking from the circle.

    #[tokio::test]
    async fn run_without_a_url_takes_no_target_flag() {
        let home = private_temp();
        let (mut ctx, _stderr) = test_context(offline_network(), &home, io::empty());
        let project = home.path().join("project");
        init::init(&project).expect("init");
        ctx.cwd = project;

        // Refused before anything is read, and the flag is not quoted.
        let error = run(&ctx, None, Some(PLANTED), None)
            .await
            .expect_err("refused");

        assert_eq!(format!("{error:#}"), TARGET_NEEDS_URL);
    }

    #[tokio::test]
    async fn a_picked_target_is_one_check_bounty_accepts_as_for_its_url() {
        let (sweeper, owner) = (random_pubky(), random_pubky());
        let bounty = BountyRef {
            owner,
            id: bounty_id(),
        };
        // A closed bounty of two targets, the first swept already, whose
        // owner is in the sweeper's circle and the sweeper in the owner's.
        let records = FakePublicRecords::default()
            .with_record(sweeper, paths::circle(), &circle_json(sweeper, &[owner]))
            .with_record(owner, paths::circle(), &circle_json(owner, &[sweeper]))
            .with_record(
                owner,
                &paths::bounty(bounty.id),
                &bounty_json(json!([repo_target_json("t1"), repo_target_json("t2")])),
            )
            .with_record(
                owner,
                &paths::sweep_record(bounty_id()),
                &sweep_json(bounty, &["t1"], "done"),
            );

        let choice = pick_target(&records, &TargetSource::Real, sweeper, None)
            .await
            .expect("picked")
            .choice
            .expect("a target");
        // The request `run` makes of the pick: the bounty, and its target
        // as --target.
        let request = RunRequest {
            bounty: choice.bounty,
            sweeper,
            circle: None,
            target: Some(choice.target.as_str()),
        };
        let checked = check_bounty(&records, &TargetSource::Real, &request)
            .await
            .expect("accepted");

        assert_eq!(checked.bounty_ref, bounty);
        assert_eq!(checked.acceptance, Acceptance::OwnersCircle);
        let ids: Vec<&str> = checked
            .targets
            .iter()
            .map(|chosen| chosen.id.as_str())
            .collect();
        assert_eq!(ids, ["t2"]);
    }
}
