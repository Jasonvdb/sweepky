//! The headless check of P5's local demo (docs/plan/phases/P5-local-demo.md):
//! steps 2 to 8 of `scripts/demo-local.sh`, on an in-process
//! `EphemeralTestnet` with its HTTP relay, and one PASS or FAIL per
//! assertion in `<scratch>/results.json`.
//!
//! ```text
//! demo_check <scratch dir>
//! ```
//!
//! Three identities, owner, sweeper and stranger, each with a
//! `SWEEPKY_HOME` of its own under the scratch directory, run every
//! command through the library's `run`, as the binary runs it. The owner
//! posts an open bounty on real targets (`post` and `run` read github.com
//! anonymously, nothing else), the sweeper submits the run directory, the
//! stranger a synthetic audit sharing one of its locations, the owner pulls
//! with `--findings` and marks the bounty done, and the checks read the
//! records the board reads, anonymously.
//!
//! The inputs are `SWEEPKY_DEMO_RUN_DIR` and `SWEEPKY_DEMO_TARGETS` (both or
//! neither); without them, the synthetic `fixtures/demo/`, which this
//! process says it falls back to. A real run directory is only copied into
//! the sweeper's `audit/` under the scratch directory and uploaded to the
//! in-process testnet. The results hold fixed text only, never a finding.
//!
//! The scratch directory must be empty (or not exist yet) and lie outside
//! the repository, `~/.config`, `~/.local` and `~/.cargo`. The testnet's
//! homeserver needs Postgres through `TEST_PUBKY_CONNECTION_STRING`. The
//! exit status is non-zero on any FAIL.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// `as _` brings `.context(...)` into scope without the name `Context`,
// which is the library's type here.
use anyhow::{Context as _, bail, ensure};
use clap::Parser;
use pubky::PublicKey;
use pubky_testnet::EphemeralTestnet;
use serde_json::{Value, json};
use sweepky_cli::{
    Browser, Cli, Context, Dirs, GitEnv, Network, Report, StderrWriter, StdinReader, TargetSource,
    run,
};
use sweepky_core::{
    Bounty, BountyRef, Discovered, Findings, KnownBountyStatus, KnownSweepStatus, KnownTarget,
    Location, MAX_RECORD_BYTES, Playbook, Pubky, RecordId, Sweep, SweepRef, Target, TargetId,
    parse_audit_findings, paths,
};
use url::Url;

/// How long the stopped testnet's tasks get to let go of their databases
/// before they are dropped, as in `sandbox_fixture.rs`.
const DATABASE_RELEASE: std::time::Duration = std::time::Duration::from_secs(3);

/// The playbook the sweeper's submit names: the one the stand-in report
/// came from (or, for the fixture, mimics).
const SWEEPER_PLAYBOOK: &str = "cloudflare/security-audit@c1c8a8c1471069fb0e188eeaff69b8e8db6564a8";
/// The playbook the stranger's synthetic sweep names.
const STRANGER_PLAYBOOK: &str = "careful-review";

/// The heading `pull --findings` prints its findings under.
const FINDINGS_HEADING: &str = "Findings of your circle";

/// `fixtures/demo/<name>`. `env!` reads `CARGO_MANIFEST_DIR` when the
/// example is compiled, so this finds the fixtures wherever the repository
/// is checked out.
fn demo_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/demo")
        .join(name)
}

/// The outcome of each check, in the order they ran.
///
/// Each name is a `&'static str`: text compiled into this binary. A string
/// built at run time cannot be one, so the type itself keeps every finding,
/// trusted or not, out of `results.json`.
#[derive(Default)]
struct Checks(Vec<(&'static str, bool)>);

impl Checks {
    fn record(&mut self, name: &'static str, passed: bool) {
        println!("{} {name}", verdict(passed));
        self.0.push((name, passed));
    }

    fn all_passed(&self) -> bool {
        self.0.iter().all(|&(_, passed)| passed)
    }

    fn to_json(&self, inputs: &'static str) -> Value {
        let results: Vec<Value> = self
            .0
            .iter()
            .map(|&(check, passed)| json!({ "check": check, "result": verdict(passed) }))
            .collect();
        json!({ "inputs": inputs, "results": results })
    }
}

fn verdict(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}

/// The run directory the sweeper submits and the targets the bounty names.
struct Inputs {
    run_dir: PathBuf,
    /// The JSON array that becomes the draft's `targets`.
    targets: Value,
    /// Where they came from, fixed text for `results.json`.
    source: &'static str,
}

impl Inputs {
    /// Both variables, or the fixtures when neither is set. One without the
    /// other is refused: a real report needs the targets it covered.
    fn from_env() -> anyhow::Result<Self> {
        let run_dir = std::env::var_os("SWEEPKY_DEMO_RUN_DIR");
        let targets = std::env::var_os("SWEEPKY_DEMO_TARGETS");
        let (run_dir, targets, source) = match (run_dir, targets) {
            (Some(run_dir), Some(targets)) => {
                let targets = targets
                    .into_string()
                    .ok()
                    .context("SWEEPKY_DEMO_TARGETS is not UTF-8")?;
                (PathBuf::from(run_dir), targets, "environment")
            }
            (None, None) => {
                eprintln!(
                    "SWEEPKY_DEMO_RUN_DIR and SWEEPKY_DEMO_TARGETS are unset: using the synthetic \
                     fixtures in fixtures/demo"
                );
                let targets = fs::read_to_string(demo_fixture("targets.json"))
                    .context("fixtures/demo/targets.json")?;
                (demo_fixture("sweeper-run"), targets, "fixtures/demo")
            }
            _ => bail!("set both SWEEPKY_DEMO_RUN_DIR and SWEEPKY_DEMO_TARGETS, or neither"),
        };
        let targets: Value =
            serde_json::from_str(&targets).context("SWEEPKY_DEMO_TARGETS is not JSON")?;
        ensure!(
            targets.is_array(),
            "SWEEPKY_DEMO_TARGETS is not a JSON array"
        );
        Ok(Self {
            run_dir,
            targets,
            source,
        })
    }
}

/// `scratch` as a canonical path, created if missing (its parent must
/// exist), once it is known to be empty and outside the repository,
/// `~/.config`, `~/.local` and `~/.cargo`: every identity and key this run
/// makes lives under it.
///
/// Checked before anything is created and again once the directory exists:
/// the first check keeps this process from making a directory in a
/// forbidden place, the second catches a symlink already standing there.
fn checked_scratch(scratch: &Path) -> anyhow::Result<PathBuf> {
    ensure!(
        scratch.is_absolute(),
        "the scratch directory must be an absolute path"
    );
    let (Some(parent), Some(name)) = (scratch.parent(), scratch.file_name()) else {
        bail!("the scratch directory must have a parent directory");
    };
    // Canonical, so `..` or a symlink cannot hide a forbidden place.
    let planned = fs::canonicalize(parent)
        .context("the scratch directory's parent must exist")?
        .join(name);
    ensure_allowed(&planned)?;
    match fs::create_dir(&planned) {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
            return Err(error).context("could not create the scratch directory");
        }
        _ => {}
    }
    let scratch = fs::canonicalize(&planned)?;
    ensure_allowed(&scratch)?;
    ensure!(
        fs::read_dir(&scratch)?.next().is_none(),
        "the scratch directory must be empty"
    );
    Ok(scratch)
}

/// Refuses `dir` if it is in the repository, `~/.config`, `~/.local` or
/// `~/.cargo`.
fn ensure_allowed(dir: &Path) -> anyhow::Result<()> {
    let mut forbidden = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")];
    if let Some(home) = std::env::var_os("HOME") {
        let home = Path::new(&home);
        forbidden.extend([".config", ".local", ".cargo"].map(|name| home.join(name)));
    }
    // A forbidden directory that does not exist stays as written, which
    // still refuses a path under it.
    let refused = forbidden
        .into_iter()
        .map(|place| fs::canonicalize(&place).unwrap_or(place))
        .any(|place| dir.starts_with(place));
    ensure!(
        !refused,
        "the scratch directory must be outside the repository, ~/.config, ~/.local and ~/.cargo"
    );
    Ok(())
}

/// The network a context uses: the testnet's client, relay and homeserver
/// injected, as the end-to-end test does.
fn network(testnet: &EphemeralTestnet) -> anyhow::Result<Network> {
    Ok(Network::injected(
        testnet.sdk()?,
        // `local_url()` ends with `/`, so this is `…/inbox`.
        format!("{}inbox", testnet.http_relay().local_url()),
        testnet.homeserver_app().public_key(),
    ))
}

/// One identity's context: `home` as its `SWEEPKY_HOME` and first working
/// directory, nothing on standard input, real targets and no browser.
fn context(testnet: &EphemeralTestnet, home: &Path) -> anyhow::Result<Context> {
    Ok(Context {
        network: network(testnet)?,
        dirs: Dirs::resolve(None, Some(home.as_os_str()))?,
        cwd: home.to_path_buf(),
        stdin: StdinReader::new(io::empty()),
        stderr: StderrWriter::new(io::stderr()),
        passphrase: None,
        // As main.rs captures it: PATH and the proxy and CA variables, so
        // git can reach github.com over https as it would for the binary.
        git_env: GitEnv::capture(std::env::var_os),
        targets: TargetSource::Real,
        browser: Browser::None,
    })
}

/// Has the next question `ctx` asks answered with yes.
fn answer_yes(ctx: &mut Context) {
    ctx.stdin = StdinReader::new(Cursor::new(b"y\n"));
}

/// Runs `sweepky <args>` against `ctx`.
async fn sweepky(ctx: &Context, args: &[&str]) -> anyhow::Result<Report> {
    let cli = Cli::try_parse_from(std::iter::once("sweepky").chain(args.iter().copied()))?;
    // `Box::pin` puts `run`'s future, which is large because it can hold
    // any command's state, on the heap instead of this function's stack.
    Box::pin(run(cli, ctx)).await
}

/// `path` as `&str`, which clap's argument list needs.
fn utf8(path: &Path) -> anyhow::Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not UTF-8", path.display()))
}

/// The pubky `ctx`'s install is logged in as, from its `login.json`.
fn logged_in(ctx: &Context) -> anyhow::Result<Pubky> {
    let login: Value = serde_json::from_slice(&fs::read(ctx.dirs.login_file())?)?;
    login["pubky"]
        .as_str()
        .context("login.json has no pubky")?
        .parse()
        .context("login.json's pubky")
}

/// `user`'s public file at `path`, read anonymously, as the board reads it,
/// chunk by chunk under the record cap.
async fn read_public(ctx: &Context, user: Pubky, path: &str) -> anyhow::Result<Vec<u8>> {
    let user = PublicKey::try_from_z32(&user.to_string())?;
    let mut response = ctx
        .network
        .pubky()
        .public_storage()
        .get((&user, path))
        .await?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        body.extend_from_slice(&chunk);
        ensure!(
            body.len() <= MAX_RECORD_BYTES,
            "a public record over the cap"
        );
    }
    Ok(body)
}

async fn read_bounty(ctx: &Context, bounty: BountyRef) -> anyhow::Result<Bounty> {
    let body = read_public(ctx, bounty.owner, &paths::bounty(bounty.id)).await?;
    Ok(Bounty::from_json(&body)?)
}

async fn read_sweep(ctx: &Context, sweep: SweepRef) -> anyhow::Result<Sweep> {
    let body = read_public(ctx, sweep.sweeper, &paths::sweep_record(sweep.id)).await?;
    Ok(Sweep::from_json(&body)?)
}

async fn read_discovered(ctx: &Context, bounty: BountyRef) -> anyhow::Result<Discovered> {
    let body = read_public(ctx, bounty.owner, &paths::discovered(bounty.id)).await?;
    Ok(Discovered::from_json(&body)?)
}

/// Whether `sweep`'s public record says `status`.
async fn sweep_is(
    ctx: &Context,
    sweep: SweepRef,
    status: KnownSweepStatus,
) -> anyhow::Result<bool> {
    Ok(read_sweep(ctx, sweep).await?.status.as_known() == Some(status))
}

/// Copies the tree `from` into `to`, plain files and directories only. A
/// symlink is skipped, never followed, so nothing outside the run
/// directory can be pulled in through one.
fn copy_tree(from: &Path, to: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        // `DirEntry::file_type` does not follow a symlink on Unix: a link
        // is reported as a link.
        let kind = entry.file_type()?;
        let (source, copy) = (entry.path(), to.join(entry.file_name()));
        if kind.is_dir() {
            copy_tree(&source, &copy)?;
        } else if kind.is_file() {
            fs::copy(&source, &copy)?;
        } else {
            eprintln!("warning: skipped an entry of the run directory that is not a plain file");
        }
    }
    Ok(())
}

/// The three identities, logged in, and the circle of owner and sweeper.
struct Identities {
    owner: Context,
    sweeper: Context,
    stranger: Context,
    sweeper_pubky: Pubky,
    stranger_pubky: Pubky,
}

/// Steps 2 and 3: three `login --identity`s, then the owner's circle with
/// the sweeper in it.
async fn log_in(testnet: &EphemeralTestnet, scratch: &Path) -> anyhow::Result<Identities> {
    let homes = scratch.join("homes");
    let owner = context(testnet, &homes.join("owner"))?;
    let sweeper = context(testnet, &homes.join("sweeper"))?;
    let stranger = context(testnet, &homes.join("stranger"))?;
    for (ctx, name) in [
        (&owner, "owner"),
        (&sweeper, "sweeper"),
        (&stranger, "stranger"),
    ] {
        sweepky(ctx, &["login", "--identity", name]).await?;
    }
    let sweeper_pubky = logged_in(&sweeper)?;
    sweepky(&owner, &["circle", "create", "Demo circle"]).await?;
    let member = sweeper_pubky.to_string();
    sweepky(&owner, &["circle", "add", &member, "--label", "Sweeper"]).await?;
    Ok(Identities {
        stranger_pubky: logged_in(&stranger)?,
        sweeper_pubky,
        owner,
        sweeper,
        stranger,
    })
}

/// Step 4: the owner posts the open bounty on `inputs.targets`, after a
/// yes. Returns the bounty's URL.
async fn post_bounty(
    owner: &mut Context,
    scratch: &Path,
    inputs: &Inputs,
) -> anyhow::Result<BountyRef> {
    let draft = scratch.join("bounty.json");
    let draft_json = json!({
        "title": "Demo bounty",
        "brief": "The bounty of Sweepky's local demo.\n",
        "targets": inputs.targets,
    });
    fs::write(&draft, serde_json::to_vec(&draft_json)?)?;
    answer_yes(owner);
    let report = sweepky(owner, &["post", utf8(&draft)?, "--open"]).await?;
    // The report's last line is the bounty's URL.
    let url = report
        .text()
        .lines()
        .last()
        .context("post printed no bounty URL")?;
    url.parse().context("post's last line is not a bounty URL")
}

/// `init`s `project` for `ctx` without the playbook (no agent runs in the
/// demo) and runs `bounty` there. Returns the new sweep.
async fn start_sweep(
    ctx: &mut Context,
    project: &Path,
    bounty: BountyRef,
) -> anyhow::Result<SweepRef> {
    sweepky(ctx, &["init", utf8(project)?, "--no-playbook"]).await?;
    // `run` and `submit` find the project from the working directory.
    ctx.cwd = project.to_path_buf();
    sweepky(ctx, &["run", &bounty.to_string()]).await?;
    let mut ids = fs::read_dir(project.join("sweeps"))?;
    let name = ids
        .next()
        .context("run made no sweep directory")??
        .file_name();
    ensure!(
        ids.next().is_none(),
        "run made more than one sweep directory"
    );
    let id: RecordId = name
        .to_str()
        .context("a sweep directory name that is not UTF-8")?
        .parse()?;
    Ok(SweepRef {
        sweeper: logged_in(ctx)?,
        id,
    })
}

/// `sweepky --no-input submit` of `sweep` with `playbook`: under
/// `--no-input` a question fails rather than waits.
async fn submit(ctx: &Context, sweep: SweepRef, playbook: &str) -> anyhow::Result<()> {
    let run_dir = format!("sweeps/{}", sweep.id);
    sweepky(
        ctx,
        &[
            "--no-input",
            "submit",
            "--run-dir",
            &run_dir,
            "--playbook",
            playbook,
        ],
    )
    .await?;
    Ok(())
}

/// The target `file` is in, and its path inside that target, by the rule
/// `pull --findings` links with: a sweep of one target holds its files as
/// written; a sweep of several holds each under `<tid>/`.
///
/// Written again here rather than shared: `pull::show` keeps its own
/// private, and a check that reused it could not catch a mistake in it.
// One lifetime `'a` on both inputs: the returned references borrow from
// `file` and from `targets`, so nothing is copied.
fn locate<'a>(
    file: &'a str,
    targets: &'a [Target],
    covered: &[TargetId],
) -> Option<(&'a Target, &'a str)> {
    let find = |id: &TargetId| targets.iter().find(|target| target.id() == id);
    if let [only] = covered {
        return Some((find(only)?, file));
    }
    covered.iter().find_map(|id| {
        let rest = file.strip_prefix(id.as_str())?.strip_prefix('/')?;
        Some((find(id)?, rest))
    })
}

/// The line `pull --findings` prints for `location` with its GitHub link
/// at the target's pinned commit, or `None` if no github.com target holds
/// it.
fn linked_line(location: &Location, targets: &[Target], covered: &[TargetId]) -> Option<String> {
    let (target, file) = locate(&location.file, targets, covered)?;
    let known = target.known().ok()??;
    let repo = match &known {
        KnownTarget::Pr(pr) => pr.repo(),
        KnownTarget::Commit(commit) => commit.repo(),
        KnownTarget::Repo(repo) => repo.repo(),
    };
    let (owner, name) = repo.as_str().strip_prefix("github.com/")?.split_once('/')?;
    let mut url = Url::parse("https://github.com/").ok()?;
    // `path_segments_mut` percent-encodes each segment it is given, as
    // `pull`'s own link builder does. The block ends the borrow of `url`.
    {
        let mut path = url.path_segments_mut().ok()?;
        path.pop_if_empty()
            .extend([owner, name, "blob", known.reviewed_commit().as_str()])
            .extend(file.split('/'));
    }
    let mut line = format!("  at {}", location.file);
    if let Some(number) = location.line {
        line.push_str(&format!(":{number}"));
        if number > 0 {
            url.set_fragment(Some(&format!("L{number}")));
        }
    }
    Some(format!("{line} {url}\n"))
}

/// Whether every location `findings` names is a file of the sweep's fetched
/// target, under `sweeps/<id>/target/<tid>/`, with at least as many lines
/// as the location's line: so each link `pull --findings` prints resolves.
fn targets_hold(
    findings: &Findings,
    sweep_dir: &Path,
    targets: &[Target],
    covered: &[TargetId],
) -> bool {
    let locations = findings
        .findings
        .iter()
        .flat_map(|finding| &finding.locations);
    // `all` on an empty list is true, so a run with no locations would
    // pass vacuously; the demo's run always has some.
    locations.into_iter().all(|location| {
        let Some((target, file)) = locate(&location.file, targets, covered) else {
            return false;
        };
        let copy = sweep_dir
            .join("target")
            .join(target.id().as_str())
            .join(file);
        let Ok(text) = fs::read_to_string(copy) else {
            return false;
        };
        let wanted = location.line.unwrap_or(0);
        u64::try_from(text.lines().count()).is_ok_and(|lines| lines >= wanted)
    })
}

/// Whether each target the bounty pins is at its input `ref` where that
/// ref is a full SHA, as the fixture's is: then the links are at the
/// commit the findings were written against.
fn pinned_as_asked(record: &Bounty, inputs: &Inputs) -> bool {
    let asked = inputs
        .targets
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    record.targets.len() == asked.len()
        && record.targets.iter().zip(asked).all(|(target, input)| {
            let Some(rev) = input["ref"].as_str().filter(|rev| rev.len() == 40) else {
                return true;
            };
            matches!(target.known(), Ok(Some(known)) if known.reviewed_commit().as_str() == rev)
        })
}

/// The stranger's `audit/`: `fixtures/demo/stranger-audit/`, with its one
/// finding moved to the locations of `shared`, the sweeper's first finding,
/// so the two group by place whatever the run directory holds. With the
/// fixtures this changes nothing: the fixture already shares that place.
fn stranger_audit(audit: &Path, shared: &[Location]) -> anyhow::Result<Findings> {
    copy_tree(&demo_fixture("stranger-audit"), audit)?;
    let mut findings =
        Findings::from_json(&fs::read(demo_fixture("stranger-audit/findings.json"))?)?;
    let finding = findings
        .findings
        .first_mut()
        .context("the stranger fixture has no finding")?;
    finding.locations = shared.to_vec();
    fs::write(
        audit.join("findings.json"),
        serde_json::to_vec_pretty(&findings)?,
    )?;
    Ok(findings)
}

/// The groups of `groups.json` whose `reportedBy` is exactly `reporters`.
fn groups_reported_by(groups: &Value, reporters: &BTreeSet<String>) -> usize {
    let groups = groups["groups"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    groups
        .iter()
        .filter(|group| {
            let by: Option<BTreeSet<String>> = group["reportedBy"].as_array().map(|by| {
                by.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            });
            by.as_ref() == Some(reporters)
        })
        .count()
}

/// Steps 2 to 8, recording each check in `checks`. An error ends the flow;
/// the checks recorded so far stay.
async fn demo(
    testnet: &EphemeralTestnet,
    scratch: &Path,
    inputs: &Inputs,
    checks: &mut Checks,
) -> anyhow::Result<()> {
    let mut ids = log_in(testnet, scratch).await?;
    let posted = post_step(&mut ids.owner, scratch, inputs, checks).await?;
    let circle = sweeper_step(&mut ids, scratch, inputs, &posted, checks).await?;
    let stranger = stranger_step(&mut ids, scratch, &posted, &circle, checks).await?;
    pull_step(&ids, &posted, &circle, &stranger, checks).await?;
    done_step(&mut ids, posted.bounty, stranger.sweep, checks).await
}

/// The open bounty: its URL and its public record as first posted.
struct Posted {
    bounty: BountyRef,
    record: Bounty,
}

/// Step 4: the owner posts the open bounty, which anyone can then read,
/// open, beside an empty `discovered.json`.
async fn post_step(
    owner: &mut Context,
    scratch: &Path,
    inputs: &Inputs,
    checks: &mut Checks,
) -> anyhow::Result<Posted> {
    let bounty = post_bounty(owner, scratch, inputs).await?;
    let record = read_bounty(owner, bounty).await?;
    checks.record(
        "the open bounty is public at its URL with status open",
        record.open && record.status().as_known() == Some(KnownBountyStatus::Open),
    );
    checks.record(
        "the bounty pins each target at the full SHA its input names",
        pinned_as_asked(&record, inputs),
    );
    checks.record(
        "post --open published the bounty's discovered.json with no sweep yet",
        read_discovered(owner, bounty).await?.sweeps.is_empty(),
    );
    Ok(Posted { bounty, record })
}

/// The circle sweeper's sweep: the findings of the run directory, as
/// `submit` converts them, and the targets the sweep covered.
struct CircleSweep {
    sweep: SweepRef,
    findings: Findings,
    covered: Vec<TargetId>,
}

/// Step 5: the sweeper runs the bounty, the run directory goes into
/// `audit/`, and `submit` finishes the sweep and moves `audit/` out.
async fn sweeper_step(
    ids: &mut Identities,
    scratch: &Path,
    inputs: &Inputs,
    posted: &Posted,
    checks: &mut Checks,
) -> anyhow::Result<CircleSweep> {
    let playbook: Playbook = SWEEPER_PLAYBOOK.parse()?;
    let run_findings = fs::read(inputs.run_dir.join("findings.json"))
        .context("the run directory has no findings.json")?;
    let (findings, _) = parse_audit_findings(&run_findings, &playbook)?;
    let project = scratch.join("sweeper-project");
    let sweep = start_sweep(&mut ids.sweeper, &project, posted.bounty).await?;
    checks.record(
        "the sweeper's sweep record reads running after run",
        sweep_is(&ids.owner, sweep, KnownSweepStatus::Running).await?,
    );
    let sweep_dir = project.join("sweeps").join(sweep.id.to_string());
    let covered = read_sweep(&ids.owner, sweep).await?.targets;
    checks.record(
        "every file a sweeper location names was fetched with at least that many lines",
        targets_hold(&findings, &sweep_dir, &posted.record.targets, &covered),
    );
    copy_tree(&inputs.run_dir, &sweep_dir.join("audit"))?;
    submit(&ids.sweeper, sweep, SWEEPER_PLAYBOOK).await?;
    checks.record(
        "the sweeper's sweep record reads done after submit",
        sweep_is(&ids.owner, sweep, KnownSweepStatus::Done).await?,
    );
    let submitted = ids
        .sweeper
        .dirs
        .data()
        .join("submitted")
        .join(sweep.id.to_string());
    checks.record(
        "submit moved audit/ out of the project into the sweeper's data directory",
        !sweep_dir.join("audit").exists() && submitted.join("audit").is_dir(),
    );
    Ok(CircleSweep {
        sweep,
        findings,
        covered,
    })
}

/// The stranger's sweep and its synthetic findings.
struct StrangerSweep {
    sweep: SweepRef,
    findings: Findings,
}

/// Step 6: the stranger runs the bounty and submits a synthetic `audit/`
/// whose one finding shares the place of the sweeper's first finding under
/// another id.
async fn stranger_step(
    ids: &mut Identities,
    scratch: &Path,
    posted: &Posted,
    circle: &CircleSweep,
    checks: &mut Checks,
) -> anyhow::Result<StrangerSweep> {
    let shared = circle
        .findings
        .findings
        .first()
        .context("the run directory's findings.json has no finding")?;
    let project = scratch.join("stranger-project");
    let sweep = start_sweep(&mut ids.stranger, &project, posted.bounty).await?;
    checks.record(
        "the stranger's sweep record reads running after run",
        sweep_is(&ids.owner, sweep, KnownSweepStatus::Running).await?,
    );
    let audit = project
        .join("sweeps")
        .join(sweep.id.to_string())
        .join("audit");
    let findings = stranger_audit(&audit, &shared.locations)?;
    ensure!(
        findings
            .findings
            .iter()
            .all(|finding| finding.id != shared.id),
        "the stranger's finding must have another id than the sweeper's"
    );
    submit(&ids.stranger, sweep, STRANGER_PLAYBOOK).await?;
    checks.record(
        "the stranger's sweep record reads done after submit",
        sweep_is(&ids.owner, sweep, KnownSweepStatus::Done).await?,
    );
    Ok(StrangerSweep { sweep, findings })
}

/// Step 7: the owner's `pull --findings`, its report and what it leaves on
/// disk and in `discovered.json`.
async fn pull_step(
    ids: &Identities,
    posted: &Posted,
    circle: &CircleSweep,
    stranger: &StrangerSweep,
    checks: &mut Checks,
) -> anyhow::Result<()> {
    let report = sweepky(&ids.owner, &["pull", "--findings"]).await?;
    let text = report.text();
    checks.record(
        "the pull report labels the sweeper's sweep circle",
        text.contains(&format!("  {}: circle; ", circle.sweep)),
    );
    checks.record(
        "the pull report labels the stranger's sweep unknown",
        text.contains(&format!("  {}: unknown; ", stranger.sweep)),
    );
    check_findings_printed(text, posted, circle, stranger, checks);
    checks.record(
        "discovered.json lists the stranger's sweep after the owner's pull",
        read_discovered(&ids.owner, posted.bounty)
            .await?
            .sweeps
            .contains(&stranger.sweep),
    );
    let bounty_dir = ids.owner.dirs.data().join(posted.bounty.id.to_string());
    let untrusted = bounty_dir
        .join("untrusted")
        .join(format!("{}-{}", stranger.sweep.sweeper, stranger.sweep.id));
    checks.record(
        "the stranger's sweep is stored under untrusted/",
        untrusted.join("findings.json").is_file(),
    );
    let groups: Value = serde_json::from_slice(&fs::read(bounty_dir.join("groups.json"))?)?;
    checks.record(
        "groups.json has one group reported by the sweeper and the stranger",
        groups_reported_by(&groups, &both(ids)) == 1,
    );
    Ok(())
}

/// The Done-when 1 checks on `pull --findings`' `text`: every finding of
/// the run directory printed, each location linked at the pinned commit,
/// and nothing of the stranger's findings anywhere.
fn check_findings_printed(
    text: &str,
    posted: &Posted,
    circle: &CircleSweep,
    stranger: &StrangerSweep,
    checks: &mut Checks,
) {
    // `find` gives `None` when the heading is missing; then nothing is
    // searched and the finding checks fail.
    let printed = text.find(FINDINGS_HEADING).map_or("", |at| &text[at..]);
    let findings = &circle.findings.findings;
    checks.record(
        "pull --findings prints the title of every finding of the run directory",
        findings
            .iter()
            .all(|finding| printed.contains(&format!("  title: {}\n", finding.title))),
    );
    checks.record(
        "pull --findings links every location of the run directory at the pinned commit",
        findings
            .iter()
            .flat_map(|finding| &finding.locations)
            .all(|location| {
                linked_line(location, &posted.record.targets, &circle.covered)
                    .is_some_and(|line| printed.contains(&line))
            }),
    );
    checks.record(
        "pull --findings prints none of the stranger's finding text",
        stranger.findings.findings.iter().all(|finding| {
            !text.contains(finding.title.as_str())
                && !text.contains(&finding.description)
                && finding.fix.as_deref().is_none_or(|fix| !text.contains(fix))
        }),
    );
}

/// Step 8: `done` after a yes credits exactly the sweeper and the
/// stranger, and the next pull labels the stranger `known: 1`.
async fn done_step(
    ids: &mut Identities,
    bounty: BountyRef,
    stranger_sweep: SweepRef,
    checks: &mut Checks,
) -> anyhow::Result<()> {
    answer_yes(&mut ids.owner);
    sweepky(&ids.owner, &["done", &bounty.to_string()]).await?;
    let record = read_bounty(&ids.owner, bounty).await?;
    let credits: BTreeSet<String> = record.credits().iter().map(ToString::to_string).collect();
    checks.record(
        "the bounty is done, crediting exactly the sweeper and the stranger",
        record.status().as_known() == Some(KnownBountyStatus::Done) && credits == both(ids),
    );
    let report = sweepky(&ids.owner, &["pull"]).await?;
    checks.record(
        "the next pull labels the stranger's sweep known: 1",
        report
            .text()
            .contains(&format!("  {stranger_sweep}: known: 1 ")),
    );
    Ok(())
}

/// The sweeper's and the stranger's pubkys, as text: the `reportedBy` of
/// their shared group and the credits `done` writes. A set, so the order
/// either is written in does not matter.
fn both(ids: &Identities) -> BTreeSet<String> {
    [ids.sweeper_pubky, ids.stranger_pubky]
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// Writes `value` to `path` whole: to a temporary name first, then renamed,
/// so a script polling for `path` never reads half a file.
fn write_json(path: &Path, value: &Value) -> anyhow::Result<()> {
    let partial = path.with_extension("partial");
    fs::write(&partial, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&partial, path)?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let mut args = std::env::args_os().skip(1);
    let (Some(scratch), None) = (args.next(), args.next()) else {
        bail!("usage: demo_check <scratch dir>");
    };
    let scratch = checked_scratch(Path::new(&scratch))?;
    let inputs = Inputs::from_env()?;

    let testnet = EphemeralTestnet::builder()
        .with_http_relay()
        .build()
        .await
        .context("could not start the ephemeral testnet")?;
    let mut checks = Checks::default();
    let outcome = demo(&testnet, &scratch, &inputs, &mut checks).await;
    // The testnet registers its test databases for dropping only once it
    // is dropped itself, so drop it first, explicitly, then drop them: only
    // the ones this process made. This runs on success and on failure
    // alike, after a wait, because at 0.16.2 the homeserver's tasks can
    // still hold a database for a moment after the drop.
    drop(testnet);
    tokio::time::sleep(DATABASE_RELEASE).await;
    pubky_testnet::drop_test_databases().await;

    if let Err(error) = &outcome {
        eprintln!("error: {error:#}");
    }
    checks.record("the demo flow ran to its end", outcome.is_ok());
    write_json(
        &scratch.join("results.json"),
        &checks.to_json(inputs.source),
    )?;
    Ok(if checks.all_passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
