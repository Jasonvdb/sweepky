//! The fixture `scripts/check-sandbox.sh` runs P3's Done-when checks on: a
//! local testnet, an owner and a sweeper made on it at run time, a closed
//! bounty on the fixture repository, and the sweeper's `init` project with
//! two sweeps of that bounty placed by `run`, each with the repository's
//! planted agent files stripped.
//!
//! ```text
//! sandbox_fixture <scratch dir> [--ephemeral]
//! ```
//!
//! Every command goes through the library's `run`, as the binary runs it,
//! with a `Context` per identity. The testnet is `StaticTestnet` on the
//! fixed local ports, the ones the binary's `--testnet` client
//! (`Pubky::testnet()`) talks to, so the script can run the real binary's
//! `submit` against it. `--ephemeral` starts an `EphemeralTestnet` on random
//! ports instead, for a machine where something else holds the fixed ports;
//! the binary cannot reach that one, so the script then asks this process
//! to run `submit` through the library (a `submit …` line on standard
//! input, below). Either way nothing leaves this machine: the targets come
//! from `fixtures/target-repo.git` through the fixture source, and the
//! homeserver is the testnet's.
//!
//! When the sweeps are placed it writes `<scratch>/ready.json`: the project,
//! the two sweep ids, both `SWEEPKY_HOME`s, which testnet it runs and
//! whether the playbook was installed. Then it reads standard input line by
//! line. `submit <args>` runs the sweeper's `sweepky --no-input submit
//! <args>` in the project and writes `<scratch>/submit-<n>.out`, `ok` or
//! `error` on the first line and the report or the error below. When
//! standard input closes, it writes `<scratch>/final.json`, each sweep's
//! public record status and whether its package is on the homeserver, as
//! anyone reads them, stops the testnet and drops the test databases it
//! made.
//!
//! The testnet's homeserver needs Postgres through
//! `TEST_PUBKY_CONNECTION_STRING`. Nothing here is a secret worth keeping:
//! the identities and device keys are made at run time, under the scratch
//! directory the script deletes.

use std::fs;
use std::io::{self, BufRead, Cursor};
use std::path::{Path, PathBuf};

// `as _` brings `.context(...)` into scope without the name `Context`,
// which is the library's type here.
use anyhow::{Context as _, bail, ensure};
use clap::Parser;
use pubky::PublicKey;
use pubky_testnet::{EphemeralTestnet, StaticTestnet};
use serde_json::{Map, Value, json};
use sweepky_cli::{
    Browser, Cli, Context, Dirs, FixtureTargets, GitEnv, Network, Report, StderrWriter,
    StdinReader, TargetSource, run,
};
use sweepky_core::{MAX_RECORD_BYTES, Pubky, RecordId, RepoName, Sweep, paths};

/// The synthetic name the fixture source serves `fixtures/target-repo.git`
/// under, the same as `tests/end_to_end.rs`: a host under
/// `example.invalid`, which no resolver answers.
const FIXTURE_REPO: &str = "example.invalid/sweepky/target-repo";

/// How long the stopped testnet's tasks get to let go of their databases
/// before they are dropped.
const DATABASE_RELEASE: std::time::Duration = std::time::Duration::from_secs(3);

/// The testnet this process runs. An enum rather than a trait object:
/// there are exactly two kinds, and the value only has to stay alive (its
/// `Drop` stops the servers) and say how to reach it.
enum Testnet {
    /// The fixed ports, which `sweepky --testnet` reaches. Nothing reads
    /// the value: contexts build their own client for those ports, as the
    /// binary does. It is held only so that dropping it stops the servers,
    /// and `expect` (rather than `allow`) fails the build if it is ever read.
    Static(#[expect(dead_code, reason = "held for its Drop")] StaticTestnet),
    /// Random ports, reached only through the client it hands out.
    Ephemeral(EphemeralTestnet),
}

impl Testnet {
    async fn start(ephemeral: bool) -> anyhow::Result<Self> {
        Ok(if ephemeral {
            Self::Ephemeral(
                EphemeralTestnet::builder()
                    .with_http_relay()
                    .build()
                    .await
                    .context("could not start the ephemeral testnet")?,
            )
        } else {
            Self::Static(StaticTestnet::start().await.context(
                "could not start the static testnet; is something else holding its fixed ports?",
            )?)
        })
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Static(_) => "static",
            Self::Ephemeral(_) => "ephemeral",
        }
    }

    /// The network a context uses. On the static testnet it is exactly the
    /// binary's `--testnet` network, so what works here works for the
    /// binary; on the ephemeral one, its client, relay and homeserver
    /// injected, as the end-to-end test does.
    fn network(&self) -> anyhow::Result<Network> {
        match self {
            Self::Static(_) => Network::testnet(),
            Self::Ephemeral(testnet) => Ok(Network::injected(
                testnet.sdk()?,
                // `local_url()` ends with `/`, so this is `…/inbox`.
                format!("{}inbox", testnet.http_relay().local_url()),
                testnet.homeserver_app().public_key(),
            )),
        }
    }
}

/// One identity's context: `home` as its `SWEEPKY_HOME` and first working
/// directory, `answers` as its standard input, the fixture repository as
/// its only target source, and no browser.
fn context(testnet: &Testnet, home: &Path, answers: &'static [u8]) -> anyhow::Result<Context> {
    let repo: RepoName = FIXTURE_REPO.parse()?;
    // `env!` reads `CARGO_MANIFEST_DIR` when the example is compiled, so
    // this finds the fixture wherever the repository is checked out.
    let fixture = fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/target-repo.git"),
    )
    .context("the fixture repository")?;
    Ok(Context {
        network: testnet.network()?,
        dirs: Dirs::resolve(None, Some(home.as_os_str()))?,
        cwd: home.to_path_buf(),
        stdin: StdinReader::new(Cursor::new(answers)),
        stderr: StderrWriter::new(io::stderr()),
        passphrase: None,
        // git sees this process's PATH and nothing else: the fixture is a
        // local repository, so no proxy or CA variable is needed.
        git_env: GitEnv::capture(|name| {
            if name == "PATH" {
                std::env::var_os(name)
            } else {
                None
            }
        }),
        targets: TargetSource::Fixture(FixtureTargets::new([(repo, fixture)])),
        browser: Browser::None,
    })
}

/// Runs `sweepky <args>` against `ctx`.
async fn sweepky(ctx: &Context, args: &[&str]) -> anyhow::Result<Report> {
    let cli = Cli::try_parse_from(std::iter::once("sweepky").chain(args.iter().copied()))?;
    // `Box::pin` puts `run`'s future, which is large because it can hold
    // any command's state, on the heap instead of this function's stack.
    Box::pin(run(cli, ctx)).await
}

/// `path` as `&str`, which clap's argument list needs. The scratch
/// directory the script makes is UTF-8, so this fails only on a bug.
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

/// The ids of the sweep directories in the project's `sweeps/`.
fn sweep_ids(sweeps: &Path) -> anyhow::Result<Vec<RecordId>> {
    let entries = match fs::read_dir(sweeps) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        entries => entries?,
    };
    entries
        .map(|entry| {
            let name = entry?.file_name();
            name.to_str()
                .context("a sweep directory name that is not UTF-8")?
                .parse()
                .context("a sweep directory name that is not a record id")
        })
        .collect()
}

/// The two identities and the project, set up as P3's checks need them.
struct Fixture {
    sweeper: Context,
    /// The sweeper's `SWEEPKY_HOME`, which `submit` from a terminal needs.
    sweeper_home: PathBuf,
    project: PathBuf,
    sweeps: [RecordId; 2],
    playbook_installed: bool,
}

/// Logs in an owner and a sweeper, posts a closed bounty on the fixture
/// repository to a circle of the two, and has the sweeper `init` a project
/// and `run` the bounty twice.
async fn set_up(testnet: &Testnet, scratch: &Path) -> anyhow::Result<Fixture> {
    let homes = scratch.join("homes");
    // The owner answers `post`'s one question with yes; the sweeper is
    // asked nothing.
    let owner = context(testnet, &homes.join("owner"), b"y\n")?;
    let sweeper_home = homes.join("sweeper");
    let mut sweeper = context(testnet, &sweeper_home, b"")?;

    sweepky(&owner, &["login", "--identity", "owner"]).await?;
    sweepky(&owner, &["circle", "create", "Sandbox check circle"]).await?;
    sweepky(&sweeper, &["login", "--identity", "sweeper"]).await?;
    let sweeper_pubky = logged_in(&sweeper)?.to_string();
    sweepky(&owner, &["circle", "add", &sweeper_pubky, "--label", "S"]).await?;

    let bounty = post_bounty(&owner, scratch).await?;
    let project = scratch.join("project");
    let playbook_installed = init_project(&sweeper, &project).await?;

    // `run` must run in the project's own directory. Two runs of one
    // bounty give two sweeps, each with its own id and snapshot.
    sweeper.cwd = project.clone();
    let sweeps_dir = project.join("sweeps");
    for _ in 0..2 {
        sweepky(&sweeper, &["run", &bounty]).await?;
    }
    let ids = sweep_ids(&sweeps_dir)?;
    // A slice pattern takes the vector apart only when it holds exactly
    // two ids; anything else is an error rather than a panic.
    let [first, second] = ids.as_slice() else {
        bail!("expected two sweep directories, found {}", ids.len());
    };
    Ok(Fixture {
        sweeps: [*first, *second],
        sweeper,
        sweeper_home,
        project,
        playbook_installed,
    })
}

/// Has `owner` post a closed bounty with one `repo` target, the whole
/// fixture repository at `main`, so the copy holds every planted agent
/// file, the nested `src/auth/CLAUDE.md` included. Returns its URL.
async fn post_bounty(owner: &Context, scratch: &Path) -> anyhow::Result<String> {
    let draft = scratch.join("bounty.json");
    let draft_json = json!({
        "title": "Sandbox check bounty",
        "brief": "A synthetic bounty for the sandbox check.\n",
        "targets": [{ "kind": "repo", "repo": FIXTURE_REPO, "ref": "main" }],
    });
    fs::write(&draft, serde_json::to_vec(&draft_json)?)?;
    let report = sweepky(owner, &["post", utf8(&draft)?]).await?;
    // The report's last line is the bounty's URL.
    let url = report.text().lines().last();
    Ok(url.context("post printed no bounty URL")?.to_owned())
}

/// Has `sweeper` `init` `project` with the playbook installed through the
/// real npx, as a sweeper would. If npm cannot be reached the install fails
/// and leaves no marker; a second `init` keeps the files the first one
/// wrote and finishes without the playbook, and the script reports that
/// check as not done. Returns whether the playbook was installed.
async fn init_project(sweeper: &Context, project: &Path) -> anyhow::Result<bool> {
    let dir = utf8(project)?;
    match sweepky(sweeper, &["init", dir, "--install-playbook"]).await {
        Ok(_) => Ok(true),
        Err(error) => {
            eprintln!("warning: the playbook install failed ({error:#}); going on without it");
            sweepky(sweeper, &["init", dir, "--no-playbook"]).await?;
            Ok(false)
        }
    }
}

/// Writes `value` to `path` whole: to a temporary name first, then renamed,
/// so the script, which polls for `path`, never reads half a file.
fn write_json(path: &Path, value: &Value) -> anyhow::Result<()> {
    let partial = path.with_extension("partial");
    fs::write(&partial, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&partial, path)?;
    Ok(())
}

/// Runs the sweeper's `sweepky --no-input submit <args>` in the project and
/// writes the outcome to `out`. `--no-input` makes a question fail rather
/// than wait on a standard input the script is still holding.
async fn submit(fixture: &Fixture, args: &str, out: &Path) -> anyhow::Result<()> {
    let mut argv = vec!["--no-input", "submit"];
    argv.extend(args.split_whitespace());
    let text = match sweepky(&fixture.sweeper, &argv).await {
        Ok(report) => format!("ok\n{}", report.text()),
        Err(error) => format!("error\n{error:#}\n"),
    };
    fs::write(out, text)?;
    Ok(())
}

/// What anyone can read of the sweeper's sweep `id`: its record's status,
/// and whether its package is there.
async fn public_state(fixture: &Fixture, user: &PublicKey, id: RecordId) -> anyhow::Result<Value> {
    let storage = fixture.sweeper.network.pubky().public_storage();
    let mut response = storage
        .get((user, paths::sweep_record(id).as_str()))
        .await?;
    // Read chunk by chunk under the record cap, as the CLI reads one, so
    // even a wrong answer cannot make this process hold more than that.
    let mut record = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        record.extend_from_slice(&chunk);
        ensure!(
            record.len() <= MAX_RECORD_BYTES,
            "sweep record {id}: over the cap"
        );
    }
    let sweep = Sweep::from_json(&record)?;
    let package = storage
        .exists((user, paths::sweep_package(id).as_str()))
        .await?;
    Ok(json!({ "status": sweep.status.as_str(), "package": package }))
}

/// Each sweep's [`public_state`], keyed by its id.
async fn final_state(fixture: &Fixture) -> anyhow::Result<Value> {
    let user = PublicKey::try_from_z32(&logged_in(&fixture.sweeper)?.to_string())?;
    let mut sweeps = Map::new();
    for id in fixture.sweeps {
        sweeps.insert(id.to_string(), public_state(fixture, &user, id).await?);
    }
    Ok(json!({ "sweeps": sweeps }))
}

/// Sets up, writes `ready.json`, answers `submit` lines until standard
/// input closes, then writes `final.json`.
async fn serve(testnet: &Testnet, scratch: &Path) -> anyhow::Result<()> {
    let fixture = set_up(testnet, scratch).await?;
    write_json(
        &scratch.join("ready.json"),
        &json!({
            "testnet": testnet.label(),
            "project": utf8(&fixture.project)?,
            "sweeps": fixture.sweeps.map(|id| id.to_string()),
            "sweeperHome": utf8(&fixture.sweeper_home)?,
            "playbookInstalled": fixture.playbook_installed,
        }),
    )?;

    // Standard input is read on a plain thread of its own, because a
    // blocking read must not sit on one of tokio's worker threads. Lines
    // come over a channel; when standard input closes, the thread ends,
    // its sender is dropped, and `recv` returns `None`.
    let (lines, mut received) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            // A read error ends the input, as end of file does.
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut count = 0_u32;
    while let Some(line) = received.recv().await {
        let Some(args) = line.strip_prefix("submit ") else {
            eprintln!("warning: ignored a line that is not `submit <args>`");
            continue;
        };
        count += 1;
        submit(&fixture, args, &scratch.join(format!("submit-{count}.out"))).await?;
    }
    write_json(&scratch.join("final.json"), &final_state(&fixture).await?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let scratch = PathBuf::from(
        args.next()
            .context("usage: sandbox_fixture <scratch dir> [--ephemeral]")?,
    );
    let ephemeral = match args.next() {
        None => false,
        Some(flag) if flag == "--ephemeral" => true,
        Some(_) => bail!("usage: sandbox_fixture <scratch dir> [--ephemeral]"),
    };
    ensure!(
        scratch.is_absolute(),
        "the scratch directory must be an absolute path"
    );

    let testnet = Testnet::start(ephemeral).await?;
    let outcome = serve(&testnet, &scratch).await;
    // The testnet registers its test databases for dropping only once it
    // is dropped itself, so drop it first, explicitly, then drop them.
    // This runs on success and on failure alike. At 0.16.2 the homeserver's
    // tasks can still hold the database for a moment after the drop, and a
    // drop then misses it (06's local-environment notes), so wait first.
    drop(testnet);
    tokio::time::sleep(DATABASE_RELEASE).await;
    pubky_testnet::drop_test_databases().await;
    outcome
}
