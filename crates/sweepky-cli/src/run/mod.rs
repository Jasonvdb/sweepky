//! `run`, the terminal command a sweeper runs before the agent: so far its
//! checking half, which reads and decides and writes nothing.
//!
//! - [`require_project`]: `run` must be run inside an `init` project, in
//!   the directory that holds its `.sweepky` marker, which `init`'s own
//!   reader reads (`init::read_project_marker`) and hands back with the
//!   playbook P3's `init` will record in it.
//! - [`parse_bounty_url`]: the bounty argument, a bounty record's
//!   `pubky://` URL as `post` prints it. Anything else is refused in fixed
//!   text that never quotes it: a sweep's URL, a web address, a malformed
//!   URL, and a pasted key, which `login`'s classifier
//!   (`identity::refuse_secret_material`) recognises.
//! - [`check_bounty`]: reads the bounty from its owner's storage and, when
//!   one decides, the circle it is checked against, through
//!   [`PublicRecords`]; then `select` decides whether this sweeper may run
//!   it and which targets it sweeps.
//! - [`CheckedBounty::summary`]: what `run` shows of the bounty: its URL,
//!   its title and focus through the terminal sanitiser, why it may be run,
//!   and each target with the commit it reviews. Never the brief, which the
//!   agent reads from a file.
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
//! must be in that circle. Picking a bounty without a URL, a later step,
//! picks from this install's own circle by default.

// `run` is not wired to the command line until the step after this one, so
// outside the tests everything here is dead code. `expect` (not `allow`)
// silences that warning only while it is true, and that step removes it.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the run command, later in P2b, is the first caller"
    )
)]

mod select;

use std::path::Path;

use anyhow::{Context as _, bail};
use sweepky_core::{Bounty, BountyRef, KnownTarget, Pubky, PubkyUrl, RepoName, SweepRef, TargetId};

use self::select::{Acceptance, ChosenTarget, ChosenTargets};
use crate::display::sanitize;
use crate::identity::refuse_secret_material;
use crate::init::{ProjectMarker, read_project_marker};
use crate::post::draft::{MAX_FOCUS_CHARS, MAX_TITLE_CHARS};
use crate::records::PublicRecords;
use crate::remote::public_key_of;
use crate::targets::TargetResolver;

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
/// flags that narrow it.
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
    use std::os::unix::fs::symlink;

    use pubky::Keypair;
    use serde_json::{Value, json};
    use sweepky_core::paths;
    use sweepky_core::{BountyRef, Pubky};

    use super::select::Acceptance;
    use super::{RunRequest, check_bounty, parse_bounty_url, require_project};
    use crate::identity::Refusal;
    use crate::init::{self, MARKER};
    use crate::targets::TargetSource;
    use crate::test_support::{
        FakePublicRecords, PLANTED, bounty_id, bounty_json, circle_json, json_bytes, random_pubky,
        repo_target_json,
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
}
