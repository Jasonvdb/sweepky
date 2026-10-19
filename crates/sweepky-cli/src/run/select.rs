//! Which bounty `run` may sweep and which of its targets, decided from the
//! records alone: no network and no disk, so each rule is tested on its own.
//!
//! - [`accept`]: whether this sweeper may run the bounty. Its `status` must
//!   be `open`. Then, with no `--circle`, an `open: true` bounty is accepted
//!   from anyone, and a closed one only when its owner's own `circle.json`,
//!   the roster that owner's `pull` reads closed-bounty sweeps from, lists
//!   the sweeper. With `--circle <admin>`, that circle is the one checked,
//!   for every bounty, and both the owner and the sweeper must be in it.
//!   [`circle_to_read`] says which circle that is, so the caller reads it
//!   first. Membership is `Circle::is_in_roster`'s: the admin or a member,
//!   compared by key bytes.
//! - [`choose_targets`]: the targets `run` sweeps, each checked into core's
//!   `KnownTarget` and through the target source's policy: every one this
//!   build can sweep, or the one `--target` names.
//!
//! Every refusal is fixed text. The only record text it names is a target
//! id, which core holds to ASCII letters, digits, `-` and `_`; it never
//! quotes an argument, a status, a kind or any other field a stranger
//! wrote.

use std::collections::HashMap;

use anyhow::{Context as _, anyhow, bail};
use sweepky_core::{
    Bounty, Circle, KnownBountyStatus, KnownTarget, KnownTargetKind, Pubky, RepoName, Target,
    TargetId,
};

use super::RunRequest;
use crate::post::draft::MAX_TARGETS;
use crate::targets::TargetResolver;

/// Why this sweeper may run a bounty, as [`accept`] found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Acceptance {
    /// `open: true`, and no `--circle`: its owner reads sweeps from anyone,
    /// labelled untrusted.
    Open,
    /// Closed, and the sweeper is in its owner's own circle.
    OwnersCircle,
    /// `--circle` was given, and the owner and the sweeper are both in that
    /// circle.
    NamedCircle,
}

/// The pubky whose `circle.json` the bounty is checked against: the one
/// `--circle` names, else, for a closed bounty, its owner. `None` for an
/// open bounty with no `--circle`, which no circle decides.
pub(crate) fn circle_to_read(request: &RunRequest<'_>, bounty: &Bounty) -> Option<Pubky> {
    match request.circle {
        Some(admin) => Some(admin),
        None if bounty.open => None,
        None => Some(request.bounty.owner),
    }
}

/// What a closed bounty's refusals say first, outside `--circle`.
const CLOSED_BOUNTY: &str = "this bounty is closed: its owner reads sweeps only from their circle";

/// What the refusals under `--circle` call the circle checked. They never
/// name the key the flag was given.
const NAMED_CIRCLE: &str = "the circle --circle names";

/// Whether the sweeper `request` names may run `bounty`, given `circle`,
/// the `circle.json` read from [`circle_to_read`]'s pubky (`None` when its
/// storage holds none, or when none was read).
pub(crate) fn accept(
    request: &RunRequest<'_>,
    bounty: &Bounty,
    circle: Option<&Circle>,
) -> anyhow::Result<Acceptance> {
    require_open_status(bounty)?;
    // `let ... else`: bind the holder, or leave with `Open` when no circle
    // decides.
    let Some(holder) = circle_to_read(request, bounty) else {
        return Ok(Acceptance::Open);
    };
    if request.circle.is_some() {
        let roster = roster_of(holder, circle)
            .with_context(|| format!("{NAMED_CIRCLE} cannot be checked"))?;
        if !roster.is_in_roster(request.bounty.owner) {
            bail!("the bounty's owner is not in {NAMED_CIRCLE}");
        }
        if !roster.is_in_roster(request.sweeper) {
            bail!("you are not in {NAMED_CIRCLE}");
        }
        Ok(Acceptance::NamedCircle)
    } else {
        // The owner admins this roster, so `is_in_roster` holds for them.
        let roster = roster_of(holder, circle).context(CLOSED_BOUNTY)?;
        if !roster.is_in_roster(request.sweeper) {
            bail!(
                "{CLOSED_BOUNTY}, and you are not in it; its owner can add you with `sweepky circle add \
                 <your pubky>`"
            );
        }
        Ok(Acceptance::OwnersCircle)
    }
}

/// Refuses a bounty whose `status` is anything but `open`. An unknown status
/// is a stranger's text, so it is not printed.
fn require_open_status(bounty: &Bounty) -> anyhow::Result<()> {
    match bounty.status().as_known() {
        Some(KnownBountyStatus::Open) => Ok(()),
        Some(KnownBountyStatus::Done) => {
            bail!("this bounty is done: its owner has finished with it and reads no more sweeps")
        }
        None => {
            bail!("this bounty has a status this build does not know, so run does not sweep it")
        }
    }
}

/// `circle`, the `circle.json` read from `holder`'s storage, as `holder`'s
/// roster. Refused when there is none, and when it names another admin:
/// anyone can put any file in their own storage, so a roster counts only
/// in its admin's.
// One input reference, so the returned `&Circle` borrows from `circle`
// (lifetime elision): the caller keeps the record and gets a view of it.
fn roster_of(holder: Pubky, circle: Option<&Circle>) -> anyhow::Result<&Circle> {
    let circle = circle.ok_or_else(|| anyhow!("there is no circle.json in its storage"))?;
    // `Pubky`'s `==` compares the 32 key bytes, never a spelling. Not
    // constant-time, and it need not be: both are public keys.
    if circle.admin != holder {
        bail!("the circle.json in its storage names another admin, so it is not that key's roster");
    }
    Ok(circle)
}

/// The targets `run` sweeps, and a warning for each one it skips.
#[derive(Debug)]
pub(crate) struct ChosenTargets {
    /// In the bounty's order, at least one and at most [`MAX_TARGETS`].
    pub(crate) targets: Vec<ChosenTarget>,
    /// One line for each target skipped, naming it by its id alone.
    pub(crate) warnings: Vec<String>,
}

/// One target `run` sweeps: its id and its checked view, from which the
/// fetch and `scope.json` are built, never from the raw record.
#[derive(Debug)]
pub(crate) struct ChosenTarget {
    /// The target's id, its directory under `target/`.
    pub(crate) id: TargetId,
    /// What core's `Target::known` checked it into.
    pub(crate) target: KnownTarget,
}

/// The targets of `bounty` that `run` sweeps: the one `target`, the
/// `--target` flag as typed, names, or else every target `source` can
/// sweep, each checked into a [`ChosenTarget`].
///
/// - A bounty two of whose ids differ only in case is refused whole.
/// - With `--target`: an id that is not a target id, is not the bounty's,
///   names a target of an unknown kind or a malformed one, or one the
///   source's policy refuses, is refused.
/// - Without it: a target of an unknown kind, or a malformed one, is
///   skipped with a warning (01: skip what you cannot read, never reject
///   the whole record for it), but one the policy refuses fails the run,
///   since the owner asked for it and this build will not sweep it. No
///   usable target, or more than [`MAX_TARGETS`], is refused.
pub(crate) fn choose_targets(
    bounty: &Bounty,
    target: Option<&str>,
    source: &impl TargetResolver,
) -> anyhow::Result<ChosenTargets> {
    refuse_case_collisions(&bounty.targets)?;
    match target {
        Some(flag) => Ok(ChosenTargets {
            targets: vec![named_target(&bounty.targets, flag, source)?],
            warnings: Vec::new(),
        }),
        None => every_target(&bounty.targets, source),
    }
}

/// Refuses targets two of whose ids differ only in case, as `t1` and `T1`
/// do: on a filesystem that ignores case, macOS's default, they would share
/// one directory under `target/`. Every target counts, of a known kind or
/// not, whichever one `--target` names.
fn refuse_case_collisions(targets: &[Target]) -> anyhow::Result<()> {
    // Keyed by the id in lower case, the equivalence
    // `TargetId::eq_ignore_ascii_case` tests: one pass, however many
    // targets a stranger's bounty holds, rather than comparing every pair.
    let mut seen: HashMap<String, &TargetId> = HashMap::with_capacity(targets.len());
    for target in targets {
        let id = target.id();
        // `insert` hands back the value it replaced: an earlier id with the
        // same lower-case form.
        if let Some(earlier) = seen.insert(id.as_str().to_ascii_lowercase(), id) {
            bail!(
                "the bounty's targets {earlier} and {id} differ only in case, so they would \
                 share one directory on a filesystem that ignores case; run refuses the whole \
                 bounty"
            );
        }
    }
    Ok(())
}

/// The target `flag`, the `--target` argument, names. No message quotes it.
fn named_target(
    targets: &[Target],
    flag: &str,
    source: &impl TargetResolver,
) -> anyhow::Result<ChosenTarget> {
    let id: TargetId = flag.parse().context(
        "--target takes a target id: 1 to 32 characters of A-Z, a-z, 0-9, '-' and '_', the \
         first a letter or digit",
    )?;
    let target = targets
        .iter()
        .find(|target| *target.id() == id)
        .ok_or_else(|| anyhow!("the bounty has no target with the id --target gives"))?;
    let known = match target.known() {
        Ok(Some(known)) => known,
        Ok(None) => bail!(
            "the target --target names is of a kind this build does not know, so run cannot \
             sweep it"
        ),
        // Core's `TargetError` names the field and the rule, never the value.
        Err(fault) => {
            return Err(
                anyhow::Error::new(fault).context("the target --target names is not well formed")
            );
        }
    };
    check_policy(source, &known).context("the target --target names cannot be swept")?;
    Ok(ChosenTarget { id, target: known })
}

/// Every target `source` can sweep, and a warning for each one skipped.
fn every_target(targets: &[Target], source: &impl TargetResolver) -> anyhow::Result<ChosenTargets> {
    let mut chosen = ChosenTargets {
        targets: Vec::new(),
        warnings: Vec::new(),
    };
    for target in targets {
        let id = target.id();
        match target.known() {
            Ok(Some(known)) => {
                check_policy(source, &known).with_context(|| {
                    format!("target {id} cannot be swept; --target can name another of its targets")
                })?;
                chosen.targets.push(ChosenTarget {
                    id: id.clone(),
                    target: known,
                });
            }
            // The kind is a stranger's text, so it is not printed.
            Ok(None) => chosen.warnings.push(format!(
                "target {id} is skipped: its kind is not one this build knows"
            )),
            Err(fault) => chosen.warnings.push(format!(
                "target {id} is skipped: it is not well formed ({fault})"
            )),
        }
    }
    if chosen.targets.is_empty() {
        bail!("the bounty has no target this build can sweep");
    }
    // Each target is a fetch, and `post` writes at most this many, so a
    // stranger's bounty cannot ask one run for unbounded work.
    if chosen.targets.len() > MAX_TARGETS {
        bail!(
            "the bounty has {} targets this build can sweep, more than the {MAX_TARGETS} one run \
             takes; name one with --target",
            chosen.targets.len()
        );
    }
    Ok(chosen)
}

/// Asks `source` whether it serves `target`: the real source takes a pull
/// request on `github.com` alone, the fixture source the names it maps.
fn check_policy(source: &impl TargetResolver, target: &KnownTarget) -> anyhow::Result<()> {
    let (kind, repo) = kind_and_repo(target);
    source.check_policy(kind, repo)
}

/// A checked target's kind and repository.
// No `_` arm: a kind added to core later does not compile until someone
// decides which repository its policy is asked about.
fn kind_and_repo(target: &KnownTarget) -> (KnownTargetKind, &RepoName) {
    match target {
        KnownTarget::Pr(pr) => (KnownTargetKind::Pr, pr.repo()),
        KnownTarget::Commit(commit) => (KnownTargetKind::Commit, commit.repo()),
        KnownTarget::Repo(repo) => (KnownTargetKind::Repo, repo.repo()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sweepky_core::{Bounty, BountyRef, Circle, KnownTargetKind, Pubky};

    use super::{Acceptance, ChosenTargets, accept, choose_targets, circle_to_read, kind_and_repo};
    use crate::post::draft::MAX_TARGETS;
    use crate::run::RunRequest;
    use crate::targets::TargetSource;
    use crate::test_support::{
        PLANTED, SYNTHETIC_SHA, bounty_id, bounty_json, circle_json, json_bytes, random_pubky,
        repo_target_json,
    };

    fn bounty(value: &Value) -> Bounty {
        Bounty::from_json(&json_bytes(value)).expect("a bounty core reads")
    }

    /// A bounty as `post` writes it: status open, closed to strangers, one
    /// repo target.
    fn closed() -> Bounty {
        bounty(&bounty_json(json!([repo_target_json("t1")])))
    }

    /// The same, with `open: true`.
    fn open() -> Bounty {
        let mut value = bounty_json(json!([repo_target_json("t1")]));
        value["open"] = json!(true);
        bounty(&value)
    }

    fn circle(admin: Pubky, members: &[Pubky]) -> Circle {
        Circle::from_json(&json_bytes(&circle_json(admin, members))).expect("a circle")
    }

    fn request(owner: Pubky, sweeper: Pubky, circle: Option<Pubky>) -> RunRequest<'static> {
        RunRequest {
            bounty: BountyRef {
                owner,
                id: bounty_id(),
            },
            sweeper,
            circle,
            target: None,
        }
    }

    /// `accept`'s refusal, as the message the user would see.
    fn refusal(request: &RunRequest<'_>, bounty: &Bounty, circle: Option<&Circle>) -> String {
        let err = accept(request, bounty, circle).expect_err("refused");
        format!("{err:#}")
    }

    #[test]
    fn a_closed_bounty_is_accepted_when_its_owner_s_circle_lists_the_sweeper() {
        let (owner, sweeper) = (random_pubky(), random_pubky());
        let bounty = closed();
        let request = request(owner, sweeper, None);

        // The owner's own circle.json, the roster their pull reads
        // closed-bounty sweeps from.
        assert_eq!(circle_to_read(&request, &bounty), Some(owner));
        let roster = circle(owner, &[owner, sweeper]);
        let acceptance = accept(&request, &bounty, Some(&roster)).expect("accepted");
        assert_eq!(acceptance, Acceptance::OwnersCircle);
    }

    #[test]
    fn a_closed_bounty_is_refused_outside_its_owner_s_circle() {
        let (owner, sweeper, other) = (random_pubky(), random_pubky(), random_pubky());
        let bounty = closed();
        let request = request(owner, sweeper, None);

        // A roster that does not list the sweeper.
        let message = refusal(&request, &bounty, Some(&circle(owner, &[owner, other])));
        assert!(message.contains("you are not in it"), "{message}");
        // A circle.json under the owner's storage that names another admin
        // is not the owner's roster, whoever it lists.
        let message = refusal(
            &request,
            &bounty,
            Some(&circle(other, &[owner, sweeper, other])),
        );
        assert!(message.contains("another admin"), "{message}");
        // No circle.json at all.
        let message = refusal(&request, &bounty, None);
        assert!(message.contains("no circle"), "{message}");
    }

    #[test]
    fn roster_membership_is_compared_by_key_bytes() {
        let (owner, sweeper) = (random_pubky(), random_pubky());
        // The roster spells every key in the SDK's `pubky<z32>` form; the
        // request holds them as parsed from the raw form.
        let value = json!({
            "schemaVersion": 1,
            "name": "Friends",
            "admin": format!("pubky{owner}"),
            "members": [{ "pubky": format!("pubky{sweeper}") }],
        });
        let roster = Circle::from_json(&json_bytes(&value)).expect("a circle");
        let acceptance =
            accept(&request(owner, sweeper, None), &closed(), Some(&roster)).expect("accepted");
        assert_eq!(acceptance, Acceptance::OwnersCircle);
    }

    #[test]
    fn an_open_bounty_is_accepted_from_anyone_and_reads_no_circle() {
        let request = request(random_pubky(), random_pubky(), None);
        let bounty = open();
        assert_eq!(circle_to_read(&request, &bounty), None);
        assert_eq!(
            accept(&request, &bounty, None).expect("accepted"),
            Acceptance::Open
        );
    }

    #[test]
    fn only_an_open_status_is_accepted() {
        let (owner, sweeper) = (random_pubky(), random_pubky());
        let roster = circle(owner, &[sweeper]);
        for (status, expected) in [("done", "is done"), (PLANTED, "does not know")] {
            // Closed in the sweeper's circle, and open to anyone: the status
            // decides before either.
            for open in [false, true] {
                let mut value = bounty_json(json!([repo_target_json("t1")]));
                value["status"] = json!(status);
                value["open"] = json!(open);
                let message = refusal(
                    &request(owner, sweeper, None),
                    &bounty(&value),
                    Some(&roster),
                );
                assert!(message.contains(expected), "{status}: {message}");
                assert!(!message.contains(PLANTED), "{message}");
            }
        }
    }

    #[test]
    fn circle_flag_checks_that_circle_for_both_the_owner_and_the_sweeper() {
        let (owner, sweeper, admin, other) = (
            random_pubky(),
            random_pubky(),
            random_pubky(),
            random_pubky(),
        );
        for bounty in [closed(), open()] {
            let request = request(owner, sweeper, Some(admin));
            // The circle `--circle` names is read, open bounty or not.
            assert_eq!(circle_to_read(&request, &bounty), Some(admin));

            let both = circle(admin, &[owner, sweeper]);
            let acceptance = accept(&request, &bounty, Some(&both)).expect("accepted");
            assert_eq!(acceptance, Acceptance::NamedCircle);

            for (roster, expected) in [
                (Some(circle(admin, &[sweeper])), "owner is not in"),
                (Some(circle(admin, &[owner])), "you are not in"),
                (Some(circle(other, &[owner, sweeper])), "another admin"),
                (None, "no circle"),
            ] {
                let message = refusal(&request, &bounty, roster.as_ref());
                assert!(message.contains(expected), "{message}");
                assert!(message.contains("--circle"), "{message}");
                // Nothing names the key the flag was given.
                assert!(!message.contains(&admin.to_string()), "{message}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // The targets.

    fn commit_target(id: &str) -> Value {
        json!({ "id": id, "kind": "commit", "repo": "github.com/org/name", "rev": SYNTHETIC_SHA })
    }

    fn pr_target(id: &str, repo: &str) -> Value {
        json!({
            "id": id, "kind": "pr", "repo": repo, "number": 7,
            "base": SYNTHETIC_SHA, "head": SYNTHETIC_SHA, "mergeBase": SYNTHETIC_SHA,
        })
    }

    /// A target of a kind no build knows yet, its fields planted.
    fn unknown_target(id: &str) -> Value {
        json!({ "id": id, "kind": format!("crate-{PLANTED}"), "name": PLANTED })
    }

    /// A repo target whose `rev` is no SHA.
    fn malformed_target(id: &str) -> Value {
        json!({ "id": id, "kind": "repo", "repo": "github.com/org/name", "rev": PLANTED })
    }

    fn choose(targets: Value, target: Option<&str>) -> anyhow::Result<ChosenTargets> {
        choose_targets(&bounty(&bounty_json(targets)), target, &TargetSource::Real)
    }

    fn chosen_ids(chosen: &ChosenTargets) -> Vec<&str> {
        chosen
            .targets
            .iter()
            .map(|target| target.id.as_str())
            .collect()
    }

    #[test]
    fn every_usable_target_is_chosen_and_the_rest_skipped_by_id() {
        let chosen = choose(
            json!([
                repo_target_json("t1"),
                unknown_target("t2"),
                commit_target("t3"),
                malformed_target("t4"),
                pr_target("t5", "github.com/org/name"),
            ]),
            None,
        )
        .expect("chosen");
        assert_eq!(chosen_ids(&chosen), ["t1", "t3", "t5"]);
        // Each keeps its checked view, of the kind written.
        let kinds: Vec<KnownTargetKind> = chosen
            .targets
            .iter()
            .map(|target| kind_and_repo(&target.target).0)
            .collect();
        assert_eq!(
            kinds,
            [
                KnownTargetKind::Repo,
                KnownTargetKind::Commit,
                KnownTargetKind::Pr
            ]
        );
        // One warning per skipped target, naming it by its id and quoting
        // nothing else it holds.
        assert_eq!(chosen.warnings.len(), 2, "{:?}", chosen.warnings);
        for (warning, id) in chosen.warnings.iter().zip(["t2", "t4"]) {
            assert!(warning.contains(&format!("target {id} ")), "{warning}");
            assert!(!warning.contains(PLANTED), "{warning}");
        }
    }

    #[test]
    fn target_flag_chooses_one_and_refuses_an_absent_unknown_or_malformed_id() {
        let targets = json!([
            repo_target_json("t1"),
            commit_target("t2"),
            unknown_target("t3"),
            malformed_target("t4"),
        ]);
        let chosen = choose(targets.clone(), Some("t2")).expect("chosen");
        assert_eq!(chosen_ids(&chosen), ["t2"]);
        assert!(chosen.warnings.is_empty(), "{:?}", chosen.warnings);

        for (flag, expected) in [
            ("absent7f3a", "no target"),
            ("t3", "kind this build does not know"),
            ("t4", "not well formed"),
            ("not/an id 7f3a", "--target takes a target id"),
        ] {
            let err = choose(targets.clone(), Some(flag)).expect_err(flag);
            let message = format!("{err:#}");
            assert!(message.contains(expected), "{flag}: {message}");
            assert!(!message.contains("7f3a"), "{flag}: {message}");
            assert!(!message.contains(PLANTED), "{flag}: {message}");
        }
    }

    #[test]
    fn ids_that_differ_only_in_case_refuse_the_whole_bounty() {
        // `t1` and `T1` would share one directory on macOS's default
        // filesystem, so neither is swept, even when --target names a
        // third.
        let targets = json!([
            repo_target_json("t1"),
            commit_target("t2"),
            unknown_target("T1"),
        ]);
        for flag in [None, Some("t2")] {
            let err = choose(targets.clone(), flag).expect_err("refused");
            let message = format!("{err:#}");
            assert!(message.contains("t1 and T1"), "{message}");
            assert!(message.contains("only in case"), "{message}");
        }
    }

    #[test]
    fn a_pr_target_the_source_policy_refuses_is_refused() {
        // The real source takes a pull request on github.com alone, and says
        // so with no network.
        let targets = json!([
            repo_target_json("t1"),
            pr_target("t2", "gitlab.example/org/name"),
        ]);
        let err = choose(targets.clone(), None).expect_err("refused");
        let message = format!("{err:#}");
        assert!(message.contains("target t2 cannot be swept"), "{message}");
        assert!(!message.contains("gitlab.example"), "{message}");

        let err = choose(targets.clone(), Some("t2")).expect_err("refused");
        assert!(format!("{err:#}").contains("cannot be swept"), "{err:#}");
        // The other target is still there to name.
        let chosen = choose(targets, Some("t1")).expect("chosen");
        assert_eq!(chosen_ids(&chosen), ["t1"]);
    }

    #[test]
    fn a_bounty_with_no_usable_target_is_refused() {
        for targets in [
            json!([]),
            json!([unknown_target("t1"), malformed_target("t2")]),
        ] {
            let err = choose(targets, None).expect_err("refused");
            let message = format!("{err:#}");
            assert!(message.contains("no target"), "{message}");
            assert!(!message.contains(PLANTED), "{message}");
        }
    }

    #[test]
    fn more_usable_targets_than_post_writes_need_one_named() {
        let at_cap: Vec<Value> = (1..=MAX_TARGETS)
            .map(|n| repo_target_json(&format!("t{n}")))
            .collect();
        assert_eq!(
            choose(json!(at_cap), None).expect("chosen").targets.len(),
            MAX_TARGETS
        );

        let mut over_cap = at_cap;
        over_cap.push(repo_target_json("t999"));
        let err = choose(json!(over_cap.clone()), None).expect_err("refused");
        assert!(format!("{err:#}").contains("--target"), "{err:#}");
        let chosen = choose(json!(over_cap), Some("t999")).expect("chosen");
        assert_eq!(chosen_ids(&chosen), ["t999"]);
    }
}
