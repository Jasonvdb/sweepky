//! The two files `run` writes beside the fetched targets for the agent:
//! `scope.json`, what to review and where, and `brief.md`, the bounty's
//! brief byte for byte.
//!
//! `scope.json`'s shape:
//!
//! ```json
//! {
//!   "schemaVersion": 1,
//!   "sweep": "pubky://<sweeper>/pub/sweepky/sweeps/<id>.json",
//!   "bounty": "pubky://<owner>/pub/sweepky/bounties/<id>.json",
//!   "focus": "security",
//!   "suggestedPlaybook": "cloudflare/security-audit@c1c8a8c",
//!   "profile": "standard",
//!   "output": "/abs/project/sweeps/<id>/audit/",
//!   "targets": [{
//!     "id": "t1",
//!     "kind": "repo",
//!     "path": "/abs/project/sweeps/<id>/target/t1/",
//!     "scope": { "kind": "repo", "summary": "…", "paths": ["src/auth/"], "notes": [] },
//!     "stripped": [".claude/", "CLAUDE.md", "src/auth/CLAUDE.md"]
//!   }]
//! }
//! ```
//!
//! - `scope` is core's `TargetScope`, built from the bounty's checked target
//!   (`KnownTarget`), never from a field a stranger wrote as text; for a
//!   commit target, from the parents of the commit as fetched.
//! - `stripped` is the agent-instruction files taken out of that target's
//!   copy (`strip.rs`). The names are the repository's, so they are data.
//! - `suggestedPlaybook` is the bounty's suggestion, a stranger's text, or
//!   `null`.
//! - `profile` is [`PROFILE`], `standard`: no flag chooses another yet.
//! - `output` is the directory the `/sweepky` skill hands the playbook as its
//!   new output directory (01, 03). `run` does not make it: the playbook
//!   wants a directory that is new, so it makes it itself.
//!
//! **Never read back.** The agent can write anywhere under `sweeps/<id>/`,
//! this file included, so nothing in this build reads `scope.json`; every
//! command, `submit` among them, works from the bounty record and its
//! checked targets. Its types are `Serialize` only.

use std::fs::OpenOptions;
use std::path::Path;

use anyhow::Context as _;
use serde::Serialize;
use sweepky_core::{BountyRef, Focus, SchemaVersion, SweepRef, TargetId, TargetKind, TargetScope};

use super::CheckedBounty;
use crate::private_fs::write_synced;

/// The profile `scope.json` names: `standard`, the playbook's default depth
/// (03's request offers `quick` or `standard`). P2b's choice, until a flag
/// lets the sweeper pick `quick` for a long whole-repository sweep.
pub(super) const PROFILE: &str = "standard";

/// One target as `scope.json` lists it.
// `Serialize` only, never `Deserialize`: see "Never read back" above.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScopeTarget {
    /// The target's id, its directory under `target/`.
    pub(crate) id: TargetId,
    /// The target's kind.
    pub(crate) kind: TargetKind,
    /// The absolute path of the target's copy, `…/sweeps/<id>/target/<tid>/`.
    pub(crate) path: String,
    /// What to review in it.
    pub(crate) scope: TargetScope,
    /// What was stripped from the copy, relative to `path`.
    pub(crate) stripped: Vec<String>,
}

/// The whole of `scope.json`. It borrows what it shows from the bounty and
/// the targets, so building it copies nothing; the lifetime `'a` says it
/// lives no longer than they do.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeFile<'a> {
    schema_version: SchemaVersion,
    sweep: SweepRef,
    bounty: BountyRef,
    focus: &'a Focus,
    suggested_playbook: Option<&'a str>,
    profile: &'static str,
    output: &'a str,
    targets: &'a [ScopeTarget],
}

/// `scope.json`'s bytes, pretty-printed for a reader and ending in a
/// newline: `sweep` and `checked`'s bounty, `output` the absolute path of
/// the audit directory, and `targets` as fetched.
pub(super) fn scope_json(
    sweep: SweepRef,
    checked: &CheckedBounty,
    output: &str,
    targets: &[ScopeTarget],
) -> anyhow::Result<Vec<u8>> {
    let file = ScopeFile {
        schema_version: SchemaVersion::CURRENT,
        sweep,
        bounty: checked.bounty_ref,
        focus: &checked.bounty.focus,
        // `as_deref` lends the `String` inside the `Option` out as a `&str`.
        suggested_playbook: checked.bounty.playbook.suggested.as_deref(),
        profile: PROFILE,
        output,
        targets,
    };
    let mut bytes = serde_json::to_vec_pretty(&file).context("could not write scope.json")?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Creates the file at `path` with `bytes`, failing if anything at all is
/// there already. `create_new` is `O_CREAT | O_EXCL`, which refuses a link
/// as well, dangling or not, so nothing is written through one.
pub(super) fn write_new_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    write_synced(path, file, bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use serde_json::{Value, json};
    use sweepky_core::{
        Bounty, BountyRef, KnownTargetKind, RepoPath, SweepRef, TargetId, TargetScope,
    };

    use super::{PROFILE, ScopeFile, ScopeTarget, scope_json, write_new_file};
    use crate::run::CheckedBounty;
    use crate::run::select::Acceptance;
    use crate::test_support::{
        PLANTED, bounty_id, bounty_json, json_bytes, private_temp, random_pubky, repo_target_json,
    };

    fn checked_bounty(suggested: Option<&str>) -> CheckedBounty {
        let mut value = bounty_json(json!([repo_target_json("t1")]));
        value["focus"] = json!("perf");
        value["playbook"] = match suggested {
            Some(text) => json!({ "suggested": text, "required": false }),
            None => json!({ "required": false }),
        };
        CheckedBounty {
            bounty_ref: BountyRef {
                owner: random_pubky(),
                id: bounty_id(),
            },
            bounty: Bounty::from_json(&json_bytes(&value)).expect("a bounty"),
            acceptance: Acceptance::Open,
            targets: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn target() -> ScopeTarget {
        let path: RepoPath = "src/auth/".parse().expect("a path");
        ScopeTarget {
            id: "t1".parse::<TargetId>().expect("an id"),
            kind: KnownTargetKind::Repo.into(),
            path: "/abs/project/sweeps/0035G87EK4XFE/target/t1/".to_owned(),
            scope: TargetScope {
                kind: KnownTargetKind::Repo.into(),
                summary: "The tree.".to_owned(),
                command: None,
                paths: Some(vec![path]),
                notes: Vec::new(),
            },
            stripped: vec!["CLAUDE.md".to_owned(), ".claude/".to_owned()],
        }
    }

    #[test]
    fn scope_json_names_the_sweep_the_bounty_the_output_and_each_target() {
        let checked = checked_bounty(Some("cloudflare/security-audit@c1c8a8c"));
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: bounty_id(),
        };
        let output = "/abs/project/sweeps/0035G87EK4XFE/audit/";
        let bytes = scope_json(sweep, &checked, output, &[target()]).expect("written");
        assert_eq!(bytes.last(), Some(&b'\n'));
        let value: Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(
            value,
            json!({
                "schemaVersion": 1,
                "sweep": sweep.to_string(),
                "bounty": checked.bounty_ref.to_string(),
                "focus": "perf",
                "suggestedPlaybook": "cloudflare/security-audit@c1c8a8c",
                "profile": PROFILE,
                "output": output,
                "targets": [{
                    "id": "t1",
                    "kind": "repo",
                    "path": "/abs/project/sweeps/0035G87EK4XFE/target/t1/",
                    "scope": { "kind": "repo", "summary": "The tree.", "paths": ["src/auth/"], "notes": [] },
                    "stripped": ["CLAUDE.md", ".claude/"],
                }],
            })
        );
        assert_eq!(PROFILE, "standard");

        // No suggestion is `null`.
        let bytes = scope_json(sweep, &checked_bounty(None), output, &[]).expect("written");
        let value: Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(value["suggestedPlaybook"], Value::Null);
    }

    #[test]
    fn scope_json_is_never_read_back() {
        // Checked when the test compiles: neither type can be deserialized,
        // so no code can take a scope, and its command, back from the file
        // the agent may have rewritten.
        crate::test_support::assert_not_impl_any!(ScopeTarget: serde::de::DeserializeOwned);
        crate::test_support::assert_not_impl_any!(
            ScopeFile<'static>: serde::de::DeserializeOwned
        );
    }

    #[test]
    fn a_new_file_never_replaces_or_writes_through_anything() {
        let temp = private_temp();
        let path = temp.path().join("brief.md");
        write_new_file(&path, b"first").expect("created");
        assert_eq!(fs::read(&path).expect("read"), b"first");
        // A file already there, and a link to elsewhere, are refused and
        // left as they were.
        assert!(write_new_file(&path, PLANTED.as_bytes()).is_err());
        assert_eq!(fs::read(&path).expect("read"), b"first");
        let link = temp.path().join("scope.json");
        symlink(&path, &link).expect("symlink");
        assert!(write_new_file(&link, PLANTED.as_bytes()).is_err());
        assert_eq!(fs::read(&path).expect("read"), b"first");
    }
}
