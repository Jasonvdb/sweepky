//! The per-sweep marker, `sweeps/<id>/.sweepky/sweep.json`: what names the
//! sweep a directory holds. `run` writes it last, once every target is
//! fetched and `scope.json` and `brief.md` are in place, so a sweep
//! directory with a marker is a whole one. It is separate from the
//! project's own `.sweepky` marker, the file `init` writes.
//!
//! Its shape, compact JSON and a newline, as `init`'s marker:
//!
//! ```json
//! {"schemaVersion":1,"sweep":"pubky://<sweeper>/pub/sweepky/sweeps/<id>.json","bounty":"pubky://<owner>/pub/sweepky/bounties/<id>.json","targets":["t1","t2"],"playbook":"cloudflare/security-audit@c1c8a8c"}
//! ```
//!
//! - `sweep` is the sweep record's URL, and `bounty` and `targets` are the
//!   record's own, so the two cannot disagree.
//! - `playbook` is the one the project's `init` recorded, and is left out
//!   when it recorded none, as P2a's `init` never does; the sweep record
//!   then names the placeholder `unspecified`, which `submit --playbook`
//!   replaces.
//! - `schemaVersion` is 1, P2b's addition, as in `scope.json`.
//!
//! **Written all at once, never through a link.** `.sweepky/` is made with a
//! plain `mkdir`, 0700, which fails if anything at all is at that name, a
//! link included. `private_fs::write_private_file` then writes `sweep.json`:
//! a temp file beside it opened with `create_new` (`O_EXCL`, which no link
//! passes), the bytes synced to disk, a `rename` onto the real name, which
//! replaces a directory entry and never follows one, and a sync of the
//! directory. So the name shows the whole marker or nothing.
//!
//! **Written, not read, here.** The agent can write anywhere under
//! `sweeps/<id>/`, this file included, so the type is `Serialize` only;
//! `submit`, later in P2b, reads the marker and must check what it says
//! against what it knows, as with any file the agent could have changed.

use std::fs::DirBuilder;
// `DirBuilderExt` adds `.mode()` to `DirBuilder`, a Unix-only extension.
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use anyhow::Context as _;
use serde::Serialize;
use sweepky_core::{BountyRef, Playbook, SchemaVersion, Sweep, SweepRef, TargetId};

use crate::private_fs::write_private_file;

/// The marker's directory, directly inside the sweep's.
const MARKER_DIR: &str = ".sweepky";

/// The marker's file, inside [`MARKER_DIR`].
const MARKER_FILE: &str = "sweep.json";

/// The per-sweep marker's contents.
///
/// It borrows the target ids and the playbook (the lifetime `'a`) from the
/// sweep record and the project's marker it is built from, so making one
/// copies nothing; the two `pubky://` references are small `Copy` values.
// `Serialize` only, never `Deserialize`: see "Written, not read, here".
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SweepMarker<'a> {
    schema_version: SchemaVersion,
    sweep: SweepRef,
    bounty: BountyRef,
    targets: &'a [TargetId],
    // Left out when `None`, rather than written as `null`: 01-style
    // optional fields are absent, as `finishedAt` on a running sweep.
    #[serde(skip_serializing_if = "Option::is_none")]
    playbook: Option<&'a Playbook>,
}

impl<'a> SweepMarker<'a> {
    /// The marker of the sweep at `sweep`, whose public record is `record`,
    /// in a project whose `init` recorded `playbook`, if any.
    pub(super) fn new(sweep: SweepRef, record: &'a Sweep, playbook: Option<&'a Playbook>) -> Self {
        Self {
            schema_version: SchemaVersion::CURRENT,
            sweep,
            bounty: record.bounty,
            targets: &record.targets,
            playbook,
        }
    }

    /// Writes the marker as `<sweep_dir>/.sweepky/sweep.json`, all at once
    /// and never through a link (see the module docs). Refused when
    /// anything is already at `.sweepky`.
    pub(super) fn write_into(&self, sweep_dir: &Path) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec(self).context("could not write the sweep's marker")?;
        bytes.push(b'\n');
        let dir = sweep_dir.join(MARKER_DIR);
        // Not `recursive`, so the `mkdir` fails if anything is there, and
        // 0700, as the sweep directory itself.
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
        write_private_file(&dir.join(MARKER_FILE), &bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use serde_json::{Value, json};
    use sweepky_core::{BountyRef, Playbook, Sweep, SweepRef};

    use super::SweepMarker;
    use crate::test_support::{PLANTED, bounty_id, json_bytes, mode, private_temp, random_pubky};

    const PLAYBOOK: &str = "cloudflare/security-audit@c1c8a8c";

    /// A running sweep record of `bounty`'s targets t1 and t2.
    fn record(bounty: BountyRef) -> Sweep {
        Sweep::from_json(&json_bytes(&json!({
            "schemaVersion": 1,
            "bounty": bounty.to_string(),
            "targets": ["t1", "t2"],
            "playbook": "unspecified",
            "status": "running",
            "startedAt": "2026-10-19T12:00:00Z",
        })))
        .expect("a sweep record")
    }

    fn sweep_ref() -> SweepRef {
        SweepRef {
            sweeper: random_pubky(),
            id: bounty_id(),
        }
    }

    fn bounty_ref() -> BountyRef {
        BountyRef {
            owner: random_pubky(),
            id: bounty_id(),
        }
    }

    /// The names directly inside `dir`.
    fn entries(dir: &Path) -> BTreeSet<String> {
        fs::read_dir(dir)
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8")
            })
            .collect()
    }

    #[test]
    fn the_marker_names_the_sweep_the_bounty_the_targets_and_the_playbook() {
        let (sweep, bounty) = (sweep_ref(), bounty_ref());
        let record = record(bounty);
        let playbook: Playbook = PLAYBOOK.parse().expect("a playbook");
        let temp = private_temp();

        SweepMarker::new(sweep, &record, Some(&playbook))
            .write_into(temp.path())
            .expect("written");

        let dir = temp.path().join(".sweepky");
        let bytes = fs::read(dir.join("sweep.json")).expect("read");
        // Compact JSON and one newline, at its end.
        assert_eq!(bytes.iter().filter(|&&byte| byte == b'\n').count(), 1);
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).expect("JSON"),
            json!({
                "schemaVersion": 1,
                "sweep": sweep.to_string(),
                "bounty": bounty.to_string(),
                "targets": ["t1", "t2"],
                "playbook": PLAYBOOK,
            })
        );
        // The sweeper's alone, and the temp file renamed away.
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("sweep.json")), 0o600);
        assert_eq!(entries(&dir), BTreeSet::from(["sweep.json".to_owned()]));

        // No playbook recorded by `init`: no `playbook` key at all.
        let temp = private_temp();
        SweepMarker::new(sweep, &record, None)
            .write_into(temp.path())
            .expect("written");
        let value: Value = serde_json::from_slice(
            &fs::read(temp.path().join(".sweepky/sweep.json")).expect("read"),
        )
        .expect("JSON");
        assert_eq!(value.get("playbook"), None, "{value}");
    }

    #[test]
    fn the_marker_is_never_written_through_a_link_or_into_a_directory_that_is_there() {
        let (sweep, bounty) = (sweep_ref(), bounty_ref());
        let record = record(bounty);
        let marker = SweepMarker::new(sweep, &record, None);

        // `.sweepky` a link to a directory elsewhere: refused, and nothing
        // is written there.
        let temp = private_temp();
        let elsewhere = private_temp();
        symlink(elsewhere.path(), temp.path().join(".sweepky")).expect("symlink");
        marker.write_into(temp.path()).expect_err("refused");
        assert_eq!(fs::read_dir(elsewhere.path()).expect("list").count(), 0);

        // A `.sweepky/` already there, with a file at the marker's name:
        // refused, and the file is left as it was.
        let temp = private_temp();
        let dir = temp.path().join(".sweepky");
        fs::create_dir(&dir).expect("mkdir");
        fs::write(dir.join("sweep.json"), PLANTED).expect("write");
        marker.write_into(temp.path()).expect_err("refused");
        assert_eq!(
            fs::read_to_string(dir.join("sweep.json")).expect("read"),
            PLANTED
        );
    }
}
