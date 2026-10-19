//! [`PublicRecords`], the seam through which `run` reads anyone's public
//! Sweepky records: a bounty, a circle and a sweep record, each from the
//! storage of the key that owns it, with no session.
//!
//! - [`PublicRecords::get_record`] is the one method an implementation
//!   writes: the bytes of one public file, at most [`MAX_RECORD_BYTES`], or
//!   `None` when there is none (a 404). [`PublicRecordReader`] is the real
//!   one, through `remote::get_public`, which finds the owner's homeserver
//!   through pkarr, asks it anonymously, refuses an answer that came through
//!   a redirect and caps the body before it is buffered. The unit tests use
//!   `test_support::FakePublicRecords`, which keeps files in memory.
//! - [`get_bounty`](PublicRecords::get_bounty),
//!   [`get_circle`](PublicRecords::get_circle) and
//!   [`get_sweep`](PublicRecords::get_sweep) are written once, on the trait,
//!   so the real reader and the fake read records the same way: each builds
//!   its path with `sweepky_core::paths` and parses the bytes with the
//!   record type's `from_json`, core's capped, version-first parse, which
//!   refuses more than `MAX_RECORD_BYTES` again before it parses anything.
//!
//! **A record is parsed, not trusted.** Holding a `Circle` means the bytes
//! had a circle's shape, nothing more: its `admin` may not be the key whose
//! storage holds it, and a `Bounty` may be done. Whether `run` may sweep a
//! bounty is `run::select`'s question.
//!
//! **Errors never quote the record.** Bytes that do not parse are refused
//! through core's `RecordError`, which keeps only the kind of fault and where
//! it is; the message names the path and the owner, which this build built
//! and checked, and never the bytes.
//!
//! The listings `run` picks a bounty from without a URL come with that step.

use anyhow::Context as _;
use sweepky_core::paths;
use sweepky_core::{
    Bounty, BountyRef, Circle, MAX_RECORD_BYTES, Pubky, Sweep, SweepRef, Zeroizing,
};

use crate::remote::{get_public, public_key_of};

/// Anyone's public Sweepky records, read with no session: the seam between
/// `run` and everyone's homeservers.
///
/// A trait so that `run` can be tested without a network, as with
/// `device::PublicKeys`. Its methods are `async fn`s, so it cannot be a
/// `dyn PublicRecords` (each implementation's futures are a different
/// type); callers take `&impl PublicRecords`, and the compiler makes one
/// copy of the caller for the real reader and one for the fake.
/// `pub(crate)`, so the warning about `Send` bounds on public async traits
/// does not apply.
///
/// Every record comes back as `Ok(None)` when its owner's storage has no
/// such file, so "there is none" and "it could not be read" stay apart.
pub(crate) trait PublicRecords {
    /// The file at `path` of `owner`'s public storage, at most
    /// [`MAX_RECORD_BYTES`], or `None` when there is none. `path` comes from
    /// `sweepky_core::paths`, never from a stranger's text: an error names
    /// it.
    async fn get_record(
        &self,
        owner: Pubky,
        path: &str,
    ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>;

    /// The bounty `bounty` points at, `bounties/<id>.json` of its owner, or
    /// `None` when there is none.
    // A *provided* method: the trait writes its body, so every
    // implementation gets it without writing it again, and the fake parses
    // exactly as the real reader does. An implementation could override
    // it, and none does.
    async fn get_bounty(&self, bounty: BountyRef) -> anyhow::Result<Option<Bounty>> {
        let path = paths::bounty(bounty.id);
        let found = self.get_record(bounty.owner, &path).await?;
        // `map` parses only a `Some`, giving an `Option<Result<..>>`;
        // `transpose` swaps it into the `Result<Option<..>>` returned, so
        // a missing file stays `None` and bytes that do not parse are the
        // error.
        found
            .map(|bytes| Bounty::from_json(&bytes))
            .transpose()
            .with_context(|| not_a_record("bounty", &path, bounty.owner))
    }

    /// The circle `admin`'s storage holds, `circle.json`, or `None` when
    /// there is none. Its own `admin` field is not checked against `admin`
    /// here; `run::select` refuses a roster whose admin is another key.
    async fn get_circle(&self, admin: Pubky) -> anyhow::Result<Option<Circle>> {
        let path = paths::circle();
        let found = self.get_record(admin, path).await?;
        found
            .map(|bytes| Circle::from_json(&bytes))
            .transpose()
            .with_context(|| not_a_record("circle", path, admin))
    }

    /// The sweep record `sweep` points at, `sweeps/<id>.json` of its
    /// sweeper, or `None` when there is none.
    // Picking a bounty, later in P2b, is the first caller outside the
    // tests: `expect` (not `allow`) silences the dead-code warning only
    // while that is true, and that caller removes it.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "picking a bounty, later in P2b, is the first caller"
        )
    )]
    async fn get_sweep(&self, sweep: SweepRef) -> anyhow::Result<Option<Sweep>> {
        let path = paths::sweep_record(sweep.id);
        let found = self.get_record(sweep.sweeper, &path).await?;
        found
            .map(|bytes| Sweep::from_json(&bytes))
            .transpose()
            .with_context(|| not_a_record("sweep", &path, sweep.sweeper))
    }
}

/// The message for bytes at `path` of `owner` that are not a `kind`
/// record: the path and the owner, which this build built and checked, and
/// never the bytes. Core's `RecordError` follows it as the cause.
fn not_a_record(kind: &str, path: &str, owner: Pubky) -> String {
    format!("{path} of {owner} is not a {kind} record this build reads")
}

/// The real [`PublicRecords`]: anyone's public storage through the client,
/// which finds each owner's homeserver through pkarr and asks it
/// anonymously. It borrows the client, which is what the `'a` says.
pub(crate) struct PublicRecordReader<'a> {
    client: &'a pubky::Pubky,
}

impl<'a> PublicRecordReader<'a> {
    /// A reader on `client`.
    pub(crate) fn new(client: &'a pubky::Pubky) -> Self {
        Self { client }
    }
}

impl PublicRecords for PublicRecordReader<'_> {
    async fn get_record(
        &self,
        owner: Pubky,
        path: &str,
    ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        // The SDK asks for its own key type, which also checks that the 32
        // bytes are a point on Ed25519; core's `Pubky` checks only the
        // spelling.
        let key = public_key_of(&owner)?;
        get_public(self.client, &key, path, MAX_RECORD_BYTES).await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sweepky_core::paths;
    use sweepky_core::{BountyRef, MAX_RECORD_BYTES, Pubky, SweepRef};

    use super::PublicRecords;
    use crate::test_support::{
        FakePublicRecords, PLANTED, bounty_id, bounty_json, circle_json, json_bytes, random_pubky,
    };

    fn sweep_json(owner: Pubky) -> Value {
        json!({
            "schemaVersion": 1,
            "bounty": BountyRef { owner, id: bounty_id() }.to_string(),
            "targets": ["t1"],
            "playbook": "cloudflare/security-audit@c1c8a8c",
            "status": "running",
            "startedAt": "2026-10-19T09:00:00Z",
        })
    }

    #[tokio::test]
    async fn each_record_is_read_from_its_owner_s_path_and_parsed() {
        let owner = random_pubky();
        let sweeper = random_pubky();
        let bounty_path = paths::bounty(bounty_id());
        let sweep_path = paths::sweep_record(bounty_id());
        let records = FakePublicRecords::default()
            .with_file(owner, &bounty_path, json_bytes(&bounty_json(json!([]))))
            .with_file(owner, paths::circle(), json_bytes(&circle_json(owner, &[])))
            .with_file(sweeper, &sweep_path, json_bytes(&sweep_json(owner)));

        let bounty = records
            .get_bounty(BountyRef {
                owner,
                id: bounty_id(),
            })
            .await
            .expect("read")
            .expect("there");
        assert!(!bounty.open);
        let circle = records
            .get_circle(owner)
            .await
            .expect("read")
            .expect("there");
        assert_eq!(circle.admin, owner);
        let sweep = records
            .get_sweep(SweepRef {
                sweeper,
                id: bounty_id(),
            })
            .await
            .expect("read")
            .expect("there");
        assert_eq!(
            sweep.bounty,
            BountyRef {
                owner,
                id: bounty_id()
            }
        );

        // Each from the storage of the key that owns it, at the path core
        // builds for it.
        assert_eq!(
            records.asked(),
            [
                (owner, bounty_path),
                (owner, paths::circle().to_owned()),
                (sweeper, sweep_path),
            ]
        );
    }

    #[tokio::test]
    async fn a_missing_record_is_none() {
        let records = FakePublicRecords::default();
        let owner = random_pubky();
        let bounty = records
            .get_bounty(BountyRef {
                owner,
                id: bounty_id(),
            })
            .await
            .expect("a 404 is no error");
        assert!(bounty.is_none());
        assert!(records.get_circle(owner).await.expect("no error").is_none());
        let sweep = records
            .get_sweep(SweepRef {
                sweeper: owner,
                id: bounty_id(),
            })
            .await
            .expect("no error");
        assert!(sweep.is_none());
    }

    #[tokio::test]
    async fn a_body_over_the_cap_or_one_that_does_not_parse_is_refused_unquoted() {
        let owner = random_pubky();
        // Three bodies each record is refused with: a valid record padded
        // with JSON whitespace to one byte over the cap, bytes that are not
        // JSON, and JSON of the wrong shape. The planted word sits where
        // serde_json's own message would quote it.
        let bad_bodies = |valid: Value| {
            let mut over_cap = json_bytes(&valid);
            over_cap.resize(MAX_RECORD_BYTES + 1, b' ');
            let mut wrong_shape = valid;
            wrong_shape["schemaVersion"] = json!(PLANTED);
            [
                over_cap,
                format!("{PLANTED} is not JSON").into_bytes(),
                json_bytes(&wrong_shape),
            ]
        };
        let bounty = BountyRef {
            owner,
            id: bounty_id(),
        };
        let sweep = SweepRef {
            sweeper: owner,
            id: bounty_id(),
        };

        for body in bad_bodies(bounty_json(json!([]))) {
            let records =
                FakePublicRecords::default().with_file(owner, &paths::bounty(bounty_id()), body);
            let err = records.get_bounty(bounty).await.expect_err("refused");
            assert_refused_unquoted(&err, "bounty");
        }
        for body in bad_bodies(circle_json(owner, &[])) {
            let records = FakePublicRecords::default().with_file(owner, paths::circle(), body);
            let err = records.get_circle(owner).await.expect_err("refused");
            assert_refused_unquoted(&err, "circle");
        }
        for body in bad_bodies(sweep_json(owner)) {
            let records = FakePublicRecords::default().with_file(
                owner,
                &paths::sweep_record(bounty_id()),
                body,
            );
            let err = records.get_sweep(sweep).await.expect_err("refused");
            assert_refused_unquoted(&err, "sweep");
        }
    }

    /// `err` says which kind of record it could not read, and quotes none of
    /// the body.
    fn assert_refused_unquoted(err: &anyhow::Error, kind: &str) {
        let message = format!("{err:#}");
        assert!(
            message.contains(&format!("not a {kind} record")),
            "{message}"
        );
        assert!(!message.contains(PLANTED), "{message}");
    }
}
