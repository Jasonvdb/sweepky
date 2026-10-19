//! [`PublicRecords`], the seam through which `run` and `submit` read
//! anyone's public Sweepky records: a bounty, a circle and a sweep record,
//! each from the storage of the key that owns it, and the bounty and sweep
//! records a key's storage lists, with no session. `submit` reads its own
//! sweep record this way too before it builds a package, as anyone would
//! see it, and reads it back through its session only under the lock.
//!
//! - [`PublicRecords::get_record`] and [`PublicRecords::list`] are the two
//!   methods an implementation writes for `run` and `submit`: the bytes of
//!   one public file, at most [`MAX_RECORD_BYTES`], or `None` when there is
//!   none (a 404); and the Sweepky files one directory lists. For `pull` it
//!   writes three more:
//!   [`list_newest_first`](PublicRecords::list_newest_first), a listing
//!   newest first that stops at the newest record id already seen;
//!   [`get_record_if_changed`](PublicRecords::get_record_if_changed), a
//!   record read again only if it changed since its tag; and
//!   [`get_package`](PublicRecords::get_package), a sweep's `.age`, at most
//!   [`MAX_CIPHERTEXT_BYTES`](sweepky_core::MAX_CIPHERTEXT_BYTES).
//!   [`PublicRecordReader`] is the real one, through `remote`'s helpers,
//!   which find the owner's homeserver through pkarr, ask it anonymously,
//!   refuse an answer that came through a redirect and cap every body
//!   before it is buffered; a listing is read within
//!   [`ListLimits::DEFAULT`], at most 1000 entries in 11 pages, and refused
//!   whole past them or when a page breaks the protocol. The unit tests use
//!   `test_support::FakePublicRecords`, which keeps files in memory.
//! - [`get_bounty`](PublicRecords::get_bounty),
//!   [`get_circle`](PublicRecords::get_circle) and
//!   [`get_sweep`](PublicRecords::get_sweep) are written once, on the trait,
//!   so the real reader and the fake read records the same way: each builds
//!   its path with `sweepky_core::paths` and parses the bytes with the
//!   record type's `from_json`, core's capped, version-first parse, which
//!   refuses more than `MAX_RECORD_BYTES` again before it parses anything.
//!   [`list_bounties`](PublicRecords::list_bounties) and
//!   [`list_sweeps`](PublicRecords::list_sweeps) keep the record ids of a
//!   listing of `bounties/` or `sweeps/`, and drop the other files there
//!   (an open bounty's `<id>.discovered.json`, a sweep's `<id>.age`).
//!
//! **A record is parsed, not trusted.** Holding a `Circle` means the bytes
//! had a circle's shape, nothing more: its `admin` may not be the key whose
//! storage holds it, and a `Bounty` may be done. Whether `run` may sweep a
//! bounty is `run::select`'s question.
//!
//! **Errors never quote the record.** Bytes that do not parse are refused
//! through core's `RecordError`, which keeps only the kind of fault and where
//! it is; the message names the path and the owner, which this build built
//! and checked, and never the bytes. A listing's refusal is
//! `remote::ListingError`'s fixed text under the directory and the owner.

use anyhow::Context as _;
use sweepky_core::paths::{self, SweepkyPath};
use sweepky_core::{
    Bounty, BountyRef, Circle, MAX_RECORD_BYTES, Pubky, RecordId, Sweep, SweepRef, Zeroizing,
};

use crate::remote::{
    self, Conditional, ETag, ListLimits, Listing, get_public, get_public_if_changed, list_dir,
    list_dir_newest_first, public_key_of,
};

/// Anyone's public Sweepky records, read with no session: the seam between
/// `run`, `submit` and `pull` and everyone's homeservers.
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

    /// The Sweepky files `dir` of `owner`'s public storage lists, in the
    /// order listed; an empty directory, or none (a 404), lists nothing.
    /// `dir` is one of `sweepky_core::paths`' directories, which ends with
    /// `/`: an error names it.
    async fn list(&self, owner: Pubky, dir: &str) -> anyhow::Result<Listing>;

    /// As [`list`](Self::list), but newest first, and stopping at `seen`,
    /// the newest record id already seen in `dir`: the first file of a
    /// record whose id is at or below it ends the listing, and is not in it
    /// (`remote::ListOrder::NewestFirst`). `None` lists the whole
    /// directory, newest first.
    async fn list_newest_first(
        &self,
        owner: Pubky,
        dir: &str,
        seen: Option<RecordId>,
    ) -> anyhow::Result<Listing>;

    /// The file at `path` of `owner`'s public storage again, at most
    /// [`MAX_RECORD_BYTES`], unless it is unchanged since `etag`, the tag
    /// its last answer gave: [`Conditional::NotModified`] then, with no
    /// body. [`Conditional::Absent`] when there is no such file. As for
    /// [`get_record`](Self::get_record), `path` comes from
    /// `sweepky_core::paths`.
    async fn get_record_if_changed(
        &self,
        owner: Pubky,
        path: &str,
        etag: Option<&ETag>,
    ) -> anyhow::Result<Conditional>;

    /// The encrypted package of `sweep`, `sweeps/<id>.age` of its sweeper,
    /// at most [`MAX_CIPHERTEXT_BYTES`](sweepky_core::MAX_CIPHERTEXT_BYTES),
    /// or `None` when there is none.
    // No caller outside the tests yet, so outside them the compiler would
    // warn that the method is never used. `expect` (not `allow`) silences
    // that only while it is true: `pull`, its first caller, must remove it.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "pull, its first caller, comes in a later step")
    )]
    async fn get_package(&self, sweep: SweepRef) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>;

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
    async fn get_sweep(&self, sweep: SweepRef) -> anyhow::Result<Option<Sweep>> {
        let path = paths::sweep_record(sweep.id);
        let found = self.get_record(sweep.sweeper, &path).await?;
        found
            .map(|bytes| Sweep::from_json(&bytes))
            .transpose()
            .with_context(|| not_a_record("sweep", &path, sweep.sweeper))
    }

    /// The ids of the bounty records `owner`'s `bounties/` lists, in the
    /// order listed.
    async fn list_bounties(&self, owner: Pubky) -> anyhow::Result<Vec<RecordId>> {
        let listing = self.list(owner, paths::BOUNTIES_DIR).await?;
        // `filter_map` keeps what the closure gives as `Some`: here the id
        // of each `Bounty` entry, and nothing for any other file.
        Ok(listing
            .entries
            .into_iter()
            .filter_map(|entry| match entry {
                SweepkyPath::Bounty(id) => Some(id),
                _ => None,
            })
            .collect())
    }

    /// The ids of the sweep records `owner`'s `sweeps/` lists, in the order
    /// listed.
    async fn list_sweeps(&self, owner: Pubky) -> anyhow::Result<Vec<RecordId>> {
        let listing = self.list(owner, paths::SWEEPS_DIR).await?;
        Ok(listing
            .entries
            .into_iter()
            .filter_map(|entry| match entry {
                SweepkyPath::SweepRecord(id) => Some(id),
                _ => None,
            })
            .collect())
    }
}

/// The message for bytes at `path` of `owner` that are not a `kind`
/// record: the path and the owner, which this build built and checked, and
/// never the bytes. Core's `RecordError` follows it as the cause.
pub(crate) fn not_a_record(kind: &str, path: &str, owner: Pubky) -> String {
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

    async fn list(&self, owner: Pubky, dir: &str) -> anyhow::Result<Listing> {
        let key = public_key_of(&owner)?;
        list_dir(self.client, &key, dir, ListLimits::DEFAULT).await
    }

    async fn list_newest_first(
        &self,
        owner: Pubky,
        dir: &str,
        seen: Option<RecordId>,
    ) -> anyhow::Result<Listing> {
        let key = public_key_of(&owner)?;
        list_dir_newest_first(self.client, &key, dir, ListLimits::DEFAULT, seen).await
    }

    async fn get_record_if_changed(
        &self,
        owner: Pubky,
        path: &str,
        etag: Option<&ETag>,
    ) -> anyhow::Result<Conditional> {
        let key = public_key_of(&owner)?;
        get_public_if_changed(self.client, &key, path, etag).await
    }

    async fn get_package(&self, sweep: SweepRef) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        let key = public_key_of(&sweep.sweeper)?;
        remote::get_package(self.client, &key, sweep.id).await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sweepky_core::paths::{self, SweepkyPath};
    use sweepky_core::{BountyRef, MAX_RECORD_BYTES, Pubky, SweepRef};

    use super::PublicRecords;
    use crate::remote::Conditional;
    use crate::test_support::{
        FakePublicRecords, PLANTED, bounty_id, bounty_json, circle_json, json_bytes, random_pubky,
        record_id, repo_target_json, sweep_json,
    };

    /// A running sweep of target t1 of `owner`'s synthetic bounty.
    fn running_sweep_json(owner: Pubky) -> Value {
        let bounty = BountyRef {
            owner,
            id: bounty_id(),
        };
        sweep_json(bounty, &["t1"], "running")
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
            .with_file(sweeper, &sweep_path, json_bytes(&running_sweep_json(owner)));

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
        for body in bad_bodies(running_sweep_json(owner)) {
            let records = FakePublicRecords::default().with_file(
                owner,
                &paths::sweep_record(bounty_id()),
                body,
            );
            let err = records.get_sweep(sweep).await.expect_err("refused");
            assert_refused_unquoted(&err, "sweep");
        }
    }

    #[tokio::test]
    async fn the_listings_give_the_owner_s_record_ids_and_drop_other_files() {
        let (owner, other) = (random_pubky(), random_pubky());
        let records = FakePublicRecords::default()
            .with_file(owner, &paths::bounty(record_id(2)), Vec::new())
            .with_file(owner, &paths::discovered(record_id(2)), Vec::new())
            .with_file(owner, &paths::bounty(record_id(1)), Vec::new())
            .with_file(owner, &paths::sweep_record(record_id(3)), Vec::new())
            .with_file(owner, &paths::sweep_package(record_id(3)), Vec::new())
            .with_file(owner, paths::circle(), Vec::new())
            .with_file(other, &paths::bounty(record_id(4)), Vec::new());

        let bounties = records.list_bounties(owner).await.expect("listed");
        assert_eq!(bounties, [record_id(1), record_id(2)]);
        let sweeps = records.list_sweeps(owner).await.expect("listed");
        assert_eq!(sweeps, [record_id(3)]);
        // One listing each, of the owner's own directory.
        assert_eq!(
            records.asked(),
            [
                (owner, paths::BOUNTIES_DIR.to_owned()),
                (owner, paths::SWEEPS_DIR.to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn a_listing_refused_is_an_error_that_names_the_directory() {
        let owner = random_pubky();
        let records = FakePublicRecords::default()
            .with_broken_listing(owner, paths::BOUNTIES_DIR)
            .with_broken_listing(owner, paths::SWEEPS_DIR);
        for err in [
            records.list_bounties(owner).await.expect_err("refused"),
            records.list_sweeps(owner).await.expect_err("refused"),
        ] {
            let message = format!("{err:#}");
            assert!(
                message.contains("could not list /pub/sweepky/"),
                "{message}"
            );
            assert!(
                message.contains("more entries than were asked for"),
                "{message}"
            );
        }
    }

    #[tokio::test]
    async fn a_newest_first_listing_stops_at_the_newest_id_already_seen() {
        let owner = random_pubky();
        let records = FakePublicRecords::default()
            .with_file(owner, &paths::bounty(record_id(1)), Vec::new())
            .with_file(owner, &paths::bounty(record_id(2)), Vec::new())
            .with_file(owner, &paths::bounty(record_id(3)), Vec::new())
            .with_file(owner, &paths::discovered(record_id(3)), Vec::new());
        let bounty = |n| SweepkyPath::Bounty(record_id(n));

        // Newest first: a bounty's record sorts after its `.discovered.json`.
        let all = records
            .list_newest_first(owner, paths::BOUNTIES_DIR, None)
            .await
            .expect("listed");
        assert_eq!(
            all.entries,
            [
                bounty(3),
                SweepkyPath::Discovered(record_id(3)),
                bounty(2),
                bounty(1)
            ]
        );
        // Stopped at the newest id already seen, which is not listed again.
        let since_1 = records
            .list_newest_first(owner, paths::BOUNTIES_DIR, Some(record_id(1)))
            .await
            .expect("listed");
        assert_eq!(
            since_1.entries,
            [bounty(3), SweepkyPath::Discovered(record_id(3)), bounty(2)]
        );
        let since_3 = records
            .list_newest_first(owner, paths::BOUNTIES_DIR, Some(record_id(3)))
            .await
            .expect("listed");
        assert!(since_3.entries.is_empty());
        // The oldest-first listing is as it was.
        let oldest_first = records
            .list(owner, paths::BOUNTIES_DIR)
            .await
            .expect("listed");
        assert_eq!(
            oldest_first.entries,
            [
                bounty(1),
                bounty(2),
                SweepkyPath::Discovered(record_id(3)),
                bounty(3)
            ]
        );
        assert_eq!(
            records.asked(),
            vec![(owner, paths::BOUNTIES_DIR.to_owned()); 4]
        );
    }

    #[tokio::test]
    async fn a_conditional_get_is_answered_by_the_content_hash() {
        let owner = random_pubky();
        let path = paths::bounty(bounty_id());
        let first = bounty_json(json!([]));
        let records = FakePublicRecords::default().with_record(owner, &path, &first);

        // Without a tag, the record and the tag to send next time.
        let Conditional::Changed {
            body,
            etag: Some(tag),
        } = records
            .get_record_if_changed(owner, &path, None)
            .await
            .expect("read")
        else {
            panic!("a first read is a change, with a tag");
        };
        assert_eq!(body.as_slice(), json_bytes(&first));
        // The tag sent back while the bytes are the same: unchanged.
        let again = records
            .get_record_if_changed(owner, &path, Some(&tag))
            .await
            .expect("read");
        assert!(matches!(again, Conditional::NotModified));

        // Once the bytes change, the old tag no longer matches.
        let second = bounty_json(json!([repo_target_json("t1")]));
        let records = records.with_record(owner, &path, &second);
        let Conditional::Changed {
            body,
            etag: Some(new_tag),
        } = records
            .get_record_if_changed(owner, &path, Some(&tag))
            .await
            .expect("read")
        else {
            panic!("changed bytes are a change, with a tag");
        };
        assert_eq!(body.as_slice(), json_bytes(&second));
        assert_ne!(new_tag, tag);

        // A record that is not there is absent.
        let missing = paths::bounty(record_id(9));
        let gone = records
            .get_record_if_changed(owner, &missing, Some(&tag))
            .await
            .expect("read");
        assert!(matches!(gone, Conditional::Absent));

        // Every request is recorded.
        assert_eq!(
            records.asked(),
            [
                (owner, path.clone()),
                (owner, path.clone()),
                (owner, path),
                (owner, missing),
            ]
        );
    }

    #[tokio::test]
    async fn a_package_is_read_from_the_sweeper_s_age_file() {
        let sweeper = random_pubky();
        let package_path = paths::sweep_package(record_id(3));
        let records = FakePublicRecords::default()
            .with_file(sweeper, &package_path, b"sealed bytes".to_vec())
            .with_file(sweeper, &paths::sweep_record(record_id(4)), Vec::new());

        let package = records
            .get_package(SweepRef {
                sweeper,
                id: record_id(3),
            })
            .await
            .expect("read")
            .expect("there");
        assert_eq!(package.as_slice(), b"sealed bytes");
        // A sweep with a record and no package has none.
        let unsubmitted = records
            .get_package(SweepRef {
                sweeper,
                id: record_id(4),
            })
            .await
            .expect("a 404 is no error");
        assert!(unsubmitted.is_none());
        assert_eq!(
            records.asked(),
            [
                (sweeper, package_path),
                (sweeper, paths::sweep_package(record_id(4))),
            ]
        );
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
