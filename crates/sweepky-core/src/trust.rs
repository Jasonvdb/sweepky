//! Trust labels: how far a reader trusts a pubky, computed from a roster and
//! the credits on the bounties its admin and members marked done.
//!
//! The rule is on [`trust_labels`], because this module is private and only
//! the re-exported items appear in the crate's docs. It has two
//! implementations, this one (the CLI's) and the board's TypeScript badge
//! (P4). `fixtures/README.md` states the rule for both, and both assert
//! `fixtures/trust-labels.json`, so a change to the rule changes that file
//! and the board in the same change.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::pubky::Pubky;
use crate::records::{Bounty, BountyStatus, Circle, KnownBountyStatus};

/// How far a reader trusts a pubky: `circle`, `known` or `unknown`.
///
/// Serializes in lower case, as `fixtures/trust-labels.json` writes it.
// A closed enum, unlike the open-string enums records use (`open_enum!`):
// those exist so a value a newer client writes still parses, but a label is
// computed here and never read from a record, so there is no foreign value
// to keep. For the same reason it derives `Serialize` only: a label someone
// else wrote down is never something to trust, so there is nothing to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLabel {
    /// In the roster (the admin, or listed in `members`), whatever its tally.
    Circle,
    /// Not in the roster, but credited on at least one counted bounty. The
    /// [`CreditTally`] says on how many, and from how many owners.
    Known,
    /// Neither in the roster nor credited on any counted bounty.
    Unknown,
}

/// The credits that counted for a pubky: the bounties and the distinct owners
/// behind them.
// `Default` is the zero tally, `{ bounties: 0, owners: 0 }`, for a pubky
// nothing credits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CreditTally {
    /// The number of counted bounties that credit the pubky. A bounty counts
    /// once, however many times its `credits` name the pubky.
    pub bounties: u64,
    /// The number of distinct owners among those bounties. Reputation built
    /// by one owner, perhaps through alternate identities, reads as
    /// `owners: 1` however many bounties it spans
    /// (`docs/plan/06-verification-and-limits.md`, "Known limits").
    pub owners: u64,
}

/// A pubky's [`TrustLabel`] and its [`CreditTally`].
///
/// Serializes as `{"label": "known", "bounties": 2, "owners": 1}`, the shape
/// of an `expected` entry in `fixtures/trust-labels.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Trust {
    /// The label.
    pub label: TrustLabel,
    /// The credits that counted. Circle members have one too: their label is
    /// always `circle`, and only the tally shows, for example, that a
    /// self-credit added nothing.
    // `flatten` writes the tally's two fields beside `label` rather than
    // nested under a `tally` key.
    #[serde(flatten)]
    pub tally: CreditTally,
}

/// The [`Trust`] of a pubky that is in no roster and no bounty.
const UNSEEN: Trust = Trust {
    label: TrustLabel::Unknown,
    tally: CreditTally {
        bounties: 0,
        owners: 0,
    },
};

/// What [`trust_labels`] reads from one bounty: its owner, its status and its
/// credits.
///
/// A bounty record does not name its owner; the key in its path does
/// (`pubky://<owner>/pub/sweepky/bounties/<id>.json`). So build one with
/// [`from_bounty`](Self::from_bounty), passing the owner from the path the
/// record was fetched from.
///
/// Pass every bounty, whatever its status or owner: [`trust_labels`] decides
/// what counts. Pass each bounty record once, though, since two entries for
/// one record count as two bounties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditedBounty {
    /// The bounty's owner: the key in the record's path.
    pub owner: Pubky,
    /// The bounty's `status`, exactly as written.
    pub status: BountyStatus,
    /// The bounty's `credits`, exactly as written: the list may name the
    /// owner, or one sweeper twice.
    pub credits: Vec<Pubky>,
}

impl CreditedBounty {
    /// The parts of `bounty` the trust label reads, owned by `owner`, the key
    /// in the path `bounty` was read from.
    // `&Bounty`: the bounty is only borrowed, so the caller keeps it.
    // `clone()` and `to_vec()` copy out what this struct owns (a short string
    // and a list of 32-byte keys), so it holds no reference into the bounty
    // and needs no lifetime parameter.
    pub fn from_bounty(owner: Pubky, bounty: &Bounty) -> Self {
        Self {
            owner,
            status: bounty.status().clone(),
            credits: bounty.credits().to_vec(),
        }
    }

    /// Whether this bounty's credits count: it is done and its owner is in
    /// the roster.
    fn is_counted(&self, circle: &Circle) -> bool {
        // `as_known` matches the status string exactly, so `Done`, `closed`
        // or a status a newer client adds is not `done`: when in doubt, a
        // bounty counts for nothing.
        self.status.as_known() == Some(KnownBountyStatus::Done) && circle.is_in_roster(self.owner)
    }

    /// The sweepers this bounty credits, each once and without its owner.
    fn credited_sweepers(&self) -> BTreeSet<Pubky> {
        // Collecting into a set drops a repeated credit, so one bounty adds at
        // most one to a pubky's `bounties`. `filter` hands the closure a
        // `&Pubky`, and the pattern `|&credit|` copies the key out of it.
        // `Pubky`'s `!=` compares the 32 key bytes, so the owner is skipped
        // whichever spelling the credit was written in. It is not
        // constant-time and need not be: these are public keys.
        self.credits
            .iter()
            .copied()
            .filter(|&credit| credit != self.owner)
            .collect()
    }
}

/// Every pubky [`trust_labels`] saw, each with its [`Trust`].
///
/// "Seen" means named anywhere in its input: the roster's admin and members,
/// and every bounty's owner and credits, on bounties that counted or not.
// The field is private, so `trust_labels` is the only way to build a table.
// A `BTreeMap` iterates in key order, here the order of the key bytes, so
// anything printed from a table comes out the same on every run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustTable(BTreeMap<Pubky, Trust>);

impl TrustTable {
    /// The trust of `pubky`.
    ///
    /// A pubky the table does not hold was in neither the roster nor any
    /// bounty, so it is `unknown` with nothing counted, the same as one that
    /// was seen and earned nothing.
    // `Pubky` and `Trust` are both `Copy`, so the key goes in by value and the
    // trust comes out by value: `copied()` turns the map's `Option<&Trust>`
    // into an `Option<Trust>`.
    pub fn get(&self, pubky: Pubky) -> Trust {
        self.0.get(&pubky).copied().unwrap_or(UNSEEN)
    }

    /// Every pubky seen and its trust, in the order of the key bytes (which
    /// is not the order of their z-base32 strings).
    // The returned iterator borrows the table, so it cannot outlive it. In
    // edition 2024 an `impl Trait` return type captures that borrow of `self`
    // without a `+ '_`. Each item is copied out, so callers get plain values
    // rather than references into the map.
    pub fn iter(&self) -> impl Iterator<Item = (Pubky, Trust)> {
        self.0.iter().map(|(&pubky, &trust)| (pubky, trust))
    }
}

/// The trust label and credit tally of every pubky named in `circle` or in
/// `bounties`.
///
/// The rule comes from 01 ("Records (v1)"), with the owner count that 00's
/// trust model adds to `known`. For each pubky:
///
/// - A credit counts only on a bounty whose `status` is `done` and whose owner
///   is trusted: in v1, anyone in the roster ([`Circle::is_in_roster`], the
///   admin and every entry in `members`, so an admin missing from `members`
///   is still trusted).
/// - A credit naming the bounty's own owner counts for nothing. The CLI never
///   writes one, but anyone can hand-write their own records, so the read
///   side is where the rule holds.
/// - `bounties` is the number of counted bounties crediting the pubky, each
///   once however many times it names the pubky, and `owners` the number of
///   distinct owners among them.
/// - The label is `circle` for anyone in the roster, whatever its tally; else
///   `known` if `bounties` > 0; else `unknown`.
///
/// Pass the whole list of bounties you have: open ones, ones from owners
/// outside the roster, ones whose credits name their own owner. This function
/// skips what does not count, so no caller has a filter to forget.
///
/// A pure function: it reads no clock, does no I/O and cannot panic.
pub fn trust_labels(circle: &Circle, bounties: &[CreditedBounty]) -> TrustTable {
    let tallies = count_credits(circle, bounties);
    // `into_iter()` consumes the set, moving each key out; `collect()` builds
    // the map from the `(key, value)` pairs.
    let table = seen_pubkys(circle, bounties)
        .into_iter()
        .map(|pubky| {
            let tally = tallies
                .get(&pubky)
                .map(RunningTally::tally)
                .unwrap_or_default();
            let label = label_for(circle, pubky, tally);
            (pubky, Trust { label, tally })
        })
        .collect();
    TrustTable(table)
}

/// For each pubky credited on a counted bounty, the bounties and their owners.
fn count_credits(circle: &Circle, bounties: &[CreditedBounty]) -> BTreeMap<Pubky, RunningTally> {
    let mut tallies: BTreeMap<Pubky, RunningTally> = BTreeMap::new();
    for bounty in bounties.iter().filter(|bounty| bounty.is_counted(circle)) {
        for sweeper in bounty.credited_sweepers() {
            // `entry(..).or_default()` finds the pubky's tally, inserting an
            // empty one first if it has none, and hands back a mutable
            // reference to it.
            tallies.entry(sweeper).or_default().add_bounty(bounty.owner);
        }
    }
    tallies
}

/// Every pubky named in `circle` or `bounties`: the admin, the members, and
/// every bounty's owner and credits, counted or not. Each gets an entry in the
/// table, so a caller can list strangers as well as members.
fn seen_pubkys(circle: &Circle, bounties: &[CreditedBounty]) -> BTreeSet<Pubky> {
    let mut seen = BTreeSet::new();
    seen.insert(circle.admin);
    seen.extend(circle.members.iter().map(|member| member.pubky));
    for bounty in bounties {
        seen.insert(bounty.owner);
        seen.extend(bounty.credits.iter().copied());
    }
    seen
}

/// The label for `pubky`, given its tally.
fn label_for(circle: &Circle, pubky: Pubky, tally: CreditTally) -> TrustLabel {
    if circle.is_in_roster(pubky) {
        TrustLabel::Circle
    } else if tally.bounties > 0 {
        TrustLabel::Known
    } else {
        TrustLabel::Unknown
    }
}

/// A pubky's counted credits while [`trust_labels`] adds them up.
#[derive(Default)]
struct RunningTally {
    /// Counted bounties crediting the pubky.
    bounties: u64,
    /// Their distinct owners.
    owners: BTreeSet<Pubky>,
}

impl RunningTally {
    /// Counts one more bounty crediting the pubky, owned by `owner`.
    fn add_bounty(&mut self, owner: Pubky) {
        // `saturating_add` stops at `u64::MAX` instead of overflowing, which
        // would panic in a debug build. A slice cannot hold that many
        // bounties, so it never saturates, but it costs nothing.
        self.bounties = self.bounties.saturating_add(1);
        // A set, so a second bounty from the same owner adds no owner.
        self.owners.insert(owner);
    }

    fn tally(&self) -> CreditTally {
        CreditTally {
            bounties: self.bounties,
            // `try_from` rather than `as`: `as` would silently cut a value
            // that does not fit. A `usize` always fits a `u64` on the
            // platforms Rust supports today, so the fallback never runs.
            owners: u64::try_from(self.owners.len()).unwrap_or(u64::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde::Deserialize;
    use serde_json::json;

    use super::{CreditTally, CreditedBounty, Trust, TrustLabel, TrustTable, trust_labels};
    use crate::ids::RecordId;
    use crate::pubky::Pubky;
    use crate::records::{Bounty, BountyStatus, Circle, KnownBountyStatus};

    /// The fixture both trust-label implementations assert:
    /// `fixtures/README.md` is its spec.
    const FIXTURE: &str = include_str!("../../../fixtures/trust-labels.json");

    /// Roster members A (also the admin), B and D; X, an owner outside the
    /// roster; and the sweepers S1 to S4. Names as in `fixtures/README.md`.
    const A: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
    const B: &str = "btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy";
    const D: &str = "5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco";
    const X: &str = "z5quft985i4g55uz4ccsxn9r8qnmmk48kmmn6byyyoacu4u37rny";
    const S1: &str = "a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy";
    const S2: &str = "kmjs3ec6imcijf5wknsbfrh1bk4ariso7en8tteestniygu159xo";
    const S3: &str = "qwujy4epafpmfei7bxn8fccfm1shzqp516sbenxi7qr6gua4n77o";
    const S4: &str = "3rus98p3q6naiqxckzo676jeewj1whf6ai8911mxacshks18eq3y";

    /// D's done bounty that credits D, its own owner, and S2.
    const SELF_CREDIT: &str = "0035JREYBXX7T";

    /// The whole fixture file. `deny_unknown_fields` makes a field this test
    /// does not read fail the test, rather than be silently ignored.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        /// A full `circle.json` record, read through `Circle::from_json`.
        roster: serde_json::Value,
        bounties: Vec<FixtureBounty>,
        /// Each entry in `Trust`'s own JSON shape.
        expected: BTreeMap<Pubky, serde_json::Value>,
    }

    /// A `bounties` entry: a reduced test shape with the owner and id inlined,
    /// which the real record takes from its path.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureBounty {
        id: RecordId,
        owner: Pubky,
        status: BountyStatus,
        credits: Vec<Pubky>,
    }

    impl Fixture {
        fn load() -> Self {
            serde_json::from_str(FIXTURE).unwrap()
        }

        fn roster(&self) -> Circle {
            Circle::from_json(self.roster.to_string().as_bytes()).unwrap()
        }

        /// The roster with its admin, A, taken out of `members`, so A is in
        /// it as the admin alone.
        fn roster_without_admin_in_members(&self) -> Circle {
            let mut roster = self.roster();
            // `Pubky` is `Copy`, so this copies the admin's key out, and
            // `retain` keeps only the members the closure returns `true` for.
            let admin = roster.admin;
            roster.members.retain(|member| member.pubky != admin);
            roster
        }

        /// Every bounty in the file, open ones and the outsider's included.
        fn bounties(&self) -> Vec<CreditedBounty> {
            self.bounties.iter().map(FixtureBounty::credited).collect()
        }

        fn bounty(&self, id: &str) -> CreditedBounty {
            let id: RecordId = id.parse().unwrap();
            self.bounties
                .iter()
                .find(|bounty| bounty.id == id)
                .unwrap()
                .credited()
        }

        fn table(&self) -> TrustTable {
            trust_labels(&self.roster(), &self.bounties())
        }
    }

    impl FixtureBounty {
        fn credited(&self) -> CreditedBounty {
            CreditedBounty {
                owner: self.owner,
                status: self.status.clone(),
                credits: self.credits.clone(),
            }
        }
    }

    fn pubky(text: &str) -> Pubky {
        text.parse().unwrap()
    }

    fn trust(label: TrustLabel, bounties: u64, owners: u64) -> Trust {
        Trust {
            label,
            tally: CreditTally { bounties, owners },
        }
    }

    /// A done bounty owned by `owner` that credits `credits`.
    fn done(owner: &str, credits: &[&str]) -> CreditedBounty {
        CreditedBounty {
            owner: pubky(owner),
            status: KnownBountyStatus::Done.into(),
            credits: credits.iter().map(|credit| pubky(credit)).collect(),
        }
    }

    #[test]
    fn every_expected_entry_gets_its_label_and_tally() {
        let fixture = Fixture::load();
        let table = fixture.table();
        for (&pubky, expected) in &fixture.expected {
            // An entry is written as a `Trust` serializes, so one comparison
            // checks the label, in the lower case the board's test reads too,
            // and both counts.
            let got = serde_json::to_value(table.get(pubky)).unwrap();
            assert_eq!(&got, expected, "{pubky}");
        }
    }

    #[test]
    fn the_table_holds_exactly_the_pubkys_in_the_fixture() {
        // The admin, the members, every owner and every credited sweeper, on
        // counted bounties or not.
        let fixture = Fixture::load();
        let listed: BTreeSet<Pubky> = fixture.table().iter().map(|(pubky, _)| pubky).collect();
        let expected: BTreeSet<Pubky> = fixture.expected.keys().copied().collect();
        assert_eq!(listed, expected);
    }

    #[test]
    fn get_returns_the_trust_that_iter_lists() {
        let table = Fixture::load().table();
        for (pubky, trust) in table.iter() {
            assert_eq!(table.get(pubky), trust, "{pubky}");
        }
    }

    #[test]
    fn a_self_credit_adds_nothing_to_the_owner() {
        let fixture = Fixture::load();
        let table = fixture.table();
        // D's one counted credit is B's bounty 0035N9QXF25NG; 2 / 2 would
        // mean D's credit to itself counted. S2 still gets that bounty's
        // credit, and A's.
        assert_eq!(table.get(pubky(D)), trust(TrustLabel::Circle, 1, 1));
        assert_eq!(table.get(pubky(S2)), trust(TrustLabel::Known, 2, 2));

        // The self-crediting bounty on its own.
        let alone = trust_labels(&fixture.roster(), &[fixture.bounty(SELF_CREDIT)]);
        assert_eq!(alone.get(pubky(D)), trust(TrustLabel::Circle, 0, 0));
        assert_eq!(alone.get(pubky(S2)), trust(TrustLabel::Known, 1, 1));
    }

    #[test]
    fn a_self_credit_is_skipped_whichever_spelling_names_the_owner() {
        // D's self-crediting bounty as a hand-written record, with the
        // self-credit in the `pubky<z32>` spelling and the owner, as from the
        // record's path, in raw z32: the key bytes are equal, so it is still
        // skipped.
        let record = json!({
            "schemaVersion": 1,
            "title": "D's own bounty",
            "focus": "security",
            "brief": "Hand-written.",
            "playbook": { "required": false },
            "targets": [],
            "status": "done",
            "credits": [format!("pubky{D}"), S2],
            "createdAt": "2026-09-01T10:00:00Z",
            "doneAt": "2026-09-08T10:00:00Z",
        });
        let bounty = Bounty::from_json(record.to_string().as_bytes()).unwrap();
        let credited = CreditedBounty::from_bounty(pubky(D), &bounty);
        let table = trust_labels(&Fixture::load().roster(), &[credited]);
        assert_eq!(table.get(pubky(D)), trust(TrustLabel::Circle, 0, 0));
        assert_eq!(table.get(pubky(S2)), trust(TrustLabel::Known, 1, 1));
    }

    #[test]
    fn only_done_bounties_from_roster_members_count() {
        let table = Fixture::load().table();
        // S3's only credits are on A's open bounty 0035Q0RCGQAHP and on
        // X's done bounty 0035TR7XPGKP0.
        assert_eq!(table.get(pubky(S3)), trust(TrustLabel::Unknown, 0, 0));
        // X's bounty also credits S1: 3 / 3 would mean it counted.
        assert_eq!(table.get(pubky(S1)), trust(TrustLabel::Known, 2, 2));
        // An owner outside the roster, credited by nobody.
        assert_eq!(table.get(pubky(X)), trust(TrustLabel::Unknown, 0, 0));
    }

    #[test]
    fn a_bounty_counts_once_however_often_it_credits_a_pubky() {
        let table = Fixture::load().table();
        // A names S4 twice on 0035G87EK4XFE, which counts once: 3 / 1 would
        // mean the duplicate counted. Two bounties from one owner read as
        // `owners: 1`.
        assert_eq!(table.get(pubky(S4)), trust(TrustLabel::Known, 2, 1));
    }

    #[test]
    fn a_status_that_is_not_exactly_done_counts_for_nothing() {
        // `status` is an open string matched exactly: a value this build does
        // not know as `done` is not done.
        let roster = Fixture::load().roster();
        for status in ["Done", "closed", ""] {
            let mut bounty = done(A, &[S3]);
            bounty.status = serde_json::from_value(json!(status)).unwrap();
            let table = trust_labels(&roster, &[bounty]);
            assert_eq!(
                table.get(pubky(S3)),
                trust(TrustLabel::Unknown, 0, 0),
                "{status:?}"
            );
        }
    }

    #[test]
    fn a_pubky_seen_nowhere_is_unknown() {
        let table = Fixture::load().table();
        let stranger = Pubky::from_bytes([7; 32]);
        assert_eq!(table.get(stranger), trust(TrustLabel::Unknown, 0, 0));
        assert!(table.iter().all(|(pubky, _)| pubky != stranger));
    }

    #[test]
    fn an_admin_left_out_of_members_is_a_trusted_owner() {
        // As in 06's end-to-end test, A is the admin and the bounty's owner;
        // here `members` leaves A out. A's done bounty credits B, a member,
        // and S3, a stranger.
        let roster = Fixture::load().roster_without_admin_in_members();
        let table = trust_labels(&roster, &[done(A, &[B, S3])]);

        assert_eq!(table.get(pubky(A)), trust(TrustLabel::Circle, 0, 0));
        assert_eq!(table.get(pubky(B)), trust(TrustLabel::Circle, 1, 1));
        // S3 would be `unknown` if A's bounty were an untrusted owner's.
        assert_eq!(table.get(pubky(S3)), trust(TrustLabel::Known, 1, 1));
    }

    #[test]
    fn leaving_the_admin_out_of_members_changes_no_label_or_tally() {
        // fixtures/README.md: the roster is the admin and every entry in
        // `members`. The fixture lists its admin, A, in `members` as well;
        // this roster leaves A out.
        let fixture = Fixture::load();
        let mut bounties = fixture.bounties();
        // B, a member, credits the admin: A stays `circle`, and the credit
        // still shows in A's tally.
        bounties.push(done(B, &[A]));
        let table = trust_labels(&fixture.roster_without_admin_in_members(), &bounties);

        // Every label and tally is the one the fixture's own roster gives.
        assert_eq!(table, trust_labels(&fixture.roster(), &bounties));
        assert_eq!(table.get(pubky(A)), trust(TrustLabel::Circle, 1, 1));
        // A's done bounties (0035G87EK4XFE and 0035M2DX3Q44W) are a trusted
        // owner's: S4's credits all came from A.
        assert_eq!(table.get(pubky(S4)), trust(TrustLabel::Known, 2, 1));
    }
}
