//! `sweepky pull` (P2c): the owner's command that reads what is new about
//! their bounties, opens the sweeps it may open, groups their findings and
//! publishes the strangers' sweeps it found. [`pull`] runs these steps, in
//! this order, each in a module of its own:
//!
//! 1. **The logged-in owner and this install's device key**, `login.json`
//!    and `device.key` (unwrapped with `--passphrase-file`), both read
//!    before any network read ([`ThisInstall::read`]): an install that is
//!    not logged in, has no key, or has a wrapped key and no passphrase
//!    fails having asked nothing of anyone. The key is read once, lent to
//!    the opens alone, and dropped, which wipes it, as soon as they finish.
//! 2. **The roster poll** (`roster`): the owner's circle and each of its
//!    keys' bounties and sweeps, every key's homeserver looked up once a run
//!    (`resolve`), on production through the host policy.
//! 3. **The key-alarm check** of the owner's `keys/` (`keys::key_alarms`,
//!    the check `keys list` and `login` make): an unknown or replaced key is
//!    an alarm, and so is a check that could not finish, since what it did
//!    not read could be such a key. `login` warns of that; `pull`, which an
//!    owner runs every time they read sweeps, says it as loudly as an alarm.
//! 4. **The feed watcher** (`feed`): each watched homeserver's events feed
//!    and each open bounty's `discovered.json`, for strangers' sweeps of
//!    the owner's open bounties. The poll state is written after it.
//! 5. **The opens** (`open`, which stores through `store`): each new done
//!    sweep fetched, decrypted with the key, checked and stored owner-only,
//!    strangers' in `untrusted/`. Then the key is dropped and the poll state
//!    written again.
//! 6. **Regrouping** (`triage`): each bounty's `groups.json` and
//!    `merged.json`, the second the circle's findings alone.
//! 7. **The `discovered.json` write** (`discovered`), `pull`'s one public
//!    write and the one step that takes the writers' lock, with a fresh
//!    session that is always signed out, and only when a file's sweeps
//!    change.
//!
//! `state` is the local state `pull` keeps between runs, whose feed cursors
//! `post --open` writes too.
//!
//! **One pull at a time.** After step 1, `pull` takes the pull lock
//! (`lock::PullLock`, on `<config>/pull.lock`) and holds it to the end of
//! step 7, so a second `pull` of this install, a scheduled one beside a
//! manual one, waits for the first, says so on standard error, and gives
//! up past the lock's timeout saying another pull is running. Each step
//! writes the local state back whole, built from what the run read as it
//! started, so two runs at once would write over each other's steps. The
//! writers' lock is still taken in step 7 alone: held for the whole run, it
//! would keep `post`, `run`, `submit` and `done` waiting on every `pull`.
//!
//! **The report** says, after any alarm: for each watched homeserver whose
//! feed was read, the cursor its read started after and where that cursor
//! came from (this install's `feed-cursors.json`, an open bounty's
//! `discovered.json`, or a search for the feed's head), in fixed text; for
//! each sweep of each of the owner's bounties that `pull` reads, its
//! sweeper's trust label (`circle`, `known: N credits across M owners` or
//! `unknown`), its record's status and where it is stored, or why it is
//! not; and the warnings of every step. A status is a stranger's text, so
//! everything a record says goes through `display::sanitize`; the rest is
//! keys, URLs and paths core and Sweepky built, numbers and fixed text. No
//! finding, recipient, secret or server text is printed.

pub(crate) mod discovered;
pub(crate) mod feed;
pub(crate) mod open;
pub(crate) mod resolve;
pub(crate) mod roster;
pub(crate) mod state;
pub(crate) mod store;
pub(crate) mod triage;

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context as _, bail};
use sweepky_core::paths;
use sweepky_core::{
    BountyRef, DeviceIdentity, KnownBountyStatus, KnownSweepStatus, Pubky, RecordId, SweepRef,
    Trust, TrustLabel, TrustTable, trust_labels,
};

use self::discovered::{LockedSession, Published, WriteUnderLock, publish_discovered};
use self::feed::{
    FeedReaders, FeedWatch, Start, StartSource, open_to_strangers, watch_open_bounties,
};
use self::open::{Opened, open_sweeps};
use self::resolve::{CheckedHomeservers, Homeservers, PkarrHomeservers, ResolveHomeserver};
use self::roster::{RosterPoll, poll_roster};
use self::state::{BountySummary, PollState, SweepSummary};
use self::store::{Stored, stored_sweep_dir};
use self::triage::{GROUPS_FILE, MERGED_FILE, Triaged, triage_bounties};
use crate::device::{PublicKeyReader, PublicKeys, read_device_key};
use crate::display::{MAX_LABEL_CHARS, sanitize};
use crate::events::{EventsFeed, HomeserverEvents, SEARCH_PACE};
use crate::installs::read_installs;
use crate::keys::key_alarms;
use crate::lock::PullLock;
use crate::passphrase::Passphrase;
use crate::records::{PublicRecordReader, PublicRecords};
use crate::remote::{pubky_of, public_key_of};
use crate::session::NOT_LOGGED_IN;
use crate::state::{LoginState, read_login_state};
use crate::targets::host::SystemResolver;
use crate::{Context, Dirs, Report};

/// What `pull` says when this install has no device key: without one it
/// can open no sweep, and only `login` makes one.
const NO_DEVICE_KEY: &str =
    "this install has no device key, so pull cannot open sweeps: run `sweepky login`";

/// What `pull` says while another `pull` of this install holds the pull
/// lock.
const WAITING_FOR_PULL: &str =
    "waiting for another sweepky pull on this install to finish (it holds the pull lock)";

/// What `pull` adds to a failure to write the poll state back.
const STATE_NOT_SAVED: &str = "pull could not save what it read this time";

/// The most characters of a path the report shows: far past any real
/// data directory, and still a bound.
const MAX_PATH_CHARS: usize = 4096;

/// Runs `sweepky pull` for the identity this install is logged in as: see
/// the module docs.
///
/// Everything comes from `ctx`, never from the process environment: the
/// directories, the passphrase, and the network with its watch list.
pub(crate) async fn pull(ctx: &Context) -> anyhow::Result<Report> {
    // First, before anything below could send a request.
    let install = ThisInstall::read(&ctx.dirs, ctx.passphrase.as_ref())?;
    let client = ctx.network.pubky();
    // The real seams, each borrowing the one client. `pkarr` is both what
    // says where a key's homeserver is and where the host policy reads the
    // records it checks.
    let records = PublicRecordReader::new(client);
    let keys = PublicKeyReader::new(client);
    let feed = HomeserverEvents::new(client.client());
    let pkarr = PkarrHomeservers::new(client);
    let hosts = SystemResolver;
    let homeservers = CheckedHomeservers::new(
        &pkarr,
        &pkarr,
        &hosts,
        &install.login,
        ctx.network.settings().kind(),
    );
    let writer = LockedSession::new(ctx, install.login.pubky);
    let seams = Seams {
        records: &records,
        keys: &keys,
        feed: &feed,
        homeservers: &homeservers,
        writer: &writer,
        pace: SEARCH_PACE,
    };
    // One pull at a time on this install, from its first read of the local
    // state to its last write (`crate::lock`). `install` moves into the
    // closure, which `hold` calls once, and on into `pull_with`.
    let mut lock = PullLock::open(&ctx.dirs)?;
    lock.hold(
        // A courtesy, as for the writers' lock: if standard error cannot be
        // written, the pull still waits and goes on.
        || {
            let _ = ctx.stderr.line(WAITING_FOR_PULL);
        },
        async || pull_with(&seams, &ctx.dirs, install, &watched_homeservers(ctx)).await,
    )
    .await
}

/// The watch list of the context's network, as core's keys: the
/// homeservers whose events feeds `pull` reads, and `post --open` finds an
/// open bounty's starting cursors on.
pub(crate) fn watched_homeservers(ctx: &Context) -> Vec<Pubky> {
    ctx.network
        .settings()
        .watch_list()
        .iter()
        .map(pubky_of)
        .collect()
}

/// What `pull` reads of this install before anything else: the login and
/// the device key.
///
/// No `Debug`: the key has none, so that it is never printed.
struct ThisInstall {
    /// `login.json`: whose bounties are pulled, and their homeserver.
    login: LoginState,
    /// This install's age key, from `device.key`. `DeviceIdentity` wipes
    /// itself when it is dropped.
    identity: DeviceIdentity,
}

impl ThisInstall {
    /// Reads `login.json` and `device.key` from `dirs`, unwrapping the key
    /// with `passphrase`. Files only: it is given no network to read, which
    /// is how it comes before any network read.
    ///
    /// Not logged in is [`NOT_LOGGED_IN`]; no key is [`NO_DEVICE_KEY`]; a
    /// wrapped key and no passphrase is `passphrase::NeedsPassphrase`.
    fn read(dirs: &Dirs, passphrase: Option<&Passphrase>) -> anyhow::Result<Self> {
        let Some(login) = read_login_state(dirs)? else {
            bail!(NOT_LOGGED_IN);
        };
        let Some(identity) = read_device_key(dirs, passphrase)? else {
            bail!(NO_DEVICE_KEY);
        };
        Ok(Self { login, identity })
    }
}

/// What a run reads and writes through: one field per seam, so a test puts
/// a fake behind each and the command the real ones.
///
/// Generic over the five seams, as the steps' own readers are: `R` anyone's
/// public records, `K` the owner's `keys/`, `F` the events feeds, `H` where
/// each key's homeserver is, and `W` the writers' lock and a session for
/// the one public write. `'a` is how long it borrows them.
struct Seams<'a, R, K, F, H, W> {
    records: &'a R,
    keys: &'a K,
    feed: &'a F,
    homeservers: &'a H,
    writer: &'a W,
    /// The pause between a head search's requests: `SEARCH_PACE` for real
    /// homeservers, zero in the tests.
    pace: Duration,
}

/// Runs the steps of the module docs for `install`, through `seams`, with
/// the local state in `dirs` and the homeservers of `watch_list` watched,
/// and gives the report.
///
/// `install` by value: the key moves in, and is dropped here once the opens
/// are done, rather than whenever the caller's locals go. Only a failure of
/// the local files is an error; every other fault is a warning or an alarm
/// in the report.
async fn pull_with<R, K, F, H, W>(
    seams: &Seams<'_, R, K, F, H, W>,
    dirs: &Dirs,
    install: ThisInstall,
    watch_list: &[Pubky],
) -> anyhow::Result<Report>
where
    R: PublicRecords,
    K: PublicKeys,
    F: EventsFeed,
    H: ResolveHomeserver,
    W: WriteUnderLock,
{
    // Taking the struct apart moves each field out of it, so the key can be
    // dropped below while the login is still borrowed.
    let ThisInstall { login, identity } = install;
    let owner = login.pubky;
    let mut state = PollState::read(dirs, owner)?;
    // One cache for the whole run: a key is looked up once, whichever step
    // reads it first.
    let mut homeservers = Homeservers::new(seams.homeservers);
    let poll = poll_roster(seams.records, &mut homeservers, owner, &mut state).await;
    let key_check = check_keys(seams.keys, dirs, &login).await;
    // `&mut homeservers` is lent to the watcher for this call only, and
    // comes back to be lent to the opens.
    let readers = FeedReaders {
        feed: seams.feed,
        records: seams.records,
        homeservers: &mut homeservers,
        pace: seams.pace,
    };
    let watch =
        watch_open_bounties(readers, dirs, owner, &poll.roster, watch_list, &mut state).await?;
    state.write(dirs, owner).context(STATE_NOT_SAVED)?;
    let opened = open_sweeps(
        seams.records,
        &mut homeservers,
        dirs,
        &identity,
        owner,
        &poll.roster,
        &mut state,
    )
    .await;
    // The opens were the key's one use: `drop` wipes it now.
    drop(identity);
    state.write(dirs, owner).context(STATE_NOT_SAVED)?;
    let triaged = triage_bounties(dirs, &poll, &state)?;
    let published =
        publish_discovered(seams.records, seams.writer, dirs, owner, &state, &watch).await?;
    let found = Found {
        owner,
        key_check,
        open: open_to_strangers(&state, owner),
        labels: trust_labels(&poll.roster, &poll.credited),
        poll: &poll,
        state: &state,
        watch: &watch,
        opened: &opened,
        triaged: &triaged,
        published: &published,
    };
    Ok(Report::new(found.render(dirs)))
}

/// The check of `login`'s owner's `keys/` through `keys`, as the report's
/// lines: one alarm per unknown or replaced key, or, when the check could
/// not finish, one line that is an alarm too.
///
/// Never an error: a check that could not run is said in the report, and
/// the rest of the run goes on. Every line is fixed text with a device id at
/// most, and the failure's cause is `remote`'s fixed text and a status: no
/// recipient and no server text.
async fn check_keys(keys: &impl PublicKeys, dirs: &Dirs, login: &LoginState) -> Vec<String> {
    // An `async` block whose `?`s end the block, not the function, so every
    // failure lands in the one `Err` below. `?` after `key_alarms` turns its
    // typed `KeyCheckError` into an `anyhow::Error`, keeping its cause.
    let checked = async {
        let installs = read_installs(dirs)?;
        let alarms = key_alarms(
            keys,
            &public_key_of(&login.pubky)?,
            installs.installs_of(&login.pubky),
            login.device_id.as_ref(),
        )
        .await?;
        anyhow::Ok(alarms)
    }
    .await;
    match checked {
        // `KeyAlarm::line` ends in a newline, which the report adds itself.
        Ok(alarms) => alarms
            .iter()
            .map(|alarm| alarm.line().trim_end().to_owned())
            .collect(),
        Err(error) => vec![format!(
            "alarm: pull could not finish its check of keys/ for device keys this owner's \
             installs did not create ({error:#}), so a key someone added there may be going \
             unseen, and whoever holds its secret can read the sweeps encrypted to it. Run \
             `sweepky keys list` to see what keys/ holds, and `sweepky keys revoke` any key you \
             did not publish."
        )],
    }
}

/// What one run found, for its report: the run's results, borrowed, and
/// the trust labels of this run's roster and credits.
///
/// No `Debug`: the roster poll's result has none, as its circle holds a
/// stranger's text.
struct Found<'a> {
    owner: Pubky,
    /// The key check's lines ([`check_keys`]).
    key_check: Vec<String>,
    /// The owner's bounties open to strangers, by id.
    open: BTreeSet<RecordId>,
    /// The labels of every key the roster and the credits name: the table
    /// `pull::triage` labels the stored sweeps with, made from the same
    /// inputs, so the report and `groups.json` agree.
    labels: TrustTable,
    poll: &'a RosterPoll,
    state: &'a PollState,
    watch: &'a FeedWatch,
    opened: &'a Opened,
    triaged: &'a Triaged,
    published: &'a Published,
}

impl Found<'_> {
    /// The report's text: the alarms, the feeds, each bounty with its
    /// sweeps, the files published, then every warning.
    fn render(&self, dirs: &Dirs) -> String {
        let mut text = format!("Pulled for {}.\n", self.owner);
        // `chain` walks the key check's alarms, then the write's.
        for alarm in self.key_check.iter().chain(&self.published.alarms) {
            push_line(&mut text, alarm);
        }
        self.render_feeds(&mut text);
        for &bounty in &self.poll.own_bounties {
            self.render_bounty(&mut text, dirs, bounty);
        }
        for id in &self.published.written {
            push_line(&mut text, &format!("Published {}.", paths::discovered(*id)));
        }
        let warnings = self
            .poll
            .warnings
            .iter()
            .chain(&self.watch.warnings)
            .chain(&self.opened.warnings)
            .chain(&self.triaged.warnings)
            .chain(&self.published.warnings);
        for warning in warnings {
            push_line(&mut text, &format!("warning: {warning}"));
        }
        text
    }

    /// Each feed read, with the cursor its read started after and where
    /// that came from; or why none was read.
    fn render_feeds(&self, text: &mut String) {
        if !self.watch.starts.is_empty() {
            push_line(text, "Events feeds:");
            // `&start` copies each `Start` out of the map: it is `Copy`.
            for (homeserver, &start) in &self.watch.starts {
                push_line(text, &feed_line(*homeserver, start));
            }
        } else if self.open.is_empty() {
            push_line(
                text,
                "Events feeds: none read, as none of your bounties is open to strangers.",
            );
        } else {
            push_line(
                text,
                "Events feeds: none read this time; the warnings below say why.",
            );
        }
    }

    /// The owner's `bounty`: what it is, each sweep `pull` reads of it, and
    /// where its triage files are when it has any.
    fn render_bounty(&self, text: &mut String, dirs: &Dirs, bounty: BountyRef) {
        let Some(summary) = self.state.bounties.get(&bounty) else {
            return;
        };
        push_line(text, &self.bounty_heading(bounty, summary));
        let sweeps = self.sweeps_of(bounty);
        if sweeps.is_empty() {
            push_line(text, "  no sweeps yet");
        }
        for (sweep, summary) in sweeps {
            push_line(text, &self.sweep_line(dirs, bounty, sweep, summary));
        }
        if let Some(line) = self.triage_line(dirs, bounty) {
            push_line(text, &line);
        }
    }

    /// `Bounty <url> (status <s>, <whose sweeps it takes>):`.
    fn bounty_heading(&self, bounty: BountyRef, summary: &BountySummary) -> String {
        // Whose sweeps it takes, while it takes any.
        let reach = if self.open.contains(&bounty.id) {
            ", open to strangers"
        } else if summary.status.as_known() == Some(KnownBountyStatus::Open) {
            ", circle only"
        } else {
            ""
        };
        format!(
            "Bounty {bounty} (status {}{reach}):",
            sanitize(summary.status.as_str(), MAX_LABEL_CHARS)
        )
    }

    /// `  <sweep url>: <label>; <status>; <place>`, everything after the URL
    /// sanitised: the status is the sweeper's text.
    fn sweep_line(
        &self,
        dirs: &Dirs,
        bounty: BountyRef,
        sweep: SweepRef,
        summary: &SweepSummary,
    ) -> String {
        let label = label_text(self.labels.get(sweep.sweeper));
        let place = self.place_of(dirs, bounty, sweep, summary);
        format!(
            "  {sweep}: {}; {}; {}",
            sanitize(&label, MAX_LABEL_CHARS),
            sanitize(summary.status.as_str(), MAX_LABEL_CHARS),
            sanitize(&place, MAX_PATH_CHARS)
        )
    }

    /// Where `bounty`'s `groups.json` and `merged.json` are, and what they
    /// hold, or `None` when it was not triaged (nothing of it is stored).
    fn triage_line(&self, dirs: &Dirs, bounty: BountyRef) -> Option<String> {
        // `?` on an `Option` gives `None` at once when no triage is found.
        let triaged = self
            .triaged
            .bounties
            .iter()
            .find(|triaged| triaged.bounty == bounty)?;
        let merged = triaged.sweeps.iter().filter(|sweep| sweep.trusted).count();
        let line = format!(
            "  {GROUPS_FILE} and {MERGED_FILE} are in {}: {} grouped, {merged} of them the \
             circle's, whose findings alone are merged",
            dirs.pulled_bounty_dir(&bounty.id).display(),
            counted(triaged.sweeps.len(), "sweep"),
        );
        Some(sanitize(&line, MAX_PATH_CHARS))
    }

    /// The sweeps of `bounty` the report lists, each once, in upload order
    /// (a sweep id is its record's creation time): the roster's the poll
    /// found, the strangers' this install accepted for it, and any stored,
    /// such as one by a sweeper who has left the circle since, whose
    /// findings are still grouped.
    fn sweeps_of(&self, bounty: BountyRef) -> Vec<(SweepRef, &SweepSummary)> {
        // `into_iter().flatten()` on the `Option` the map lends gives
        // nothing for a bounty with no sweep accepted.
        let accepted = self
            .state
            .accepted_sweeps
            .get(&bounty.id)
            .into_iter()
            .flatten();
        let stored = self
            .state
            .sweeps
            .iter()
            .filter(|(_, summary)| summary.pulled)
            .map(|(sweep, _)| sweep);
        // A set, so a sweep in two of the lists is listed once.
        let listed: BTreeSet<SweepRef> = self
            .poll
            .sweeps
            .iter()
            .chain(accepted)
            .chain(stored)
            .copied()
            .collect();
        let mut sweeps: Vec<(SweepRef, &SweepSummary)> = listed
            .into_iter()
            .filter_map(|sweep| {
                let summary = self.state.sweeps.get(&sweep)?;
                // `then_some` gives `Some` of the pair only when the sweep
                // is of this bounty.
                (summary.bounty == bounty).then_some((sweep, summary))
            })
            .collect();
        sweeps.sort_by_key(|(sweep, _)| (sweep.id, sweep.sweeper));
        sweeps
    }

    /// Where `sweep` of `bounty` is stored, or why it is not.
    fn place_of(
        &self,
        dirs: &Dirs,
        bounty: BountyRef,
        sweep: SweepRef,
        summary: &SweepSummary,
    ) -> String {
        let opened_now = self
            .opened
            .stored
            .iter()
            .find(|opened| opened.bounty == bounty && opened.sweep == sweep);
        if let Some(opened) = opened_now {
            return match &opened.stored {
                Stored::Written(dir) => format!("stored now in {}", dir.display()),
                Stored::AlreadyThere(dir) => format!("stored in {}", dir.display()),
            };
        }
        if summary.pulled {
            return match stored_sweep_dir(dirs, bounty, sweep) {
                Ok(Some(dir)) => format!("stored in {}", dir.display()),
                Ok(None) => "marked pulled, but not found in the data directory".to_owned(),
                Err(error) => format!("stored, but where could not be checked: {error:#}"),
            };
        }
        if summary.refused {
            return "not stored: refused for good".to_owned();
        }
        let why = match summary.status.as_known() {
            Some(KnownSweepStatus::Done) => "not stored yet: it waits for the next pull",
            Some(KnownSweepStatus::Running) => "not stored: still running",
            Some(KnownSweepStatus::Aborted) => "nothing to store: aborted",
            None => "not stored: its status is not one this build opens",
        };
        why.to_owned()
    }
}

/// The report's line for the feed of `homeserver`, read from `start`: keys,
/// a number and fixed text.
fn feed_line(homeserver: Pubky, start: Start) -> String {
    // No `_ =>` arm: a source added later does not compile until it has
    // its words.
    let source = match start.source {
        StartSource::Local => "this install's feed-cursors.json",
        StartSource::Discovered => "the open bounties' discovered.json",
        StartSource::HeadSearch => "a search for the head of the feed",
    };
    format!(
        "  {homeserver}: read from cursor {}, from {source}",
        start.cursor
    )
}

/// A sweeper's trust as the report shows it: `circle`, `known: N credits
/// across M owners` (00's words), or `unknown`. `done` shows a proposed
/// sweeper's label in the same words.
pub(crate) fn label_text(trust: Trust) -> String {
    match trust.label {
        TrustLabel::Circle => "circle".to_owned(),
        TrustLabel::Known => format!(
            "known: {} across {}",
            counted(trust.tally.bounties, "credit"),
            counted(trust.tally.owners, "owner")
        ),
        TrustLabel::Unknown => "unknown".to_owned(),
    }
}

/// `n` and `noun`, plural unless `n` is 1. Generic over `n`'s type, any
/// that compares with 1 and prints, so a `u64` tally and a `usize` length
/// both go in as they are.
pub(crate) fn counted<N: PartialEq + From<u8> + std::fmt::Display>(n: N, noun: &str) -> String {
    if n == N::from(1) {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Adds `line` and a newline to `text`.
fn push_line(text: &mut String, line: &str) {
    text.push_str(line);
    text.push('\n');
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::mem;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use clap::Parser;
    use pubky::{Keypair, PubkyHttpClient};
    use serde_json::{Map, Value, json};
    use sweepky_core::paths::{self, SweepkyPath};
    use sweepky_core::{
        AgeRecipient, BountyRef, DeviceId, DeviceIdentity, Discovered, EventCursor,
        MAX_RECORD_BYTES, Pubky, PubkyUrl, SweepPackage, SweepRef, seal_package,
    };
    use tempfile::TempDir;
    use tokio::sync::oneshot;
    use tokio::time::sleep;

    use super::discovered::FakeSession;
    use super::feed::MAX_ACCEPTED_PER_BOUNTY;
    use super::state::{FeedCursors, PollState};
    use super::{NO_DEVICE_KEY, Seams, ThisInstall, WAITING_FOR_PULL, pull_with};
    use crate::device::{
        create_device_key, device_key_bytes, device_key_record, remove_device_key,
    };
    use crate::identity::IdentityName;
    use crate::installs::record_install_key;
    use crate::lock::PullLock;
    use crate::own_storage::OwnStorage;
    use crate::passphrase::{NeedsPassphrase, Passphrase};
    use crate::session::NOT_LOGGED_IN;
    use crate::state::{LoginState, write_login_state};
    use crate::test_support::{
        FAKE_HOMESERVER, FakeEventsFeed, FakeHomeservers, FakeKeyStore, FakePublicRecords,
        LocalHttp, PLANTED, SYNTHETIC_SHA, TEST_PASSPHRASE, bounty_json, circle_json, dirs_in,
        done_record, json_bytes, offline_network, package_json, private_temp, random_pubky,
        record_id, repo_target_json, sweep_json, test_context,
    };
    use crate::{Cli, Dirs, Network};

    /// The device id this install's `login.json` records.
    fn this_install() -> DeviceId {
        "this-install".parse().expect("a device id")
    }

    fn id(text: &str) -> DeviceId {
        text.parse().expect("a device id")
    }

    /// `keys/<id>.json` as `login` publishes it, for `recipient`.
    fn key_record(recipient: &AgeRecipient) -> Vec<u8> {
        let created = "2026-10-19T08:00:00Z".parse().expect("a time");
        device_key_bytes(&device_key_record(recipient, created)).expect("JSON")
    }

    /// Logs `owner` in on `dirs` as `login --identity` leaves an install:
    /// `login.json` naming this install's device id, `device.key` holding
    /// `key` (wrapped with `passphrase` when there is one), and
    /// `installs.json` recording the key it published.
    fn log_in(dirs: &Dirs, owner: Pubky, key: &DeviceIdentity, passphrase: Option<&Passphrase>) {
        let name: IdentityName = "owner".parse().expect("a name");
        let mut login = LoginState::identity(name, owner, FAKE_HOMESERVER);
        login.device_id = Some(this_install());
        write_login_state(dirs, &login).expect("written");
        create_device_key(dirs, key, passphrase).expect("written");
        record_install_key(dirs, owner, &this_install(), &key.recipient()).expect("recorded");
    }

    /// One owner's install, logged in with its device key, and the world
    /// around it in memory: everyone's public storage, the owner's `keys/`,
    /// the watched homeservers' feeds, pkarr, and the owner's own storage
    /// behind the writers' lock.
    struct Install {
        // Held so the directory lives as long as the install; never read.
        _home: TempDir,
        dirs: Dirs,
        owner: Pubky,
        /// This install's key, as `device.key` holds it.
        key: DeviceIdentity,
        records: FakePublicRecords,
        keys: FakeKeyStore,
        feed: FakeEventsFeed,
        resolver: FakeHomeservers,
        session: FakeSession,
        /// The homeserver watched, unless a test watches others.
        home: Pubky,
        watch_list: Vec<Pubky>,
    }

    impl Install {
        /// A new owner's install with no circle, no bounty and a quiet
        /// feed, whose `keys/` holds this install's key alone.
        fn new() -> Self {
            let temp = private_temp();
            let dirs = dirs_in(&temp);
            let owner = random_pubky();
            let key = DeviceIdentity::generate();
            log_in(&dirs, owner, &key, None);
            let keys = FakeKeyStore::default();
            keys.set_record(&this_install(), key_record(&key.recipient()));
            let home = random_pubky();
            Self {
                _home: temp,
                dirs,
                owner,
                key,
                records: FakePublicRecords::default(),
                keys,
                feed: FakeEventsFeed::of_ids(&[]),
                resolver: FakeHomeservers::default(),
                session: FakeSession::default(),
                home,
                watch_list: vec![home],
            }
        }

        /// One run of `pull`, as the command makes it, with the fakes as
        /// its seams and no pause in a head search: its report.
        async fn pull(&self) -> anyhow::Result<String> {
            let install = ThisInstall::read(&self.dirs, None)?;
            let seams = Seams {
                records: &self.records,
                keys: &self.keys,
                feed: &self.feed,
                homeservers: &self.resolver,
                writer: &self.session,
                pace: Duration::ZERO,
            };
            let report = pull_with(&seams, &self.dirs, install, &self.watch_list).await?;
            Ok(report.text().to_owned())
        }

        /// Puts `record` at `path` of `owner`'s public storage.
        fn put(&mut self, owner: Pubky, path: &str, record: &Value) {
            // `mem::take` moves the fake out, leaving an empty one, so the
            // builder method, which takes it by value, can be used on it.
            self.records = mem::take(&mut self.records).with_record(owner, path, record);
        }

        /// Gives the owner a circle listing `members`.
        fn circle(&mut self, members: &[Pubky]) {
            let owner = self.owner;
            self.put(owner, paths::circle(), &circle_json(owner, members));
        }

        /// Posts the owner's bounty `n`, of target `t1`: `open` to
        /// strangers or not, with `status`, and crediting `credits`.
        fn post(&mut self, n: u64, open: bool, status: &str, credits: &[Pubky]) -> BountyRef {
            let mut record = bounty_json(json!([repo_target_json("t1")]));
            record["open"] = json!(open);
            record["status"] = json!(status);
            let credits: Vec<String> = credits.iter().map(ToString::to_string).collect();
            record["credits"] = json!(credits);
            if status == "done" {
                record["doneAt"] = json!("2026-10-19T10:00:00Z");
            }
            let bounty = BountyRef {
                owner: self.owner,
                id: record_id(n),
            };
            self.put(self.owner, &paths::bounty(bounty.id), &record);
            bounty
        }

        /// Posts the owner's bounty `n` open, with a `discovered.json`
        /// listing `sweeps` with `cursors`, where anyone reads it and where
        /// the session reads it back.
        fn post_open(
            &mut self,
            n: u64,
            cursors: &[(Pubky, u64)],
            sweeps: &[SweepRef],
        ) -> BountyRef {
            let bounty = self.post(n, true, "open", &[]);
            let file = discovered_json(sweeps, cursors);
            self.put(self.owner, &paths::discovered(bounty.id), &file);
            self.session
                .storage
                .insert(&paths::discovered(bounty.id), json_bytes(&file));
            bounty
        }

        /// Publishes `sweeper`'s sweep `n` of `bounty`, of `t1`, with
        /// `status`; when `sealed_to` names keys, with a package sealed to
        /// them beside it, as `submit` leaves one.
        fn sweep(
            &mut self,
            sweeper: Pubky,
            n: u64,
            bounty: BountyRef,
            status: &str,
            sealed_to: &[AgeRecipient],
        ) -> SweepRef {
            let sweep = SweepRef {
                sweeper,
                id: record_id(n),
            };
            let record = if status == "done" {
                done_record(bounty, &["t1"])
            } else {
                sweep_json(bounty, &["t1"], status)
            };
            self.put(sweeper, &paths::sweep_record(sweep.id), &record);
            if !sealed_to.is_empty() {
                let shas = json!({ "t1": SYNTHETIC_SHA });
                let package =
                    SweepPackage::from_json(&json_bytes(&package_json(sweeper, bounty, shas)))
                        .expect("a package");
                let sealed = seal_package(&package, sealed_to).expect("sealed");
                self.records = mem::take(&mut self.records).with_file(
                    sweeper,
                    &paths::sweep_package(sweep.id),
                    sealed,
                );
            }
            sweep
        }

        /// The bytes of the owner's `discovered.json` of `bounty` as the
        /// session's storage holds them now: what the last write left.
        async fn written_bytes(&self, bounty: BountyRef) -> Vec<u8> {
            let bytes = self
                .session
                .storage
                .get_own(&paths::discovered(bounty.id))
                .await
                .expect("read")
                .expect("there");
            bytes.to_vec()
        }

        /// [`written_bytes`](Self::written_bytes), parsed.
        async fn written(&self, bounty: BountyRef) -> Discovered {
            let bytes = self.written_bytes(bounty).await;
            Discovered::from_json(&bytes).expect("a discovered-sweeps file")
        }

        /// Makes what the last write left of `bounty`'s `discovered.json`
        /// what anyone reads, as the homeserver would serve it.
        async fn serve_written(&mut self, bounty: BountyRef) {
            let bytes = self.written_bytes(bounty).await;
            let path = paths::discovered(bounty.id);
            self.records = mem::take(&mut self.records).with_file(self.owner, &path, bytes);
        }

        /// Stores `cursor` as this owner's local cursor on `homeserver`.
        fn store_cursor(&self, homeserver: Pubky, cursor: u64) {
            let mut cursors = FeedCursors::read(&self.dirs, self.owner).expect("reads");
            cursors.set(homeserver, EventCursor::new(cursor));
            cursors.write(&self.dirs, self.owner).expect("written");
        }

        /// This owner's local cursor on `homeserver`.
        fn stored_cursor(&self, homeserver: Pubky) -> Option<u64> {
            FeedCursors::read(&self.dirs, self.owner)
                .expect("reads")
                .get(&homeserver)
                .map(EventCursor::id)
        }

        /// This install's key, alone: what `submit` seals to for the owner.
        fn ours(&self) -> Vec<AgeRecipient> {
            vec![self.key.recipient()]
        }
    }

    /// A `discovered.json` listing `sweeps`, with `cursors`.
    fn discovered_json(sweeps: &[SweepRef], cursors: &[(Pubky, u64)]) -> Value {
        let cursors: Map<String, Value> = cursors
            .iter()
            .map(|(homeserver, cursor)| (homeserver.to_string(), json!(cursor.to_string())))
            .collect();
        let sweeps: Vec<String> = sweeps.iter().map(ToString::to_string).collect();
        json!({ "schemaVersion": 1, "sweeps": sweeps, "cursors": cursors })
    }

    /// The feed line of a write of `sweep`'s record.
    fn put_event(sweep: SweepRef) -> String {
        format!("PUT {}", sweep.url())
    }

    /// The report's line for `sweep`.
    fn line_of(report: &str, sweep: SweepRef) -> &str {
        let start = format!("  {sweep}: ");
        report
            .lines()
            .find(|line| line.starts_with(&start))
            .unwrap_or_else(|| panic!("no line for {sweep} in:\n{report}"))
    }

    /// Checks that `report` holds no finding and nothing that could drive a
    /// terminal: the only control character in it is the newline.
    fn assert_safe_to_print(report: &str) {
        assert!(!report.contains(PLANTED), "{report}");
        assert!(
            !report.chars().any(|c| c.is_control() && c != '\n'),
            "{report:?}"
        );
    }

    #[tokio::test]
    async fn not_logged_in_is_not_logged_in_and_the_context_is_all_it_reads() {
        // The command gets its directories from the context: here a fresh
        // temporary SWEEPKY_HOME, not the process's HOME, so "not logged
        // in" can only have come from the context's.
        let home = private_temp();
        let (ctx, stderr) = test_context(offline_network(), &home, io::empty());
        let cli = Cli::try_parse_from(["sweepky", "pull"]).expect("parses");

        let err = crate::run(cli, &ctx).await.expect_err("not logged in");
        assert_eq!(format!("{err:#}"), NOT_LOGGED_IN);
        assert_eq!(stderr.text(), "");
        // Nothing was written either: not even the data directory exists.
        assert!(!ctx.dirs.data().exists());
    }

    /// A client whose only pkarr relay is `relay`, and no DHT: every lookup
    /// of a key, which every read of anyone's storage starts with, is a
    /// request `relay` keeps.
    fn client_through(relay: &LocalHttp) -> PubkyHttpClient {
        let url = relay.url("");
        PubkyHttpClient::builder()
            .pkarr(|pkarr| {
                pkarr
                    .no_dht()
                    .relays(&[url.as_str()])
                    .expect("a valid relay URL")
            })
            .build()
            .expect("a client")
    }

    #[tokio::test]
    async fn a_wrapped_device_key_without_its_passphrase_fails_before_any_network_read() {
        let relay = LocalHttp::start(Vec::new()).await;
        let network = Network::injected(
            pubky::Pubky::with_client(client_through(&relay)),
            "http://127.0.0.1:1/inbox".to_owned(),
            Keypair::random().public_key(),
        );
        let home = private_temp();
        let (mut ctx, _stderr) = test_context(network, &home, io::empty());
        let passphrase = Passphrase::for_tests(TEST_PASSPHRASE);
        log_in(
            &ctx.dirs,
            random_pubky(),
            &DeviceIdentity::generate(),
            Some(&passphrase),
        );
        let pull = || Cli::try_parse_from(["sweepky", "pull"]).expect("parses");

        let err = crate::run(pull(), &ctx)
            .await
            .expect_err("needs the passphrase");
        assert!(err.is::<NeedsPassphrase>(), "{err:#}");
        assert!(format!("{err:#}").contains("--passphrase-file"), "{err:#}");
        assert_eq!(relay.heads(), Vec::<String>::new());

        // With the passphrase, the same pull goes out: the relay sees its
        // lookups, so it would have seen any made before the failure.
        ctx.passphrase = Some(passphrase);
        crate::run(pull(), &ctx).await.expect("pulled");
        assert!(!relay.heads().is_empty());

        // With no key at all, it fails before any request too.
        remove_device_key(&ctx.dirs).expect("removed");
        let asked = relay.heads().len();
        let err = crate::run(pull(), &ctx).await.expect_err("no key");
        assert_eq!(format!("{err:#}"), NO_DEVICE_KEY);
        assert_eq!(relay.heads().len(), asked);
    }

    // Two pulls of one install never run at once: the second waits for the
    // first's pull lock, says so once, and starts only once the first lets
    // go. The first is the lock itself, opened as `pull` opens it: a `flock`
    // belongs to one open of the file, so two opens in one process exclude
    // each other as two processes do. All three futures run in this one
    // task (`tokio::join!`), each going on while the others wait.
    #[tokio::test]
    async fn a_second_pull_waits_for_the_first_to_finish_and_says_so() {
        let home = private_temp();
        let (ctx, stderr) = test_context(offline_network(), &home, io::empty());
        log_in(&ctx.dirs, random_pubky(), &DeviceIdentity::generate(), None);
        let mut first = PullLock::open(&ctx.dirs).expect("opened");
        let (release, released) = oneshot::channel::<()>();
        let let_go = AtomicBool::new(false);

        let holding = first.hold(
            || {},
            async || {
                released.await.expect("the test lets go");
                let_go.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        let second = async {
            let cli = Cli::try_parse_from(["sweepky", "pull"]).expect("parses");
            let pulled = crate::run(cli, &ctx).await;
            assert!(
                let_go.load(Ordering::SeqCst),
                "the second pull ran while the first held the lock"
            );
            pulled
        };
        let watching = async {
            sleep(Duration::from_millis(300)).await;
            // Still waiting, having said so once, and having written none of
            // pull's state.
            assert_eq!(stderr.text().matches(WAITING_FOR_PULL).count(), 1);
            assert!(!ctx.dirs.poll_state_file().exists());
            release.send(()).expect("the first holds the lock");
        };
        let (held, pulled, ()) = tokio::join!(holding, second, watching);
        held.expect("held");
        pulled.expect("pulled once the first let go");
        assert!(ctx.dirs.poll_state_file().exists());
    }

    #[tokio::test]
    async fn the_report_gives_each_sweep_its_label_its_status_and_where_it_is_all_sanitised() {
        let mut fx = Install::new();
        let (member, stranger, credited) = (random_pubky(), random_pubky(), random_pubky());
        fx.circle(&[member]);
        // A done bounty of the owner's that credits `credited`.
        fx.post(1, false, "done", &[credited]);
        let open = fx.post_open(2, &[(fx.home, 0)], &[]);
        let ours = fx.ours();
        let circle_sweep = fx.sweep(member, 10, open, "done", &ours);
        let strangers = fx.sweep(stranger, 11, open, "done", &ours);
        // A status with an ESC sequence and a right-to-left override in it.
        let planted = fx.sweep(credited, 12, open, "\u{1b}[2J\u{202e}enod", &[]);
        fx.feed =
            FakeEventsFeed::of_events(vec![(1, put_event(strangers)), (2, put_event(planted))]);

        let report = fx.pull().await.expect("pulled");
        assert_safe_to_print(&report);
        let trusted_dir = fx.dirs.pulled_bounty_dir(&open.id);
        let untrusted_dir = fx.dirs.pulled_untrusted_dir(&open.id);
        assert_eq!(
            line_of(&report, circle_sweep),
            format!(
                "  {circle_sweep}: circle; done; stored now in {}",
                trusted_dir
                    .join(format!("{member}-{}", circle_sweep.id))
                    .display()
            )
        );
        assert_eq!(
            line_of(&report, strangers),
            format!(
                "  {strangers}: unknown; done; stored now in {}",
                untrusted_dir
                    .join(format!("{stranger}-{}", strangers.id))
                    .display()
            )
        );
        // Escaped where the terminal would have acted on them.
        assert_eq!(
            line_of(&report, planted),
            format!(
                "  {planted}: known: 1 credit across 1 owner; \\u{{1b}}[2J\\u{{202e}}enod; not \
                 stored: its status is not one this build opens"
            )
        );
        // Both stored sweeps grouped; the circle's alone merged.
        assert!(
            report.contains(&format!(
                "  groups.json and merged.json are in {}: 2 sweeps grouped, 1 of them the \
                 circle's, whose findings alone are merged\n",
                trusted_dir.display()
            )),
            "{report}"
        );

        // A later run finds both stored by the earlier one.
        let again = fx.pull().await.expect("pulled again");
        assert!(
            line_of(&again, strangers).ends_with(&format!(
                "unknown; done; stored in {}",
                untrusted_dir
                    .join(format!("{stranger}-{}", strangers.id))
                    .display()
            )),
            "{again}"
        );
    }

    #[tokio::test]
    async fn the_report_names_each_feed_with_the_cursor_it_resumed_from_and_where_that_came_from() {
        let mut fx = Install::new();
        let (local, listed, searched) = (random_pubky(), random_pubky(), random_pubky());
        fx.watch_list = vec![local, listed, searched];
        fx.store_cursor(local, 3);
        fx.post_open(1, &[(listed, 4)], &[]);
        // Ten events of another app on every homeserver, so a head is at 10.
        fx.feed = FakeEventsFeed::of_ids(&(1..=10).collect::<Vec<u64>>());

        let report = fx.pull().await.expect("pulled");
        assert_safe_to_print(&report);
        for line in [
            format!("  {local}: read from cursor 3, from this install's feed-cursors.json"),
            format!("  {listed}: read from cursor 4, from the open bounties' discovered.json"),
            format!("  {searched}: read from cursor 10, from a search for the head of the feed"),
        ] {
            assert!(
                report.lines().any(|shown| shown == line),
                "{line}\n{report}"
            );
        }

        // With no bounty open to strangers, no feed is read, and the report
        // says why.
        let fx = Install::new();
        let report = fx.pull().await.expect("pulled");
        assert!(
            report.contains(
                "Events feeds: none read, as none of your bounties is open to strangers.\n"
            )
        );
        assert!(fx.feed.asked().is_empty());
    }

    #[tokio::test]
    async fn an_unknown_key_under_keys_alarms_with_its_device_id_and_never_its_recipient() {
        let fx = Install::new();
        let injected = DeviceIdentity::generate().recipient();
        fx.keys
            .set_record(&id("injected-key"), key_record(&injected));

        let report = fx.pull().await.expect("pulled");
        // First, right after the line that says whose pull it is.
        let alarm = report.lines().nth(1).expect("a second line");
        assert!(
            alarm.starts_with("alarm: keys/injected-key.json is a device key"),
            "{report}"
        );
        assert!(!report.contains(&injected.to_string()), "{report}");
        assert!(
            !report.contains(&fx.key.recipient().to_string()),
            "{report}"
        );
    }

    #[tokio::test]
    async fn a_key_check_that_cannot_finish_is_an_alarm_not_a_quiet_warning() {
        // A listing that fails, one past the listing limit, and records
        // past the check's budget: each is an alarm-level line, never a
        // warning, with the check's own fixed reason.
        let failing = Install::new();
        failing.keys.fail_listings();
        let past_the_limit = Install::new();
        for n in 0..1000 {
            past_the_limit
                .keys
                .list_without_record(&id(&format!("k{n}")));
        }
        let over_budget = Install::new();
        for n in 0..9 {
            over_budget
                .keys
                .set_record(&id(&format!("filler-{n}")), vec![b' '; MAX_RECORD_BYTES]);
        }
        for (fx, reason) in [
            (failing, "keys/ could not be listed"),
            (
                past_the_limit,
                "keys/ lists more than the 1000 entries one check reads",
            ),
            (
                over_budget,
                "the records under keys/ are more than one check reads",
            ),
        ] {
            let report = fx.pull().await.expect("pulled");
            let alarm = report.lines().nth(1).expect("a second line");
            assert!(
                alarm.starts_with(
                    "alarm: pull could not finish its check of keys/ for device keys this \
                     owner's installs did not create ("
                ),
                "{report}"
            );
            assert!(alarm.contains(reason), "{alarm}");
            assert!(
                !report.contains("warning: could not check keys/"),
                "{report}"
            );
        }
    }

    #[tokio::test]
    async fn a_stranger_s_sweep_from_the_feed_is_appended_to_discovered_json_in_pull_s_one_put() {
        let mut fx = Install::new();
        let open = fx.post_open(1, &[(fx.home, 0)], &[]);
        let stranger = fx.sweep(random_pubky(), 10, open, "running", &[]);
        fx.feed = FakeEventsFeed::of_events(vec![(5, put_event(stranger))]);

        let report = fx.pull().await.expect("pulled");
        assert_safe_to_print(&report);
        // pull rewrites discovered.json and nothing else, in one session.
        assert_eq!(fx.session.storage.puts(), [paths::discovered(open.id)]);
        assert_eq!(fx.session.sessions(), (1, 1));
        let written = fx.written(open).await;
        assert_eq!(written.sweeps, [stranger]);
        assert_eq!(
            written.cursors.into_iter().collect::<Vec<_>>(),
            [(fx.home, EventCursor::new(5))]
        );
        assert_eq!(fx.stored_cursor(fx.home), Some(5));
        assert!(
            report.contains(&format!("Published {}.\n", paths::discovered(open.id))),
            "{report}"
        );
        assert_eq!(
            line_of(&report, stranger),
            format!("  {stranger}: unknown; running; not stored: still running")
        );
    }

    #[tokio::test]
    async fn a_stranger_s_sweep_rewritten_for_another_open_bounty_moves_to_that_one_s_file() {
        let mut fx = Install::new();
        let first = fx.post_open(1, &[(fx.home, 0)], &[]);
        let second = fx.post_open(2, &[(fx.home, 0)], &[]);
        let stranger = random_pubky();
        let moved = fx.sweep(stranger, 10, first, "running", &[]);
        fx.feed = FakeEventsFeed::of_events(vec![(5, put_event(moved))]);
        fx.pull().await.expect("pulled");
        assert_eq!(fx.written(first).await.sweeps, [moved]);
        fx.serve_written(first).await;

        // Its sweeper rewrites the record for the second bounty.
        fx.sweep(stranger, 10, second, "running", &[]);
        fx.feed = FakeEventsFeed::of_events(vec![(5, put_event(moved)), (6, put_event(moved))]);
        let report = fx.pull().await.expect("pulled again");
        // The first bounty's file drops it and the second's lists it.
        assert!(fx.written(first).await.sweeps.is_empty());
        assert_eq!(fx.written(second).await.sweeps, [moved]);
        // The report lists it once, under the second bounty.
        let start = format!("  {moved}: ");
        assert_eq!(
            report
                .lines()
                .filter(|line| line.starts_with(&start))
                .count(),
            1,
            "{report}"
        );
        let (_, under_second) = report
            .split_once(&format!("Bounty {second} "))
            .expect("the second bounty");
        assert!(under_second.contains(&start), "{report}");
    }

    #[tokio::test]
    async fn a_second_pull_with_only_its_own_write_new_in_the_feed_writes_nothing_and_takes_no_lock()
     {
        let mut fx = Install::new();
        let open = fx.post_open(1, &[(fx.home, 0)], &[]);
        let stranger = fx.sweep(random_pubky(), 10, open, "running", &[]);
        fx.feed = FakeEventsFeed::of_events(vec![(5, put_event(stranger))]);
        fx.pull().await.expect("pulled");
        assert_eq!(fx.session.sessions(), (1, 1));

        // The homeserver now serves what that pull wrote, and its feed holds
        // the event of that write, after the cursor the pull stored.
        fx.serve_written(open).await;
        let written = PubkyUrl::sweepky(fx.owner, &SweepkyPath::Discovered(open.id));
        fx.feed = FakeEventsFeed::of_events(vec![
            (5, put_event(stranger)),
            (6, format!("PUT {written}")),
        ]);

        let report = fx.pull().await.expect("pulled again");
        assert_eq!(fx.session.storage.puts().len(), 1);
        // No session opened, so no lock taken either.
        assert_eq!(fx.session.sessions(), (1, 1));
        assert!(!report.contains("Published"), "{report}");
        // The cursor survived the restart: the feed was read on from the
        // one the first pull stored, and moved past its own write.
        assert!(
            report.lines().any(|line| line
                == format!(
                    "  {}: read from cursor 5, from this install's feed-cursors.json",
                    fx.home
                )),
            "{report}"
        );
        assert_eq!(fx.stored_cursor(fx.home), Some(6));
    }

    #[tokio::test]
    async fn a_fresh_install_confirms_the_sweeps_discovered_json_lists_and_rewrites_nothing() {
        // The owner's other install found a stranger's done sweep and listed
        // it. This install, a fresh SWEEPKY_HOME of the same owner with its
        // own key, has no cursor and no poll state, and the feed, read on
        // from the file's cursor, no longer shows the sweep's events.
        let mut fx = Install::new();
        let other_install = DeviceIdentity::generate();
        fx.keys
            .set_record(&id("other-install"), key_record(&other_install.recipient()));
        let stranger = random_pubky();
        let listed = SweepRef {
            sweeper: stranger,
            id: record_id(10),
        };
        let open = fx.post_open(1, &[(fx.home, 7)], &[listed]);
        fx.sweep(stranger, 10, open, "done", &[other_install.recipient()]);
        fx.feed = FakeEventsFeed::of_ids(&[1, 2, 3, 4, 5, 6, 7]);

        let report = fx.pull().await.expect("pulled");
        assert_safe_to_print(&report);
        // Read again from the stranger's own storage, then its package.
        let asked = fx.records.asked();
        assert!(asked.contains(&(stranger, paths::sweep_record(listed.id))));
        assert!(asked.contains(&(stranger, paths::sweep_package(listed.id))));
        assert_eq!(
            line_of(&report, listed),
            format!("  {listed}: unknown; done; not stored: refused for good")
        );
        assert!(
            report.contains(&format!(
                "warning: pull skipped {listed} for good: not encrypted to this install's key \
                 (sealed before this install's key was published, or to another install)\n"
            )),
            "{report}"
        );
        assert!(
            report.lines().any(|line| line
                == format!(
                    "  {}: read from cursor 7, from the open bounties' discovered.json",
                    fx.home
                )),
            "{report}"
        );
        // The file lists every sweep this install accepted: nothing to write.
        assert!(fx.session.storage.puts().is_empty());
        assert_eq!(fx.session.sessions(), (0, 0));
        // installs.json is this install's own, so the other install's key
        // alarms here, as P2c records: `keys list` there tells the two apart.
        assert!(
            report.contains("alarm: keys/other-install.json is a device key"),
            "{report}"
        );
    }

    /// A feed of a `PUT` of each of `sweeps`, at events 1, 2 and on.
    fn feed_of_puts(sweeps: &[SweepRef]) -> FakeEventsFeed {
        FakeEventsFeed::of_events(
            (1..)
                .zip(sweeps.iter().map(|&sweep| put_event(sweep)))
                .collect(),
        )
    }

    #[tokio::test]
    async fn a_flood_past_the_cap_is_left_out_and_the_circle_s_sweeps_are_still_opened_and_grouped()
    {
        let mut fx = Install::new();
        let member = random_pubky();
        fx.circle(&[member]);
        let open = fx.post_open(1, &[(fx.home, 0)], &[]);
        let ours = fx.ours();
        let circle_sweep = fx.sweep(member, 10, open, "done", &ours);
        // A flood of running sweeps, each under a throwaway key: more than
        // one bounty keeps.
        let flood: Vec<SweepRef> = (100..)
            .take(MAX_ACCEPTED_PER_BOUNTY + 4)
            .map(|n| fx.sweep(random_pubky(), n, open, "running", &[]))
            .collect();
        fx.feed = feed_of_puts(&flood);

        let report = fx.pull().await.expect("pulled");
        assert_safe_to_print(&report);
        // The cap held, the poll state was written, and the report says
        // sweeps were left out.
        let state = PollState::read(&fx.dirs, fx.owner).expect("reads");
        assert_eq!(
            state.accepted_sweeps[&open.id].len(),
            MAX_ACCEPTED_PER_BOUNTY
        );
        assert!(
            report.contains(&format!(
                "warning: pull leaves out new strangers' sweeps of your bounty {open}"
            )),
            "{report}"
        );
        assert_eq!(fx.written(open).await.sweeps.len(), MAX_ACCEPTED_PER_BOUNTY);
        // The feed read on past them.
        let last = u64::try_from(flood.len()).expect("a few");
        assert_eq!(fx.stored_cursor(fx.home), Some(last));
        // The circle's sweep was opened, stored and grouped as ever.
        assert!(
            line_of(&report, circle_sweep)
                .starts_with(&format!("  {circle_sweep}: circle; done; stored now in ")),
            "{report}"
        );
        assert!(
            report.contains("  groups.json and merged.json are in "),
            "{report}"
        );
    }

    #[tokio::test]
    async fn a_poll_state_with_no_room_for_the_feed_does_not_fail_pull_run_after_run() {
        let mut fx = Install::new();
        let member = random_pubky();
        fx.circle(&[member]);
        let open = fx.post_open(1, &[(fx.home, 0)], &[]);
        // A first pull with a quiet feed, then the poll state filled to
        // within 1 KiB of its cap: room for what the roster adds next, a
        // circle member's done sweep, and none for a page of strangers'.
        fx.pull().await.expect("pulled");
        PollState::read(&fx.dirs, fx.owner)
            .expect("reads")
            .write_with_room(&fx.dirs, fx.owner, 1024);
        let ours = fx.ours();
        let circle_sweep = fx.sweep(member, 10, open, "done", &ours);
        let flood: Vec<SweepRef> = (100..120)
            .map(|n| fx.sweep(random_pubky(), n, open, "running", &[]))
            .collect();
        fx.feed = feed_of_puts(&flood);

        for (run, place) in [(1, "stored now in"), (2, "stored in")] {
            let report = fx
                .pull()
                .await
                .unwrap_or_else(|error| panic!("pull {run} failed: {error:#}"));
            assert_safe_to_print(&report);
            assert!(
                report.contains("warning: poll-state.json has no room for the strangers' sweeps"),
                "{report}"
            );
            // Nothing of the page is kept, and the cursor is where it was.
            let state = PollState::read(&fx.dirs, fx.owner).expect("reads");
            assert!(state.accepted_sweeps.is_empty());
            assert_eq!(fx.stored_cursor(fx.home), Some(0));
            // The circle's sweep is opened, stored and grouped all the same.
            assert!(
                line_of(&report, circle_sweep)
                    .starts_with(&format!("  {circle_sweep}: circle; done; {place} ")),
                "{report}"
            );
            assert!(
                report.contains("  groups.json and merged.json are in "),
                "{report}"
            );
        }
        // No sweep was accepted, so no discovered.json was rewritten.
        assert!(fx.session.storage.puts().is_empty());
    }
}
