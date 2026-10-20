//! `post <draft> --open`: publishing a bounty that takes sweeps from
//! anyone, with its discovered-sweeps file, once the owner has said yes.
//!
//! Strangers' sweeps of an open bounty are found through each watched
//! homeserver's public `/events/` feed (01, "Open bounties"). The feed has
//! no "latest" shortcut, so `post --open` finds once where `pull` starts
//! reading each one: the bounty's **starting cursors**. After the yes
//! (`post` asks first, so a no searches nothing and writes nothing):
//!
//! 1. read `login.json` for the owner and their homeserver. The homeserver
//!    is the one the login recorded: no pkarr lookup of the owner's record;
//! 2. for every watched homeserver but the owner's, find the head of its
//!    feed with `events::find_head`, before the bounty exists, so that the
//!    cursor is at or before the bounty's creation and no sweep of it can
//!    come before it. The search is paced for production's rate limit and
//!    can take some seconds, so it runs outside the writers' lock;
//! 3. under the pull lock, and inside it the writers' lock with a fresh
//!    session that is always signed out (`session::with_writer_session`),
//!    after checking that `login.json` still says what step 1 read:
//!    1. PUT the bounty, `bounties/<id>.json`;
//!    2. when the owner's homeserver is on the watch list, read its
//!       `/events-stream` for the owner's latest event of exactly that
//!       file: the event id of the PUT just made. This comes right after
//!       the PUT and before anything else is written under `bounties/`,
//!       whose `discovered.json` is a file too; the filter on the exact
//!       path keeps the answer right even if another install writes there
//!       at the same moment;
//!    3. PUT `bounties/<id>.discovered.json`, `{schemaVersion: 1, sweeps:
//!       [], cursors: {<homeserver z32>: "<event id>"}}`, one cursor for
//!       each watched homeserver: public values only;
//!    4. store the same cursors in the local `feed-cursors.json`
//!       (`pull::state`), each lowered to, never raised past, a cursor
//!       already there for this owner and homeserver, so an earlier open
//!       bounty's unread events are never skipped. Also when step 3.3 was
//!       refused, so that `pull` can write the file later.
//!
//! **What the locks cover.** The sign-in, the two PUTs with the one stream
//! read between them, the local cursor update and the sign-out; never the
//! question or the search, which can wait on a person or on a rate limit.
//! The pull lock is there for the local update: `pull` reads, changes and
//! writes `feed-cursors.json` while it holds the pull lock, so every writer
//! of the file holds it too (`pull::state`), or a cursor lowered here could
//! be written over by a `pull` that read the file before. It is taken
//! first, and the writers' lock inside it, the order `pull` takes them in,
//! so neither command can hold one while it waits for the other. While a
//! `pull` of this install runs, `post --open` waits for it, says so once on
//! standard error, and past the lock's timeout gives up, before anything is
//! posted, saying another pull is running.
//!
//! **Known gap.** An owner whose homeserver is not on the watch list gets
//! no cursor for it, and `pull` does not watch it: 01's "a sweeper on a
//! homeserver not on the watch list is not seen". The watch list is what
//! the network settings give.
//!
//! **Once the bounty is posted, every error says so**, with its `pubky://`
//! URL and not to post it again: a second `post` would be a second bounty.
//! A refused write is mapped by `write_error`, fixed text and the status,
//! never the server's words; a failed read by `events`, which quotes
//! nothing either.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context as _, bail};
use sweepky_core::paths::{self, SweepkyPath};
use sweepky_core::{
    BountyRef, Discovered, EventCursor, Pubky, RecordId, SchemaVersion, UnknownFields,
};

use super::{NOTHING_POSTED, publish};
use crate::events::{EventsFeed, HomeserverEvents, SEARCH_PACE, find_head};
use crate::lock::PullLock;
use crate::own_storage::{OwnStorage, SessionStorage};
use crate::pull::state::FeedCursors;
use crate::pull::watched_homeservers;
use crate::remote::write_error;
use crate::session::{NOT_LOGGED_IN, with_writer_session};
use crate::state::{LoginState, read_login_state};
use crate::{Context, Dirs, clock};

/// What `post --open` says when `login.json` changed between the search and
/// the sign-in, as when another login ran meanwhile: the cursors were found
/// for the login read first, so nothing is written for another.
const LOGIN_CHANGED: &str = "this install's login changed while post was finding the starting \
     cursors, so nothing was posted; run post again";

/// What `post --open` says on standard error while a `pull` of this install
/// holds the pull lock, which it takes to store the starting cursors.
const WAITING_FOR_PULL: &str = "waiting for a sweepky pull on this install to finish (it holds \
     the pull lock, which post --open takes to store the bounty's starting cursors)";

/// What `post --open` says on standard error before it searches: the
/// search can take some seconds on a busy homeserver.
const SEARCHING: &str = "Finding where each watched homeserver's events feed stands, where pull \
     starts looking for this bounty's sweeps; this can take some seconds.";

/// Publishes `record`, an open bounty's bytes, with its discovered-sweeps
/// file and its starting cursors, as the module docs say, and gives the
/// bounty's address. `post` calls this only after the owner's yes.
pub(super) async fn publish_signed_in(ctx: &Context, record: Vec<u8>) -> anyhow::Result<BountyRef> {
    // Read before anything else, so that with no login nothing is searched
    // either. `Option::context` (anyhow's) turns a missing login into an
    // error with that text; the outer `context` adds that nothing was
    // posted, whichever of the two failed.
    let login = read_login_state(&ctx.dirs)
        .and_then(|login| login.context(NOT_LOGGED_IN))
        .context(NOTHING_POSTED)?;
    let watch_list = watched_homeservers(ctx);
    // One reader for the search and the stream read: it borrows the SDK's
    // HTTP client, which resolves each homeserver's key to reach it.
    let feed = HomeserverEvents::new(ctx.network.pubky().client());
    if watch_list
        .iter()
        .any(|homeserver| *homeserver != login.homeserver)
    {
        ctx.stderr.line(SEARCHING)?;
    }
    let starting = StartingCursors::search(&feed, &watch_list, &login, SEARCH_PACE)
        .await
        .context(NOTHING_POSTED)?;
    // The pull lock first, then the writers' lock inside it
    // (`with_writer_session`): the order `pull` takes them in (the module
    // docs).
    let mut pull_lock = PullLock::open(&ctx.dirs).context(NOTHING_POSTED)?;
    pull_lock
        .hold(
            // A courtesy, as for the writers' lock: if standard error cannot
            // be written, `post` still waits and goes on.
            || {
                let _ = ctx.stderr.line(WAITING_FOR_PULL);
            },
            // `async move` moves `login`, `feed`, `record` and `starting`
            // into this closure, and the inner one moves them on again, to
            // hand the last two to `publish_open` by value.
            async move || {
                // From the clock once the pull lock is held, after the search
                // and any wait for a pull, so that the id, the record's
                // creation time, stays close to the PUT.
                let id = clock::new_record_id()?;
                with_writer_session(ctx, async move |signed| {
                    if signed.login() != &login {
                        bail!(LOGIN_CHANGED);
                    }
                    let storage = SessionStorage::new(signed);
                    publish_open(&storage, &feed, &ctx.dirs, &login, id, record, starting).await
                })
                .await
            },
        )
        .await
}

/// An open bounty's starting cursors as far as they are known before its
/// PUT: the head of each watched homeserver's feed but the owner's, and
/// the owner's homeserver when it is on the watch list, whose cursor is
/// read after the PUT ([`complete`](Self::complete)).
struct StartingCursors {
    /// The head found on each watched homeserver but the owner's.
    searched: BTreeMap<Pubky, EventCursor>,
    /// The owner's homeserver, when it is on the watch list.
    owner_homeserver: Option<Pubky>,
}

impl StartingCursors {
    /// Searches the head of every homeserver of `watch_list` but the owner's,
    /// which is the one `login` records, each with `find_head` at `pace`
    /// ([`SEARCH_PACE`] for a real homeserver, zero in the tests). The first
    /// error, a 429 among them, stops it.
    async fn search(
        feed: &impl EventsFeed,
        watch_list: &[Pubky],
        login: &LoginState,
        pace: Duration,
    ) -> anyhow::Result<Self> {
        let mut searched = BTreeMap::new();
        let mut owner_homeserver = None;
        // `&homeserver` in the pattern copies each `Pubky` (it is `Copy`) out
        // of the borrowed slice.
        for &homeserver in watch_list {
            // `Pubky`'s `==` compares the key bytes, whichever spelling
            // either side was read from.
            if homeserver == login.homeserver {
                owner_homeserver = Some(homeserver);
            } else {
                searched.insert(homeserver, find_head(feed, homeserver, pace).await?);
            }
        }
        Ok(Self {
            searched,
            owner_homeserver,
        })
    }

    /// Every cursor, once `posted` is written: the heads searched, and on
    /// the owner's homeserver, when it is watched, the id of the event of
    /// that write, from its stream (`EventsFeed::latest_event`).
    ///
    /// `self` by value: the map moves into the answer rather than being
    /// copied, and the cursors cannot be completed twice.
    async fn complete(
        self,
        feed: &impl EventsFeed,
        posted: BountyRef,
    ) -> anyhow::Result<BTreeMap<Pubky, EventCursor>> {
        // Taking `self` apart moves each field out of it.
        let Self {
            mut searched,
            owner_homeserver,
        } = self;
        if let Some(homeserver) = owner_homeserver {
            let cursor = feed
                .latest_event(homeserver, posted.owner, &SweepkyPath::Bounty(posted.id))
                .await
                .context("could not read the bounty's starting cursor on its own homeserver")?;
            searched.insert(homeserver, cursor);
        }
        Ok(searched)
    }
}

/// Writes the open bounty `record` as `bounties/<id>.json` of `login`'s
/// owner through `storage`, then its discovered-sweeps file with every
/// cursor of `starting`, and stores those cursors in `dirs`, in the order
/// and with the rules of the module docs. Gives the bounty's address.
///
/// `storage` is the session's storage in `post`, a fake in the tests, and
/// so is `feed`. An error before the bounty PUT went through means nothing
/// was posted; every one after it names the bounty's URL.
async fn publish_open(
    storage: &impl OwnStorage,
    feed: &impl EventsFeed,
    dirs: &Dirs,
    login: &LoginState,
    id: RecordId,
    record: Vec<u8>,
    starting: StartingCursors,
) -> anyhow::Result<BountyRef> {
    publish(storage, id, record).await?;
    let posted = BountyRef {
        owner: login.pubky,
        id,
    };
    // An `async` block, so that one context, the bounty's URL, is added to
    // whichever of the steps after the PUT fails.
    async {
        // No sweeps yet: `pull` appends the strangers' sweeps it accepts.
        let discovered = Discovered {
            schema_version: SchemaVersion::CURRENT,
            sweeps: Vec::new(),
            cursors: starting.complete(feed, posted).await?,
            extra: UnknownFields::new(),
        };
        let published = put_discovered(storage, id, &discovered).await;
        // Stored whether or not the file was written, so `pull` can write
        // it later from these.
        lower_stored_cursors(dirs, login.pubky, &discovered.cursors)?;
        published
    }
    .await
    .with_context(|| format!("the bounty is posted, open, at {posted}; do not post it again"))?;
    Ok(posted)
}

/// Writes `discovered` as `bounties/<id>.discovered.json` through
/// `storage`, compact. A refusal is mapped by `write_error`: 403 and 507 to
/// their messages, anything else to fixed text and the status, never the
/// server's words.
async fn put_discovered(
    storage: &impl OwnStorage,
    id: RecordId,
    discovered: &Discovered,
) -> anyhow::Result<()> {
    let path = paths::discovered(id);
    // One cursor of at most 80 bytes per watched homeserver, so the file
    // stays far under `MAX_RECORD_BYTES` for any watch list Sweepky has.
    let bytes =
        serde_json::to_vec(discovered).with_context(|| format!("could not write {path}"))?;
    storage.put(&path, bytes).await.map_err(|error| {
        write_error(&error).context(format!(
            "could not write {path}, which `sweepky pull` writes later from the starting \
             cursors stored here"
        ))
    })
}

/// Lowers `owner`'s local feed cursors to `cursors`: for each homeserver,
/// keeps the cursor already there when it is lower, and stores the new one
/// otherwise (`FeedCursors::lower_to`). Every other owner's entry stays as
/// it was. 0600, through `private_fs`.
fn lower_stored_cursors(
    dirs: &Dirs,
    owner: Pubky,
    cursors: &BTreeMap<Pubky, EventCursor>,
) -> anyhow::Result<()> {
    let mut stored = FeedCursors::read(dirs, owner)?;
    // Iterating a `&BTreeMap` lends each key and value; `&homeserver` and
    // `&cursor` copy them out, as both are `Copy`.
    for (&homeserver, &cursor) in cursors {
        stored.lower_to(homeserver, cursor);
    }
    stored
        .write(dirs, owner)
        .context("could not store the bounty's starting cursors")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use anyhow::bail;
    use pubky::StatusCode;
    use serde_json::{Value, json};
    use sweepky_core::paths::{self, SweepkyPath};
    use sweepky_core::{BountyRef, Discovered, EventCursor, Pubky, PubkyUrl, RecordId};
    use tempfile::TempDir;
    use tokio::sync::oneshot;
    use tokio::time::sleep;

    use super::{StartingCursors, WAITING_FOR_PULL, publish_open, publish_signed_in};
    use crate::Dirs;
    use crate::lock::{PullLock, WritersLock};
    use crate::own_storage::OwnStorage;
    use crate::pull::state::FeedCursors;
    use crate::remote::{QUOTA_FULL, pubky_of};
    use crate::state::{LoginState, write_login_state};
    use crate::test_support::{
        FakeEventsFeed, FakeOwnStorage, FileSnapshot, PLANTED, StreamRequest, dirs_in, feed_page,
        mode, offline_network, private_temp, random_pubky, record_id, stream_event, test_context,
    };

    /// No pause between the search's requests: the tests' pace.
    const UNPACED: Duration = Duration::ZERO;

    /// The events every watched homeserver's feed holds in these tests: its
    /// head, where its starting cursor goes, is the last.
    const FEED: [u64; 3] = [3, 9, 1023];

    /// The id of the bounty PUT's event on the owner's homeserver.
    const BOUNTY_EVENT: u64 = 4242;

    /// The bytes the tests publish as the bounty: `publish_open` writes
    /// them as they are, whatever they hold.
    const RECORD: &[u8] = b"{\"open\":true}";

    /// A logged-in owner on their homeserver, the bounty's id, the data
    /// directory, and the storage, shared so a fake feed can look at it.
    struct Setup {
        login: LoginState,
        id: RecordId,
        // Never read, only kept: the directory is deleted when this is
        // dropped, so it lives as long as the setup. The leading `_` tells
        // the compiler the field is unused on purpose.
        _home: TempDir,
        dirs: Dirs,
        storage: Arc<FakeOwnStorage>,
    }

    impl Setup {
        fn new() -> Self {
            let home = private_temp();
            Self {
                login: LoginState::identity(
                    "owner".parse().expect("a name"),
                    random_pubky(),
                    random_pubky(),
                ),
                id: record_id(77),
                dirs: dirs_in(&home),
                _home: home,
                storage: Arc::new(FakeOwnStorage::default()),
            }
        }

        fn bounty_path(&self) -> String {
            paths::bounty(self.id)
        }

        fn discovered_path(&self) -> String {
            paths::discovered(self.id)
        }

        fn posted(&self) -> BountyRef {
            BountyRef {
                owner: self.login.pubky,
                id: self.id,
            }
        }

        /// A feed whose every homeserver holds [`FEED`], and whose stream
        /// answers with the PUT of the file asked for at [`BOUNTY_EVENT`].
        /// Its pages fail when anything is written already, and its stream
        /// unless exactly the bounty is, so each answers only where the
        /// module docs' order asks it.
        fn feed(&self) -> FakeEventsFeed {
            // `Arc::clone` is a second handle on the one storage, which each
            // `move` closure owns; the test keeps its own.
            let storage = Arc::clone(&self.storage);
            let feed = FakeEventsFeed::answering(move |cursor, limit| {
                if !storage.puts().is_empty() {
                    bail!("a feed was searched after a write");
                }
                Ok(feed_page(&FEED, cursor, limit))
            });
            let storage = Arc::clone(&self.storage);
            let bounty_path = self.bounty_path();
            feed.with_stream_answer(move |_homeserver, owner, path| {
                if storage.puts() != [bounty_path.as_str()] {
                    bail!("the stream was read with {:?} written", storage.puts());
                }
                let url = PubkyUrl::sweepky(owner, path).to_string();
                Ok(stream_event("PUT", &url, BOUNTY_EVENT).into_bytes())
            })
        }

        /// Searches `watch_list` with `feed` and publishes [`RECORD`], as
        /// `publish_signed_in` does in a session.
        async fn post(
            &self,
            feed: &FakeEventsFeed,
            watch_list: &[Pubky],
        ) -> anyhow::Result<BountyRef> {
            let starting = StartingCursors::search(feed, watch_list, &self.login, UNPACED).await?;
            publish_open(
                &*self.storage,
                feed,
                &self.dirs,
                &self.login,
                self.id,
                RECORD.to_vec(),
                starting,
            )
            .await
        }

        /// The discovered-sweeps file written, as JSON, after checking that
        /// core reads it back.
        async fn discovered(&self) -> Value {
            let bytes = self
                .storage
                .get_own(&self.discovered_path())
                .await
                .expect("reads")
                .expect("written");
            Discovered::from_json(&bytes).expect("core reads it");
            serde_json::from_slice(&bytes).expect("JSON")
        }
    }

    #[tokio::test]
    async fn the_bounty_is_put_first_then_its_discovered_json_with_a_cursor_per_watched_homeserver()
    {
        let setup = Setup::new();
        let home = setup.login.homeserver;
        let watched = random_pubky();
        let feed = setup.feed();

        let posted = setup.post(&feed, &[home, watched]).await.expect("posted");

        assert_eq!(posted, setup.posted());
        // The bounty, its bytes as they were given, then its file.
        assert_eq!(
            setup.storage.puts(),
            [setup.bounty_path(), setup.discovered_path()]
        );
        let bounty = setup
            .storage
            .get_own(&setup.bounty_path())
            .await
            .expect("reads")
            .expect("written");
        assert_eq!(bounty.as_slice(), RECORD);
        // The owner's homeserver, the one login.json records, is read once
        // through its stream, for exactly the bounty's file, and never
        // searched; the other watched one is searched, before any write.
        assert_eq!(
            feed.streams_asked(),
            [StreamRequest {
                homeserver: home,
                owner: setup.login.pubky,
                path: SweepkyPath::Bounty(setup.id),
            }]
        );
        assert_eq!(feed.homeservers_asked(), BTreeSet::from([watched]));
        // No sweeps, and one cursor per watched homeserver: the PUT's own
        // event on the owner's, the head found before it on the other.
        assert_eq!(
            setup.discovered().await,
            json!({
                "schemaVersion": 1,
                "sweeps": [],
                "cursors": {
                    home.to_string(): BOUNTY_EVENT.to_string(),
                    watched.to_string(): "1023",
                },
            })
        );
    }

    #[tokio::test]
    async fn with_the_owner_s_homeserver_off_the_watch_list_no_stream_is_read() {
        let setup = Setup::new();
        let (first, second) = (random_pubky(), random_pubky());
        let feed = setup.feed();

        setup.post(&feed, &[first, second]).await.expect("posted");

        assert!(feed.streams_asked().is_empty());
        assert_eq!(feed.homeservers_asked(), BTreeSet::from([first, second]));
        // The watch list's homeservers and no other: not the owner's.
        assert_eq!(
            setup.discovered().await["cursors"],
            json!({ first.to_string(): "1023", second.to_string(): "1023" })
        );
        let stored = FeedCursors::read(&setup.dirs, setup.login.pubky).expect("reads");
        assert_eq!(stored.get(&setup.login.homeserver), None);
    }

    #[tokio::test]
    async fn the_local_cursors_are_stored_0600_and_a_lower_one_already_there_is_kept() {
        let setup = Setup::new();
        let (owner, home, watched) = (setup.login.pubky, setup.login.homeserver, random_pubky());
        // An earlier open bounty left this owner behind the new cursor on
        // their homeserver and ahead of it on the other; another owner is
        // further behind on the other.
        let mut earlier = FeedCursors::default();
        earlier.set(home, EventCursor::new(7));
        earlier.set(watched, EventCursor::new(5000));
        earlier.write(&setup.dirs, owner).expect("written");
        let other_owner = random_pubky();
        let mut theirs = FeedCursors::default();
        theirs.set(watched, EventCursor::new(2));
        theirs.write(&setup.dirs, other_owner).expect("written");

        setup
            .post(&setup.feed(), &[home, watched])
            .await
            .expect("posted");

        let stored = FeedCursors::read(&setup.dirs, owner).expect("reads");
        assert_eq!(
            stored.get(&home),
            Some(EventCursor::new(7)),
            "the lower kept"
        );
        assert_eq!(
            stored.get(&watched),
            Some(EventCursor::new(1023)),
            "lowered"
        );
        assert_eq!(
            FeedCursors::read(&setup.dirs, other_owner).expect("reads"),
            theirs
        );
        assert_eq!(mode(&setup.dirs.feed_cursors_file()), 0o600);
        // The public file holds the bounty's own cursors, not the lower ones.
        assert_eq!(
            setup.discovered().await["cursors"][home.to_string()],
            BOUNTY_EVENT.to_string()
        );
    }

    #[tokio::test]
    async fn a_refused_discovered_json_is_reported_in_fixed_text_with_the_url_and_the_cursors_are_stored()
     {
        let setup = Setup::new();
        let (home, watched) = (setup.login.homeserver, random_pubky());
        setup.storage.refuse(
            &setup.discovered_path(),
            StatusCode::INSUFFICIENT_STORAGE,
            PLANTED,
        );

        let error = setup
            .post(&setup.feed(), &[home, watched])
            .await
            .expect_err("refused");

        let message = format!("{error:#}");
        assert!(message.contains(QUOTA_FULL), "{message}");
        assert!(message.contains(&setup.posted().to_string()), "{message}");
        assert!(message.contains("do not post it again"), "{message}");
        assert!(!message.contains(PLANTED), "{message}");
        // The bounty stands; its file was asked for and refused.
        assert_eq!(
            setup.storage.puts(),
            [setup.bounty_path(), setup.discovered_path()]
        );
        assert!(
            setup
                .storage
                .get_own(&setup.discovered_path())
                .await
                .expect("reads")
                .is_none()
        );
        // The cursors are here for `pull` to write the file from.
        let stored = FeedCursors::read(&setup.dirs, setup.login.pubky).expect("reads");
        assert_eq!(stored.get(&home), Some(EventCursor::new(BOUNTY_EVENT)));
        assert_eq!(stored.get(&watched), Some(EventCursor::new(1023)));
    }

    #[tokio::test]
    async fn a_failed_stream_read_writes_nothing_after_the_bounty_and_names_its_url() {
        let setup = Setup::new();
        // A stream with no event in it: the homeserver gave no cursor.
        let feed = FakeEventsFeed::of_ids(&FEED);

        let error = setup
            .post(&feed, &[setup.login.homeserver])
            .await
            .expect_err("no cursor");

        let message = format!("{error:#}");
        assert!(message.contains(&setup.posted().to_string()), "{message}");
        assert!(message.contains("do not post it again"), "{message}");
        assert_eq!(setup.storage.puts(), [setup.bounty_path()]);
        assert_eq!(FileSnapshot::of(&setup.dirs.feed_cursors_file()), None);
    }

    // `post --open` stores the bounty's starting cursors in feed-cursors.json,
    // which `pull` rewrites while it holds the pull lock, so it takes the
    // pull lock too, and before the writers' lock, the order `pull` takes
    // them in: while a pull runs, it waits, says so once, holds neither lock
    // and writes nothing. The running pull is the lock itself, opened as
    // `pull` opens it, and all three futures run in this one task
    // (`tokio::join!`), each going on while the others wait.
    #[tokio::test]
    async fn post_open_waits_for_a_running_pull_before_it_takes_the_writers_lock() {
        let home = private_temp();
        let (ctx, stderr) = test_context(offline_network(), &home, io::empty());
        // Logged in on the one homeserver the network watches, so there is no
        // head to search for before the locks.
        let homeserver = pubky_of(ctx.network.settings().default_homeserver());
        let login =
            LoginState::identity("owner".parse().expect("a name"), random_pubky(), homeserver);
        write_login_state(&ctx.dirs, &login).expect("written");
        let mut pull = PullLock::open(&ctx.dirs).expect("opened");
        let (release, released) = oneshot::channel::<()>();
        let let_go = AtomicBool::new(false);

        let pulling = pull.hold(
            || {},
            async || {
                released.await.expect("the test lets go");
                let_go.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        let posting = async {
            let posted = publish_signed_in(&ctx, RECORD.to_vec()).await;
            assert!(
                let_go.load(Ordering::SeqCst),
                "post --open went on while a pull held the pull lock"
            );
            posted
        };
        let watching = async {
            sleep(Duration::from_millis(300)).await;
            assert_eq!(stderr.text().matches(WAITING_FOR_PULL).count(), 1);
            // The writers' lock is free meanwhile: taken at once, never
            // waited for.
            let mut writers = WritersLock::open(&ctx.dirs).expect("opened");
            writers
                .hold(
                    || panic!("post --open held the writers' lock while it waited for the pull"),
                    async || Ok(()),
                )
                .await
                .expect("held");
            assert_eq!(FileSnapshot::of(&ctx.dirs.feed_cursors_file()), None);
            release.send(()).expect("the pull holds the lock");
        };
        let (pulled, posted, ()) = tokio::join!(pulling, posting, watching);
        pulled.expect("held");
        // Past both locks it signs in, which fails here: this install has no
        // identity file to sign in with.
        let error = posted.expect_err("cannot sign in");
        assert!(format!("{error:#}").contains("cannot sign in"), "{error:#}");
    }
}
