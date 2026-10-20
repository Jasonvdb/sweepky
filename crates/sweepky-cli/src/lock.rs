//! The install's two locks: the writers' lock, so that one `sweepky`
//! command at a time holds a session and writes, and the pull lock, so that
//! one `pull` at a time reads and writes its local state.
//!
//! **Why.** Under a Ring login (P2d) every command restores the saved grant
//! token, and each restore mints a fresh bearer that invalidates the previous
//! one, so two commands writing at once would cut each other's session off
//! mid-write. Every command that opens a session (`post`, `run`, `submit`,
//! `done`, `circle`, `keys` and `logout`) therefore holds this lock around the
//! session restore plus its writes, and `pull` holds it for its one
//! `discovered.json` write. `keys list` and `circle show` read public data and
//! take no lock.
//!
//! **The pull lock** ([`PullLock`]) is the same kind of lock on a file of its
//! own, `<config>/pull.lock`, which `pull` holds for its whole run, and
//! `post --open` around its writes, as it stores cursors in a file `pull`
//! rewrites (`pull::state`). `pull` reads its local state
//! (`poll-state.json`, `feed-cursors.json`) as it starts, changes it in
//! memory for minutes, and writes it back after each step, each write
//! replacing this owner's whole entry. Two pulls at once
//! would each write back what they read before the other's write: one could
//! drop the strangers' sweeps the other accepted while the other's feed cursor
//! had already moved past their events, so they would never be read again.
//! Holding the writers' lock that long instead would keep `post`, `run`,
//! `submit` and `done` waiting on every `pull`. `pull` takes the writers' lock
//! inside the pull lock, for its one public write, and so does `post --open`,
//! for its writes; no command takes the pull lock while it holds the writers'
//! lock, so no two commands each hold one while they wait for the other.
//!
//! **How.** An exclusive `flock` on the lock's file, `<config>/credential.lock`
//! or `<config>/pull.lock`, through the `fd-lock` crate, which makes the
//! system call with rustix, so there is no `unsafe` here. What that gives,
//! and what it asks of the code, for both:
//!
//! - **Advisory.** Only `sweepky` commands look at the lock; it stops nothing
//!   else from touching the config directory.
//! - **Per open file, not per process.** A `flock` belongs to one open of the
//!   file, so two [`WritersLock::open`]s in the same process exclude each
//!   other exactly as two processes do. The end-to-end tests run several
//!   commands in one process and rely on this.
//! - **Never stale.** The kernel releases the lock when its file is closed,
//!   and a process that exits or crashes has all its files closed, so there is
//!   never a leftover lock to clean up. Rust opens every file close-on-exec, so
//!   a child process such as `git` does not inherit the lock and cannot keep it
//!   alive after `sweepky` exits.
//! - **Never blocks the async runtime.** The lock is tried without blocking
//!   (`try_write`) and, while another command holds it, tried again after a
//!   `tokio` sleep, which yields the thread to other tasks. A blocking `flock`
//!   would park a runtime worker thread instead, and with two commands on one
//!   runtime it could deadlock: the waiting one would sit on the thread the
//!   holder needs in order to finish. A wait gives up after [`WAIT_TIMEOUT`].
//! - **The lock files stay.** Nothing deletes, replaces or writes to
//!   `credential.lock` or `pull.lock`, `logout` included: if one were deleted
//!   while a command held it, the next command would create a new file and
//!   lock that one, and two would be in at once. Each is always empty, and is
//!   opened with [`open_private_lock_file`] under the rules of every other
//!   file in the config directory: 0600 in a 0700 directory, never through a
//!   link.
//!
//! **Why [`WritersLock::hold`] runs the work, instead of handing back a guard
//! the way `Mutex::lock` does.** `fd-lock`'s guard borrows the lock it came
//! from. A function that tries in a loop and returns that borrow on success
//! (`loop { match self.file.try_write() { Ok(guard) => return Ok(guard), .. } }`)
//! is rejected by today's borrow checker: because the borrow *may* be
//! returned, it counts as alive for the rest of the function, so the next
//! try's borrow collides with it (`E0499`, the known "NLL problem case 3",
//! which Polonius, the borrow checker meant to replace today's, is designed
//! to accept). Running the caller's work while the guard is still in scope
//! sidesteps that with no `unsafe` and no tricks, and makes the release
//! impossible to forget: the lock is let go when the work finishes, fails or
//! is cancelled (a dropped future drops the guard it holds).

use std::fs::File;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, bail};
use fd_lock::RwLock;
use tokio::time::{Instant, sleep};

use crate::Dirs;
use crate::private_fs::{ensure_private_dir, open_private_lock_file};

/// How long a command waits for another to release the lock before it gives
/// up: 10 minutes.
///
/// Long, because the holder may be a `submit` uploading a large package over
/// a slow link, and a waiting command has already said what it is waiting
/// for. Finite, so a command left stuck holding the lock does not leave every
/// other one hanging with it.
const WAIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// The pause after the first failed try. Each later pause doubles, up to
/// [`MAX_RETRY_PAUSE`].
const FIRST_RETRY_PAUSE: Duration = Duration::from_millis(10);

/// The longest pause between tries, so a waiting command starts at most half
/// a second after the lock comes free.
const MAX_RETRY_PAUSE: Duration = Duration::from_millis(500);

/// What a command that gives up waiting for the writers' lock says holds it.
const WRITERS_LOCK_HELD: &str = "another sweepky command still holds the writers' lock";

/// What a command that gives up waiting for the pull lock, a `pull` or a
/// `post --open`, says holds it.
const PULL_LOCK_HELD: &str =
    "another sweepky pull on this install is still running and holds the pull lock";

/// The writers' lock file, open and ready to lock: `<config>/credential.lock`.
///
/// Opening it takes no lock; [`WritersLock::hold`] does. Each command opens its
/// own, even inside one process (see the module docs).
// A struct of one unnamed field (a "newtype"): the two locks work alike, so
// each wraps the same `LockFile`, and as two types the compiler never lets
// one stand in for the other.
#[derive(Debug)]
pub(crate) struct WritersLock(LockFile);

impl WritersLock {
    /// Opens `credential.lock` in the config directory of `dirs`, creating the
    /// directory (0700) and the file (0600, empty) if they are not there yet.
    ///
    /// Refuses a symlink in place of either, a config directory or lock file
    /// open to other users, and anything that is not a directory or a regular
    /// file. These are a few quick local file operations, done directly even
    /// in async code, as `init` does; only the wait for the lock itself has to
    /// avoid blocking.
    pub(crate) fn open(dirs: &Dirs) -> anyhow::Result<Self> {
        LockFile::open(dirs, dirs.credential_lock_file(), WRITERS_LOCK_HELD).map(Self)
    }

    /// Takes the lock, runs `work` while holding it, then releases it and
    /// returns what `work` returned.
    ///
    /// If another command holds the lock, this calls `on_wait` once, so the
    /// caller can say what it is waiting for, and tries again until the lock
    /// comes free, giving up with an error after [`WAIT_TIMEOUT`]. An error
    /// from `work` comes back unchanged, after the lock is released.
    ///
    /// `work` is an async closure (`async || { ... }`), and
    /// `AsyncFnOnce() -> anyhow::Result<T>` is the trait such a closure
    /// implements when it is called at most once. It can borrow the caller's
    /// variables, so a command writes its body inline. It is called only once
    /// the lock is held, so none of its code runs before that.
    ///
    /// `&mut self` because taking the lock needs exclusive use of the open
    /// file: `fd-lock`'s `try_write` takes `&mut`, so the compiler itself
    /// rules out one `WritersLock` being taken twice at once.
    pub(crate) async fn hold<T>(
        &mut self,
        on_wait: impl FnOnce(),
        work: impl AsyncFnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        self.0.hold_within(WAIT_TIMEOUT, on_wait, work).await
    }
}

/// The pull lock file, open and ready to lock: `<config>/pull.lock`, which
/// `pull` holds for its whole run and `post --open` around its writes (see
/// the module docs).
#[derive(Debug)]
pub(crate) struct PullLock(LockFile);

impl PullLock {
    /// Opens `pull.lock` in the config directory of `dirs`, as
    /// [`WritersLock::open`] opens `credential.lock`.
    pub(crate) fn open(dirs: &Dirs) -> anyhow::Result<Self> {
        LockFile::open(dirs, dirs.pull_lock_file(), PULL_LOCK_HELD).map(Self)
    }

    /// Takes the lock and runs `work` while holding it, as
    /// [`WritersLock::hold`] does: a command that waits past
    /// [`WAIT_TIMEOUT`] for a pull to finish gives up, saying another pull
    /// is running.
    pub(crate) async fn hold<T>(
        &mut self,
        on_wait: impl FnOnce(),
        work: impl AsyncFnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        self.0.hold_within(WAIT_TIMEOUT, on_wait, work).await
    }
}

/// One of the install's lock files, open and ready to lock: what
/// [`WritersLock`] and [`PullLock`] share.
#[derive(Debug)]
struct LockFile {
    /// Where the lock file is, for messages.
    path: PathBuf,
    /// The open lock file. `fd_lock::RwLock` owns the `File` and hands out
    /// guards; dropping a guard releases the lock.
    file: RwLock<File>,
    /// What holds the lock, for the message of a wait that gives up: fixed
    /// text.
    held: &'static str,
}

impl LockFile {
    /// Opens the lock file at `path`, in the config directory of `dirs`,
    /// creating both if they are not there yet: see [`WritersLock::open`].
    fn open(dirs: &Dirs, path: PathBuf, held: &'static str) -> anyhow::Result<Self> {
        ensure_private_dir(dirs.config())?;
        let file = open_private_lock_file(&path)?;
        Ok(Self {
            path,
            file: RwLock::new(file),
            held,
        })
    }

    /// [`WritersLock::hold`] with the wait limited to `timeout`, so the tests
    /// can check the give-up without waiting [`WAIT_TIMEOUT`].
    async fn hold_within<T>(
        &mut self,
        timeout: Duration,
        on_wait: impl FnOnce(),
        work: impl AsyncFnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut backoff = Backoff::starting_now(timeout);
        // An `FnOnce` can be called only once, and calling it moves it, which
        // the compiler will not allow inside a loop that might come round
        // again. In an `Option`, `take()` moves it out the first time and
        // leaves `None`, so it runs once and the loop stays legal.
        let mut on_wait = Some(on_wait);
        loop {
            // `try_write` is `flock(LOCK_EX | LOCK_NB)`: it returns at once,
            // with the lock or with `WouldBlock`. Never `write()`, which
            // blocks the thread (see the module docs).
            match self.file.try_write() {
                Ok(guard) => {
                    let result = work().await;
                    // Dropping the guard releases the lock; the explicit
                    // `drop` shows the release comes after the work. (The trap
                    // is `let _ = self.file.try_write()?;`: `_` binds nothing,
                    // so that `let` drops the guard, and releases the lock, at
                    // once.)
                    drop(guard);
                    return result;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    if let Some(on_wait) = on_wait.take() {
                        on_wait();
                    }
                }
                // A signal arrived during the call. Nothing is wrong: try
                // again, without telling the caller it is waiting.
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("could not lock {}", self.path.display()));
                }
            }
            if backoff.has_timed_out() {
                bail!(
                    "{} ({}) after {timeout:?} of waiting; let it finish, then run this command \
                     again",
                    self.held,
                    self.path.display()
                );
            }
            backoff.pause().await;
        }
    }
}

/// The pacing of one wait for the lock: a pause of [`FIRST_RETRY_PAUSE`]
/// that doubles after each try, up to [`MAX_RETRY_PAUSE`], and a deadline
/// `timeout` after the wait began.
struct Backoff {
    /// When the wait began, just before the first try.
    started: Instant,
    /// How long the whole wait may last.
    timeout: Duration,
    /// How long the next pause lasts.
    pause: Duration,
}

impl Backoff {
    /// A wait that begins now and may last `timeout`.
    fn starting_now(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
            pause: FIRST_RETRY_PAUSE,
        }
    }

    /// Whether the whole `timeout` has passed since the wait began.
    fn has_timed_out(&self) -> bool {
        self.started.elapsed() >= self.timeout
    }

    /// Sleeps until the next try, never past the deadline, and doubles the
    /// pause after it. `saturating_*` cannot overflow or panic: at its limit
    /// it stays there.
    async fn pause(&mut self) {
        let left = self.timeout.saturating_sub(self.started.elapsed());
        sleep(self.pause.min(left)).await;
        self.pause = self.pause.saturating_mul(2).min(MAX_RETRY_PAUSE);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::sync::{Barrier, oneshot};
    use tokio::time::{sleep, timeout};

    use super::{PullLock, WritersLock};
    use crate::Dirs;
    use crate::private_fs::ensure_private_dir;
    use crate::test_support::{chmod, dirs_in, mode, private_temp};

    // Done when: "the lock serialising two writers". Two tasks on a
    // multi-thread runtime, so they really do run at the same time, each
    // with its own `WritersLock`, as two commands would have. `flock` locks
    // belong to an open file, not to a process, so two opens of the same
    // file in one process exclude each other just as two processes do.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lock_serialises_two_writers() {
        let home = private_temp();
        let dirs = dirs_in(&home);
        let inside = Arc::new(AtomicBool::new(false));
        // Both writers ask for the lock at the same moment, so one of them
        // has to wait for the other.
        let start = Arc::new(Barrier::new(2));

        // The closure only borrows `dirs`, `inside` and `start` and clones
        // them, so it can be called again for each writer; every task moves
        // its own copies in (`async move`).
        let spawn_writer = || {
            let dirs = dirs.clone();
            let inside = Arc::clone(&inside);
            let start = Arc::clone(&start);
            tokio::spawn(async move {
                let mut lock = WritersLock::open(&dirs).expect("opened");
                start.wait().await;
                lock.hold(
                    || {},
                    async || {
                        // `swap` sets the flag and returns the old value in
                        // one step, so two writers cannot both see `false`.
                        assert!(
                            !inside.swap(true, Ordering::SeqCst),
                            "two writers held the lock at once"
                        );
                        // Long enough that, without the lock, the other
                        // writer would come in meanwhile.
                        sleep(Duration::from_millis(100)).await;
                        inside.store(false, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .await
                .expect("held");
            })
        };

        let writers = [spawn_writer(), spawn_writer()];
        for writer in writers {
            // A panic inside a task, the assertion above included, comes
            // back here as an error.
            writer.await.expect("writer task");
        }
    }

    // A second writer waits while the first holds the lock, and says so once.
    // This is also the check that waiting never blocks the runtime. The
    // scenario runs on a single-thread runtime, where every task shares one
    // thread: if the second writer's wait blocked it (a `flock` without
    // `LOCK_NB`), the first writer could never be told to let go, which is
    // the deadlock two commands on one runtime would hit. The runtime runs in
    // a thread of its own and this test waits at most 30 seconds for it, so
    // such a wait fails the test instead of hanging it.
    #[test]
    fn a_held_lock_makes_the_second_writer_wait() {
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("runtime");
            runtime.block_on(second_writer_waits_for_the_first());
            // Reached only when the scenario did not panic.
            let _ = finished_tx.send(());
        });
        finished_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the scenario failed, or hung because a wait blocked the runtime's thread");
    }

    async fn second_writer_waits_for_the_first() {
        let home = private_temp();
        let dirs = dirs_in(&home);

        let (entered_tx, entered_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let first = tokio::spawn({
            let dirs = dirs.clone();
            async move {
                let mut lock = WritersLock::open(&dirs).expect("opened");
                lock.hold(
                    || {},
                    async move || {
                        entered_tx.send(()).expect("test is listening");
                        release_rx.await.expect("test releases the lock");
                        Ok(())
                    },
                )
                .await
            }
        });
        entered_rx.await.expect("the first writer holds the lock");

        let waits = Arc::new(AtomicUsize::new(0));
        let second = tokio::spawn({
            let dirs = dirs.clone();
            let waits = Arc::clone(&waits);
            async move {
                let mut lock = WritersLock::open(&dirs).expect("opened");
                lock.hold(
                    move || {
                        waits.fetch_add(1, Ordering::SeqCst);
                    },
                    async || Ok(()),
                )
                .await
            }
        });

        // Long enough for many retries; the second writer is still waiting,
        // and has said so exactly once.
        sleep(Duration::from_millis(300)).await;
        assert!(!second.is_finished(), "the second writer did not wait");
        assert_eq!(waits.load(Ordering::SeqCst), 1);

        release_tx.send(()).expect("first writer is waiting");
        first.await.expect("first task").expect("first held");
        timeout(Duration::from_secs(5), second)
            .await
            .expect("the second writer goes ahead once the first lets go")
            .expect("second task")
            .expect("second held");
        assert_eq!(waits.load(Ordering::SeqCst), 1, "on_wait runs once");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_writer_gives_up_after_its_timeout() {
        let home = private_temp();
        let dirs = dirs_in(&home);
        let mut first = WritersLock::open(&dirs).expect("opened");
        let mut second = WritersLock::open(&dirs).expect("opened");

        first
            .hold(
                || {},
                async || {
                    // While the first holds the lock, the second gives up,
                    // with an error naming the lock file, and never runs
                    // its work.
                    let ran = AtomicBool::new(false);
                    let err = second
                        .0
                        .hold_within(
                            Duration::from_millis(200),
                            || {},
                            async || {
                                ran.store(true, Ordering::SeqCst);
                                Ok(())
                            },
                        )
                        .await
                        .expect_err("gives up");
                    assert!(format!("{err:#}").contains("credential.lock"), "{err:#}");
                    assert!(!ran.load(Ordering::SeqCst));
                    Ok(())
                },
            )
            .await
            .expect("held");
    }

    // Two pulls of one install exclude each other as two writers do, and a
    // pull that waits past its timeout says another pull is running.
    #[tokio::test(flavor = "current_thread")]
    async fn a_pull_gives_up_after_its_timeout_saying_another_pull_is_running() {
        let home = private_temp();
        let dirs = dirs_in(&home);
        let mut first = PullLock::open(&dirs).expect("opened");
        let mut second = PullLock::open(&dirs).expect("opened");

        first
            .hold(
                || {},
                async || {
                    let ran = AtomicBool::new(false);
                    let err = second
                        .0
                        .hold_within(
                            Duration::from_millis(200),
                            || {},
                            async || {
                                ran.store(true, Ordering::SeqCst);
                                Ok(())
                            },
                        )
                        .await
                        .expect_err("gives up");
                    let shown = format!("{err:#}");
                    assert!(
                        shown.contains("another sweepky pull on this install is still running"),
                        "{shown}"
                    );
                    assert!(shown.contains("pull.lock"), "{shown}");
                    assert!(!ran.load(Ordering::SeqCst));
                    Ok(())
                },
            )
            .await
            .expect("held");
    }

    // The pull lock is a file of its own, made as the writers' lock is:
    // 0600 and empty, in the 0700 config directory. `pull` holds it for its
    // whole run and the writers' lock for its one public write alone, so
    // holding one never makes the other wait: a zero timeout still takes it,
    // and `on_wait` never runs.
    #[tokio::test(flavor = "current_thread")]
    async fn the_pull_lock_is_its_own_private_file_and_never_waits_for_the_writers_lock() {
        let home = private_temp();
        let dirs = dirs_in(&home);
        let mut pull = PullLock::open(&dirs).expect("opened");
        let mut writers = WritersLock::open(&dirs).expect("opened");

        pull.hold(
            || {},
            async || {
                writers
                    .0
                    .hold_within(
                        Duration::ZERO,
                        || panic!("the writers' lock waited for the pull lock"),
                        async || Ok(()),
                    )
                    .await
            },
        )
        .await
        .expect("both held at once");

        let path = dirs.pull_lock_file();
        assert_ne!(path, dirs.credential_lock_file());
        assert_eq!(mode(dirs.config()), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(fs::symlink_metadata(&path).expect("exists").len(), 0);
    }

    /// The directories under `home`, with the config directory made but no
    /// lock file in it yet, so a test can put something else in its place.
    fn dirs_without_lock_file(home: &TempDir) -> Dirs {
        let dirs = dirs_in(home);
        ensure_private_dir(dirs.config()).expect("config dir");
        dirs
    }

    // Nothing exists yet: the config directory is created 0700 and the lock
    // file 0600, empty.
    #[test]
    fn open_creates_a_private_empty_lock_file() {
        let home = private_temp();
        let dirs = dirs_in(&home);

        drop(WritersLock::open(&dirs).expect("opened"));

        let path = dirs.credential_lock_file();
        assert_eq!(mode(dirs.config()), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(fs::symlink_metadata(&path).expect("exists").len(), 0);
    }

    // Opening it again opens that same file (same inode), never a new one:
    // the lock lives on the file, so a replaced file would let two writers in
    // at once.
    #[test]
    fn reopening_keeps_the_same_lock_file() {
        let home = private_temp();
        let dirs = dirs_in(&home);
        let path = dirs.credential_lock_file();
        drop(WritersLock::open(&dirs).expect("opened"));
        let inode = fs::symlink_metadata(&path).expect("exists").ino();

        drop(WritersLock::open(&dirs).expect("reopened"));

        assert_eq!(fs::symlink_metadata(&path).expect("exists").ino(), inode);
    }

    // A symlink in its place, to a private file or to nothing, is refused,
    // and nothing changes or appears where it points.
    #[test]
    fn a_symlink_in_place_of_the_lock_file_is_refused() {
        let home = private_temp();
        let dirs = dirs_without_lock_file(&home);
        let path = dirs.credential_lock_file();

        let elsewhere = home.path().join("elsewhere");
        fs::write(&elsewhere, "x").expect("write");
        chmod(&elsewhere, 0o600);
        symlink(&elsewhere, &path).expect("symlink");
        let err = WritersLock::open(&dirs).expect_err("a link is refused");
        assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
        assert_eq!(fs::read(&elsewhere).expect("read"), b"x");

        let nowhere = home.path().join("nowhere");
        fs::remove_file(&path).expect("remove");
        symlink(&nowhere, &path).expect("symlink");
        assert!(
            WritersLock::open(&dirs).is_err(),
            "a dangling link is refused"
        );
        assert!(
            fs::symlink_metadata(&nowhere).is_err(),
            "created through a link"
        );
    }

    // A lock file other users could open is refused, not fixed.
    #[test]
    fn a_loose_lock_file_is_refused() {
        let home = private_temp();
        let dirs = dirs_without_lock_file(&home);
        let path = dirs.credential_lock_file();
        fs::write(&path, "").expect("write");
        chmod(&path, 0o644);

        let err = WritersLock::open(&dirs).expect_err("a loose file is refused");

        assert!(format!("{err:#}").contains("chmod 600"), "{err:#}");
        assert_eq!(mode(&path), 0o644);
    }
}
