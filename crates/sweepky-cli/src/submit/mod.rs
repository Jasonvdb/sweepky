//! `sweepky submit [--run-dir <dir>] [--playbook <name>]`, the terminal
//! command the human runs after the agent: it packages the sweep's
//! `audit/`, encrypts it for the bounty's owner and this install, uploads
//! it as `sweeps/<id>.age` and flips the sweep's record to `done`.
//!
//! [`submit`](fn@submit), in the order 00's loop (step 4) and 03's
//! `submit` row give:
//!
//! 1. **The sweep directory** ([`collect_sweep`]). The agent wrote it after
//!    reading untrusted code, so it is treated as hostile (02, "`submit`
//!    trusts nothing in the sweep directory"): `sweep_dir` finds it, from
//!    `--run-dir` or by picking the one sweep in the working directory's
//!    project not yet submitted, and checks it is a real directory directly
//!    in the canonical `init` project's real `sweeps/`, holding the marker
//!    `run` wrote, which must point at this login's own sweep of that
//!    directory's id. `walk` then walks it from the handle those checks
//!    opened, following no link, refusing links, hard links, FIFOs,
//!    sockets and devices, skipping `target/` and the agents' `scratch/`,
//!    within caps on entries, depth and sizes, and reads `audit/`'s files.
//! 2. **The records**, with no session: the sweep's own record, which must
//!    say `running`, and the bounty it names, from its owner's storage. A
//!    bounty that is no longer open gets a warning, not a refusal: the
//!    sweep was run while it was, and its owner can still read it.
//! 3. **The playbook and the manifest** (`manifest`): `--playbook`, or the
//!    record's own unless it is still `run`'s placeholder; and the
//!    manifest, from the record and the commits `run` checked out, which
//!    it kept in the data directory (`crate::sweep_state`), never from the
//!    marker or `scope.json`. A sweep with no such snapshot is refused, and
//!    so is one whose bounty no longer pins its targets as `run` fetched
//!    them: the sweep must be run again.
//! 4. **The package**: core's `SweepPackage::build`, which converts a
//!    Cloudflare `findings.json` and leaves out, with a warning naming the
//!    file, anything that is not text or sits at a path a package may not
//!    hold.
//! 5. **The owner's keys** (`owner_keys`): only their unrevoked, strictly
//!    parsed `keys/` records, checked against the pin in `owner-keys.json`;
//!    a new key is warned of and asked about, so this may wait on a person,
//!    which is why it comes before the lock. A no ends the command, with
//!    nothing written.
//! 6. **The file list** on standard error, then this install's own key,
//!    read from `device.key`, whose secret is dropped as soon as its public
//!    half is taken, and core's `seal_package` to the owner's keys plus
//!    that one.
//! 7. **Under the writers' lock, with a fresh session** ([`finish_sweep`]):
//!    the record is read back and must still say `running`, for the same
//!    bounty and targets; the pin is written; `sweeps/<id>.age` is
//!    uploaded; and the record is rewritten as `done`, with `finishedAt`
//!    and the playbook. Once the record says `done`, or a refused upload
//!    has flipped it to `aborted`, the snapshot is removed; while it says
//!    `running`, the snapshot stays for the next try.
//! 8. **The stamp** `.sweepky/submitted`, after the lock, so that picking
//!    without `--run-dir` passes this sweep over.
//!
//! **What a failure leaves.** Every step before 7, and a retryable
//! failure in it (the sign-in, a network error, a 429), changes nothing in
//! public: the record still says `running`, and `submit` can be run again.
//! A homeserver that refuses the package itself (413, 507 or any other
//! non-2xx) flips the record to `aborted`, which is final: 01's polling
//! re-fetches only `running` sweeps and 04 shows an aborted one struck,
//! so a new `run` is the retry.
//!
//! **What is printed.** Paths in the sweep directory, sanitised, counts,
//! checked values (ids, keys, URLs) and fixed text: never a byte of a
//! finding or an attachment, never a package, and never a server's words.

mod manifest;
mod owner_keys;
mod sweep_dir;
// `pub(crate)`: `run` places a sweep with the walk's handle calls too.
pub(crate) mod walk;

use std::iter;
use std::path::Path;

use anyhow::{Context as _, bail};
use pubky::StatusCode;
use sweepky_core::paths;
use sweepky_core::{
    AgeRecipient, AttachmentPath, Bounty, BuiltPackage, FindingsSource, KnownBountyStatus,
    KnownSweepStatus, Manifest, Playbook, Pubky, RecordId, RecordTime, SkipReason, SkippedFile,
    Sweep, SweepPackage, SweepRef, seal_package,
};

use self::manifest::{build_manifest, final_playbook, require_running};
use self::owner_keys::{AcceptedKeys, accept_owner_keys};
use self::sweep_dir::{SweepDir, find_sweep_dir};
use self::walk::{AuditFiles, read_audit};
use crate::device::{PublicKeyReader, PublicKeys, read_device_key};
use crate::display::sanitize;
use crate::identity::refuse_secret_material;
use crate::own_storage::{OwnStorage, SessionStorage};
use crate::prompt::Prompting;
use crate::records::{PublicRecordReader, PublicRecords};
use crate::remote::{status_of, upload_error};
use crate::run::{logged_in_sweeper, put_record, record_bytes};
use crate::session::with_writer_session;
use crate::sweep_state::{forget_snapshot, read_snapshot};
use crate::{Context, Dirs, Report, clock};

/// What the report says when the person answered no to the question about
/// the owner's new keys.
const NOT_CONFIRMED: &str = "Not confirmed, so nothing was encrypted or uploaded; the sweep's \
                             record still says running, and submit can be run again.\n";

/// What the error says, in front of the failure, once a refused upload has
/// flipped the record to `aborted`.
const ABORTED: &str = "submit stopped, and the sweep's public record now says aborted, which is \
                       final: start a new sweep of the bounty with `sweepky run`";

/// What the error says, in front of the failure, when the record could not
/// be flipped to `aborted` either.
const NOT_ABORTED: &str = "submit stopped, but the sweep's public record could not be changed to \
                           aborted and still says running";

/// What the error says, in front of a failure that changed nothing in
/// public: the record still says `running`, so `submit` can be run again.
const STILL_RUNNING: &str = "submit stopped, and the sweep's public record still says running, \
                             so run submit again";

/// What the write under the lock refuses when `login.json` names another
/// pubky than the one the sweep directory was checked for.
const LOGIN_CHANGED: &str = "this install was logged in as another identity while submit built \
                             the package, so nothing was uploaded; run it again";

/// Runs `sweepky submit [--run-dir <dir>] [--playbook <name>]` from
/// `ctx.cwd`: see the module docs for the order and why. `prompting` is
/// `--no-input`, for the question about the owner's new keys.
pub(crate) async fn submit(
    ctx: &Context,
    prompting: Prompting,
    run_dir: Option<&Path>,
    playbook: Option<&str>,
) -> anyhow::Result<Report> {
    // `map` parses only a `Some`, and `transpose` turns the
    // `Option<Result<..>>` into the `Result<Option<..>>` that `?` takes.
    let playbook = playbook.map(parse_playbook_flag).transpose()?;
    let request = SubmitRequest {
        prompting,
        run_dir,
        playbook,
        sweeper: logged_in_sweeper(&ctx.dirs)?,
    };
    let client = ctx.network.pubky();
    let locked = LockedSession {
        ctx,
        sweeper: request.sweeper,
    };
    submit_through(
        ctx,
        &request,
        &PublicRecordReader::new(client),
        &PublicKeyReader::new(client),
        &locked,
    )
    .await
}

/// What `submit` was asked to do: the flags, checked, and who asks.
struct SubmitRequest<'a> {
    /// `--no-input`, as a `Prompting`.
    prompting: Prompting,
    /// `--run-dir`, as given, relative to the working directory.
    run_dir: Option<&'a Path>,
    /// `--playbook`, checked as core's `Playbook`.
    playbook: Option<Playbook>,
    /// The sweeper: the pubky this install is logged in as.
    sweeper: Pubky,
}

/// `--playbook`'s value, checked: the playbook the manifest and the public
/// record name, so 01's pattern, `^[A-Za-z0-9._/-]{1,64}(@[0-9a-f]{7,40})?$`.
///
/// A raw key in z-base32 or hex passes that pattern, and the record is
/// public, so a key or phrase pasted here is refused first, by `login`'s
/// classifier. Neither refusal quotes the value.
fn parse_playbook_flag(text: &str) -> anyhow::Result<Playbook> {
    if let Some(refusal) = refuse_secret_material(text.as_bytes()) {
        // `into` makes the `Refusal` the error itself, which says what the
        // text looks like and why Sweepky never takes one.
        return Err(refusal.into());
    }
    // `map_err(|_| …)` drops core's error, whose text is fixed anyway, for
    // one that says what the flag takes.
    text.parse().map_err(|_| {
        anyhow::anyhow!(
            "--playbook must name a playbook as a sweep record holds it: up to 64 of A-Z a-z 0-9 \
             . _ / -, then optionally @ and 7 to 40 lower-case hex digits of a commit, such as \
             cloudflare/security-audit@c1c8a8c"
        )
    })
}

/// [`submit`](fn@submit) with its seams given: `records` for the sweep's
/// record and the bounty, `keys` for the owner's `keys/`, and `finisher`
/// for the steps under the writers' lock. The tests pass fakes.
async fn submit_through(
    ctx: &Context,
    request: &SubmitRequest<'_>,
    records: &impl PublicRecords,
    keys: &impl PublicKeys,
    finisher: &impl FinishSweep,
) -> anyhow::Result<Report> {
    // Taking the struct apart moves its two fields out, so the files can
    // move into the package below while the directory stays here.
    let CollectedSweep { dir, audit } = collect_sweep(&ctx.cwd, request.run_dir, &request.sweeper)?;
    let sweep = dir.sweep();
    let (record, bounty) = read_records(ctx, records, sweep).await?;
    let playbook = final_playbook(request.playbook.as_ref(), &record)?;
    let fetched = read_snapshot(&ctx.dirs, sweep)?;
    let manifest = build_manifest(
        request.sweeper,
        &record,
        record.bounty,
        &bounty,
        &fetched,
        playbook.clone(),
        clock::now()?,
    )?;
    let finished_at = manifest.finished_at.clone();
    // The list is made before the files move into the package.
    let listing = audit.listing();
    let built = build_package(ctx, manifest, audit)?;
    let Some(accepted) =
        accept_owner_keys(ctx, request.prompting, keys, record.bounty.owner).await?
    else {
        return Ok(Report::new(NOT_CONFIRMED));
    };
    ctx.stderr.write_flushed(&file_list(&listing))?;
    let ciphertext = seal_for(&built.package, &accepted, own_recipient(ctx)?)?;
    // The package is sealed content in ordinary strings: dropped as soon
    // as it is sealed, rather than kept through the uploads.
    drop(built);
    let sealed_len = ciphertext.len();
    finisher
        .finish(Upload {
            sweep,
            read: &record,
            playbook: playbook.clone(),
            finished_at,
            ciphertext,
            keys: &accepted,
            dirs: &ctx.dirs,
        })
        .await?;
    stamp(ctx, &dir);
    Ok(Report::new(submitted_report(
        sweep,
        sealed_len,
        accepted.keys().len(),
        &playbook,
    )))
}

/// Stamps `dir` as submitted, step 8 of the module docs. A failure is a
/// warning, never an error: the sweep is done by then, and the stamp only
/// narrows what `submit` without `--run-dir` picks.
fn stamp(ctx: &Context, dir: &SweepDir) {
    if let Err(error) = dir.stamp_submitted() {
        // A courtesy, like the lock's waiting line: if standard error
        // cannot be written either, the command still reports its success,
        // so the result is dropped with `let _ =`.
        let _ = ctx.stderr.line(&format!(
            "warning: the sweep is submitted, but {error:#}; submit without --run-dir may offer \
             it again, and will then find it done"
        ));
    }
}

/// What `submit` takes from a sweep directory before it builds a package.
// No `Debug`: `AuditFiles` has none, as it holds the agent's file names
// and the audit's bytes.
struct CollectedSweep {
    /// The sweep directory, checked, and the sweep its marker points at.
    dir: SweepDir,
    /// `audit/`'s files, read.
    audit: AuditFiles,
}

/// Finds and checks the sweep directory `run_dir` names, relative to `cwd`
/// (without it, the one sweep waiting in the project at `cwd`), for
/// `sweeper`, this login's pubky, then walks it and reads `audit/`'s files.
/// See the module docs; any refusal names the entry, sanitised, and quotes
/// no file.
fn collect_sweep(
    cwd: &Path,
    run_dir: Option<&Path>,
    sweeper: &Pubky,
) -> anyhow::Result<CollectedSweep> {
    let dir = find_sweep_dir(cwd, run_dir, sweeper)?;
    let audit = read_audit(&dir)?;
    Ok(CollectedSweep { dir, audit })
}

/// The record of `sweep` and the bounty it names, read with no session
/// through `records`: step 2 of the module docs. The record must say
/// `running`; a bounty that is no longer open is a warning on standard
/// error.
async fn read_records(
    ctx: &Context,
    records: &impl PublicRecords,
    sweep: SweepRef,
) -> anyhow::Result<(Sweep, Bounty)> {
    let Some(record) = records.get_sweep(sweep).await? else {
        bail!(
            "this login's storage holds no {}, the record `sweepky run` publishes, so there is no \
             sweep to complete",
            paths::sweep_record(sweep.id)
        );
    };
    require_running(&record)?;
    let Some(bounty) = records.get_bounty(record.bounty).await? else {
        bail!(
            "the bounty this sweep was run for is gone from its owner's storage, so submit cannot \
             tell which commits were swept and sent nothing"
        );
    };
    if bounty.status().as_known() != Some(KnownBountyStatus::Open) {
        ctx.stderr.line(
            "warning: the bounty is no longer open (its owner may have marked it done), so its \
             owner may not read this sweep; submitting it all the same",
        )?;
    }
    Ok((record, bounty))
}

/// The package of `manifest` and `audit`'s files, through core's
/// `SweepPackage::build`, and a line on standard error for what the
/// sweeper should know of it: a Cloudflare `findings.json` converted, and
/// each file left out, named by its sanitised path, and why.
fn build_package(
    ctx: &Context,
    manifest: Manifest,
    audit: AuditFiles,
) -> anyhow::Result<BuiltPackage> {
    // core's `PackageError` names a file by its position, never its path or
    // a byte of it.
    let built = SweepPackage::build(manifest, audit.files)
        .context("could not build the sweep package from audit/")?;
    if built.findings_source == FindingsSource::Cloudflare {
        ctx.stderr.line(
            "audit/findings.json is in Cloudflare's format: converted to Sweepky's common \
             format, each record kept whole in its extra.cloudflare",
        )?;
    }
    for skipped in &built.skipped {
        ctx.stderr.line(&skipped_warning(skipped))?;
    }
    Ok(built)
}

/// The warning for a file `SweepPackage::build` left out. The path is the
/// agent's, so it goes through the terminal sanitiser.
fn skipped_warning(skipped: &SkippedFile) -> String {
    let why = match skipped.reason {
        SkipReason::NotText => "it is not UTF-8 text, and a sweep package holds text only",
        SkipReason::BadPath => "its path is not one a sweep package may hold",
    };
    format!(
        "warning: audit/{} is left out of the package: {why}",
        sanitize(&skipped.path, AttachmentPath::MAX_LEN)
    )
}

/// The file list printed before the package is encrypted: `listing`, the
/// walk's sanitised lines, under a heading.
fn file_list(listing: &[String]) -> String {
    let mut text = format!(
        "The package is built from these {} files of audit/ (any left out is warned of above):\n",
        listing.len()
    );
    for line in listing {
        text.push_str(&format!("  {line}\n"));
    }
    text
}

/// This install's own key, the public half of `device.key`, so the sweeper
/// can read their own sweep (02). The file is unwrapped with the context's
/// passphrase when it is wrapped.
fn own_recipient(ctx: &Context) -> anyhow::Result<AgeRecipient> {
    let Some(identity) = read_device_key(&ctx.dirs, ctx.passphrase.as_ref())? else {
        bail!(
            "this install has no device key ({} is missing), so it could not read its own sweep; \
             run `sweepky login` first",
            ctx.dirs.device_key_file().display()
        );
    };
    // `recipient()` derives the public half; `identity`, which holds the
    // secret, is dropped (and wipes itself) when this function returns,
    // right after.
    Ok(identity.recipient())
}

/// `package` sealed with core's `seal_package` to `owner_keys` and `own`,
/// this install's key: at most `MAX_RECIPIENTS`, since `owner_keys` holds
/// at most one fewer, and core checks again.
fn seal_for(
    package: &SweepPackage,
    owner_keys: &AcceptedKeys,
    own: AgeRecipient,
) -> anyhow::Result<Vec<u8>> {
    let recipients: Vec<AgeRecipient> = owner_keys
        .keys()
        .iter()
        .map(|key| key.recipient.clone())
        .chain(iter::once(own))
        .collect();
    // core's `SealError` is fixed text.
    seal_package(package, &recipients).context("could not encrypt the sweep package")
}

/// Everything the steps under the writers' lock need, all made before the
/// lock is taken. It borrows the record read, the keys and the
/// directories from `submit` (the lifetime `'a`) and owns the rest.
struct Upload<'a> {
    /// The sweep: this login's, with the sweep directory's id.
    sweep: SweepRef,
    /// The record as `submit` read it before it built the package: under
    /// the lock it must still say `running`, for this bounty and targets.
    read: &'a Sweep,
    /// The playbook the `done` record names.
    playbook: Playbook,
    /// When the sweep finished, as the manifest says.
    finished_at: RecordTime,
    /// The sealed package, `sweeps/<id>.age`. Public, so a plain `Vec`.
    ciphertext: Vec<u8>,
    /// The owner's keys it was sealed to, whose pin is written under the
    /// lock.
    keys: &'a AcceptedKeys,
    /// Where the pin is written.
    dirs: &'a Dirs,
}

/// Runs [`finish_sweep`] with this login's own storage, under the writers'
/// lock.
///
/// A trait so that the steps under the lock can be tested without a
/// homeserver: the tests implement it for `test_support::FakeOwnStorage`,
/// as `run` does its `PublishRecord`. Its method is an `async fn`, so
/// callers take `&impl FinishSweep`.
trait FinishSweep {
    /// Step 7 of the module docs for `upload`.
    async fn finish(&self, upload: Upload<'_>) -> anyhow::Result<()>;
}

/// The real [`FinishSweep`]: the writers' lock and a session signed in for
/// these steps alone, and signed out at once, so the lock is held around
/// a sign-in, the pin write, the uploads and a sign-out, and never while
/// a question waits on a person.
struct LockedSession<'a> {
    ctx: &'a Context,
    /// The pubky the sweep directory was checked for, which the session
    /// must be.
    sweeper: Pubky,
}

impl FinishSweep for LockedSession<'_> {
    async fn finish(&self, upload: Upload<'_>) -> anyhow::Result<()> {
        // `async move` moves `upload` into the body. The body only borrows
        // the session, so `with_writer_session` signs it out whatever the
        // body returns.
        //
        // The body hands its own result back inside an `Ok`, so an `Err`
        // out of `with_writer_session` is one the body never saw: the lock
        // or the sign-in failed, before anything was written. Only that
        // one gets [`STILL_RUNNING`] here; `?` then leaves the body's own
        // result, whose errors say what they changed, as the value.
        with_writer_session(self.ctx, async move |signed| {
            // `login.json` is read again under the lock: a `login` as
            // another identity since would upload this sweep under a pubky
            // the sweep directory was not checked for.
            if signed.login().pubky != self.sweeper {
                return Ok(Err(anyhow::Error::msg(LOGIN_CHANGED)));
            }
            Ok(finish_sweep(&SessionStorage::new(signed), upload).await)
        })
        .await
        .context(STILL_RUNNING)?
    }
}

/// Step 7 of the module docs, through `storage`, this login's own: the
/// record read back and checked, the pin written, `sweeps/<id>.age`
/// uploaded and the record flipped to `done`. A refused upload flips it to
/// `aborted` instead ([`abort_upload`]); a 429 or a failure that is no
/// answer at all leaves it `running`. The snapshot of what `run` fetched
/// is forgotten once the record says `done` or `aborted`, and kept while
/// it says `running`, so that `submit` can be run again.
async fn finish_sweep(storage: &impl OwnStorage, upload: Upload<'_>) -> anyhow::Result<()> {
    // Taking `upload` apart moves each field out on its own, so the
    // ciphertext can move into its PUT while the rest is still used.
    let Upload {
        sweep,
        read,
        playbook,
        finished_at,
        ciphertext,
        keys,
        dirs,
    } = upload;
    let record_path = paths::sweep_record(sweep.id);
    let current = read_own_record(storage, &record_path).await?;
    require_unchanged(&current, read, &record_path)?;
    keys.write_pin(dirs)?;
    let package_path = paths::sweep_package(sweep.id);
    if let Err(error) = storage.put(&package_path, ciphertext).await {
        let failure = upload_error(&error).context(format!("could not upload {package_path}"));
        if !refuses_the_package(&error) {
            return Err(failure.context(STILL_RUNNING));
        }
        let aborted = finished_record(current, KnownSweepStatus::Aborted, playbook, finished_at);
        return Err(abort_upload(storage, &record_path, &aborted, failure, dirs, &sweep.id).await);
    }
    let done = finished_record(current, KnownSweepStatus::Done, playbook, finished_at);
    put_record(storage, &record_path, record_bytes(&done)?)
        .await
        .with_context(|| {
            format!(
                "uploaded {package_path}, but could not change the sweep's record to done, so it \
                 still says running; run submit again"
            )
        })?;
    forget_snapshot(dirs, &sweep.id);
    Ok(())
}

/// Whether `error`, from the `.age` PUT, is the homeserver refusing the
/// package: any answer but a 429, which asks to come back later. An error
/// that is no answer at all (a network failure) may go through on another
/// try too.
fn refuses_the_package(error: &pubky::Error) -> bool {
    status_of(error).is_some_and(|status| status != StatusCode::TOO_MANY_REQUESTS)
}

/// This login's own record at `path`, read back through `storage` (under
/// the lock, through the session).
async fn read_own_record(storage: &impl OwnStorage, path: &str) -> anyhow::Result<Sweep> {
    let Some(bytes) = storage.get_own(path).await? else {
        bail!("{path} is gone from this login's storage, so nothing was uploaded");
    };
    // core's `RecordError` names the kind of fault and where, never a byte.
    Sweep::from_json(&bytes)
        .with_context(|| format!("{path} in this login's storage is not a sweep record"))
}

/// Refuses `current`, the record read back under the lock, unless it still
/// says `running`, for the bounty and targets of `read`, the record the
/// package was built from.
fn require_unchanged(current: &Sweep, read: &Sweep, path: &str) -> anyhow::Result<()> {
    require_running(current)?;
    if current.bounty != read.bounty || current.targets != read.targets {
        bail!(
            "{path} changed while submit built the package: it names another bounty or other \
             targets now, so nothing was uploaded; run submit again"
        );
    }
    Ok(())
}

/// The error `submit` stops with when the homeserver refused the package
/// with `failure`: `failure` behind [`ABORTED`] once `aborted` is written
/// at `path`, which is final, so the snapshot of sweep `id` under `dirs` is
/// forgotten; or behind [`NOT_ABORTED`] and the flip's own error, fixed
/// text too, when it could not be, the snapshot kept for the next try.
async fn abort_upload(
    storage: &impl OwnStorage,
    path: &str,
    aborted: &Sweep,
    failure: anyhow::Error,
    dirs: &Dirs,
    id: &RecordId,
) -> anyhow::Error {
    // An `async` block, so that `?` inside it stops the block, not this
    // function, and both ways the flip can fail end up in `flipped`.
    let flipped = async { put_record(storage, path, record_bytes(aborted)?).await }.await;
    match flipped {
        Ok(()) => {
            forget_snapshot(dirs, id);
            failure.context(ABORTED)
        }
        // `{:#}` writes the flip's whole chain of context on one line.
        Err(flip) => failure.context(format!("{NOT_ABORTED} ({flip:#})")),
    }
}

/// `record`, read back under the lock, finished: `status` (`done` or
/// `aborted`), the final `playbook` and `finished_at`. Every other field is
/// kept as it was, those a newer Sweepky wrote included. `sha256` is left
/// as it is, unset: 01 does not say what it is a digest of.
// `mut record`: this function owns the record it was given, so it may
// change it before handing it back.
fn finished_record(
    mut record: Sweep,
    status: KnownSweepStatus,
    playbook: Playbook,
    finished_at: RecordTime,
) -> Sweep {
    record.status = status.into();
    record.playbook = playbook;
    record.finished_at = Some(finished_at);
    record
}

/// What `submit` reports once the sweep is done: checked values and
/// counts alone.
fn submitted_report(
    sweep: SweepRef,
    sealed_len: usize,
    owner_keys: usize,
    playbook: &Playbook,
) -> String {
    format!(
        "Submitted the sweep {sweep}.\nUploaded sweeps/{}.age ({sealed_len} bytes), encrypted to \
         {owner_keys} key(s) of the bounty's owner and this install's own, and the record now \
         says done, with the playbook {playbook}.\n",
        sweep.id
    )
}

/// An `init` project with a whole sweep directory in it, as `run` leaves
/// one, for the tests of this module and the two below it, and a config
/// directory beside it to plant links to.
#[cfg(test)]
mod fixture {
    use std::fs;
    use std::path::{Path, PathBuf};

    use serde_json::json;
    use sweepky_core::{BountyRef, Pubky, RecordId, SweepRef};
    use tempfile::TempDir;

    use super::sweep_dir::{SweepDir, find_sweep_dir};
    use crate::Dirs;
    use crate::private_fs::{ensure_private_dir, write_private_file};
    use crate::test_support::{PLANTED, bounty_id, json_bytes, private_temp, random_pubky};

    /// A common-format `findings.json` with no findings.
    const FINDINGS: &str = "{\"schemaVersion\":1,\"playbook\":\"cloudflare/security-audit@c1c8a8c\",\"findings\":[]}\n";

    /// A project at `<root>/<name>`, made by `init`, with the sweep
    /// directory `sweeps/<id>/` of `sweeper`'s sweep `id`: `target/t1/`,
    /// `scope.json`, `brief.md`, the marker, and `audit/findings.json`.
    pub(in crate::submit) struct SweepFixture {
        root: PathBuf,
        project: PathBuf,
        id: RecordId,
        sweeper: Pubky,
        /// The temp directory `root` is, deleted when dropped; `None` for
        /// a fixture made beside another, whose temp directory holds both.
        _temp: Option<TempDir>,
    }

    impl SweepFixture {
        /// A fixture in a new private temp directory, for a random sweeper.
        pub(in crate::submit) fn new() -> Self {
            let temp = private_temp();
            let mut fixture = Self::make(temp.path(), "p", random_pubky(), bounty_id());
            fixture._temp = Some(temp);
            fixture
        }

        /// A second project, `name`, beside `other`'s, with a sweep
        /// directory of the same id for the same sweeper. `other` must
        /// outlive it, since it owns the temp directory.
        pub(in crate::submit) fn in_temp_with(other: &Self, name: &str) -> Self {
            Self::make(&other.root, name, other.sweeper, other.id)
        }

        fn make(root: &Path, name: &str, sweeper: Pubky, id: RecordId) -> Self {
            let project = root.join(name);
            crate::init::init(&project).expect("init");
            let fixture = Self {
                root: root.to_owned(),
                project,
                id,
                sweeper,
                _temp: None,
            };
            fixture.add_sweep(id);
            fixture
        }

        /// Adds the whole sweep directory `sweeps/<id>/` to the project,
        /// and gives its path.
        pub(in crate::submit) fn add_sweep(&self, id: RecordId) -> PathBuf {
            let dir = self.project.join("sweeps").join(id.to_string());
            fs::create_dir_all(dir.join("target/t1")).expect("mkdir");
            fs::write(dir.join("target/t1/README.md"), "the target\n").expect("write");
            fs::write(dir.join("scope.json"), "{\"schemaVersion\":1}\n").expect("write");
            fs::write(dir.join("brief.md"), "Look at the session handling.\n").expect("write");
            fs::create_dir(dir.join(".sweepky")).expect("mkdir");
            self.write_marker(&dir, &self.marker_bytes(self.sweeper, id));
            fs::create_dir(dir.join("audit")).expect("mkdir");
            fs::write(dir.join("audit/findings.json"), FINDINGS).expect("write");
            dir
        }

        /// A marker as `run` writes one, pointing at `sweeper`'s sweep
        /// `id`.
        pub(in crate::submit) fn marker_bytes(&self, sweeper: Pubky, id: RecordId) -> Vec<u8> {
            let bounty = BountyRef {
                owner: random_pubky(),
                id: bounty_id(),
            };
            json_bytes(&json!({
                "schemaVersion": 1,
                "sweep": SweepRef { sweeper, id }.to_string(),
                "bounty": bounty.to_string(),
                "targets": ["t1"],
            }))
        }

        /// Writes `bytes` as the marker of the sweep directory `dir`.
        pub(in crate::submit) fn write_marker(&self, dir: &Path, bytes: &[u8]) {
            fs::write(dir.join(".sweepky/sweep.json"), bytes).expect("write");
        }

        /// Stamps the sweep directory `dir` as submitted, as the command
        /// will: `.sweepky/submitted`.
        pub(in crate::submit) fn stamp(&self, dir: &Path) {
            fs::write(dir.join(".sweepky/submitted"), "").expect("write");
        }

        /// The sweep directory, checked as `--run-dir sweeps/<id>` from
        /// the project.
        pub(in crate::submit) fn open(&self) -> SweepDir {
            let run_dir = PathBuf::from(format!("sweeps/{}", self.id));
            find_sweep_dir(&self.project, Some(&run_dir), &self.sweeper)
                .unwrap_or_else(|err| panic!("refused: {err:#}"))
        }

        /// The temp directory everything is in.
        pub(in crate::submit) fn temp(&self) -> &Path {
            &self.root
        }

        pub(in crate::submit) fn project(&self) -> &Path {
            &self.project
        }

        /// `<project>/sweeps/<id>`, as made (not canonicalised).
        pub(in crate::submit) fn dir(&self) -> PathBuf {
            self.project.join("sweeps").join(self.id.to_string())
        }

        pub(in crate::submit) fn audit(&self) -> PathBuf {
            self.dir().join("audit")
        }

        pub(in crate::submit) fn id(&self) -> RecordId {
            self.id
        }

        pub(in crate::submit) fn sweeper(&self) -> Pubky {
            self.sweeper
        }

        /// The length of the `findings.json` every sweep directory starts
        /// with.
        pub(in crate::submit) fn findings_len(&self) -> usize {
            FINDINGS.len()
        }
    }

    /// This install's config directory, as `SWEEPKY_HOME=<temp>/home` gives
    /// it, beside a fixture's project, so on the same filesystem and a hard
    /// link can reach it. It holds a `device.key` of synthetic text.
    pub(in crate::submit) struct ConfigDir {
        dirs: Dirs,
    }

    impl ConfigDir {
        pub(in crate::submit) fn new(fixture: &SweepFixture) -> Self {
            let home = fixture.root.join("home");
            let dirs = Dirs::resolve(None, Some(home.as_os_str())).expect("absolute");
            ensure_private_dir(dirs.config()).expect("config dir");
            write_private_file(&dirs.device_key_file(), PLANTED.as_bytes()).expect("device.key");
            Self { dirs }
        }

        pub(in crate::submit) fn path(&self) -> &Path {
            self.dirs.config()
        }

        pub(in crate::submit) fn device_key(&self) -> PathBuf {
            self.dirs.device_key_file()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use sweepky_core::SweepRef;

    use super::collect_sweep;
    use super::fixture::{ConfigDir, SweepFixture};
    use crate::test_support::PLANTED;

    #[test]
    fn a_whole_sweep_directory_is_collected_with_or_without_run_dir() {
        let fixture = SweepFixture::new();
        let run_dir = PathBuf::from(format!("sweeps/{}", fixture.id()));
        for run_dir in [Some(run_dir.as_path()), None] {
            let collected = collect_sweep(fixture.project(), run_dir, &fixture.sweeper())
                .unwrap_or_else(|err| panic!("refused: {err:#}"));
            assert_eq!(
                collected.dir.sweep(),
                SweepRef {
                    sweeper: fixture.sweeper(),
                    id: fixture.id(),
                }
            );
            let paths: Vec<&str> = collected
                .audit
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect();
            assert_eq!(paths, ["findings.json"]);
        }
    }

    // 06's check: a run directory holding a planted symlink, or a hard
    // link, to a file in the config directory is refused, and nothing of
    // the file is read or shown.
    #[test]
    fn a_planted_link_or_hard_link_to_the_config_dir_is_refused() {
        // `what` is also what the refusal says of the planted file.
        for what in ["a symbolic link", "hard links"] {
            let fixture = SweepFixture::new();
            let config = ConfigDir::new(&fixture);
            let (key, planted) = (config.device_key(), fixture.audit().join("device.key"));
            if what == "hard links" {
                fs::hard_link(&key, &planted)
            } else {
                symlink(&key, &planted)
            }
            .expect("planted");
            let run_dir = PathBuf::from(format!("sweeps/{}", fixture.id()));

            let err = match collect_sweep(fixture.project(), Some(&run_dir), &fixture.sweeper()) {
                Ok(_) => panic!("{what}: accepted"),
                Err(err) => format!("{err:#}"),
            };

            assert!(err.contains("audit/device.key"), "{what}: {err}");
            assert!(err.contains(what), "{what}: {err}");
            assert!(!err.contains(PLANTED), "{what}: {err}");
        }
    }
}

/// The command, against fakes: the sweeper's own storage, the bounty
/// owner's, and the owner's `keys/`.
#[cfg(test)]
mod command_tests {
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};

    use pubky::StatusCode;
    use serde_json::{Value, json};
    use sweepky_core::paths;
    use sweepky_core::{
        AttachmentPath, BountyRef, DeviceId, DeviceIdentity, KnownSweepStatus, Playbook, Pubky,
        RecordId, Sweep, SweepRef, Zeroizing, open_package, parse_audit_findings,
    };
    use tempfile::TempDir;

    use super::fixture::SweepFixture;
    use super::manifest::{ABORTED_IS_FINAL, TARGETS_CHANGED};
    use super::owner_keys::accept_owner_keys;
    use super::{
        ABORTED, FinishSweep, NOT_ABORTED, NOT_CONFIRMED, STILL_RUNNING, SubmitRequest, Upload,
        finish_sweep, parse_playbook_flag, submit_through,
    };
    use crate::Report;
    use crate::device::{create_device_key, device_key_bytes, device_key_record};
    use crate::identity::Refusal;
    use crate::own_storage::OwnStorage;
    use crate::pins::{OwnerKey, pin_owner_keys, read_pins};
    use crate::prompt::Prompting;
    use crate::records::PublicRecords;
    use crate::remote::{
        Conditional, ETag, Listing, PACKAGE_TOO_LARGE, QUOTA_FULL, RATE_LIMITED, UPLOAD_QUOTA_FULL,
    };
    use crate::sweep_state::NO_SNAPSHOT;
    use crate::test_support::{
        FakeKeyStore, FakeOwnStorage, FakePublicRecords, SYNTHETIC_HEAD, SYNTHETIC_SHA, bounty_id,
        bounty_json, bounty_of, dirs_in, json_bytes, offline_network, pr_target_json, private_temp,
        random_pubky, repo_target_json, snapshot_of, sweep_json, test_context,
    };

    /// What the fake storage answers a refused write with: no message may
    /// repeat it.
    const SERVER_TEXT: &str = "MARKER-5k8d: tenant over quota, path policy says no";

    const PLAYBOOK: &str = "cloudflare/security-audit@c1c8a8c";

    /// In the tests, the fake storage stands for the sweeper's own storage
    /// under the lock: the steps run straight against it. (An `impl` may
    /// sit in any module of the crate; here it is with the tests that use
    /// it.)
    impl FinishSweep for FakeOwnStorage {
        async fn finish(&self, upload: Upload<'_>) -> anyhow::Result<()> {
            finish_sweep(self, upload).await
        }
    }

    /// The homeservers as `submit` sees them here: the sweeper's own files
    /// in `own`, which a public read sees too, and everyone else's in
    /// `others`.
    struct Homeservers {
        sweeper: Pubky,
        own: FakeOwnStorage,
        others: FakePublicRecords,
    }

    impl PublicRecords for Homeservers {
        async fn get_record(
            &self,
            owner: Pubky,
            path: &str,
        ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
            if owner == self.sweeper {
                self.own.get_own(path).await
            } else {
                self.others.get_record(owner, path).await
            }
        }

        async fn list(&self, owner: Pubky, dir: &str) -> anyhow::Result<Listing> {
            self.others.list(owner, dir).await
        }

        // `submit` calls none of the three below; the trait asks for them,
        // and like `list` they answer from everyone else's storage.
        async fn list_newest_first(
            &self,
            owner: Pubky,
            dir: &str,
            seen: Option<RecordId>,
        ) -> anyhow::Result<Listing> {
            self.others.list_newest_first(owner, dir, seen).await
        }

        async fn get_record_if_changed(
            &self,
            owner: Pubky,
            path: &str,
            etag: Option<&ETag>,
        ) -> anyhow::Result<Conditional> {
            self.others.get_record_if_changed(owner, path, etag).await
        }

        async fn get_package(&self, sweep: SweepRef) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
            self.others.get_package(sweep).await
        }
    }

    /// `fixtures/cloudflare/<name>`: the Cloudflare-shaped run directory.
    fn cloudflare_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/cloudflare")
            .join(name)
    }

    /// The three files of `fixtures/cloudflare/`.
    const CLOUDFLARE_FILES: [&str; 3] = ["REPORT.md", "coverage-ledger.json", "findings.json"];

    /// A sweep `run` started and the agent finished: the sweep directory
    /// with `fixtures/cloudflare/` copied into its `audit/`; this install,
    /// the sweeper, with its device key and the snapshot `run` kept of its
    /// fetch; the bounty owner, with one key under `keys/laptop.json`; the
    /// bounty, of a repo target t1 and a pull request t2; and the running
    /// record of both, naming `playbook`. Every key is made at run time.
    struct Scenario {
        fixture: SweepFixture,
        home: TempDir,
        owner_key: DeviceIdentity,
        own_key: DeviceIdentity,
        bounty: BountyRef,
        servers: Homeservers,
        keys: FakeKeyStore,
    }

    impl Scenario {
        fn new(playbook: &str) -> Self {
            let fixture = SweepFixture::new();
            for name in CLOUDFLARE_FILES {
                fs::copy(cloudflare_fixture(name), fixture.audit().join(name)).expect("copy");
            }
            let home = private_temp();
            let own_key = DeviceIdentity::generate();
            create_device_key(&dirs_in(&home), &own_key, None).expect("device.key");
            let bounty = BountyRef {
                owner: random_pubky(),
                id: bounty_id(),
            };
            let others = bounty_served(bounty, as_posted());
            // What `run` kept of its fetch of both targets, from the bounty
            // as it is served.
            let sweep = SweepRef {
                sweeper: fixture.sweeper(),
                id: fixture.id(),
            };
            let fetched = bounty_of(as_posted());
            snapshot_of(sweep, bounty, &fetched, &["t1", "t2"])
                .write(&dirs_in(&home))
                .expect("the snapshot");
            let own = FakeOwnStorage::default();
            let mut record = sweep_json(bounty, &["t1", "t2"], "running");
            record["playbook"] = json!(playbook);
            own.insert(&paths::sweep_record(fixture.id()), json_bytes(&record));
            let owner_key = DeviceIdentity::generate();
            let keys = FakeKeyStore::default();
            let created_at = "2026-10-19T08:00:00Z".parse().expect("a time");
            let published = device_key_record(&owner_key.recipient(), created_at);
            keys.set_record(
                &device_id("laptop"),
                device_key_bytes(&published).expect("JSON"),
            );
            Self {
                servers: Homeservers {
                    sweeper: fixture.sweeper(),
                    own,
                    others,
                },
                fixture,
                home,
                owner_key,
                own_key,
                bounty,
                keys,
            }
        }

        /// `submit --run-dir sweeps/<id>`, with `--playbook <flag>` if
        /// given, from the project, answering `answer` if asked; and what
        /// it wrote to standard error.
        async fn submit(
            &self,
            flag: Option<&str>,
            answer: &'static str,
        ) -> (anyhow::Result<Report>, String) {
            let (mut ctx, stderr) =
                test_context(offline_network(), &self.home, Cursor::new(answer));
            ctx.cwd = self.fixture.project().to_owned();
            let run_dir = PathBuf::from(format!("sweeps/{}", self.fixture.id()));
            let request = SubmitRequest {
                prompting: Prompting::Allowed,
                run_dir: Some(&run_dir),
                playbook: flag.map(|text| text.parse().expect("a playbook")),
                sweeper: self.fixture.sweeper(),
            };
            let submitted =
                submit_through(&ctx, &request, &self.servers, &self.keys, &self.servers.own).await;
            (submitted, stderr.text())
        }

        /// The same, which must fail: its error, all on one line.
        async fn refusal(&self, flag: Option<&str>) -> String {
            match self.submit(flag, "").await.0 {
                Ok(report) => panic!("submitted: {}", report.text()),
                Err(error) => format!("{error:#}"),
            }
        }

        fn sweep(&self) -> SweepRef {
            SweepRef {
                sweeper: self.fixture.sweeper(),
                id: self.fixture.id(),
            }
        }

        fn record_path(&self) -> String {
            paths::sweep_record(self.fixture.id())
        }

        fn package_path(&self) -> String {
            paths::sweep_package(self.fixture.id())
        }

        /// The sweep record in the sweeper's storage now.
        async fn record(&self) -> Sweep {
            let bytes = self.servers.own.get_own(&self.record_path()).await;
            Sweep::from_json(&bytes.expect("reads").expect("there")).expect("a sweep record")
        }

        /// `sweeps/<id>.age` in the sweeper's storage, if it is there.
        async fn package(&self) -> Option<Zeroizing<Vec<u8>>> {
            self.servers
                .own
                .get_own(&self.package_path())
                .await
                .expect("reads")
        }

        fn stamped(&self) -> bool {
            fs::symlink_metadata(self.fixture.dir().join(".sweepky/submitted")).is_ok()
        }

        /// Where the snapshot of `run`'s fetch of this sweep is kept.
        fn snapshot_file(&self) -> PathBuf {
            dirs_in(&self.home).sweep_snapshot_file(&self.fixture.id())
        }

        /// Whether that snapshot is still there.
        fn has_snapshot(&self) -> bool {
            fs::symlink_metadata(self.snapshot_file()).is_ok()
        }

        /// The keys pinned for the bounty's owner, as `(device id, key)`.
        fn pinned(&self) -> Option<Vec<(String, String)>> {
            let pins = read_pins(&dirs_in(&self.home)).expect("reads");
            let pinned = pins.pinned(&self.bounty.owner)?;
            Some(
                pinned
                    .iter()
                    .map(|pin| (pin.device_id.to_string(), pin.recipient.to_string()))
                    .collect(),
            )
        }
    }

    fn device_id(text: &str) -> DeviceId {
        text.parse().expect("a device id")
    }

    /// The scenario's bounty's targets, as posted: a repo target t1 and a
    /// pull request t2.
    fn as_posted() -> Value {
        json!([repo_target_json("t1"), pr_target_json("t2")])
    }

    /// Everyone else's storage, holding the bounty at `at`, of `targets`.
    fn bounty_served(at: BountyRef, targets: Value) -> FakePublicRecords {
        FakePublicRecords::default().with_record(
            at.owner,
            &paths::bounty(at.id),
            &bounty_json(targets),
        )
    }

    // DW1: B's submit of a Cloudflare-format sweep, in unit form.
    #[tokio::test]
    async fn a_cloudflare_audit_is_sealed_to_the_owner_and_this_install_and_marked_done() {
        let scenario = Scenario::new("unspecified");
        let audit = scenario.fixture.audit();
        // A file that is not text, and one whose name holds an escape that
        // would clear the screen, which no package path may.
        fs::write(audit.join("capture.bin"), [0xff, 0xfe, 0x00, 0x80]).expect("write");
        fs::write(audit.join("\u{1b}[2Jnotes.md"), "notes\n").expect("write");

        let (submitted, stderr) = scenario.submit(Some(PLAYBOOK), "").await;
        let report = submitted.unwrap_or_else(|error| panic!("refused: {error:#}"));

        // What the sweeper was told: the conversion, each file left out by
        // its sanitised path, and the file list; no byte of a finding.
        assert!(stderr.contains("Cloudflare's format"), "{stderr}");
        assert!(
            stderr.contains("warning: audit/capture.bin is left out of the package: it is not"),
            "{stderr}"
        );
        assert!(
            stderr
                .contains("warning: audit/\\u{1b}[2Jnotes.md is left out of the package: its path"),
            "{stderr}"
        );
        assert!(!stderr.contains('\u{1b}'), "{stderr}");
        for name in CLOUDFLARE_FILES {
            assert!(stderr.contains(&format!("  audit/{name} (")), "{stderr}");
        }
        assert!(!stderr.contains("auth-expiry-inclusive"), "{stderr}");
        assert!(
            report.text().contains(&scenario.sweep().to_string()),
            "{}",
            report.text()
        );

        // The package, then the record flipped to done with the playbook
        // given, finished, everything else as `run` wrote it.
        assert_eq!(
            scenario.servers.own.puts(),
            [scenario.package_path(), scenario.record_path()]
        );
        let record = scenario.record().await;
        let playbook: Playbook = PLAYBOOK.parse().expect("a playbook");
        assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Done));
        assert_eq!(record.playbook, playbook);
        assert_eq!(record.bounty, scenario.bounty);
        assert_eq!(record.started_at.as_str(), "2026-10-19T09:00:00Z");
        assert!(record.finished_at.is_some());
        assert_eq!(record.sha256, None);

        // The bounty's owner and this install each open it, bound to the
        // record; the manifest says what the record and the bounty say.
        let sealed = scenario.package().await.expect("uploaded");
        for identity in [&scenario.owner_key, &scenario.own_key] {
            let package = open_package(&sealed, identity, &scenario.sweep(), &record)
                .unwrap_or_else(|error| panic!("does not open: {error}"));
            let manifest = &package.manifest;
            assert_eq!(manifest.sweeper, scenario.fixture.sweeper());
            assert_eq!(manifest.playbook, playbook);
            assert_eq!(Some(&manifest.finished_at), record.finished_at.as_ref());
            let shas: Vec<(&str, &str)> = manifest
                .target_shas
                .iter()
                .map(|(id, sha)| (id.as_str(), sha.as_str()))
                .collect();
            // The pull request target, t2, by its head.
            assert_eq!(shas, [("t1", SYNTHETIC_SHA), ("t2", SYNTHETIC_HEAD)]);
            // The findings are the fixture's, converted; `assert!` rather
            // than `assert_eq!`, so a failure prints no finding.
            let fixture = fs::read(cloudflare_fixture("findings.json")).expect("read");
            let (expected, _) = parse_audit_findings(&fixture, &playbook).expect("findings");
            assert!(package.findings == expected, "the findings differ");
            let attached: Vec<&str> = package
                .attachments
                .iter()
                .map(|(path, _)| path.as_str())
                .collect();
            assert_eq!(attached, ["REPORT.md", "coverage-ledger.json"]);
            let report_md: AttachmentPath = "REPORT.md".parse().expect("a path");
            let original = fs::read_to_string(cloudflare_fixture("REPORT.md")).expect("read");
            assert_eq!(package.attachments.get(&report_md), Some(original.as_str()));
        }

        // Stamped, the owner's one key pinned, and the snapshot of the
        // fetch forgotten, the record being final.
        assert!(scenario.stamped());
        assert!(!scenario.has_snapshot());
        assert_eq!(
            scenario.pinned(),
            Some(vec![(
                "laptop".to_owned(),
                scenario.owner_key.recipient().to_string()
            )])
        );

        // A second submit of the same directory is refused: the record says
        // done. Nothing more is written.
        let message = scenario.refusal(Some(PLAYBOOK)).await;
        assert!(message.contains("says done"), "{message}");
        assert_eq!(scenario.servers.own.puts().len(), 2);
    }

    #[tokio::test]
    async fn the_placeholder_needs_the_flag_and_a_named_playbook_is_kept() {
        // The placeholder and no --playbook: refused, asking for the flag,
        // with nothing pinned, uploaded or stamped.
        let scenario = Scenario::new("unspecified");
        let message = scenario.refusal(None).await;
        assert!(message.contains("--playbook"), "{message}");
        assert_eq!(scenario.servers.own.puts(), Vec::<String>::new());
        assert_eq!(scenario.pinned(), None);
        assert!(!scenario.stamped());

        // A playbook `init` recorded, and no flag: the record keeps it.
        let scenario = Scenario::new("my-own-review@abcdef1");
        let (submitted, _) = scenario.submit(None, "").await;
        submitted.unwrap_or_else(|error| panic!("refused: {error:#}"));
        assert_eq!(
            scenario.record().await.playbook.as_str(),
            "my-own-review@abcdef1"
        );
    }

    #[tokio::test]
    async fn a_new_owner_key_declined_writes_nothing() {
        let scenario = Scenario::new(PLAYBOOK);
        // The owner was pinned to another key, so laptop's is new.
        let other = OwnerKey {
            device_id: device_id("desk"),
            recipient: DeviceIdentity::generate().recipient(),
        };
        pin_owner_keys(&dirs_in(&scenario.home), scenario.bounty.owner, &[other]).expect("pinned");

        let (submitted, stderr) = scenario.submit(None, "n\n").await;

        let report = submitted.unwrap_or_else(|error| panic!("refused: {error:#}"));
        assert_eq!(report.text(), NOT_CONFIRMED);
        assert!(stderr.contains("keys/laptop.json"), "{stderr}");
        assert_eq!(scenario.servers.own.puts(), Vec::<String>::new());
        assert!(!scenario.stamped());
    }

    #[tokio::test]
    async fn a_refused_upload_flips_the_sweep_to_aborted_for_good() {
        for (status, said) in [
            (StatusCode::PAYLOAD_TOO_LARGE, PACKAGE_TOO_LARGE),
            (StatusCode::INSUFFICIENT_STORAGE, UPLOAD_QUOTA_FULL),
        ] {
            let scenario = Scenario::new(PLAYBOOK);
            scenario
                .servers
                .own
                .refuse(&scenario.package_path(), status, SERVER_TEXT);

            let message = scenario.refusal(None).await;

            assert!(message.starts_with(ABORTED), "{status}: {message}");
            assert!(message.contains(said), "{status}: {message}");
            assert!(!message.contains("MARKER-5k8d"), "{status}: {message}");
            assert_eq!(
                scenario.servers.own.puts(),
                [scenario.package_path(), scenario.record_path()]
            );
            let record = scenario.record().await;
            assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Aborted));
            assert!(record.finished_at.is_some());
            assert!(!scenario.stamped());
            assert!(!scenario.has_snapshot());

            // Aborted is final: a later submit is refused, and says to start
            // a new run, even once the homeserver would take the package.
            scenario.servers.own.stop_failing();
            let message = scenario.refusal(None).await;
            assert_eq!(message, ABORTED_IS_FINAL, "{status}");
            assert_eq!(scenario.servers.own.puts().len(), 2);
        }
    }

    #[tokio::test]
    async fn a_rate_limit_or_a_network_error_leaves_the_sweep_running_to_submit_again() {
        for rate_limited in [true, false] {
            let scenario = Scenario::new(PLAYBOOK);
            let package = scenario.package_path();
            if rate_limited {
                scenario
                    .servers
                    .own
                    .refuse(&package, StatusCode::TOO_MANY_REQUESTS, SERVER_TEXT);
            } else {
                scenario.servers.own.fail_transport(&package);
            }

            let message = scenario.refusal(None).await;

            assert!(message.starts_with(STILL_RUNNING), "{message}");
            let said = if rate_limited {
                RATE_LIMITED
            } else {
                "network error (could not connect)"
            };
            assert!(message.contains(said), "{message}");
            assert!(!message.contains("MARKER-5k8d"), "{message}");
            assert!(!message.contains("127.0.0.1"), "{message}");
            // No flip: the record was never written.
            assert_eq!(scenario.servers.own.puts(), [package.as_str()]);
            let record = scenario.record().await;
            assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Running));
            assert!(!scenario.stamped());
            // Kept for the next try.
            assert!(scenario.has_snapshot());

            // Run again once the homeserver takes it: done.
            scenario.servers.own.stop_failing();
            let (submitted, _) = scenario.submit(None, "").await;
            submitted.unwrap_or_else(|error| panic!("refused again: {error:#}"));
            let record = scenario.record().await;
            assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Done));
            assert!(scenario.stamped());
            assert!(!scenario.has_snapshot());
        }
    }

    #[tokio::test]
    async fn a_flip_to_aborted_that_fails_is_reported_with_the_refusal() {
        let scenario = Scenario::new(PLAYBOOK);
        let own = &scenario.servers.own;
        own.refuse(
            &scenario.package_path(),
            StatusCode::PAYLOAD_TOO_LARGE,
            SERVER_TEXT,
        );
        own.refuse(
            &scenario.record_path(),
            StatusCode::INSUFFICIENT_STORAGE,
            SERVER_TEXT,
        );

        let message = scenario.refusal(None).await;

        assert!(message.starts_with(NOT_ABORTED), "{message}");
        assert!(message.contains(QUOTA_FULL), "{message}");
        assert!(message.ends_with(PACKAGE_TOO_LARGE), "{message}");
        assert!(!message.contains("MARKER-5k8d"), "{message}");
        let record = scenario.record().await;
        assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Running));
        // Still running, so the snapshot stays for the next try.
        assert!(scenario.has_snapshot());
    }

    // The review finding: the owner, or their homeserver, rewrote a
    // target's pinned revision after `run` fetched it. Taking the commits
    // from the bounty now would seal a manifest that claims the new commit
    // was audited.
    #[tokio::test]
    async fn a_bounty_whose_pinned_revision_moved_since_run_is_refused_unpublished() {
        let mut scenario = Scenario::new(PLAYBOOK);
        let mut moved = repo_target_json("t1");
        moved["rev"] = json!(SYNTHETIC_HEAD);
        scenario.servers.others =
            bounty_served(scenario.bounty, json!([moved, pr_target_json("t2")]));

        let message = scenario.refusal(None).await;

        // Fixed text, and nothing written anywhere: no package, no flip,
        // no pin, no stamp; the record still says running and the
        // snapshot is kept.
        assert_eq!(message, TARGETS_CHANGED);
        assert_eq!(scenario.servers.own.puts(), Vec::<String>::new());
        assert_eq!(scenario.pinned(), None);
        assert!(!scenario.stamped());
        assert_eq!(
            scenario.record().await.status.as_known(),
            Some(KnownSweepStatus::Running)
        );
        assert!(scenario.has_snapshot());

        // The bounty put back as `run` fetched it: the same sweep submits,
        // its manifest naming the commits fetched.
        scenario.servers.others = bounty_served(scenario.bounty, as_posted());
        let (submitted, _) = scenario.submit(None, "").await;
        submitted.unwrap_or_else(|error| panic!("refused: {error:#}"));
        assert_eq!(
            scenario.record().await.status.as_known(),
            Some(KnownSweepStatus::Done)
        );
    }

    #[tokio::test]
    async fn a_sweep_with_no_snapshot_of_its_fetch_is_refused_unpublished() {
        let scenario = Scenario::new(PLAYBOOK);
        fs::remove_file(scenario.snapshot_file()).expect("removed");

        let message = scenario.refusal(None).await;

        assert_eq!(message, NO_SNAPSHOT);
        assert_eq!(scenario.servers.own.puts(), Vec::<String>::new());
        assert_eq!(scenario.pinned(), None);
        assert!(!scenario.stamped());
    }

    #[tokio::test]
    async fn a_record_changed_before_the_lock_stops_the_upload() {
        let scenario = Scenario::new(PLAYBOOK);
        let (ctx, _) = test_context(offline_network(), &scenario.home, Cursor::new(""));
        let accepted = accept_owner_keys(
            &ctx,
            Prompting::Allowed,
            &scenario.keys,
            scenario.bounty.owner,
        )
        .await
        .expect("read")
        .expect("accepted");
        // What `submit` read before it built the package: the same sweep,
        // but of another bounty.
        let mut read = scenario.record().await;
        read.bounty.id = crate::test_support::record_id(1);
        let upload = Upload {
            sweep: scenario.sweep(),
            read: &read,
            playbook: PLAYBOOK.parse().expect("a playbook"),
            finished_at: "2026-10-19T12:00:00Z".parse().expect("a time"),
            ciphertext: Vec::new(),
            keys: &accepted,
            dirs: &ctx.dirs,
        };

        let refused = finish_sweep(&scenario.servers.own, upload)
            .await
            .expect_err("changed");

        assert!(
            format!("{refused:#}").contains("changed while submit"),
            "{refused:#}"
        );
        assert_eq!(scenario.servers.own.puts(), Vec::<String>::new());
        assert_eq!(scenario.pinned(), None);
    }

    #[test]
    fn the_playbook_flag_is_checked_and_never_quoted() {
        assert_eq!(
            parse_playbook_flag(PLAYBOOK).expect("a playbook").as_str(),
            PLAYBOOK
        );
        // A key pasted as the playbook, which 01's pattern would let into
        // a public record: refused by `login`'s classifier.
        let secret = pubky::Keypair::random().secret();
        let z32 = Pubky::from_bytes(secret).to_string();
        let refused = parse_playbook_flag(&z32).expect_err("a key");
        assert_eq!(refused.downcast_ref::<Refusal>(), Some(&Refusal::RawKey));
        assert!(!format!("{refused:#}").contains(&z32));
        // Outside 01's pattern.
        let refused = parse_playbook_flag("my playbook").expect_err("a space");
        let message = format!("{refused:#}");
        assert!(message.contains("--playbook must name"), "{message}");
        assert!(!message.contains("my playbook"), "{message}");
    }
}
