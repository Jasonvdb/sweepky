//! `sweepky circle create|add|remove|show`: the roster an admin keeps at
//! `/pub/sweepky/circle.json`, `{schemaVersion, name, admin, members:
//! [{pubky, label?}]}` (01). It is the default trust set and the default
//! discovery set; which circle a sweeper follows is `run`'s business (P2b).
//!
//! **The writes** ([`create`], [`add`], [`remove`]) each run in three steps:
//!
//! 1. The command line is checked before anything else: a pubky is parsed by
//!    core (either spelling, `pubky<z32>` or raw z-base32) and then by the
//!    SDK, whose parse checks that the key is a point on Ed25519; a name or
//!    a label must be short plain text ([`RosterText`]). The result is a
//!    [`Change`], which holds only checked values, so a bad argument never
//!    takes the lock, signs in or reaches the homeserver.
//! 2. Under the writers' lock, with a session of its own that is always
//!    signed out (`session::with_writer_session`), the signed-in user's own
//!    `circle.json` is read (capped at `MAX_RECORD_BYTES`) and handed to
//!    [`apply`], a pure function: it parses the record with core's
//!    `Circle::from_json`, makes the change and says what to write, if
//!    anything, and what to report.
//! 3. The new record is PUT, compact JSON, and a refusal is mapped by
//!    `remote::write_error` (403 and 507 to their messages, anything else to
//!    fixed text and the status).
//!
//! The rules [`apply`] keeps:
//!
//! - `create` writes the admin into `members` as well as `admin` (P1a's
//!   carry-forward note: `Circle::is_in_roster` counts the admin anyway, and
//!   the board reads the same file), and never writes over a `circle.json`
//!   that is there, even one it cannot parse: it may be the only copy.
//! - `add` and `remove` need a `circle.json` that parses and names this
//!   identity as its admin; anything else is left as it is.
//! - Members are found by key bytes (core's `Pubky` compares its 32 bytes),
//!   so the two spellings of one key are one member. Adding a member that is
//!   there writes nothing, unless it brings a new label.
//! - `remove` refuses the admin, who is always in the roster, and a key that
//!   is not a member.
//! - Every field this build does not know, at the top level and in each
//!   member, is written back as it was read: core's `Circle` and
//!   `CircleMember` keep them in a `#[serde(flatten)]` map.
//!
//! The lock serialises the commands of one install, so a read, change and
//! write never interleaves with another `sweepky` command here. Two installs
//! of one admin changing the circle at the same moment is last-writer-wins,
//! as for a bounty record (01).
//!
//! **`show`** ([`show`]) reads anyone's `circle.json` from public storage,
//! with no session and no lock, defaulting to this install's own pubky. The
//! name and the labels are a stranger's text, so they go through
//! `display::sanitize`; pubkys are printed from the parsed keys, which are
//! z-base32 and nothing else.

use anyhow::{Context as _, bail};
use pubky::PubkySession;
use sweepky_core::paths;
use sweepky_core::{Circle, CircleMember, MAX_RECORD_BYTES, Pubky, SchemaVersion, UnknownFields};

use crate::display::{MAX_LABEL_CHARS, sanitize};
use crate::remote::{get_own, get_public, public_key_of, write_error};
use crate::session::with_writer_session;
use crate::state::read_login_state;
use crate::{Context, Dirs, Report};

// ---------------------------------------------------------------------------
// Checking the command line.

/// A circle's name or a member's label as this CLI writes one: 1 to
/// [`MAX_LABEL_CHARS`] characters, not all of them spaces, each of which the
/// terminal sanitiser prints as itself.
///
/// That last rule refuses every control character (newline and tab among
/// them), every bidi, zero-width or other invisible character and the
/// noncharacters, which `display::sanitize` would write as escapes, and a
/// backslash, which it doubles. So whatever this CLI publishes in a circle
/// reads back unchanged in every Sweepky, and nothing it writes can drive a
/// reader's terminal. Text another client wrote is not checked this way when
/// it is read; it is sanitised when it is shown.
///
/// A newtype whose field only [`RosterText::new`] fills, so holding one is
/// the proof that the check ran.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RosterText(String);

impl RosterText {
    /// Checks `value`. `what` names it in the error ("the circle's name"),
    /// which is fixed text and never repeats the value.
    fn new(value: &str, what: &'static str) -> anyhow::Result<Self> {
        // The sanitiser cuts anything over `MAX_LABEL_CHARS` and marks the
        // cut, so a value it gives back unchanged is short enough, too.
        if value.trim().is_empty() || sanitize(value, MAX_LABEL_CHARS) != value {
            bail!(
                "{what} must be 1 to {MAX_LABEL_CHARS} characters of plain text: no control, \
                 formatting or invisible characters and no backslash"
            );
        }
        Ok(Self(value.to_owned()))
    }

    /// The text, which prints as it is.
    fn as_str(&self) -> &str {
        &self.0
    }

    /// The text, moved out to go into a record.
    fn into_string(self) -> String {
        self.0
    }
}

/// A pubky from the command line, for `command`: core's parse (either
/// spelling, length, alphabet and canonical form), then the SDK's
/// `PublicKey` parse, which also checks that the key is a point on Ed25519.
///
/// Both messages are fixed text, and so is core's error under the first: a
/// value that fails either check is not a public key, and may be something
/// pasted in by mistake, so it is never repeated. `run --circle` reads its
/// value with it too.
pub(crate) fn parse_pubky(text: &str, command: &str) -> anyhow::Result<Pubky> {
    let pubky: Pubky = text.parse().with_context(|| {
        format!(
            "{command} takes a pubky: 52 characters of z-base32, with or without the `pubky` \
             prefix"
        )
    })?;
    // Only the check is wanted: the SDK's key is dropped, and the circle
    // holds core's `Pubky`, the same 32 bytes. Its error names the key, so
    // it is replaced by fixed text rather than kept as the cause.
    if public_key_of(&pubky).is_err() {
        bail!("{command} takes a pubky that is an Ed25519 public key");
    }
    Ok(pubky)
}

/// A change to this identity's own circle. Each value in it was checked when
/// the command line was read (see the constructors), so [`apply`] has
/// nothing left to check about the arguments.
enum Change {
    /// `circle create <name>`.
    Create { name: RosterText },
    /// `circle add <pubky> [--label <label>]`.
    Add {
        member: Pubky,
        label: Option<RosterText>,
    },
    /// `circle remove <pubky>`.
    Remove { member: Pubky },
}

impl Change {
    /// `circle create`, checked.
    fn create(name: &str) -> anyhow::Result<Self> {
        Ok(Self::Create {
            name: RosterText::new(name, "the circle's name")?,
        })
    }

    /// `circle add`, checked.
    fn add(pubky: &str, label: Option<&str>) -> anyhow::Result<Self> {
        let member = parse_pubky(pubky, "circle add")?;
        // `map` checks the label when there is one, giving an
        // `Option<Result<..>>`; `transpose` turns that inside out into a
        // `Result<Option<..>>`, so `?` can return the error.
        let label = label
            .map(|label| RosterText::new(label, "a member's label"))
            .transpose()?;
        Ok(Self::Add { member, label })
    }

    /// `circle remove`, checked.
    fn remove(pubky: &str) -> anyhow::Result<Self> {
        Ok(Self::Remove {
            member: parse_pubky(pubky, "circle remove")?,
        })
    }
}

// ---------------------------------------------------------------------------
// Changing the record: pure functions, no I/O.

/// What [`apply`] decided: the record to write, `None` when nothing changed,
/// and the report.
struct Applied {
    record: Option<Vec<u8>>,
    report: String,
}

impl Applied {
    /// Write `circle`, encoded by [`circle_bytes`], and report `report`.
    fn write(circle: &Circle, report: String) -> anyhow::Result<Self> {
        Ok(Self {
            record: Some(circle_bytes(circle)?),
            report,
        })
    }

    /// Write nothing: the record stays exactly as it is.
    fn unchanged(report: String) -> Self {
        Self {
            record: None,
            report,
        }
    }
}

/// Applies `change` to `stored`, the signed-in user's `circle.json` as the
/// homeserver gave it (`None` when there is none), for `me`, the pubky
/// signed in. See the module docs for the rules.
///
/// `change` is taken by value because its checked name or label moves into
/// the record; `me` because core's `Pubky` is `Copy` (32 bytes), so passing
/// it copies it and the caller keeps theirs.
fn apply(change: Change, me: Pubky, stored: Option<&[u8]>) -> anyhow::Result<Applied> {
    match change {
        Change::Create { name } => {
            if stored.is_some() {
                bail!(
                    "this identity's circle.json exists already, so circle create left it as it \
                     is; `sweepky circle show` shows it, and `sweepky circle add` and `sweepky \
                     circle remove` change it"
                );
            }
            // A checked name prints as it is, so it needs no sanitising.
            let report = format!(
                "Created the circle {} at {}, with {me} as its admin and first member.\n",
                name.as_str(),
                paths::circle()
            );
            Applied::write(&new_circle(me, name), report)
        }
        Change::Add { member, label } => {
            let mut circle = own_circle(stored, me)?;
            match add_member(&mut circle, member, label) {
                Added::New => Applied::write(&circle, format!("Added {member} to the circle.\n")),
                Added::Relabelled => Applied::write(
                    &circle,
                    format!("Set the label of {member} in the circle.\n"),
                ),
                Added::AlreadyIn => Ok(Applied::unchanged(format!(
                    "{member} is in the circle already, so nothing changed.\n"
                ))),
            }
        }
        Change::Remove { member } => {
            let mut circle = own_circle(stored, me)?;
            remove_member(&mut circle, member)?;
            Applied::write(&circle, format!("Removed {member} from the circle.\n"))
        }
    }
}

/// The circle `circle create` writes: `admin` is `me`, and `members` lists
/// `me` too, with no label.
fn new_circle(me: Pubky, name: RosterText) -> Circle {
    Circle {
        schema_version: SchemaVersion::CURRENT,
        name: name.into_string(),
        admin: me,
        members: vec![CircleMember {
            pubky: me,
            label: None,
            extra: UnknownFields::new(),
        }],
        extra: UnknownFields::new(),
    }
}

/// `stored` parsed, for `add` and `remove`: there must be a circle, core
/// must read it, and it must name `me` as its admin. Anything else is an
/// error, and the record is left as it is.
fn own_circle(stored: Option<&[u8]>, me: Pubky) -> anyhow::Result<Circle> {
    let Some(bytes) = stored else {
        bail!(
            "this identity has no circle yet, so there is nothing to change; `sweepky circle \
             create <name>` makes one"
        );
    };
    // core's parse: capped, `schemaVersion` first, and every member's key
    // checked. Its error names the kind of fault and where, never the input.
    let circle = Circle::from_json(bytes).context(
        "this identity's circle.json is not a circle record this build reads, so it was left as \
         it is",
    )?;
    // Compared as keys, by their bytes. A record in this identity's storage
    // that names someone else as its admin is not this identity's circle:
    // `is_in_roster` would count that other key as in the roster, and a
    // rewrite would keep the claim alive, so it is left for the user to look
    // at instead.
    if circle.admin != me {
        bail!(
            "this identity's circle.json names another admin, {}, so it was left as it is: a \
             circle is its admin's own record",
            circle.admin
        );
    }
    Ok(circle)
}

/// What [`add_member`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Added {
    /// A new entry at the end of `members`.
    New,
    /// The member was there; its label is now the new one.
    Relabelled,
    /// The member was there, with that label or none given: no change.
    AlreadyIn,
}

/// Adds `member` to `circle`, found by key bytes, or sets its label.
fn add_member(circle: &mut Circle, member: Pubky, label: Option<RosterText>) -> Added {
    // `iter_mut().find` lends out `&mut` to the first entry with this key,
    // so the label can be changed in place and the entry's unknown fields
    // stay with it. `==` on `Pubky` compares the 32 key bytes.
    if let Some(entry) = circle
        .members
        .iter_mut()
        .find(|entry| entry.pubky == member)
    {
        return match label {
            Some(label) if entry.label.as_deref() != Some(label.as_str()) => {
                entry.label = Some(label.into_string());
                Added::Relabelled
            }
            _ => Added::AlreadyIn,
        };
    }
    circle.members.push(CircleMember {
        pubky: member,
        // A method's path can stand in for the closure: `map` calls
        // `RosterText::into_string` on the label, when there is one, and
        // gets its `String`.
        label: label.map(RosterText::into_string),
        extra: UnknownFields::new(),
    });
    Added::New
}

/// Removes every entry of `member` from `circle`. Refuses the admin, and a
/// key with no entry.
fn remove_member(circle: &mut Circle, member: Pubky) -> anyhow::Result<()> {
    if member == circle.admin {
        bail!(
            "{member} is the circle's admin, who is always in the roster, so it cannot be removed"
        );
    }
    let before = circle.members.len();
    // `retain` keeps the entries the closure says `true` for. Every entry of
    // the key goes, in case a hand-written record lists it twice.
    circle.members.retain(|entry| entry.pubky != member);
    if circle.members.len() == before {
        bail!("{member} is not a member of this circle, so nothing changed");
    }
    Ok(())
}

/// `circle` as it is published: compact JSON, refused when it would be over
/// `MAX_RECORD_BYTES`, which no Sweepky would read back.
fn circle_bytes(circle: &Circle) -> anyhow::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(circle).context("could not write the circle record")?;
    if bytes.len() > MAX_RECORD_BYTES {
        bail!(
            "the circle would be {} bytes, over the {MAX_RECORD_BYTES} bytes Sweepky reads a \
             record up to, so nothing was written",
            bytes.len()
        );
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Showing a circle.

/// What `circle show` prints for `circle`, read from `owner`'s storage: the
/// name, the admin, then one line per member, the name and the labels
/// sanitised; and a warning when the record names another admin than its
/// owner.
fn render(circle: &Circle, owner: Pubky) -> String {
    let mut text = format!(
        "Circle: {}\nAdmin: {}\nMembers ({}):\n",
        sanitize(&circle.name, MAX_LABEL_CHARS),
        circle.admin,
        circle.members.len()
    );
    for member in &circle.members {
        text.push_str(&member_line(member, circle.admin));
    }
    if circle.admin != owner {
        text.push_str(&format!(
            "warning: this circle.json is kept by {owner} but names {} as its admin; only that \
             admin's own circle.json is their circle.\n",
            circle.admin
        ));
    }
    text
}

/// One member's line: the key, `(admin)` for the admin, and the label.
fn member_line(member: &CircleMember, admin: Pubky) -> String {
    // A `Pubky` prints as its 52 z-base32 characters and nothing else, so
    // it needs no sanitising; the label is the record's text.
    let mut line = format!("  {}", member.pubky);
    if member.pubky == admin {
        line.push_str(" (admin)");
    }
    if let Some(label) = &member.label {
        line.push_str(", label ");
        line.push_str(&sanitize(label, MAX_LABEL_CHARS));
    }
    line.push('\n');
    line
}

/// `owner`'s `circle.json` from public storage, capped at
/// `MAX_RECORD_BYTES` and parsed by core, or `None` when there is none.
async fn read_circle(client: &pubky::Pubky, owner: Pubky) -> anyhow::Result<Option<Circle>> {
    let key = public_key_of(&owner)?;
    let Some(bytes) = get_public(client, &key, paths::circle(), MAX_RECORD_BYTES).await? else {
        return Ok(None);
    };
    let circle = Circle::from_json(&bytes).with_context(|| {
        format!("circle.json of {owner} is not a circle record this build reads")
    })?;
    Ok(Some(circle))
}

// ---------------------------------------------------------------------------
// The commands.

/// Runs `circle create <name>`.
pub(crate) async fn create(ctx: &Context, name: &str) -> anyhow::Result<Report> {
    change_circle(ctx, Change::create(name)?).await
}

/// Runs `circle add <pubky> [--label <label>]`.
pub(crate) async fn add(ctx: &Context, pubky: &str, label: Option<&str>) -> anyhow::Result<Report> {
    change_circle(ctx, Change::add(pubky, label)?).await
}

/// Runs `circle remove <pubky>`.
pub(crate) async fn remove(ctx: &Context, pubky: &str) -> anyhow::Result<Report> {
    change_circle(ctx, Change::remove(pubky)?).await
}

/// Reads this identity's `circle.json`, applies `change` and writes the
/// result, under the writers' lock with a session that is always signed out
/// afterwards.
async fn change_circle(ctx: &Context, change: Change) -> anyhow::Result<Report> {
    // `async move` moves `change` into the closure, which `apply` then
    // consumes: the closure is called once (`AsyncFnOnce`), so it may give
    // away what it owns. `signed` is lent to the closure for the call only.
    with_writer_session(ctx, async move |signed| {
        let session = signed.session();
        let stored = get_own(session, paths::circle(), MAX_RECORD_BYTES).await?;
        // `as_deref` lends the `Zeroizing<Vec<u8>>` inside the `Option` out
        // as a `&Vec<u8>`, and `Vec::as_slice` that as the `&[u8]` `apply`
        // takes; nothing is copied.
        let applied = apply(
            change,
            signed.login().pubky,
            stored.as_deref().map(Vec::as_slice),
        )?;
        if let Some(record) = applied.record {
            put_circle(session, record).await?;
        }
        Ok(Report::new(applied.report))
    })
    .await
}

/// Writes `record` as the signed-in user's own `circle.json`.
async fn put_circle(session: &PubkySession, record: Vec<u8>) -> anyhow::Result<()> {
    // `map(drop)` throws the successful response away unread: a 2xx is all
    // that matters. `write_error` maps a 403 or a 507 to its own message and
    // anything else to fixed text and the status, never the server's words.
    session
        .storage()
        .put(paths::circle(), record)
        .await
        .map(drop)
        .map_err(|error| write_error(&error).context("could not write circle.json"))
}

/// Runs `circle show [<admin>]`: `admin`'s circle, or this install's own
/// when it is left out. Public data only: no session and no lock.
pub(crate) async fn show(ctx: &Context, admin: Option<&str>) -> anyhow::Result<Report> {
    let owner = match admin {
        Some(text) => parse_pubky(text, "circle show")?,
        None => logged_in_pubky(&ctx.dirs)?,
    };
    let Some(circle) = read_circle(ctx.network.pubky(), owner).await? else {
        bail!(
            "{owner} has no circle: there is no circle.json under its /pub/sweepky/; its admin \
             makes one with `sweepky circle create <name>`"
        );
    };
    Ok(Report::new(render(&circle, owner)))
}

/// The pubky `login.json` records: whose circle `circle show` shows when it
/// is given none.
fn logged_in_pubky(dirs: &Dirs) -> anyhow::Result<Pubky> {
    let Some(login) = read_login_state(dirs)? else {
        bail!(
            "circle show takes the pubky of a circle's admin, or shows this identity's own \
             circle once this install is logged in"
        );
    };
    Ok(login.pubky)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sweepky_core::{Circle, Pubky};

    use super::{Applied, Change, RosterText, apply, parse_pubky, render};
    use crate::test_support::random_pubky;

    /// What `apply` says it would write, as core reads it back: the bytes go
    /// through the same capped parser every reader of `circle.json` uses.
    fn written(applied: &Applied) -> Circle {
        Circle::from_json(applied.record.as_deref().expect("a record to write"))
            .expect("core reads what is written")
    }

    /// The bytes of `value`, as a homeserver would hand them back.
    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("JSON")
    }

    /// The circle `circle create` writes for `me`, as stored bytes.
    fn created(me: Pubky) -> Vec<u8> {
        let change = Change::create("Friends").expect("a valid name");
        apply(change, me, None)
            .expect("created")
            .record
            .expect("written")
    }

    #[test]
    fn create_lists_the_admin_in_members() {
        let me = random_pubky();
        let applied = apply(Change::create("Friends").expect("a name"), me, None).expect("created");
        let circle = written(&applied);
        assert_eq!(circle.name, "Friends");
        assert_eq!(circle.admin, me);
        // The admin is listed in `members` too (P1a's carry-forward note):
        // `is_in_roster` would count them anyway, and the board reads the
        // same file.
        assert_eq!(circle.members.len(), 1);
        assert_eq!(circle.members[0].pubky, me);
        assert_eq!(circle.members[0].label, None);
        assert!(circle.is_in_roster(me));
        assert!(
            applied.report.contains("Created the circle"),
            "{}",
            applied.report
        );
    }

    #[test]
    fn create_refuses_to_overwrite_an_existing_circle() {
        let me = random_pubky();
        // A circle that parses, and bytes that do not: neither is written
        // over, because the file is the admin's and may be the only copy.
        for stored in [created(me), b"{\"schemaVersion\":1,\"name\":".to_vec()] {
            let change = Change::create("Another").expect("a name");
            let err = apply(change, me, Some(&stored)).err().expect("refused");
            let shown = format!("{err:#}");
            assert!(shown.contains("exists already"), "{shown}");
            assert!(shown.contains("`sweepky circle add`"), "{shown}");
        }
    }

    #[test]
    fn add_dedupes_by_key_bytes() {
        let me = random_pubky();
        let member = random_pubky();
        // The SDK's spelling, `pubky<z32>`, and the raw z-base32 records use:
        // two strings, one key.
        let sdk_form = format!("pubky{member}");
        let raw_form = member.to_string();

        let added = apply(
            Change::add(&sdk_form, Some("Bob's laptop")).expect("valid"),
            me,
            Some(&created(me)),
        )
        .expect("added");
        let circle = written(&added);
        assert_eq!(circle.members.len(), 2);
        assert_eq!(circle.members[1].pubky, member);
        assert_eq!(circle.members[1].label.as_deref(), Some("Bob's laptop"));

        // The same key in the other spelling is the same member: nothing to
        // write.
        let stored = added.record.expect("written");
        let again = apply(
            Change::add(&raw_form, None).expect("valid"),
            me,
            Some(&stored),
        )
        .expect("not an error");
        assert!(again.record.is_none(), "rewritten for a member already in");
        assert!(again.report.contains("already"), "{}", again.report);

        // With a new label, the one entry gets it; still one entry.
        let relabelled = apply(
            Change::add(&raw_form, Some("Bob")).expect("valid"),
            me,
            Some(&stored),
        )
        .expect("relabelled");
        let circle = written(&relabelled);
        assert_eq!(circle.members.len(), 2);
        assert_eq!(circle.members[1].label.as_deref(), Some("Bob"));
    }

    #[test]
    fn names_and_labels_must_be_plain_text() {
        let member = random_pubky().to_string();
        // Labels, and names, are short plain text: each character printed as
        // itself, so nothing this CLI writes needs the sanitiser to show it.
        for good in ["Bob", "Zoë in Zürich", "東京", &"x".repeat(64)] {
            assert!(RosterText::new(good, "a label").is_ok(), "{good:?}");
        }
        let too_long = "x".repeat(65);
        for bad in [
            "",
            "   ",
            too_long.as_str(),
            "red\u{1b}[31m",
            "two\nlines",
            "tab\there",
            "txt\u{202e}exe",
            "zero\u{200b}width",
            "back\\slash",
        ] {
            let err = RosterText::new(bad, "a member's label").expect_err("refused");
            let shown = format!("{err:#}");
            assert!(shown.contains("a member's label"), "{shown}");
            // The message is fixed text: it never repeats the value.
            if !bad.trim().is_empty() {
                assert!(!shown.contains(bad), "{shown}");
            }
            assert!(Change::add(&member, Some(bad)).is_err(), "{bad:?}");
        }
        assert!(Change::create("bad\u{7}name").is_err());
    }

    #[test]
    fn add_refuses_an_invalid_pubky() {
        // 32 bytes of 2 have a z-base32 form core accepts, but no point on
        // Ed25519 has them as its encoding, so the SDK's parse refuses them.
        let not_a_point = Pubky::from_bytes([2; 32]).to_string();
        assert!(
            not_a_point.parse::<Pubky>().is_ok(),
            "core accepts the form"
        );
        assert!(pubky::PublicKey::try_from_z32(&not_a_point).is_err());

        // The check runs when the command line is read, before the writers'
        // lock, the sign-in or any read: a `Change` holds only a checked key.
        for bad in [
            not_a_point.as_str(),
            "not-a-pubky",
            &random_pubky().to_string().to_uppercase(),
            "",
        ] {
            let err = Change::add(bad, None).err().expect("refused");
            let shown = format!("{err:#}");
            assert!(shown.contains("circle add"), "{shown}");
            // Fixed text: the value is never repeated, in either spelling.
            if !bad.is_empty() {
                assert!(!shown.contains(bad), "{shown}");
                assert!(!shown.contains(&bad.to_lowercase()), "{shown}");
            }
            assert!(Change::remove(bad).is_err(), "{bad:?}");
            assert!(parse_pubky(bad, "circle show").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn remove_refuses_the_admin_and_unknown_members() {
        let me = random_pubky();
        let member = random_pubky();
        let stored = apply(
            Change::add(&member.to_string(), None).expect("valid"),
            me,
            Some(&created(me)),
        )
        .expect("added")
        .record
        .expect("written");

        // The admin is always in the roster, so cannot be removed.
        let err = apply(
            Change::remove(&me.to_string()).expect("valid"),
            me,
            Some(&stored),
        )
        .err()
        .expect("refused");
        assert!(format!("{err:#}").contains("admin"), "{err:#}");
        // A key that is not a member is an error too, not a quiet no-op.
        let stranger = random_pubky();
        let err = apply(
            Change::remove(&stranger.to_string()).expect("valid"),
            me,
            Some(&stored),
        )
        .err()
        .expect("refused");
        assert!(format!("{err:#}").contains("not a member"), "{err:#}");

        // A member goes, in the SDK's spelling too; the admin stays.
        let removed = apply(
            Change::remove(&format!("pubky{member}")).expect("valid"),
            me,
            Some(&stored),
        )
        .expect("removed");
        let circle = written(&removed);
        assert_eq!(circle.members.len(), 1);
        assert_eq!(circle.members[0].pubky, me);
        assert!(!circle.is_in_roster(member));
    }

    #[test]
    fn add_and_remove_without_a_circle_point_at_create() {
        let me = random_pubky();
        let member = random_pubky();
        // With no circle.json yet, add and remove say to create one.
        for change in [
            Change::add(&member.to_string(), None).expect("valid"),
            Change::remove(&member.to_string()).expect("valid"),
        ] {
            let err = apply(change, me, None).err().expect("no circle");
            assert!(
                format!("{err:#}").contains("`sweepky circle create"),
                "{err:#}"
            );
        }
    }

    #[test]
    fn rewrite_preserves_unknown_fields() {
        let me = random_pubky();
        let kept = random_pubky();
        let gone = random_pubky();
        let stored = json!({
            "schemaVersion": 1,
            "name": "Friends",
            "admin": me.to_string(),
            "members": [
                { "pubky": me.to_string() },
                { "pubky": kept.to_string(), "label": "Kept", "since": "2026-08-01" },
                { "pubky": gone.to_string(), "label": "Gone", "role": { "x": [1, null] } },
            ],
            "addedLater": { "nested": [1, "two", null] },
        });

        // Add: the new entry goes last; every other byte of meaning stays.
        let new = random_pubky();
        let added = apply(
            Change::add(&new.to_string(), Some("New")).expect("valid"),
            me,
            Some(&bytes(&stored)),
        )
        .expect("added");
        let mut expected = stored.clone();
        expected["members"]
            .as_array_mut()
            .expect("an array")
            .push(json!({ "pubky": new.to_string(), "label": "New" }));
        let rewritten: Value =
            serde_json::from_slice(added.record.as_deref().expect("written")).expect("JSON");
        assert_eq!(rewritten, expected);

        // Remove: the other members keep their unknown fields, and the
        // record keeps its own.
        let removed = apply(
            Change::remove(&gone.to_string()).expect("valid"),
            me,
            Some(&bytes(&stored)),
        )
        .expect("removed");
        let mut expected = stored;
        expected["members"]
            .as_array_mut()
            .expect("an array")
            .remove(2);
        let rewritten: Value =
            serde_json::from_slice(removed.record.as_deref().expect("written")).expect("JSON");
        assert_eq!(rewritten, expected);
    }

    #[test]
    fn a_circle_naming_another_admin_is_left_alone_and_flagged() {
        // circle.json under my storage that names someone else as admin is
        // not mine to rewrite: keeping it would keep their claim to the
        // roster's trust.
        let me = random_pubky();
        let other = random_pubky();
        let stored = bytes(&json!({
            "schemaVersion": 1,
            "name": "Not mine",
            "admin": other.to_string(),
            "members": [{ "pubky": other.to_string() }],
        }));
        let err = apply(
            Change::add(&random_pubky().to_string(), None).expect("valid"),
            me,
            Some(&stored),
        )
        .err()
        .expect("refused");
        assert!(format!("{err:#}").contains("another admin"), "{err:#}");

        // `circle show` of my storage says so.
        let circle = Circle::from_json(&stored).expect("parses");
        let text = render(&circle, me);
        assert!(text.contains("warning:"), "{text}");
        assert!(text.contains(&other.to_string()), "{text}");
    }

    #[test]
    fn show_sanitises_name_and_labels() {
        let me = random_pubky();
        let member = random_pubky();
        // A name and a label as a stranger's homeserver could serve them: a
        // colour escape, a right-to-left override, a zero-width space and a
        // newline that would forge a line of output.
        let circle = Circle::from_json(&bytes(&json!({
            "schemaVersion": 1,
            "name": "\u{1b}[31mred\u{202e}txt.exe",
            "admin": me.to_string(),
            "members": [
                { "pubky": me.to_string() },
                { "pubky": member.to_string(), "label": "zero\u{200b}width\nAdmin: forged" },
            ],
        })))
        .expect("parses");
        let text = render(&circle, me);
        for raw in ['\u{1b}', '\u{202e}', '\u{200b}'] {
            assert!(!text.contains(raw), "{raw:?} printed raw: {text:?}");
        }
        assert!(text.contains(r"\u{1b}[31mred\u{202e}txt.exe"), "{text:?}");
        assert!(
            text.contains(r"zero\u{200b}width\u{a}Admin: forged"),
            "{text:?}"
        );
        // The admin and both members, each on a line of its own.
        assert!(text.contains(&format!("Admin: {me}\n")), "{text}");
        assert!(text.contains(&format!("  {me} (admin)\n")), "{text}");
        assert!(text.contains(&format!("  {member}, label ")), "{text}");
        assert!(!text.contains("warning:"), "{text}");
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("Admin:"))
                .count(),
            1
        );
    }
}
