//! The command line, declared with clap's derive API: each struct field or
//! enum variant below becomes an argument or a subcommand, and its `///` doc
//! comment becomes the `--help` text.

use std::convert::Infallible;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sweepky_core::SecretString;

/// Sweepky: sweep bounties on other people's code, findings readable only by
/// the bounty's owner.
//
// `version = crate::VERSION` gives `sweepky --version`, printing the
// package version from Cargo.toml.
#[derive(Debug, Parser)]
#[command(name = "sweepky", version = crate::VERSION)]
pub struct Cli {
    /// Talk to the local pubky-testnet instead of production. Setting
    /// SWEEPKY_TESTNET=1 does the same.
    //
    // `global = true` lets the flag appear before or after the subcommand,
    // as in `sweepky --testnet init d` and `sweepky init d --testnet`. The
    // variable is read by main.rs, not by clap: clap's `env` feature stays
    // off so nothing here reads the environment.
    #[arg(long, global = true)]
    pub testnet: bool,

    /// Read the passphrase that wraps this install's secret files from
    /// FILE: its one line, without the line ending. With it, `login` writes
    /// the secret files it creates wrapped with the passphrase (age's
    /// scrypt): the identity file and device key with --identity, the grant
    /// token and device key for a Pubky Ring login. Every command that
    /// reads a wrapped file needs it again. Meant for process substitution, as in
    /// --passphrase-file <(pass show sweepky), which keeps the passphrase out
    /// of the argument list, the shell history and the disk.
    //
    // A path, not the passphrase: a value on the command line would sit in
    // the process list and the shell history. `main.rs` reads the file into
    // `Context::passphrase` before the command runs; nothing in clap reads
    // it. Global, like `--testnet`, because every command that signs in
    // needs it when the files are wrapped. An interactive prompt that does
    // not echo would need a new crate or `unsafe` terminal calls, so it is
    // left for later; this also keeps standard input free for P2b.
    #[arg(long, global = true, value_name = "FILE")]
    pub passphrase_file: Option<PathBuf>,

    /// Never stop to ask a question. Where a command needs an answer, such
    /// as `post` confirming a bounty's title and brief, `submit` finding
    /// keys the owner added since the last submit, or `done` confirming
    /// credits its flags do not settle, it fails instead and says what it
    /// would have asked.
    //
    // Global, like --testnet. `run` hands it, as a `prompt::Prompting`, to
    // each command that asks; the context does not carry it, so this field
    // is the one place it lives.
    #[arg(long, global = true)]
    pub no_input: bool,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The commands.
///
/// No `PartialEq`: `login`'s signup token is a [`SecretString`], which
/// deliberately has none, so a secret is never compared by accident. Its
/// `Debug` prints `[REDACTED]` in the token's place.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Make DIR a sweeper project: create it, write the .sweepky marker
    /// and a .gitignore that ignores sweeps/.
    //
    // `DIR`, not `<DIR>`: this text is both the `--help` line and rustdoc,
    // and rustdoc reads `<DIR>` as an unclosed HTML tag. clap's usage line
    // still prints the argument as `<DIR>`.
    Init {
        /// The project directory; created if it does not exist.
        //
        // `PathBuf`, not `String`: clap reads it as an `OsString`, so a path
        // that is not valid UTF-8 is still accepted as the user typed it.
        dir: PathBuf,
    },

    /// Log in. Without --identity: through Pubky Ring, by approving the
    /// sign-in page it opens in the browser (or the link and QR code it
    /// prints) in Ring; it saves the grant token Ring approves, which lasts
    /// two years. With --identity NAME: create a dedicated identity under
    /// that name, or reuse the one created earlier, sign it up on its
    /// homeserver the first time, and sign in. Either way it publishes this
    /// install's device key. With --passphrase-file, the secret files it
    /// creates (the grant token or the identity file, and the device key)
    /// are wrapped with that passphrase.
    Login {
        /// The name of a dedicated Sweepky identity: 1 to 32 characters of
        /// a-z, 0-9, - and _, starting with a letter. Never a key, a recovery
        /// phrase or a recovery file: Sweepky does not import identities.
        //
        // A plain `String`: `IdentityName::from_arg` reads it, and only it
        // decides whether it is a name, so its refusals never quote a pasted
        // secret back.
        #[arg(long, value_name = "NAME")]
        identity: Option<String>,

        /// The homeserver to sign the identity up on, as its public key.
        /// Defaults to the local testnet's homeserver under --testnet, else to
        /// homeserver.pubky.app. Only with --identity.
        //
        // Read as text and parsed by `login`, not by clap: clap's error for a
        // value it cannot parse quotes the value, and a key pasted into the
        // wrong flag must not be printed back.
        #[arg(long, value_name = "PK")]
        homeserver: Option<String>,

        /// The signup token homeserver.pubky.app asks for when an identity
        /// first signs up. Spent by that signup. Only with --identity.
        //
        // `value_parser` moves the text into a `SecretString` as clap parses
        // it, so the rest of the program only ever holds the wrapped value,
        // whose `Debug` is redacted. (The process's own argument list still
        // holds it, as for any command-line argument; a signup token is
        // single-use, which is why the plan takes it as an argument.)
        #[arg(long, value_name = "CODE", value_parser = secret_arg)]
        signup_token: Option<SecretString>,
    },

    /// Log out and retire this install: revoke its device key, sign out,
    /// forget the dedicated identity, then delete this install's files.
    /// Deletes nothing when the key cannot be revoked. Sweeps encrypted to
    /// this install's key that were not pulled can no longer be opened.
    Logout,

    /// This identity's published device keys, keys/DEVICE_ID.json, one per
    /// install: list them, or revoke one.
    Keys {
        /// What to do with them.
        //
        // `#[command(subcommand)]` makes the field a nested command line:
        // `sweepky keys list`, `sweepky keys revoke <DEVICE_ID>`.
        #[command(subcommand)]
        command: KeysCommand,
    },

    /// The circle: the roster this identity keeps as its admin, at
    /// /pub/sweepky/circle.json. Create it, add or remove a member, or show
    /// a circle.
    Circle {
        /// What to do with it.
        #[command(subcommand)]
        command: CircleCommand,
    },

    /// Post a bounty from the draft file DRAFT, closed unless --open: only
    /// sweeps from this identity's circle are read. Pins every target to
    /// exact SHAs, shows the bounty (title, focus, suggested playbook, each
    /// target with its SHAs, and the brief) and asks before it publishes
    /// /pub/sweepky/bounties/ID.json, which anyone can read. With
    /// --no-input it shows the bounty and fails instead of asking, so
    /// nothing is posted.
    Post {
        /// The bounty draft: a JSON file with the title, an optional focus,
        /// the markdown brief, an optional suggested playbook and the
        /// targets, unpinned, and no other field. Public once posted.
        //
        // A path, not the text: a multi-line brief and several targets fit
        // a file, and stay out of the argument list, where clap would echo
        // them back in a usage error. `PathBuf`, as for `init`'s `DIR`, so
        // a path that is not UTF-8 is still taken as typed.
        #[arg(value_name = "DRAFT")]
        draft: PathBuf,

        /// Post the bounty open: sweeps from anyone are read, each labelled
        /// by how far you trust its sweeper. After the yes, post finds
        /// where each watched homeserver's events feed stands, and beside
        /// the bounty it publishes /pub/sweepky/bounties/ID.discovered.json,
        /// the list of strangers' sweeps `pull` finds, starting there.
        //
        // A plain flag, before or after DRAFT: clap reads `--open` wherever
        // it comes among the subcommand's arguments.
        #[arg(long)]
        open: bool,
    },

    /// Start a sweep of the bounty at BOUNTY_URL, or without one of the
    /// target your circle has swept least, in the init project this is run
    /// in: check that you may run it, publish
    /// /pub/sweepky/sweeps/ID.json as running, fetch each target by its
    /// pinned SHA into sweeps/ID/target/TID/ with its agent-instruction
    /// files stripped, and write scope.json, brief.md and the
    /// sweeps/ID/.sweepky/sweep.json marker. If a fetch fails, the sweep is
    /// marked aborted and its directory removed. Then run Claude Code here,
    /// /sweepky, and `sweepky submit`.
    Run {
        /// The bounty's pubky:// URL, as `sweepky post` printed it. Without
        /// one, run picks, from the open bounties of your circle's members
        /// (or of the circle --circle names), the target their sweep
        /// records name least, and sweeps that target alone.
        //
        // Plain text, checked by `run`, for the same reason as
        // `--homeserver`: clap's own parse error would quote the value,
        // and a key pasted in the wrong place must not be printed back.
        #[arg(value_name = "BOUNTY_URL")]
        bounty: Option<String>,

        /// Sweep only the target with this id, instead of every target this
        /// build can sweep. Needs BOUNTY_URL.
        #[arg(long, value_name = "TID")]
        target: Option<String>,

        /// Check the bounty against the circle ADMIN keeps, instead of its
        /// owner's own: both the owner and you must be in it. Without
        /// BOUNTY_URL, pick from that circle instead of your own. ADMIN is
        /// a pubky, with or without the `pubky` prefix.
        #[arg(long, value_name = "ADMIN")]
        circle: Option<String>,
    },

    /// Finish a sweep once the agent has exited: check the sweep directory
    /// and walk it without following a link, build the package from its
    /// audit/ (Cloudflare's findings.json converted), check the bounty
    /// owner's keys against the ones pinned when you last submitted to them
    /// and ask about new ones, print the file list, encrypt the package to
    /// the owner's keys and this install's own, upload
    /// /pub/sweepky/sweeps/ID.age and mark the sweep done. A homeserver that
    /// refuses the package marks it aborted, which is final; a network
    /// error or a rate limit leaves it running, to submit again.
    Submit {
        /// The sweep directory, as `sweepky run` printed it: sweeps/ID from
        /// the init project, or that path in full. Without it, submit must
        /// be run in the init project's own directory, and takes the one
        /// sweep there not yet submitted.
        //
        // `PathBuf`, as for `init`'s `DIR`, so a path that is not UTF-8 is
        // still taken as typed; `submit` checks it and never quotes it.
        #[arg(long, value_name = "DIR")]
        run_dir: Option<PathBuf>,

        /// The playbook the agent followed, as the sweep's public record
        /// and the package name it, such as
        /// cloudflare/security-audit@c1c8a8c: up to 64 of A-Z a-z 0-9 . _ /
        /// -, then optionally @ and 7 to 40 hex digits of a commit. Needed
        /// while the record names none (until init records one).
        //
        // Plain text, checked by `submit`, as `run`'s arguments are: clap's
        // own parse error would quote it, and a key pasted here must be
        // refused before it reaches a public record.
        #[arg(long, value_name = "NAME")]
        playbook: Option<String>,
    },

    /// Read what is new about your bounties and open the sweeps you can:
    /// poll your circle's records, check keys/ for device keys your installs
    /// did not create, watch the watched homeservers' events feeds for
    /// strangers' sweeps of your open bounties, decrypt each new done sweep
    /// into the data directory (strangers' into untrusted/), group each
    /// bounty's findings by location into groups.json and merged.json, and
    /// add the strangers' sweeps it found to each open bounty's
    /// /pub/sweepky/bounties/ID.discovered.json. Prints where each feed was
    /// read from, and each sweep's trust label, status and where it was
    /// stored; never a finding.
    //
    // No arguments: everything it needs is the login, the device key and
    // the state files of this install, and the network settings.
    Pull,

    /// Mark the bounty at BOUNTY_URL done and credit every sweeper whose
    /// sweep helped. From the groups your last `pull` wrote, done proposes
    /// each sweeper with a done sweep in a group, never you, and shows each
    /// one's trust label and the places they reported. --credit adds a
    /// sweeper and --no-credit drops one. Then it asks before it rewrites
    /// /pub/sweepky/bounties/ID.json, where anyone can read it, with status
    /// done, doneAt and the credits, keeping every other field. It does not
    /// ask when the flags name every proposed sweeper. Run it again to
    /// change the credits: the last write wins.
    //
    // Every value is plain text, checked by `done`, as `run`'s arguments
    // are: clap's own parse error would quote a value, and a key pasted in
    // the wrong place must not be printed back.
    Done {
        /// The bounty's pubky:// URL, as `sweepky post` printed it.
        #[arg(value_name = "BOUNTY_URL")]
        bounty: String,

        /// Credit this sweeper, proposed or not: a pubky, with or without
        /// the `pubky` prefix. Repeat it for each one. Never your own.
        //
        // A `Vec` makes the flag repeatable: clap appends each value.
        #[arg(long, value_name = "PUBKY")]
        credit: Vec<String>,

        /// Do not credit this proposed sweeper, a pubky in either form.
        /// Repeat it for each one.
        #[arg(long, value_name = "PUBKY")]
        no_credit: Vec<String>,
    },
}

/// The `circle` commands.
///
/// Every pubky and label is read as plain text and checked by the command,
/// not by clap, whose parse error would quote the value back.
#[derive(Debug, Subcommand)]
pub enum CircleCommand {
    /// Create this identity's circle, named NAME, with this identity as its
    /// admin and its first member. Refused when the circle exists already.
    Create {
        /// The circle's name: 1 to 64 characters, with no control,
        /// formatting or invisible characters and no backslash. Public.
        #[arg(value_name = "NAME")]
        name: String,
    },

    /// Add PUBKY to this identity's circle, or set its label when it is a
    /// member already.
    Add {
        /// The member's public key: 52 characters of z-base32, with or
        /// without the `pubky` prefix the Pubky SDK prints.
        #[arg(value_name = "PUBKY")]
        pubky: String,

        /// A short name for the member, shown beside the key: 1 to 64
        /// characters, with no control, formatting or invisible characters
        /// and no backslash. Public.
        #[arg(long, value_name = "LABEL")]
        label: Option<String>,
    },

    /// Remove PUBKY from this identity's circle. The admin cannot be
    /// removed.
    Remove {
        /// The member's public key, in either form.
        #[arg(value_name = "PUBKY")]
        pubky: String,
    },

    /// Show a circle: the one ADMIN keeps, or this identity's own. Reads
    /// public data only.
    Show {
        /// The admin whose circle to show, in either form; this identity
        /// when left out.
        #[arg(value_name = "ADMIN")]
        admin: Option<String>,
    },
}

/// The `keys` commands.
#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// List the device keys published under this identity's keys/, and
    /// raise an alarm for any that this owner's installs did not create.
    /// Keys this build cannot encrypt to are flagged too. Reads public data
    /// only.
    List,

    /// Revoke the device key keys/DEVICE_ID.json: set its revokedAt, so
    /// sweeps are no longer encrypted to it. Any other field is kept.
    Revoke {
        /// The device id, as `sweepky keys list` shows it.
        //
        // A plain `String`, checked by `keys revoke` with core's
        // `DeviceId`, for the same reason as `--homeserver` above: clap's
        // own parse error would quote the value.
        #[arg(value_name = "DEVICE_ID")]
        device_id: String,
    },
}

/// Wraps a secret argument the moment clap reads it.
///
/// `Infallible` is the error type of a function that cannot fail: clap's
/// `value_parser` wants a `Result`, and this one is always `Ok`.
fn secret_arg(value: &str) -> Result<SecretString, Infallible> {
    Ok(SecretString::from(value))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::Parser;
    use sweepky_core::ExposeSecret;

    use super::{Cli, Command};

    #[test]
    fn testnet_is_a_global_flag() {
        for args in [
            ["sweepky", "--testnet", "init", "d"],
            ["sweepky", "init", "d", "--testnet"],
        ] {
            let cli = Cli::try_parse_from(args).expect("parses");
            assert!(cli.testnet, "{args:?}");
            // `matches!` with a guard, because `Command` has no `==`.
            assert!(
                matches!(&cli.command, Command::Init { dir } if dir == Path::new("d")),
                "{args:?}"
            );
        }

        let cli = Cli::try_parse_from(["sweepky", "init", "d"]).expect("parses");
        assert!(!cli.testnet);
    }

    #[test]
    fn passphrase_file_is_a_global_flag() {
        // Before or after the command, and with any command, as for
        // --testnet: the shell's process substitution hands over a path such
        // as /dev/fd/63.
        for args in [
            vec![
                "sweepky",
                "--passphrase-file",
                "/dev/fd/63",
                "login",
                "--identity",
                "x",
            ],
            vec![
                "sweepky",
                "login",
                "--identity",
                "x",
                "--passphrase-file",
                "/dev/fd/63",
            ],
            vec![
                "sweepky",
                "keys",
                "revoke",
                "id",
                "--passphrase-file",
                "/dev/fd/63",
            ],
        ] {
            let cli = Cli::try_parse_from(&args).expect("parses");
            assert_eq!(
                cli.passphrase_file.as_deref(),
                Some(Path::new("/dev/fd/63")),
                "{args:?}"
            );
        }
        let cli = Cli::try_parse_from(["sweepky", "logout"]).expect("parses");
        assert_eq!(cli.passphrase_file, None);
    }

    #[test]
    fn no_input_is_a_global_flag_off_by_default() {
        // Before or after the command, as for --testnet, and with any
        // command: `run` hands it to the commands that ask a question.
        for args in [
            ["sweepky", "--no-input", "keys", "list"],
            ["sweepky", "keys", "list", "--no-input"],
            ["sweepky", "--no-input", "init", "d"],
        ] {
            let cli = Cli::try_parse_from(args).expect("parses");
            assert!(cli.no_input, "{args:?}");
        }
        let cli = Cli::try_parse_from(["sweepky", "keys", "list"]).expect("parses");
        assert!(!cli.no_input);
    }

    #[test]
    fn post_takes_one_draft_path_and_open_on_either_side_of_it() {
        let cli = Cli::try_parse_from(["sweepky", "post", "draft.json"]).expect("parses");
        assert!(
            matches!(
                &cli.command,
                Command::Post { draft, open: false } if draft == Path::new("draft.json")
            ),
            "{cli:?}"
        );
        for args in [
            ["sweepky", "post", "--open", "draft.json"],
            ["sweepky", "post", "draft.json", "--open"],
        ] {
            let cli = Cli::try_parse_from(args).expect("parses");
            assert!(
                matches!(
                    &cli.command,
                    Command::Post { draft, open: true } if draft == Path::new("draft.json")
                ),
                "{args:?}: {cli:?}"
            );
        }
        // Exactly one draft: none, or a second, is a usage error, and so is
        // `--open` given a value.
        assert!(Cli::try_parse_from(["sweepky", "post"]).is_err());
        assert!(Cli::try_parse_from(["sweepky", "post", "--open"]).is_err());
        assert!(Cli::try_parse_from(["sweepky", "post", "a.json", "b.json"]).is_err());
        assert!(Cli::try_parse_from(["sweepky", "post", "--open=yes", "a.json"]).is_err());
    }

    #[test]
    fn run_takes_an_optional_url_a_target_and_a_circle() {
        let url = "pubky://owner/pub/sweepky/bounties/0035G87EK4XFE.json";
        let cli =
            Cli::try_parse_from(["sweepky", "run", url, "--target", "t1", "--circle", "admin"])
                .expect("parses");
        let Command::Run {
            bounty,
            target,
            circle,
        } = &cli.command
        else {
            panic!("run parses as Run: {cli:?}");
        };
        assert_eq!(bounty.as_deref(), Some(url));
        assert_eq!(target.as_deref(), Some("t1"));
        assert_eq!(circle.as_deref(), Some("admin"));

        // Each is optional to clap: `run` says what a missing URL means. All
        // three are plain text, which `run` checks, so a value clap would
        // refuse, and quote, never reaches clap's own parse.
        let cli = Cli::try_parse_from(["sweepky", "run"]).expect("parses");
        assert!(matches!(
            cli.command,
            Command::Run {
                bounty: None,
                target: None,
                circle: None
            }
        ));
        // One URL at most.
        assert!(Cli::try_parse_from(["sweepky", "run", url, url]).is_err());
    }

    #[test]
    fn submit_takes_an_optional_run_dir_and_playbook() {
        let cli = Cli::try_parse_from([
            "sweepky",
            "submit",
            "--run-dir",
            "sweeps/0035G87EK4XFE",
            "--playbook",
            "cloudflare/security-audit@c1c8a8c",
        ])
        .expect("parses");
        let Command::Submit { run_dir, playbook } = &cli.command else {
            panic!("submit parses as Submit: {cli:?}");
        };
        assert_eq!(run_dir.as_deref(), Some(Path::new("sweeps/0035G87EK4XFE")));
        assert_eq!(
            playbook.as_deref(),
            Some("cloudflare/security-audit@c1c8a8c")
        );

        // Both optional to clap, and both plain text that `submit` checks.
        let cli = Cli::try_parse_from(["sweepky", "submit"]).expect("parses");
        assert!(matches!(
            cli.command,
            Command::Submit {
                run_dir: None,
                playbook: None
            }
        ));
        // No positional argument.
        assert!(Cli::try_parse_from(["sweepky", "submit", "sweeps/0035G87EK4XFE"]).is_err());
    }

    #[test]
    fn pull_takes_no_argument() {
        let cli = Cli::try_parse_from(["sweepky", "pull"]).expect("parses");
        assert!(matches!(cli.command, Command::Pull), "{cli:?}");
        // Global flags still go before or after it.
        let cli = Cli::try_parse_from(["sweepky", "pull", "--testnet"]).expect("parses");
        assert!(cli.testnet && matches!(cli.command, Command::Pull));
        // Nothing else: no positional argument and no flag of its own.
        assert!(Cli::try_parse_from(["sweepky", "pull", "bounty"]).is_err());
        assert!(Cli::try_parse_from(["sweepky", "pull", "--open"]).is_err());
    }

    #[test]
    fn done_takes_one_url_and_repeated_credit_flags_as_text() {
        let url = "pubky://owner/pub/sweepky/bounties/0035G87EK4XFE.json";
        let cli = Cli::try_parse_from([
            "sweepky",
            "done",
            url,
            "--credit",
            "b",
            "--no-credit",
            "c",
            "--credit",
            "d",
        ])
        .expect("parses");
        let Command::Done {
            bounty,
            credit,
            no_credit,
        } = &cli.command
        else {
            panic!("done parses as Done: {cli:?}");
        };
        // Plain text, in the order given: `done` checks every value.
        assert_eq!(bounty, url);
        assert_eq!(credit, &["b", "d"]);
        assert_eq!(no_credit, &["c"]);

        let cli = Cli::try_parse_from(["sweepky", "done", url]).expect("parses");
        assert!(
            matches!(&cli.command, Command::Done { credit, no_credit, .. }
                if credit.is_empty() && no_credit.is_empty()),
            "{cli:?}"
        );
        // Exactly one URL, and a flag with no value is a usage error.
        assert!(Cli::try_parse_from(["sweepky", "done"]).is_err());
        assert!(Cli::try_parse_from(["sweepky", "done", url, url]).is_err());
        assert!(Cli::try_parse_from(["sweepky", "done", url, "--credit"]).is_err());
    }

    #[test]
    fn login_takes_a_name_a_homeserver_and_a_signup_token_never_printed() {
        let token = "SYNTHETIC-TOKEN-0000";
        let cli = Cli::try_parse_from([
            "sweepky",
            "login",
            "--identity",
            "throwaway",
            "--homeserver",
            "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
            "--signup-token",
            token,
        ])
        .expect("parses");
        let Command::Login {
            identity,
            homeserver,
            signup_token,
        } = &cli.command
        else {
            panic!("login parses as Login");
        };
        assert_eq!(identity.as_deref(), Some("throwaway"));
        assert!(homeserver.is_some());
        assert_eq!(
            signup_token.as_ref().map(|t| t.expose_secret()),
            Some(token)
        );
        // Printing the parsed arguments, as a failing test or a stray `{:?}`
        // would, shows `[REDACTED]` in the token's place.
        assert!(!format!("{cli:?}").contains(token));

        // Every flag is optional to clap; `login` itself says what is missing.
        let cli = Cli::try_parse_from(["sweepky", "login"]).expect("parses");
        assert!(matches!(
            cli.command,
            Command::Login {
                identity: None,
                homeserver: None,
                signup_token: None
            }
        ));
    }
}
