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

    /// Log in. With --identity NAME: create a dedicated identity under that
    /// name, or reuse the one created earlier, sign it up on its homeserver
    /// the first time, and sign in. (The Pubky Ring sign-in comes in a later
    /// build.)
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
        /// homeserver.pubky.app.
        //
        // Read as text and parsed by `login`, not by clap: clap's error for a
        // value it cannot parse quotes the value, and a key pasted into the
        // wrong flag must not be printed back.
        #[arg(long, value_name = "PK")]
        homeserver: Option<String>,

        /// The signup token homeserver.pubky.app asks for when an identity
        /// first signs up. Spent by that signup.
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
