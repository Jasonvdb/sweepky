//! The command line, declared with clap's derive API: each struct field or
//! enum variant below becomes an argument or a subcommand, and its `///` doc
//! comment becomes the `--help` text.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
#[derive(Debug, PartialEq, Eq, Subcommand)]
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
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;

    use super::{Cli, Command};

    #[test]
    fn testnet_is_a_global_flag() {
        for args in [
            ["sweepky", "--testnet", "init", "d"],
            ["sweepky", "init", "d", "--testnet"],
        ] {
            let cli = Cli::try_parse_from(args).expect("parses");
            assert!(cli.testnet, "{args:?}");
            assert_eq!(
                cli.command,
                Command::Init {
                    dir: PathBuf::from("d")
                }
            );
        }

        let cli = Cli::try_parse_from(["sweepky", "init", "d"]).expect("parses");
        assert!(!cli.testnet);
    }
}
