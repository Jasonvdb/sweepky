//! `sweepky pull` (P2c). So far `state`, the local state `pull` keeps
//! between runs, whose feed cursors `post --open` already starts;
//! `resolve`, where each key's homeserver is, looked up once a run;
//! `roster`, the polling of the owner's circle; `feed`, the watcher of
//! the events feeds and `discovered.json` for strangers' sweeps of the
//! owner's open bounties; `open`, which fetches, decrypts and checks each
//! waiting sweep in a fair order within caps per run; `store`, which
//! writes each decrypted sweep into the data directory, strangers' in
//! `untrusted/`; `triage`, which labels each stored sweep's sweeper,
//! groups the findings of a bounty's sweeps and writes its `groups.json`
//! and its `merged.json`, the circle's content alone; and `discovered`,
//! `pull`'s one public write, each open bounty's `discovered.json`, under
//! the writers' lock and only when its sweeps change. The command itself
//! comes in a later step.

pub(crate) mod discovered;
pub(crate) mod feed;
pub(crate) mod open;
pub(crate) mod resolve;
pub(crate) mod roster;
pub(crate) mod state;
pub(crate) mod store;
pub(crate) mod triage;
