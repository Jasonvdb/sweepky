//! `sweepky pull` (P2c). So far `state`, the local state `pull` keeps
//! between runs, whose feed cursors `post --open` already starts;
//! `resolve`, where each key's homeserver is, looked up once a run;
//! `roster`, the polling of the owner's circle; and `feed`, the watcher of
//! the events feeds and `discovered.json` for strangers' sweeps of the
//! owner's open bounties. The command itself comes in a later step.

pub(crate) mod feed;
pub(crate) mod resolve;
pub(crate) mod roster;
pub(crate) mod state;
