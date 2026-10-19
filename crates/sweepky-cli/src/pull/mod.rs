//! `sweepky pull` (P2c). So far `state`, the local state `pull` keeps
//! between runs, whose feed cursors `post --open` already starts;
//! `resolve`, where each key's homeserver is, looked up once a run; and
//! `roster`, the polling of the owner's circle. The command itself comes in
//! a later step.

pub(crate) mod resolve;
pub(crate) mod roster;
pub(crate) mod state;
