//! `sweepky pull` (P2c). So far only `state`, the local state `pull` keeps
//! between runs, whose feed cursors `post --open` already starts; the
//! command itself comes in a later step.

pub(crate) mod state;
