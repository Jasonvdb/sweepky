//! The records under `/pub/sweepky/`, one module per kind of record, and the
//! [`Manifest`] a sweep package carries.
//!
//! Every record type here is built the same way:
//!
//! - **`schemaVersion` first**, as a [`SchemaVersion`](crate::SchemaVersion).
//!   01 gives every record one, though the shapes in 01's table leave it
//!   out.
//! - **camelCase on the wire.** `#[serde(rename_all = "camelCase")]` maps a
//!   Rust field such as `created_at` to the JSON key `createdAt`, so the Rust
//!   code keeps Rust's snake_case names.
//! - **Unknown fields kept.** The last field is `#[serde(flatten)] pub extra:
//!   UnknownFields`, so a field a newer client added survives a rewrite. A
//!   nested object that a newer client might extend, such as a circle member
//!   or a bounty's `playbook`, has its own `extra`.
//! - **One way in from bytes:** `from_json`, which goes through the crate's
//!   record parse: it refuses input over [`MAX_RECORD_BYTES`] before reading
//!   it, and a newer `schemaVersion` before reading the rest. The types also
//!   implement `Deserialize`, so a record nested in a larger document (as
//!   `roster` is in `fixtures/trust-labels.json`) can be read, but bytes from
//!   a homeserver go through `from_json`.
//! - **Canonical writing.** A field 01 shows as `null` (`revokedAt`, a
//!   bounty's `reward` and `doneAt`) is always written, `null` included; an
//!   optional field (a member's `label`, a bounty's `playbook.suggested`, a
//!   sweep's `finishedAt` and `sha256`) is left out when it is `None`. So a
//!   record already in that form parses and writes back as the same JSON
//!   value.
//! - **Nothing from findings in a public record.** `/pub/` is world-readable,
//!   so [`Bounty`] and [`Sweep`] have no field for a severity, a count or a
//!   finding's title. Findings exist only inside the encrypted package.
//!
//! [`Manifest`] has no `schemaVersion` and no `from_json`: it is part of the
//! sweep package, not a file of its own. The package envelope around it
//! carries the version and is parsed with its own cap (P1b).
//!
//! The text fields (a circle's `name`, the `label`s, a bounty's `title`,
//! `brief` and suggested playbook) hold whatever the writer put there, and
//! the writer may be a stranger. Code that prints one to a terminal treats it
//! as untrusted text.
//!
//! [`MAX_RECORD_BYTES`]: crate::MAX_RECORD_BYTES

mod bounty;
mod circle;
mod device_key;
mod discovered;
mod manifest;
mod sweep;

pub use bounty::{
    Bounty, BountyPlaybook, BountyStatus, Focus, KnownBountyStatus, KnownFocus, MarkDoneError,
};
pub use circle::{Circle, CircleMember};
pub use device_key::{DeviceKey, KeyAlg, KnownKeyAlg};
pub use discovered::Discovered;
pub use manifest::Manifest;
pub use sweep::{KnownSweepStatus, Sweep, SweepStatus};
