//! The records under `/pub/sweepky/`, one module per kind of record.
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
//!   nested object that a newer client might extend, such as a circle member,
//!   has its own `extra`.
//! - **One way in from bytes:** `from_json`, which goes through the crate's
//!   record parse: it refuses input over [`MAX_RECORD_BYTES`] before reading
//!   it, and a newer `schemaVersion` before reading the rest. The types also
//!   implement `Deserialize`, so a record nested in a larger document (as
//!   `roster` is in `fixtures/trust-labels.json`) can be read, but bytes from
//!   a homeserver go through `from_json`.
//! - **Canonical writing.** A field 01 makes nullable (`revokedAt`) is always
//!   written, `null` included; an optional field (a member's `label`) is left
//!   out when it is `None`. So a record already in that form parses and writes
//!   back as the same JSON value.
//!
//! The text fields (a circle's `name`, the `label`s) hold whatever the writer
//! put there, and the writer may be a stranger. Code that prints one to a
//! terminal treats it as untrusted text.
//!
//! [`MAX_RECORD_BYTES`]: crate::MAX_RECORD_BYTES

mod circle;
mod device_key;
mod discovered;

pub use circle::{Circle, CircleMember};
pub use device_key::{DeviceKey, KeyAlg, KnownKeyAlg};
pub use discovered::Discovered;
