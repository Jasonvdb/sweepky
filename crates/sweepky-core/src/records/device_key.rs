//! [`DeviceKey`], one CLI install's public encryption key in
//! `keys/<deviceId>.json`, and [`KeyAlg`], its `alg`.

use serde::{Deserialize, Serialize};

use crate::error::RecordError;
use crate::open_enum::open_enum;
use crate::schema::{MAX_RECORD_BYTES, SchemaVersion, UnknownFields, parse_record};
use crate::time::RecordTime;

open_enum! {
    /// A device key's `alg`: what kind of key its `recipient` is.
    ///
    /// Open, so a newer client can publish another kind of key, say a
    /// post-quantum `mlkem768x25519` one, without a migration (01's rule).
    /// An older build still reads that record, finds `as_known()` is `None`,
    /// and does not encrypt to it.
    pub struct KeyAlg;

    /// The key algorithms this build knows.
    pub enum KnownKeyAlg {
        /// An age X25519 recipient, written `age1…`.
        AgeX25519 = "age-x25519",
    }
}

/// One CLI install's public encryption key, at
/// `/pub/sweepky/keys/<deviceId>.json`: `{schemaVersion, alg, recipient,
/// label, createdAt, revokedAt}`.
///
/// A sweeper's CLI encrypts a sweep to every unrevoked key of the bounty's
/// owner whose `alg` it knows. This type only reads and writes the record: it
/// does not check `recipient`. Before encrypting, the CLI parses the recipient
/// strictly for its `alg` (P1b), because anyone holding the owner's grant, or
/// an active operator of the owner's homeserver, can write a record here
/// (`docs/plan/02-encryption-and-safety.md`).
///
/// `alg` and `revokedAt` must both be present, as 01 requires of every
/// `keys/*.json`; `revokedAt` is `null` while the key is in use. A record
/// missing either is an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKey {
    /// The record's `schemaVersion`.
    pub schema_version: SchemaVersion,
    /// The kind of key `recipient` holds.
    pub alg: KeyAlg,
    /// The public key, in `alg`'s own text form: `age1…` for `age-x25519`.
    /// Not checked here; parse it for its `alg` before using it.
    pub recipient: String,
    /// A name for the install, such as the machine's. Untrusted text.
    pub label: String,
    /// When the key was published.
    pub created_at: RecordTime,
    /// When the key was revoked, or `None` (`null`) while it is in use.
    // serde's derive treats an `Option` field as optional: a missing key
    // reads as `None`. 01 says `revokedAt` is always there, so that default
    // is turned off. Naming a `deserialize_with` function makes serde require
    // the key, and `Option::deserialize` is the ordinary `Option` reader
    // (`null` is `None`, a string is `Some`), so the only change is that the
    // key must be present. Writing is unchanged: `None` is written as `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub revoked_at: Option<RecordTime>,
    /// The top-level fields this build does not know, kept for a rewrite.
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl DeviceKey {
    /// Parses a `keys/<deviceId>.json` record fetched from a homeserver.
    ///
    /// Refuses input over [`MAX_RECORD_BYTES`] with
    /// [`RecordError::TooLarge`] and a newer `schemaVersion` with
    /// [`RecordError::UnsupportedVersion`], before reading the rest; anything
    /// malformed is a [`RecordError::Json`]. An unknown `alg` is not
    /// malformed: the record parses, and [`KeyAlg::as_known`] says `None`.
    pub fn from_json(input: &[u8]) -> Result<Self, RecordError> {
        parse_record(input, MAX_RECORD_BYTES)
    }

    /// Whether the key is revoked: `revokedAt` holds a time.
    ///
    /// The time is opaque ([`RecordTime`]), so this does not say when, and it
    /// need not: a sweep is encrypted once, at upload, so a key revoked at any
    /// time takes no further sweeps.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{DeviceKey, KnownKeyAlg};
    use crate::error::{JsonCategory, RecordError};

    /// A synthetic age recipient: random bytes in age's bech32 form, with no
    /// private key behind them.
    const RECIPIENT: &str = "age190ltw9hvaa3upy6ggv376qr6tk2a7rh650w9g4zs8e2yk8hkrw0s4af8k6";

    fn key_json(alg: &str, revoked_at: Value) -> Value {
        json!({
            "schemaVersion": 1,
            "alg": alg,
            "recipient": RECIPIENT,
            "label": "laptop",
            "createdAt": "2026-10-15T09:30:00Z",
            "revokedAt": revoked_at,
        })
    }

    fn parse(input: &Value) -> Result<DeviceKey, RecordError> {
        DeviceKey::from_json(input.to_string().as_bytes())
    }

    #[test]
    fn a_key_round_trips_with_revoked_at_kept_as_null() {
        let mut input = key_json("age-x25519", Value::Null);
        input["addedLater"] = json!({ "by": "a newer client" });

        let key = parse(&input).unwrap();
        assert_eq!(key.alg.as_known(), Some(KnownKeyAlg::AgeX25519));
        assert!(!key.is_revoked());
        assert_eq!(key.extra.len(), 1);
        let output = serde_json::to_value(&key).unwrap();
        // `null` is written out, not left out.
        assert_eq!(output.get("revokedAt"), Some(&Value::Null));
        assert_eq!(output, input);
    }

    #[test]
    fn a_key_with_an_unknown_alg_parses_and_round_trips() {
        let mut input = key_json("mlkem768x25519", json!("2026-10-16T08:00:00Z"));
        // The recipient is opaque here, whatever the alg.
        input["recipient"] = json!("age1pq1-a-format-this-build-does-not-read");

        let key = parse(&input).unwrap();
        assert_eq!(key.alg.as_known(), None);
        assert_eq!(key.alg.as_str(), "mlkem768x25519");
        assert!(key.is_revoked());
        assert_eq!(serde_json::to_value(&key).unwrap(), input);
    }

    #[test]
    fn a_key_without_alg_or_revoked_at_is_rejected() {
        // 01: `keys/*.json` always carries `alg` and `revokedAt`.
        for field in ["alg", "revokedAt"] {
            let mut input = key_json("age-x25519", Value::Null);
            input.as_object_mut().unwrap().remove(field);
            assert!(
                matches!(
                    parse(&input),
                    Err(RecordError::Json {
                        category: JsonCategory::Data,
                        ..
                    })
                ),
                "{field}"
            );
        }
    }
}
