//! A package to a sweep's `.age` file and back in one call each:
//! [`seal_package`] for `submit` (P2b) and [`open_package`] for `pull` (P2c),
//! so neither command can leave a step out. Each function's doc lists its
//! steps. The steps themselves stay public for tests and tools, but the CLI
//! calls these two.

use age::secrecy::ExposeSecret;

use super::{PackageError, SweepPackage};
use crate::crypto::{AgeRecipient, DecryptError, DeviceIdentity, EncryptError, decrypt, encrypt};
use crate::error::RecordError;
use crate::records::{BindingError, Sweep};
use crate::url::SweepRef;

/// Why [`seal_package`] refused. No variant holds data from the package or
/// a key.
// `#[from]` writes the `From` impl that lets `?` turn the inner error into
// this one, and makes the inner error this one's `source()`. The messages
// leave the inner error out, so a caller that prints the chain of sources
// (anyhow's `{:#}` does) shows each part once.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// The manifest lists a target twice, or its `targetShas` keys are not
    /// exactly its targets. [`open_package`] would refuse such a package
    /// under any record, so it is not sealed.
    #[error("the manifest's targets repeat one or differ from its targetShas")]
    TargetsMismatch,
    /// The package could not be padded: over the 32 MiB limit, or (which
    /// these types never cause) serde_json failed.
    #[error("the sweep package could not be padded")]
    Package(#[from] PackageError),
    /// age refused the recipients: none, or more than
    /// [`MAX_RECIPIENTS`](crate::MAX_RECIPIENTS).
    #[error("the sweep package could not be encrypted")]
    Encrypt(#[from] EncryptError),
}

/// Why [`open_package`] returned no package, by the step that failed. No
/// variant holds data from the ciphertext, the plaintext, the record or a
/// key: each inner error is a fixed variant or numbers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// The `.age` file did not decrypt with this identity: not an age file,
    /// not encrypted to this key, altered, or over a size limit.
    #[error("the sweep package could not be decrypted")]
    Decrypt(#[from] DecryptError),
    /// It decrypted, but the plaintext is not a sweep package this build
    /// reads: malformed, or of a newer `schemaVersion`. (A plaintext over
    /// [`MAX_PACKAGE_BYTES`](crate::MAX_PACKAGE_BYTES) is refused while it is
    /// decrypted, as [`DecryptError::PlaintextTooLarge`].)
    #[error("the decrypted sweep package could not be read")]
    Record(#[from] RecordError),
    /// It is a package, but not the one this record and path describe: its
    /// manifest names another sweeper, bounty or targets.
    #[error("the sweep package does not belong to the sweep record it was fetched with")]
    Binding(#[from] BindingError),
}

/// Seals a sweep package for its readers, as `submit` uploads it to
/// `sweeps/<id>.age`: checks the manifest's targets, pads the package to its
/// bucket and encrypts it as binary age v1 to `recipients` (the bounty
/// owner's unrevoked keys plus the sweeper's own, chosen by the CLI).
///
/// The padded plaintext lives only in a wiped buffer, which is dropped when
/// this returns. The ciphertext is public, so it comes back as a plain
/// `Vec`.
///
/// It does not compare the manifest with the sweep record: the sweeper's
/// CLI wrote both. [`open_package`] does, on the owner's side.
///
/// # Errors
///
/// [`SealError::TargetsMismatch`] for a manifest no record could bind,
/// [`SealError::Package`] for a package over the size limit, and
/// [`SealError::Encrypt`] for an empty or too long recipient list.
pub fn seal_package(
    package: &SweepPackage,
    recipients: &[AgeRecipient],
) -> Result<Vec<u8>, SealError> {
    // Only whether the targets pass matters here, not the set they make.
    if package.manifest.checked_target_set().is_err() {
        return Err(SealError::TargetsMismatch);
    }
    // `?` converts a `PackageError` and then an `EncryptError` through the
    // `From` impls `#[from]` wrote.
    let padded = package.to_padded()?;
    Ok(encrypt(&padded, recipients)?)
}

/// Opens a sweep's `.age` file with this install's identity and returns the
/// package, only if it is the package of the record `sweep` at the path
/// `sweep_ref`.
///
/// `ciphertext` and `sweep` are what the caller fetched from
/// [`SweepRef::package_url`] and [`SweepRef::url`] on the sweeper's own
/// storage, resolved by the caller, and `sweep_ref` is that path; see
/// [`Manifest::check_binding`](crate::Manifest::check_binding) for why it
/// must not come from the feed, the record or the package.
///
/// The steps, each bounding the next: [`decrypt`], with its
/// caps on the file, the header and the plaintext; then
/// [`SweepPackage::from_json`], with its size cap, version check and
/// serde_json's recursion limit; then the manifest binding. The plaintext's
/// wiped buffer is dropped as soon as it is parsed. When the binding fails,
/// the parsed package is dropped, never returned. Its strings are not wiped
/// as they drop, as for every [`SweepPackage`].
///
/// Nothing in the ciphertext or the record can make this panic.
///
/// # Errors
///
/// The step that failed: [`OpenError::Decrypt`], [`OpenError::Record`] or
/// [`OpenError::Binding`].
pub fn open_package(
    ciphertext: &[u8],
    identity: &DeviceIdentity,
    sweep_ref: &SweepRef,
    sweep: &Sweep,
) -> Result<SweepPackage, OpenError> {
    let plaintext = decrypt(ciphertext, identity)?;
    // `expose_secret` lends the plaintext's bytes for the parse; the package
    // holds copies of what it needs.
    let package = SweepPackage::from_json(plaintext.expose_secret())?;
    // Wiped now rather than at the end of the function.
    drop(plaintext);
    // On an error, `?` returns before the package is moved out, so it is
    // dropped here and the caller never sees it.
    package.manifest.check_binding(sweep_ref, sweep)?;
    Ok(package)
}

#[cfg(test)]
mod tests {
    use age::secrecy::ExposeSecret;
    use serde_json::{Value, json};

    use super::{OpenError, SealError, open_package, seal_package};
    use crate::crypto::{
        DecryptError, DeviceIdentity, EncryptError, PADDING_BUCKET_BYTES, PaddedPlaintext, decrypt,
        encrypt,
    };
    use crate::error::RecordError;
    use crate::findings::Findings;
    use crate::package::test_support::{
        BOUNTY_ID, MARKER, OWNER, REV, SWEEPER, bounty_url, manifest_json, path,
    };
    use crate::package::{PackageError, SweepPackage};
    use crate::records::{BindingError, Manifest, Sweep};
    use crate::schema::MAX_PACKAGE_BYTES;
    use crate::url::SweepRef;

    /// C from `fixtures/trust-labels.json`: a stranger who copies the
    /// sweeper's package.
    const COPIER: &str = "3rus98p3q6naiqxckzo676jeewj1whf6ai8911mxacshks18eq3y";
    /// The sweeper's sweep id, and the copier's.
    const SWEEP_ID: &str = "0035M2DX3Q44W";
    const COPY_ID: &str = "0035N9QXF25NG";
    /// Another bounty id, used here under A as owner.
    const OTHER_BOUNTY_ID: &str = "0035HHKN24QMC";

    /// The sweeper's package: test_support's manifest, one finding and one
    /// attachment, both holding `MARKER`.
    fn package() -> SweepPackage {
        let manifest: Manifest = serde_json::from_value(manifest_json()).unwrap();
        let findings = json!({
            "schemaVersion": 1,
            "playbook": "cloudflare/security-audit@c1c8a8c",
            "findings": [{
                "id": "f1",
                "title": MARKER,
                "severity": null,
                "confidence": null,
                "status": "needs_validation",
                "locations": [{ "file": "src/auth/session.rs", "line": 120 }],
                "description": MARKER,
            }],
        });
        let findings = Findings::from_json(findings.to_string().as_bytes()).unwrap();
        let mut package = SweepPackage::new(manifest, findings);
        package
            .attachments
            .insert(path("REPORT.md"), format!("# {MARKER}\n"))
            .unwrap();
        package
    }

    /// A sweep record of the manifest's bounty and targets. The sweeper's
    /// and the copier's say the same: a record does not name its sweeper,
    /// its path does.
    fn record() -> Sweep {
        let record = json!({
            "schemaVersion": 1,
            "bounty": bounty_url(OWNER, BOUNTY_ID),
            "targets": ["t1"],
            "playbook": "cloudflare/security-audit@c1c8a8c",
            "status": "done",
            "startedAt": "2026-10-16T08:00:00Z",
            "finishedAt": "2026-10-16T09:10:00Z",
        });
        Sweep::from_json(record.to_string().as_bytes()).unwrap()
    }

    /// The path `sweeper`'s record `id` and its package were fetched from.
    fn path_of(sweeper: &str, id: &str) -> SweepRef {
        format!("pubky://{sweeper}/pub/sweepky/sweeps/{id}.json")
            .parse()
            .unwrap()
    }

    /// A package of test_support's manifest with `targets` and `targetShas`
    /// replaced.
    fn package_with_targets(targets: Value, shas: Value) -> SweepPackage {
        let mut manifest = manifest_json();
        manifest["targets"] = targets;
        manifest["targetShas"] = shas;
        let mut package = package();
        package.manifest = serde_json::from_value(manifest).unwrap();
        package
    }

    #[test]
    fn open_package_rejects_a_copied_package() {
        // The sweeper seals a package to the bounty's owner and to their own
        // key, as `submit` does.
        let owner = DeviceIdentity::generate();
        let own_key = DeviceIdentity::generate();
        let package = package();
        let sealed = seal_package(&package, &[owner.recipient(), own_key.recipient()]).unwrap();
        // Under the sweeper's own path and record, it opens.
        let sweeper_path = path_of(SWEEPER, SWEEP_ID);
        assert_eq!(
            open_package(&sealed, &owner, &sweeper_path, &record()),
            Ok(package)
        );

        // The copier uploads the same bytes as a sweep of their own, beside
        // a record of the same bounty and targets. It still decrypts for the
        // owner, but the manifest inside names the sweeper, so no package
        // comes back.
        let copied = open_package(&sealed, &owner, &path_of(COPIER, COPY_ID), &record());
        assert_eq!(
            copied,
            Err(OpenError::Binding(BindingError::SweeperMismatch))
        );
    }

    #[test]
    fn open_package_returns_a_package_only_after_every_step() {
        let owner = DeviceIdentity::generate();
        let sweeper_path = path_of(SWEEPER, SWEEP_ID);
        let sealed = seal_package(&package(), &[owner.recipient()]).unwrap();

        // Decryption: a key the package was not sealed to, and bytes that
        // are no age file at all.
        let stranger = DeviceIdentity::generate();
        assert_eq!(
            open_package(&sealed, &stranger, &sweeper_path, &record()),
            Err(OpenError::Decrypt(DecryptError::NoMatchingKey))
        );
        assert_eq!(
            open_package(MARKER.as_bytes(), &owner, &sweeper_path, &record()),
            Err(OpenError::Decrypt(DecryptError::InvalidHeader))
        );

        // The parse: an age file for the owner whose plaintext is not a
        // package.
        let not_a_package = format!(r#"{{"schemaVersion":1,"note":"{MARKER}"}}"#);
        let padded = PaddedPlaintext::pad(not_a_package.as_bytes()).unwrap();
        let sealed_junk = encrypt(&padded, &[owner.recipient()]).unwrap();
        assert!(
            matches!(
                open_package(&sealed_junk, &owner, &sweeper_path, &record()),
                Err(OpenError::Record(RecordError::Json { .. }))
            ),
            "not a package"
        );

        // The binding: the right path, but a record of another bounty.
        let mut other_bounty = record();
        other_bounty.bounty = bounty_url(OWNER, OTHER_BOUNTY_ID).parse().unwrap();
        assert_eq!(
            open_package(&sealed, &owner, &sweeper_path, &other_bounty),
            Err(OpenError::Binding(BindingError::BountyMismatch))
        );

        // All three pass: the package, as it was sealed.
        assert_eq!(
            open_package(&sealed, &owner, &sweeper_path, &record()),
            Ok(package())
        );
    }

    #[test]
    fn seal_package_pads_before_encrypting() {
        // The plaintext inside is a whole number of buckets, and parses back
        // to the package.
        let owner = DeviceIdentity::generate();
        let sealed = seal_package(&package(), &[owner.recipient()]).unwrap();
        let plaintext = decrypt(&sealed, &owner).unwrap();
        assert_eq!(plaintext.len(), PADDING_BUCKET_BYTES);
        assert_eq!(
            SweepPackage::from_json(plaintext.expose_secret()).unwrap(),
            package()
        );
    }

    #[test]
    fn seal_package_refuses_a_manifest_no_record_could_bind() {
        // A repeated target, or `targetShas` keys other than its targets.
        let owner = DeviceIdentity::generate();
        for package in [
            package_with_targets(json!(["t1", "t1"]), json!({ "t1": REV })),
            package_with_targets(json!(["t1"]), json!({ "t1": REV, "t2": REV })),
            package_with_targets(json!(["t1", "t2"]), json!({ "t1": REV })),
        ] {
            assert_eq!(
                seal_package(&package, &[owner.recipient()]),
                Err(SealError::TargetsMismatch)
            );
        }
    }

    #[test]
    fn seal_package_passes_on_padding_and_encryption_refusals() {
        assert_eq!(
            seal_package(&package(), &[]),
            Err(SealError::Encrypt(EncryptError::NoRecipients))
        );

        let owner = DeviceIdentity::generate();
        let mut too_large = package();
        too_large
            .attachments
            .insert(path("huge.txt"), "x".repeat(MAX_PACKAGE_BYTES))
            .unwrap();
        assert_eq!(
            seal_package(&too_large, &[owner.recipient()]),
            Err(SealError::Package(PackageError::TooLarge))
        );
    }

    #[test]
    fn open_and_seal_errors_carry_no_content() {
        // Every error these two functions give, from inputs that carry the
        // marker, the keys and the ids: none of it may print.
        let owner = DeviceIdentity::generate();
        let sealed = seal_package(&package(), &[owner.recipient()]).unwrap();
        let sweeper_path = path_of(SWEEPER, SWEEP_ID);
        let padded = PaddedPlaintext::pad(format!("{{\"{MARKER}\":1}}").as_bytes()).unwrap();
        let junk = encrypt(&padded, &[owner.recipient()]).unwrap();
        let open_errors = [
            open_package(MARKER.as_bytes(), &owner, &sweeper_path, &record()),
            open_package(
                &sealed,
                &DeviceIdentity::generate(),
                &sweeper_path,
                &record(),
            ),
            open_package(&junk, &owner, &sweeper_path, &record()),
            open_package(&sealed, &owner, &path_of(COPIER, COPY_ID), &record()),
        ]
        .map(|result| result.unwrap_err());
        let seal_errors = [
            seal_package(&package(), &[]).unwrap_err(),
            seal_package(
                &package_with_targets(json!(["t1", "t1"]), json!({ "t1": REV })),
                &[owner.recipient()],
            )
            .unwrap_err(),
        ];
        // Each error's message, its `Debug`, and its source's message.
        fn printed<E: std::error::Error>(error: &E) -> Vec<String> {
            let mut texts = vec![error.to_string(), format!("{error:?}")];
            texts.extend(error.source().map(|source| source.to_string()));
            texts
        }
        let texts: Vec<String> = open_errors
            .iter()
            .flat_map(printed)
            .chain(seal_errors.iter().flat_map(printed))
            .collect();
        let content = [
            MARKER,
            SWEEPER,
            COPIER,
            OWNER,
            BOUNTY_ID,
            SWEEP_ID,
            COPY_ID,
            REV,
            "REPORT.md",
            "\"t1\"",
        ];
        for text in &texts {
            for value in content {
                assert!(!text.contains(value), "{value} in {text}");
            }
        }
    }
}
