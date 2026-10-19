//! The fixture source: targets served from the bare repository under
//! `fixtures/`, so the tests reach no real host. `main.rs` never builds it.
//! So far this holds only its remote, [`LocalRemote`]; the source itself
//! comes later in P2b.

use std::path::Path;

use anyhow::bail;

/// A repository on this disk as git is given it, `file://<absolute path>`:
/// the fixture source's remote, and the only one besides
/// [`HttpsRemote`](super::host::HttpsRemote) that git's network commands
/// take (`git::Remote`).
///
/// Its constructor is private to this module, so only the fixture source
/// can make one (the tests of other modules have
/// `LocalRemote::for_tests`). git reaches it only through a runner that
/// allows the `file` transport (`AllowedProtocols::HttpsAndFile`), which
/// the fixture source alone asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalRemote {
    url: String,
}

impl LocalRemote {
    /// `file://<path>`. `path` must be absolute and UTF-8. git
    /// percent-decodes a URL, so a path with a `%` in it would name another
    /// directory; the fixture's has none.
    fn new(path: &Path) -> anyhow::Result<Self> {
        match path.to_str() {
            Some(text) if path.is_absolute() => Ok(Self {
                url: format!("file://{text}"),
            }),
            _ => bail!(
                "{} is not an absolute UTF-8 path, so it cannot be a file:// URL",
                path.display()
            ),
        }
    }

    /// [`LocalRemote::new`], for the tests of other modules that run git
    /// against the fixture, such as the git runner's. `cfg(test)`, so the
    /// binary has no way to call it.
    #[cfg(test)]
    pub(crate) fn for_tests(path: &Path) -> anyhow::Result<Self> {
        Self::new(path)
    }

    /// The URL as git is given it.
    pub(crate) fn as_str(&self) -> &str {
        &self.url
    }
}

#[cfg(test)]
mod tests {
    use super::LocalRemote;
    use crate::test_support::inert_target_repo;

    #[test]
    fn a_local_remote_is_the_file_url_of_an_absolute_path_only() {
        let fixture = inert_target_repo();
        let remote = LocalRemote::for_tests(&fixture).expect("an absolute UTF-8 path");
        assert_eq!(
            remote.as_str(),
            format!("file://{}", fixture.to_str().expect("UTF-8"))
        );
        assert!(LocalRemote::for_tests("relative/path".as_ref()).is_err());
        // Like an `HttpsRemote`, it comes from no string, default or JSON.
        crate::test_support::assert_not_impl_any!(
            LocalRemote: Default,
            std::str::FromStr,
            From<String>,
            From<&'static str>,
            serde::de::DeserializeOwned,
        );
    }
}
