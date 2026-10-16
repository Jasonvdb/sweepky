//! The `open_enum!` macro behind every open-string enum: `kind`, `status`,
//! `alg`, `method`, `proof.kind`.
//!
//! Why not a closed serde enum (`#[derive(Deserialize)] enum Kind { Pr,
//! Commit, Repo }`)? Deserializing one fails on any value it does not list.
//! The failure takes the whole record with it, and a whole listing if the
//! records are parsed together, so a newer client adding a target kind would
//! break every older client. 01's rule is the opposite: keep the record, skip
//! or show a placeholder for the value you do not know, and write it back
//! unchanged on a rewrite.
//!
//! So an open enum is two types:
//!
//! - a `String` newtype that holds the value exactly as the record had it, and
//!   is what records store and serialize;
//! - a plain `Known…` enum of the values this build understands, which code
//!   gets from `as_known()` and can `match` on exhaustively.

/// Defines an open-string enum. Crate-internal: other modules bring it in with
/// `use crate::open_enum::open_enum;`.
///
/// ```text
/// open_enum! {
///     /// What a target points at.
///     pub struct TargetKind;
///
///     /// The target kinds this build knows.
///     pub enum KnownTargetKind {
///         /// A pull request.
///         Pr = "pr",
///         /// A single commit.
///         Commit = "commit",
///     }
/// }
/// ```
///
/// generates
///
/// - `TargetKind`, a `String` newtype with `#[serde(transparent)]`, so it reads
///   and writes as a bare JSON string. Methods: `as_known() ->
///   Option<KnownTargetKind>` and `as_str()`; `Display` writes the string as
///   it is, and `From<KnownTargetKind>` builds one from a known value. The
///   string is whatever the record held, so code that prints it to a terminal
///   treats it as untrusted text.
/// - `KnownTargetKind`, a `Copy` enum of the listed values, with
///   `as_str() -> &'static str` giving each one's string.
///
/// The doc comments are required, because `missing_docs` checks the generated
/// public items. Matching in `as_known()` is exact and case-sensitive. Listing
/// one string twice makes the compiler warn about an unreachable pattern,
/// which CI's `-D warnings` turns into an error.
macro_rules! open_enum {
    (
        $(#[$open_meta:meta])*
        $open_vis:vis struct $open:ident;

        $(#[$known_meta:meta])*
        $known_vis:vis enum $known:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $value:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$open_meta])*
        #[derive(
            Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize, ::serde::Deserialize,
        )]
        // `transparent`: serialize as the inner `String` itself, not wrapped
        // in an array or object.
        #[serde(transparent)]
        $open_vis struct $open(::std::string::String);

        $(#[$known_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $known_vis enum $known {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl $known {
            /// The string this value is written as in a record.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value,)+
                }
            }
        }

        impl $open {
            /// The value this build knows, or `None` for one it does not,
            /// such as a value a newer client added.
            pub fn as_known(&self) -> ::core::option::Option<$known> {
                match self.0.as_str() {
                    $($value => ::core::option::Option::Some($known::$variant),)+
                    _ => ::core::option::Option::None,
                }
            }

            /// The string exactly as the record had it.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl ::core::convert::From<$known> for $open {
            fn from(known: $known) -> Self {
                Self(::std::string::String::from(known.as_str()))
            }
        }

        impl ::core::fmt::Display for $open {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

// A `macro_rules!` macro is visible only further down this file unless it is
// re-exported. This `use` gives it a path, `crate::open_enum::open_enum`, that
// the record modules import like any other item; `pub(crate)` keeps it out of
// the public API.
pub(crate) use open_enum;

#[cfg(test)]
mod tests {
    // Called by its path, through the `pub(crate) use` above, the way the
    // record modules call it, so the test checks that path works. (Inside
    // this file the bare name would work too.)
    crate::open_enum::open_enum! {
        /// A test-only open enum.
        pub struct Fruit;

        /// The fruits this build knows.
        pub enum KnownFruit {
            /// An apple.
            Apple = "apple",
            /// A pear.
            Pear = "pear",
        }
    }

    #[test]
    fn a_known_value_maps_through_as_known() {
        let pear: Fruit = serde_json::from_str(r#""pear""#).unwrap();
        assert_eq!(pear.as_known(), Some(KnownFruit::Pear));
        assert_eq!(pear.as_str(), "pear");

        let apple = Fruit::from(KnownFruit::Apple);
        assert_eq!(apple.as_known(), Some(KnownFruit::Apple));
        assert_eq!(apple.to_string(), "apple");
        assert_eq!(serde_json::to_string(&apple).unwrap(), r#""apple""#);
    }

    #[test]
    fn an_unknown_value_is_kept_verbatim() {
        let future: Fruit = serde_json::from_str(r#""future-kind""#).unwrap();
        assert_eq!(future.as_known(), None);
        assert_eq!(future.as_str(), "future-kind");
        assert_eq!(serde_json::to_string(&future).unwrap(), r#""future-kind""#);
        // Matching is exact: another spelling is a different, unknown value.
        let shouted: Fruit = serde_json::from_str(r#""PEAR""#).unwrap();
        assert_eq!(shouted.as_known(), None);
        // Open means any string, not any JSON value.
        assert!(serde_json::from_str::<Fruit>("1").is_err());
    }
}
