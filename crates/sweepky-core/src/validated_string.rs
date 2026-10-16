//! The `validated_string!` macro behind every `String` newtype that checks
//! its value: [`RecordTime`](crate::RecordTime) and the names in `names.rs`.

/// Adds what every checked `String` newtype shares: `as_str()`, `FromStr`,
/// `TryFrom<String>`, `From<T> for String` and `Display`. Crate-internal:
/// other modules bring it in with
/// `use crate::validated_string::validated_string;`.
///
/// The type is a tuple struct with one private `String` field, and writes
/// only its own `fn check(value: &str) -> Result<(), RecordError>`. The macro
/// wires that check into both constructors, so no way of making a value skips
/// it. The derives stay on the type, because not every type wants the same
/// ones (`RecordTime` has no ordering).
///
/// A macro rather than a trait with default methods: Rust's coherence rules
/// refuse `impl<T: Check> FromStr for T` (a trait from `std` for every type
/// that has some local trait), so each type needs its own `impl` blocks, and
/// the macro writes them out.
// Paths outside the prelude are written in full (`::core::fmt`,
// `$crate::RecordError`) because a `macro_rules!` body resolves names where
// it is called, not where it is defined: a bare `FromStr` would need every
// calling module to import it. `$crate` is this crate, whoever calls.
macro_rules! validated_string {
    ($name:ident) => {
        impl $name {
            /// The value exactly as written.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        /// Checks a `&str` and copies it, so `"…".parse()` works.
        impl ::core::str::FromStr for $name {
            type Err = $crate::RecordError;

            fn from_str(value: &str) -> Result<Self, $crate::RecordError> {
                Self::check(value)?;
                Ok(Self(value.to_owned()))
            }
        }

        /// Checks a `String` and takes ownership of it without copying.
        /// Deserializing goes through this.
        impl TryFrom<String> for $name {
            type Error = $crate::RecordError;

            fn try_from(value: String) -> Result<Self, $crate::RecordError> {
                Self::check(&value)?;
                Ok(Self(value))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

// A `macro_rules!` macro is visible only further down this file unless it is
// re-exported. This `use` gives it a path that other modules import like any
// other item; `pub(crate)` keeps it out of the public API.
pub(crate) use validated_string;
