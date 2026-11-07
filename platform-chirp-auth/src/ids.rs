//! The two human-identity namespaces chirp hands to platform services, as two
//! types (shared-rust#5).
//!
//! - [`PairwiseSub`] (`sub_…`): the per-app pseudonym in a token's `sub`. One
//!   person has a different one at every relying app.
//! - [`RootId`] (`usr_…`): the account the pairwise subs hang off. Only trusted
//!   platform services learn it, through chirp's `POST /control/root-for-sub`.
//!
//! Services used to carry both as bare `String`s and tell them apart with
//! `starts_with("sub_")`, and comparing one namespace against the other kept
//! shipping (drive#29, drive#34, drive#40, drive#51). As distinct types the
//! mix-up is a compile error. Both serialize as the bare string, so a stored id
//! reads back unchanged.

use std::fmt;

/// Longest id either type accepts, in bytes. chirp mints far shorter ids; the
/// cap only bounds what an untrusted input can make a service store or send.
pub const MAX_ID_LEN: usize = 128;

/// Why a string is not a [`PairwiseSub`] or a [`RootId`]. Names the expected
/// namespace but never echoes the input, which may be any caller's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidId {
    expected: &'static str,
}

impl fmt::Display for InvalidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "not a chirp {}… id (prefix, then 1-{} printable, non-space ASCII bytes in all)",
            self.expected, MAX_ID_LEN
        )
    }
}

impl std::error::Error for InvalidId {}

/// The one validation rule both types share: the namespace prefix, a non-empty
/// remainder, at most [`MAX_ID_LEN`] bytes, printable ASCII with no spaces.
/// No trimming: a padded id is a different string, and a service that keys
/// storage by it must not quietly accept two spellings of one id.
fn validate(raw: &str, prefix: &'static str) -> Result<(), InvalidId> {
    let ok = raw.len() <= MAX_ID_LEN
        && raw
            .strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty())
        && raw.bytes().all(|b| b.is_ascii_graphic());
    if ok {
        Ok(())
    } else {
        Err(InvalidId { expected: prefix })
    }
}

macro_rules! chirp_id {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// The namespace prefix every value carries.
            pub const PREFIX: &'static str = $prefix;

            /// Parse an untrusted string. Fails unless it is in this namespace;
            /// see [`InvalidId`].
            pub fn parse(raw: &str) -> Result<Self, InvalidId> {
                validate(raw, $prefix)?;
                Ok(Self(raw.to_owned()))
            }

            /// The id as chirp writes it.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The id as an owned `String`, for a store or wire format that
            /// still takes one.
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = InvalidId;
            fn from_str(raw: &str) -> Result<Self, InvalidId> {
                Self::parse(raw)
            }
        }

        impl TryFrom<String> for $name {
            type Error = InvalidId;
            fn try_from(raw: String) -> Result<Self, InvalidId> {
                validate(&raw, $prefix)?;
                Ok(Self(raw))
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        /// Deserializing validates: a wire or stored value in the other
        /// namespace is an error, not a value of this type.
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                Self::try_from(raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

chirp_id!(
    /// A per-app pairwise chirp subject (`sub_…`): what a chirp token's `sub`
    /// names for a human. The same person has a different one at every app, so
    /// two of them never identify one account without a root resolve.
    PairwiseSub,
    "sub_"
);

chirp_id!(
    /// A chirp root account id (`usr_…`): the one account a person's pairwise
    /// subs belong to. Learning it defeats pairwise unlinkability, so only a
    /// trusted platform service holds one, from
    /// [`RootResolver`](crate::RootResolver).
    RootId,
    "usr_"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_namespace_and_refuses_the_other() {
        let sub = PairwiseSub::parse("sub_abc123").unwrap();
        assert_eq!(sub.as_str(), "sub_abc123");
        let root = RootId::parse("usr_0f0f").unwrap();
        assert_eq!(root.to_string(), "usr_0f0f");

        assert!(PairwiseSub::parse("usr_0f0f").is_err());
        assert!(RootId::parse("sub_abc123").is_err());
    }

    #[test]
    fn refuses_malformed_ids() {
        for bad in [
            "",
            "sub_",
            "sub",
            "SUB_abc",
            " sub_abc",
            "sub_abc ",
            "sub_a b",
            "sub_a\nb",
            "sub_\u{e9}",
            "agent_abc",
            "test:abc",
        ] {
            assert!(PairwiseSub::parse(bad).is_err(), "{bad:?} parsed");
        }
        let at_cap = format!("sub_{}", "a".repeat(MAX_ID_LEN - 4));
        assert!(PairwiseSub::parse(&at_cap).is_ok());
        let over_cap = format!("sub_{}", "a".repeat(MAX_ID_LEN - 3));
        assert!(PairwiseSub::parse(&over_cap).is_err());
    }

    #[test]
    fn error_names_the_namespace_but_not_the_input() {
        let err = RootId::parse("sub_secretish").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("usr_"), "{msg}");
        assert!(!msg.contains("secretish"), "{msg}");
    }

    #[test]
    fn serde_is_the_bare_string_and_validates() {
        let root = RootId::parse("usr_abc").unwrap();
        assert_eq!(serde_json::to_string(&root).unwrap(), "\"usr_abc\"");
        let back: RootId = serde_json::from_str("\"usr_abc\"").unwrap();
        assert_eq!(back, root);
        assert!(serde_json::from_str::<RootId>("\"sub_abc\"").is_err());
        assert!(serde_json::from_str::<PairwiseSub>("\"usr_abc\"").is_err());
    }

    #[test]
    fn conversions_round_trip() {
        let sub: PairwiseSub = "sub_x".parse().unwrap();
        let owned: String = sub.clone().into();
        assert_eq!(PairwiseSub::try_from(owned).unwrap(), sub);
        assert_eq!(sub.into_string(), "sub_x");
        assert!(PairwiseSub::try_from("usr_x".to_owned()).is_err());
    }
}
