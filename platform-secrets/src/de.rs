//! Deserialize a flat JSON object of strings into the service's own type
//! without any secret value reaching an error.
//!
//! `serde_json::from_str::<S>` quotes values in its messages
//! (``invalid type: integer `12345` ``), so it is never run on the secret.
//! Instead the JSON is first split into [`Entries`] (syntax errors are kept by
//! position only), and `S` is deserialized from those through a deserializer
//! whose error type, [`Fault`], has nowhere to put a value: every `serde::de::Error`
//! constructor that is handed one (an `Unexpected`, a variant name, a custom
//! message) drops it. Only key names and what the field expected survive.
//!
//! The same deserializer sees which keys `S` declares: serde's derive skips a
//! field it does not know with `deserialize_ignored_any`, which is where such a
//! key is set aside. And [`Secret`](crate::Secret)'s `Deserialize` asks for a
//! newtype struct with a private name, which is how keys holding secrets are
//! told apart from plain config.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

use serde::de::{
    self, value::StrDeserializer, DeserializeOwned, DeserializeSeed, IntoDeserializer, MapAccess,
    Visitor,
};

use crate::SecretsError;

/// The newtype-struct name [`Secret`](crate::Secret) deserializes as. Private
/// to this crate, so no other type can be mistaken for a secret.
pub(crate) const SECRET_MARKER: &str = "platform_secrets::Secret";

/// The secret's keys, each a trimmed non-blank string or a non-string.
/// A blank string is absent: it never becomes an entry.
pub(crate) type Entries = BTreeMap<String, Entry>;

pub(crate) enum Entry {
    Str(String),
    /// A number, bool, null, array or object: allowed only under a key `S`
    /// does not declare.
    NotString,
}

/// Split `json` into entries. `origin` names the secret in errors.
pub(crate) fn entries(origin: &str, json: &str) -> Result<Entries, SecretsError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| SecretsError::NotJson {
            origin: origin.to_owned(),
            line: e.line(),
            column: e.column(),
        })?;
    let serde_json::Value::Object(object) = value else {
        return Err(SecretsError::NotObject {
            origin: origin.to_owned(),
        });
    };
    Ok(object
        .into_iter()
        .filter_map(|(key, value)| match value {
            serde_json::Value::String(s) => {
                let s = s.trim();
                (!s.is_empty()).then(|| (key, Entry::Str(s.to_owned())))
            }
            _ => Some((key, Entry::NotString)),
        })
        .collect())
}

/// Key names only, for the cold-start log line and the plaintext-copy check.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Report {
    /// Keys `S` read.
    pub(crate) present: Vec<String>,
    /// Keys `S` does not declare, set aside.
    pub(crate) ignored: Vec<String>,
    /// Of `present`, the keys read into a [`Secret`](crate::Secret).
    pub(crate) secrets: Vec<String>,
}

pub(crate) fn deserialize<S: DeserializeOwned>(
    origin: &str,
    entries: &Entries,
) -> Result<(S, Report), SecretsError> {
    let report = RefCell::new(Report::default());
    let value = S::deserialize(Top {
        entries,
        report: &report,
    })
    .map_err(|fault| fault.into_error(origin))?;
    Ok((value, report.into_inner()))
}

/// The only error the deserializer can raise. It holds key names and the
/// field's expectation (a type name or a variant list), never a value.
#[derive(Debug)]
pub(crate) struct Fault {
    key: Option<String>,
    kind: FaultKind,
}

#[derive(Debug)]
enum FaultKind {
    Missing(String),
    NotString,
    /// What the field expected, e.g. "u16" or "one of [a, b]". `None` for a
    /// custom message, which is dropped because it may quote the value.
    Invalid(Option<String>),
}

impl Fault {
    fn new(kind: FaultKind) -> Self {
        Self { key: None, kind }
    }

    fn at(mut self, key: &str) -> Self {
        self.key.get_or_insert_with(|| key.to_owned());
        self
    }

    fn into_error(self, origin: &str) -> SecretsError {
        let origin = origin.to_owned();
        match self.kind {
            FaultKind::Missing(key) => SecretsError::Missing { origin, key },
            FaultKind::NotString => SecretsError::NotString {
                origin,
                key: self.key.unwrap_or_default(),
            },
            FaultKind::Invalid(expected) => SecretsError::Invalid {
                origin,
                key: self.key,
                expected,
            },
        }
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)
    }
}

impl std::error::Error for Fault {}

impl de::Error for Fault {
    fn custom<T: fmt::Display>(_message: T) -> Self {
        Self::new(FaultKind::Invalid(None))
    }
    fn invalid_type(_unexpected: de::Unexpected, expected: &dyn de::Expected) -> Self {
        Self::new(FaultKind::Invalid(Some(expected.to_string())))
    }
    fn invalid_value(_unexpected: de::Unexpected, expected: &dyn de::Expected) -> Self {
        Self::new(FaultKind::Invalid(Some(expected.to_string())))
    }
    fn invalid_length(_len: usize, expected: &dyn de::Expected) -> Self {
        Self::new(FaultKind::Invalid(Some(expected.to_string())))
    }
    fn unknown_variant(_variant: &str, expected: &'static [&'static str]) -> Self {
        Self::new(FaultKind::Invalid(Some(format!("one of {expected:?}"))))
    }
    fn unknown_field(_field: &str, expected: &'static [&'static str]) -> Self {
        Self::new(FaultKind::Invalid(Some(format!("one of {expected:?}"))))
    }
    fn missing_field(field: &'static str) -> Self {
        Self::new(FaultKind::Missing(field.to_owned()))
    }
    fn duplicate_field(_field: &'static str) -> Self {
        Self::new(FaultKind::Invalid(None))
    }
}

/// The whole secret, as a map.
struct Top<'a> {
    entries: &'a Entries,
    report: &'a RefCell<Report>,
}

impl<'de> de::Deserializer<'de> for Top<'_> {
    type Error = Fault;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Fault> {
        visitor.visit_map(Fields {
            iter: self.entries.iter(),
            current: None,
            report: self.report,
        })
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

struct Fields<'a> {
    iter: std::collections::btree_map::Iter<'a, String, Entry>,
    current: Option<(&'a str, &'a Entry)>,
    report: &'a RefCell<Report>,
}

impl<'de> MapAccess<'de> for Fields<'_> {
    type Error = Fault;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Fault> {
        let Some((key, entry)) = self.iter.next() else {
            return Ok(None);
        };
        self.current = Some((key, entry));
        let key: StrDeserializer<'_, Fault> = key.as_str().into_deserializer();
        seed.deserialize(key).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Fault> {
        let (key, entry) = self
            .current
            .take()
            .ok_or_else(|| Fault::new(FaultKind::Invalid(None)))?;
        let mut role = Role::Plain;
        let value = seed
            .deserialize(Field {
                entry,
                role: &mut role,
            })
            .map_err(|fault| fault.at(key))?;
        let mut report = self.report.borrow_mut();
        match role {
            Role::Ignored => report.ignored.push(key.to_owned()),
            Role::Plain => report.present.push(key.to_owned()),
            Role::Secret => {
                report.present.push(key.to_owned());
                report.secrets.push(key.to_owned());
            }
        }
        Ok(value)
    }
}

/// What the field's type made of a key.
enum Role {
    Plain,
    Secret,
    Ignored,
}

/// One key's value.
struct Field<'a> {
    entry: &'a Entry,
    role: &'a mut Role,
}

impl Field<'_> {
    fn text(&self) -> Result<&str, Fault> {
        match self.entry {
            Entry::Str(s) => Ok(s),
            Entry::NotString => Err(Fault::new(FaultKind::NotString)),
        }
    }
}

impl<'de> de::Deserializer<'de> for Field<'_> {
    type Error = Fault;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Fault> {
        visitor.visit_str(self.text()?)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Fault> {
        // A blank value never became an entry, so a present key is `Some`.
        self.text()?;
        visitor.visit_some(self)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Fault> {
        if name == SECRET_MARKER {
            *self.role = Role::Secret;
        }
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Fault> {
        let text: StrDeserializer<'_, Fault> = self.text()?.into_deserializer();
        visitor.visit_enum(text)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Fault> {
        *self.role = Role::Ignored;
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct map struct identifier
    }
}
