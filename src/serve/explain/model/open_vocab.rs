//! Open-vocabulary enum infrastructure + concrete enums (`Command`,
//! `ErrorLabel`, `ServerErrorCodeName`).
//!
//! Open-vocabulary = a fixed set of named variants the library models
//! exhaustively, plus an `Other(OtherName)` fallback so the server can ship
//! new strings (new commands, new labels) without breaking consumers.

use super::newtypes::OtherName;

/// Defines an open-vocabulary enum + the boilerplate around it:
///   - the public `#[non_exhaustive]` enum,
///   - `from_wire_str(&str)` — single source of truth for the wire-string mapping,
///   - `from_wire_string(String)` — owned-input variant, avoids re-alloc on `Other`,
///   - `serde::Deserialize` via a `Visitor` with `visit_str` / `visit_string`.
macro_rules! open_vocab_enum {
    (
        $(#[$attr:meta])*
        pub enum $Name:ident {
            $($variant:ident => $($pat:literal)|+),+ $(,)?
        }
    ) => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $Name {
            $($variant,)+
            Other(OtherName),
        }

        impl $Name {
            /// Single source of truth: wire-string → enum.
            // Consumed by upcoming parse.rs / classify.rs modules; tests
            // already exercise it.
            #[allow(dead_code)]
            pub(crate) fn from_wire_str(s: &str) -> Self {
                match s {
                    $( $($pat)|+ => $Name::$variant, )+
                    _ => $Name::Other(OtherName::new(s.to_owned())),
                }
            }

            /// Owned-input flavour — avoids a re-allocation when the caller
            /// already owns the `String` and the value falls into the
            /// `Other` arm.
            #[allow(dead_code)]
            pub(crate) fn from_wire_string(s: String) -> Self {
                match s.as_str() {
                    $( $($pat)|+ => $Name::$variant, )+
                    _ => $Name::Other(OtherName::new(s)),
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $Name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = $Name;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f, "a string identifying a {}", stringify!($Name))
                    }
                    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<$Name, E> {
                        Ok($Name::from_wire_str(s))
                    }
                    fn visit_string<E: serde::de::Error>(self, s: String) -> Result<$Name, E> {
                        Ok($Name::from_wire_string(s))
                    }
                }
                d.deserialize_str(V)
            }
        }
    };
}

open_vocab_enum! {
    /// MongoDB command name carried as the first key of an OP_MSG body.
    /// Exhaustive over commands the explain inspector recognises; unknown
    /// values land in `Other`.
    pub enum Command {
        Find          => "find",
        Aggregate     => "aggregate",
        Count         => "count",
        Distinct      => "distinct",
        Update        => "update",
        Delete        => "delete",
        FindAndModify => "findAndModify" | "findandmodify",
    }
}

impl Command {
    /// Parse a wire command-name into a known [`Command`], returning `None`
    /// for command names not modelled exhaustively. Used by `classify` as
    /// the explainable-command filter so unknown commands skip explain.
    #[allow(dead_code)]
    pub(crate) fn from_command_name(s: &str) -> Option<Self> {
        match Self::from_wire_str(s) {
            Command::Other(_) => None,
            known => Some(known),
        }
    }
}

open_vocab_enum! {
    /// MongoDB `errorLabels` entry (e.g. `"RetryableWriteError"`).
    pub enum ErrorLabel {
        TransientTransactionError  => "TransientTransactionError",
        RetryableWriteError        => "RetryableWriteError",
        NoWritesPerformed          => "NoWritesPerformed",
        ResumableChangeStreamError => "ResumableChangeStreamError",
        NetworkError               => "NetworkError",
    }
}

open_vocab_enum! {
    /// Symbolic name for a MongoDB server error code (e.g. `"NamespaceNotFound"`).
    pub enum ServerErrorCodeName {
        NamespaceNotFound       => "NamespaceNotFound",
        Unauthorized            => "Unauthorized",
        Interrupted             => "Interrupted",
        InterruptedAtShutdown   => "InterruptedAtShutdown",
        NotMaster               => "NotMaster" | "NotWritablePrimary",
        WriteConflict           => "WriteConflict",
        DuplicateKey            => "DuplicateKey",
        QueryPlanKilled         => "QueryPlanKilled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_from_wire_str_maps_known_variants() {
        assert_eq!(Command::from_wire_str("find"), Command::Find);
        assert_eq!(Command::from_wire_str("aggregate"), Command::Aggregate);
        assert_eq!(
            Command::from_wire_str("findAndModify"),
            Command::FindAndModify
        );
        assert_eq!(
            Command::from_wire_str("findandmodify"),
            Command::FindAndModify
        );
    }

    #[test]
    fn command_from_wire_str_unknown_goes_to_other_lowercased() {
        match Command::from_wire_str("HELLO") {
            Command::Other(name) => assert_eq!(name.as_ref(), "hello"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn command_from_command_name_returns_none_for_unknown() {
        assert!(Command::from_command_name("hello").is_none());
        assert!(Command::from_command_name("ping").is_none());
    }

    #[test]
    fn command_from_command_name_returns_some_for_known() {
        assert_eq!(Command::from_command_name("find"), Some(Command::Find));
        assert_eq!(
            Command::from_command_name("findandmodify"),
            Some(Command::FindAndModify),
        );
    }

    #[test]
    fn error_label_maps_known() {
        assert_eq!(
            ErrorLabel::from_wire_str("RetryableWriteError"),
            ErrorLabel::RetryableWriteError,
        );
    }

    #[test]
    fn server_error_code_name_maps_aliases() {
        assert_eq!(
            ServerErrorCodeName::from_wire_str("NotMaster"),
            ServerErrorCodeName::NotMaster,
        );
        assert_eq!(
            ServerErrorCodeName::from_wire_str("NotWritablePrimary"),
            ServerErrorCodeName::NotMaster,
        );
    }

    #[test]
    fn from_wire_string_consumes_owned_input_for_other() {
        let owned = "UnknownThing".to_owned();
        match Command::from_wire_string(owned) {
            Command::Other(name) => assert_eq!(name.as_ref(), "unknownthing"),
            other => panic!("expected Other, got {other:?}"),
        }
    }
}
