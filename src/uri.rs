//! Minimal parser for MongoDB connection strings.
//!
//! Covers just enough of the [connection-string spec] to route a URI to
//! the right [`Proxy`](crate::Proxy) constructor: which scheme, which
//! upstream host(s) (and optional port), and whether to enable TLS. The
//! proxy is wire-level, so user/password and database-name segments are
//! stripped without being inspected, and every other option is ignored.
//!
//! Use [`Proxy::from_uri`](crate::Proxy::from_uri) rather than calling
//! [`parse`] directly — this module is internal-but-`pub` only because
//! the error type leaks through that constructor's `Result`.
//!
//! [connection-string spec]: https://www.mongodb.com/docs/manual/reference/connection-string/

/// Parsed shape of a MongoDB connection string.
///
/// All hosts in the URI's host list are kept, in order. A plain
/// `mongodb://host1,host2,host3/` seed list yields every host so
/// [`Proxy::from_uri`](crate::Proxy::from_uri) can probe them for the
/// replica-set primary rather than blindly forwarding to the first one;
/// a `mongodb+srv://` URI always carries exactly one host (the parser
/// rejects anything else with [`ConnectionUriError::InvalidSrvHost`]).
///
/// Internal — consumers reach this via [`Proxy::from_uri`](crate::Proxy::from_uri).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedConnectionUri {
    pub scheme: Scheme,
    /// Every host in the URI's host list, in URI order. Guaranteed
    /// non-empty (an empty host list is rejected with
    /// [`ConnectionUriError::MissingHost`]); exactly one entry for
    /// `mongodb+srv://`.
    pub hosts: Vec<HostSpec>,
    /// `?tls=true|false` / `?ssl=true|false` if present in the query
    /// string. `None` when neither was set — callers apply the
    /// scheme-specific default themselves.
    pub tls: Option<bool>,
    /// `?srvServiceName=...` override for the SRV query prefix, if present.
    /// Only valid with the `mongodb+srv://` scheme — pairing it with a
    /// plain `mongodb://` URI is rejected with
    /// [`ConnectionUriError::SrvServiceNameOnNonSrv`]. `None` when absent,
    /// in which case callers fall back to
    /// [`DEFAULT_SRV_SERVICE_NAME`](crate::srv::DEFAULT_SRV_SERVICE_NAME).
    pub srv_service_name: Option<String>,
}

/// One `host[:port]` entry from a connection string's host list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostSpec {
    /// The hostname (no port, no trailing `/`).
    pub host: String,
    /// Explicit port, if this entry carried one. Always `None` for
    /// `mongodb+srv://` URIs (the SRV record supplies the port).
    pub port: Option<u16>,
}

/// Connection-string scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scheme {
    /// `mongodb://` — direct host(s) and port(s).
    Mongodb,
    /// `mongodb+srv://` — single hostname resolved via DNS SRV.
    MongodbSrv,
}

/// Failure modes for [`Proxy::from_uri`](crate::Proxy::from_uri).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionUriError {
    /// URI does not contain `://`.
    #[error("connection string is missing the `://` scheme separator")]
    MissingScheme,
    /// Scheme is not `mongodb` or `mongodb+srv`.
    #[error("unsupported connection-string scheme `{0}`; expected `mongodb` or `mongodb+srv`")]
    UnsupportedScheme(String),
    /// Host list after the scheme is empty (`mongodb://` / `mongodb://:27017`).
    #[error("connection string has no host")]
    MissingHost,
    /// `:port` segment did not parse as a `u16`.
    #[error("invalid port `{0}`")]
    InvalidPort(String),
    /// `?tls=` / `?ssl=` value was neither `true` nor `false`.
    #[error("invalid `{key}` value `{value}`; expected `true` or `false`")]
    InvalidTlsValue {
        /// `tls` or `ssl` — the option whose value failed to parse.
        key: &'static str,
        /// The offending value as it appeared in the URI.
        value: String,
    },
    /// Both `tls=` and `ssl=` were set, and they disagreed.
    #[error("conflicting `tls={tls}` and `ssl={ssl}` in connection string")]
    ConflictingTlsSsl {
        /// The `tls=` value.
        tls: bool,
        /// The `ssl=` value.
        ssl: bool,
    },
    /// `mongodb+srv://` URIs may only list a single host with no port —
    /// the SRV record provides both.
    #[error("`mongodb+srv://` must have exactly one host without a port")]
    InvalidSrvHost,
    /// `srvServiceName=` was set on a plain `mongodb://` URI. The option
    /// only configures the SRV query prefix, so it is meaningless — and an
    /// error per the mongo-rust-driver — without the `mongodb+srv://`
    /// scheme.
    #[error("`srvServiceName` is only valid with the `mongodb+srv://` scheme")]
    SrvServiceNameOnNonSrv {
        /// The `srvServiceName` value as it appeared in the URI.
        value: String,
    },
    /// Host segment shape is unparseable (e.g. unmatched `[` for IPv6).
    #[error("invalid host `{0}` (IPv6 literals in `[...]` are not supported)")]
    InvalidHost(String),
}

/// Parses a MongoDB connection string into the minimal shape the proxy
/// needs.
///
/// Only the scheme, the host list (each with an optional port), and the
/// `tls`/`ssl` query option are extracted. Everything else
/// (user:password, database name, every other query option) is dropped
/// without being inspected. See [`ParsedConnectionUri`].
///
/// # Errors
///
/// See [`ConnectionUriError`].
pub(crate) fn parse(uri: &str) -> Result<ParsedConnectionUri, ConnectionUriError> {
    let (scheme_str, after_scheme) = uri
        .split_once("://")
        .ok_or(ConnectionUriError::MissingScheme)?;
    let scheme = match scheme_str {
        "mongodb" => Scheme::Mongodb,
        "mongodb+srv" => Scheme::MongodbSrv,
        other => return Err(ConnectionUriError::UnsupportedScheme(other.to_owned())),
    };

    // Split off the query string first so user-info `@`s don't get
    // confused with anything past `?`.
    let (before_query, query) = match after_scheme.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (after_scheme, None),
    };

    // Strip `[user:pass@]`. Rightmost `@` wins so passwords containing
    // `@` parse the same way the spec mandates.
    let hosts_and_db = match before_query.rsplit_once('@') {
        Some((_, rest)) => rest,
        None => before_query,
    };

    // `/database` is everything after the *first* `/` in the
    // hosts-and-db segment — we ignore the database name entirely.
    let hosts_str = match hosts_and_db.split_once('/') {
        Some((h, _)) => h,
        None => hosts_and_db,
    };

    if hosts_str.is_empty() {
        return Err(ConnectionUriError::MissingHost);
    }

    let host_specs: Vec<&str> = hosts_str.split(',').collect();
    if scheme == Scheme::MongodbSrv && host_specs.len() != 1 {
        return Err(ConnectionUriError::InvalidSrvHost);
    }

    let mut hosts = Vec::with_capacity(host_specs.len());
    for spec in host_specs {
        let (host, port) = parse_host_port(spec)?;
        // SRV records supply the port themselves, so an explicit one on a
        // `mongodb+srv://` host is a contradiction (the host list is
        // length 1 here, so this checks the only entry).
        if scheme == Scheme::MongodbSrv && port.is_some() {
            return Err(ConnectionUriError::InvalidSrvHost);
        }
        hosts.push(HostSpec { host, port });
    }

    let tls = parse_tls_option(query)?;

    // `srvServiceName` only configures the SRV query prefix, so it is an
    // error on a non-SRV URI (matches the mongo-rust-driver rule).
    let srv_service_name = match (scheme, parse_srv_service_name(query)?) {
        (Scheme::Mongodb, Some(value)) => {
            return Err(ConnectionUriError::SrvServiceNameOnNonSrv { value });
        }
        (_, srv_service_name) => srv_service_name,
    };

    Ok(ParsedConnectionUri {
        scheme,
        hosts,
        tls,
        srv_service_name,
    })
}

/// Extracts the `srvServiceName` query option (case-insensitive key, like
/// `tls`/`ssl`). Returns the *last* occurrence's value, or `None` when the
/// option is absent. An empty value is treated as absent so callers fall
/// back to the default service name rather than building an `_._tcp.`
/// query.
fn parse_srv_service_name(query: Option<&str>) -> Result<Option<String>, ConnectionUriError> {
    let Some(query) = query else {
        return Ok(None);
    };
    let mut value: Option<String> = None;
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k.eq_ignore_ascii_case("srvServiceName") && !v.is_empty() {
            value = Some(v.to_owned());
        }
    }
    Ok(value)
}

fn parse_host_port(s: &str) -> Result<(String, Option<u16>), ConnectionUriError> {
    if s.is_empty() {
        return Err(ConnectionUriError::MissingHost);
    }
    // IPv6 literals (`[::1]:27017`) need bracket-aware splitting, and we
    // don't support them — the upstream TLS path needs a DNS name and
    // the connect path assumes `host:port` formats. Reject explicitly
    // rather than misparse.
    if s.starts_with('[') {
        return Err(ConnectionUriError::InvalidHost(s.to_owned()));
    }
    match s.rsplit_once(':') {
        None => Ok((s.to_owned(), None)),
        Some(("", _)) => Err(ConnectionUriError::MissingHost),
        Some((host, port_str)) => {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| ConnectionUriError::InvalidPort(port_str.to_owned()))?;
            Ok((host.to_owned(), Some(port)))
        }
    }
}

fn parse_tls_option(query: Option<&str>) -> Result<Option<bool>, ConnectionUriError> {
    let Some(query) = query else {
        return Ok(None);
    };
    let mut tls: Option<bool> = None;
    let mut ssl: Option<bool> = None;
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        // Option names are case-insensitive per spec.
        match k.to_ascii_lowercase().as_str() {
            "tls" => tls = Some(parse_bool("tls", v)?),
            "ssl" => ssl = Some(parse_bool("ssl", v)?),
            _ => {}
        }
    }
    match (tls, ssl) {
        (Some(t), Some(s)) if t != s => {
            Err(ConnectionUriError::ConflictingTlsSsl { tls: t, ssl: s })
        }
        (Some(t), _) | (None, Some(t)) => Ok(Some(t)),
        (None, None) => Ok(None),
    }
}

fn parse_bool(key: &'static str, value: &str) -> Result<bool, ConnectionUriError> {
    match value.to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ConnectionUriError::InvalidTlsValue {
            key,
            value: value.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(
        scheme: Scheme,
        host: &str,
        port: Option<u16>,
        tls: Option<bool>,
    ) -> ParsedConnectionUri {
        ParsedConnectionUri {
            scheme,
            hosts: vec![HostSpec {
                host: host.to_owned(),
                port,
            }],
            tls,
            srv_service_name: None,
        }
    }

    fn host_spec(host: &str, port: Option<u16>) -> HostSpec {
        HostSpec {
            host: host.to_owned(),
            port,
        }
    }

    // ---------- scheme + host basics ----------

    #[test]
    fn plain_mongodb_uri_with_port() {
        assert_eq!(
            parse("mongodb://host:27017/").unwrap(),
            parsed(Scheme::Mongodb, "host", Some(27017), None)
        );
    }

    #[test]
    fn plain_mongodb_uri_without_port_leaves_port_none() {
        assert_eq!(
            parse("mongodb://host/").unwrap(),
            parsed(Scheme::Mongodb, "host", None, None)
        );
    }

    #[test]
    fn plain_mongodb_uri_without_trailing_slash() {
        assert_eq!(
            parse("mongodb://host:27017").unwrap(),
            parsed(Scheme::Mongodb, "host", Some(27017), None)
        );
    }

    #[test]
    fn srv_uri_parses_to_srv_scheme() {
        assert_eq!(
            parse("mongodb+srv://cluster.foo.mongodb.net/").unwrap(),
            parsed(Scheme::MongodbSrv, "cluster.foo.mongodb.net", None, None)
        );
    }

    // ---------- scheme errors ----------

    #[test]
    fn no_scheme_separator_errors() {
        assert_eq!(parse("host:27017"), Err(ConnectionUriError::MissingScheme));
    }

    #[test]
    fn unknown_scheme_errors() {
        assert_eq!(
            parse("http://host"),
            Err(ConnectionUriError::UnsupportedScheme("http".to_owned()))
        );
    }

    #[test]
    fn empty_scheme_errors_with_scheme_name() {
        assert_eq!(
            parse("://host"),
            Err(ConnectionUriError::UnsupportedScheme(String::new()))
        );
    }

    // ---------- host errors ----------

    #[test]
    fn empty_host_list_errors() {
        assert_eq!(parse("mongodb://"), Err(ConnectionUriError::MissingHost));
        assert_eq!(parse("mongodb:///db"), Err(ConnectionUriError::MissingHost));
    }

    #[test]
    fn host_with_only_a_port_errors() {
        // `:27017` would otherwise parse as (host="", port=Some(27017)).
        assert_eq!(
            parse("mongodb://:27017/"),
            Err(ConnectionUriError::MissingHost)
        );
    }

    #[test]
    fn ipv6_literal_is_rejected_with_dedicated_error() {
        match parse("mongodb://[::1]:27017/") {
            Err(ConnectionUriError::InvalidHost(h)) => assert_eq!(h, "[::1]:27017"),
            other => panic!("expected InvalidHost, got {other:?}"),
        }
    }

    // ---------- port errors ----------

    #[test]
    fn non_numeric_port_errors() {
        assert_eq!(
            parse("mongodb://host:abc/"),
            Err(ConnectionUriError::InvalidPort("abc".to_owned()))
        );
    }

    #[test]
    fn port_above_u16_max_errors() {
        match parse("mongodb://host:70000/") {
            Err(ConnectionUriError::InvalidPort(p)) => assert_eq!(p, "70000"),
            other => panic!("expected InvalidPort, got {other:?}"),
        }
    }

    // ---------- user info / db are stripped without being parsed ----------

    #[test]
    fn user_password_stripped_via_rightmost_at_sign() {
        // Spec rule: rightmost `@` separates user-info from hosts, so
        // passwords that themselves contain `@` parse the same way the
        // mongo-rust-driver parses them.
        assert_eq!(
            parse("mongodb://user:p%40ss@host:27017/").unwrap(),
            parsed(Scheme::Mongodb, "host", Some(27017), None)
        );
        assert_eq!(
            parse("mongodb://user:p@ss@host:27017/").unwrap(),
            parsed(Scheme::Mongodb, "host", Some(27017), None)
        );
    }

    #[test]
    fn database_name_after_slash_is_ignored() {
        assert_eq!(
            parse("mongodb://host:27017/admin").unwrap(),
            parsed(Scheme::Mongodb, "host", Some(27017), None)
        );
    }

    // ---------- multi-host handling ----------

    #[test]
    fn multi_host_mongodb_keeps_every_host_in_order() {
        assert_eq!(
            parse("mongodb://host1:27017,host2:27018,host3:27019/").unwrap(),
            ParsedConnectionUri {
                scheme: Scheme::Mongodb,
                hosts: vec![
                    host_spec("host1", Some(27017)),
                    host_spec("host2", Some(27018)),
                    host_spec("host3", Some(27019)),
                ],
                tls: None,
                srv_service_name: None,
            }
        );
    }

    #[test]
    fn multi_host_mongodb_allows_per_host_default_port() {
        // A seed list may mix explicit and implicit ports; each entry
        // keeps its own `port` so the caller can default per host.
        assert_eq!(
            parse("mongodb://host1,host2:27018/").unwrap(),
            ParsedConnectionUri {
                scheme: Scheme::Mongodb,
                hosts: vec![host_spec("host1", None), host_spec("host2", Some(27018))],
                tls: None,
                srv_service_name: None,
            }
        );
    }

    #[test]
    fn multi_host_mongodb_rejects_a_bad_host_anywhere_in_the_list() {
        // The second host has an unparseable port — the whole URI fails
        // rather than silently dropping the offending entry.
        assert_eq!(
            parse("mongodb://host1:27017,host2:bogus/"),
            Err(ConnectionUriError::InvalidPort("bogus".to_owned()))
        );
    }

    #[test]
    fn srv_uri_with_multiple_hosts_errors() {
        assert_eq!(
            parse("mongodb+srv://host1,host2/"),
            Err(ConnectionUriError::InvalidSrvHost)
        );
    }

    #[test]
    fn srv_uri_with_explicit_port_errors() {
        assert_eq!(
            parse("mongodb+srv://host:27017/"),
            Err(ConnectionUriError::InvalidSrvHost)
        );
    }

    // ---------- tls / ssl query option ----------

    #[test]
    fn tls_true_is_picked_up() {
        assert_eq!(
            parse("mongodb://host/?tls=true").unwrap(),
            parsed(Scheme::Mongodb, "host", None, Some(true))
        );
    }

    #[test]
    fn tls_false_is_picked_up() {
        assert_eq!(
            parse("mongodb://host/?tls=false").unwrap(),
            parsed(Scheme::Mongodb, "host", None, Some(false))
        );
    }

    #[test]
    fn ssl_is_accepted_as_alias_for_tls() {
        assert_eq!(
            parse("mongodb://host/?ssl=true").unwrap(),
            parsed(Scheme::Mongodb, "host", None, Some(true))
        );
    }

    #[test]
    fn tls_option_key_is_case_insensitive() {
        assert_eq!(
            parse("mongodb://host/?TLS=TRUE").unwrap(),
            parsed(Scheme::Mongodb, "host", None, Some(true))
        );
    }

    #[test]
    fn query_string_without_leading_slash_still_parses() {
        // `mongodb://host?tls=true` (no `/` before `?`) is in the wild.
        assert_eq!(
            parse("mongodb://host?tls=true").unwrap(),
            parsed(Scheme::Mongodb, "host", None, Some(true))
        );
    }

    #[test]
    fn unrelated_query_options_are_ignored() {
        assert_eq!(
            parse("mongodb://host/?retryWrites=true&w=majority&tls=true").unwrap(),
            parsed(Scheme::Mongodb, "host", None, Some(true))
        );
    }

    #[test]
    fn tls_and_ssl_agreeing_is_fine() {
        assert_eq!(
            parse("mongodb://host/?tls=true&ssl=true").unwrap(),
            parsed(Scheme::Mongodb, "host", None, Some(true))
        );
    }

    #[test]
    fn tls_and_ssl_disagreeing_errors() {
        assert_eq!(
            parse("mongodb://host/?tls=true&ssl=false"),
            Err(ConnectionUriError::ConflictingTlsSsl {
                tls: true,
                ssl: false
            })
        );
    }

    #[test]
    fn invalid_tls_value_errors() {
        assert_eq!(
            parse("mongodb://host/?tls=maybe"),
            Err(ConnectionUriError::InvalidTlsValue {
                key: "tls",
                value: "maybe".to_owned()
            })
        );
    }

    #[test]
    fn invalid_ssl_value_errors_with_ssl_key() {
        assert_eq!(
            parse("mongodb://host/?ssl=yes"),
            Err(ConnectionUriError::InvalidTlsValue {
                key: "ssl",
                value: "yes".to_owned()
            })
        );
    }

    #[test]
    fn query_pair_without_equals_is_ignored() {
        // Bare flag-style options are tolerated even though MongoDB URIs
        // don't actually allow them; we just ignore the segment.
        assert_eq!(
            parse("mongodb://host/?retryWrites&tls=true").unwrap(),
            parsed(Scheme::Mongodb, "host", None, Some(true))
        );
    }

    // ---------- srv composition ----------

    #[test]
    fn srv_uri_with_tls_false_query_is_kept() {
        // Spec defaults SRV TLS to true, but explicit `?tls=false` must
        // still round-trip — the from_uri caller applies the default
        // when this field is None, not when it's Some(false).
        assert_eq!(
            parse("mongodb+srv://cluster.foo.mongodb.net/?tls=false").unwrap(),
            parsed(
                Scheme::MongodbSrv,
                "cluster.foo.mongodb.net",
                None,
                Some(false)
            )
        );
    }

    #[test]
    fn srv_uri_with_user_info_and_db_strips_both() {
        assert_eq!(
            parse("mongodb+srv://admin:secret@cluster.foo.mongodb.net/mydb?tls=true").unwrap(),
            parsed(
                Scheme::MongodbSrv,
                "cluster.foo.mongodb.net",
                None,
                Some(true)
            )
        );
    }

    // ---------- srvServiceName query option ----------

    #[test]
    fn srv_service_name_defaults_to_none_when_absent() {
        let parsed = parse("mongodb+srv://cluster.foo.mongodb.net/").unwrap();
        assert_eq!(parsed.srv_service_name, None);
    }

    #[test]
    fn srv_service_name_is_picked_up_for_srv_scheme() {
        let parsed =
            parse("mongodb+srv://cluster.foo.mongodb.net/?srvServiceName=mongodb").unwrap();
        assert_eq!(parsed.srv_service_name.as_deref(), Some("mongodb"));
    }

    #[test]
    fn srv_service_name_custom_value_is_kept() {
        let parsed =
            parse("mongodb+srv://cluster.foo.mongodb.net/?srvServiceName=customdb").unwrap();
        assert_eq!(parsed.srv_service_name.as_deref(), Some("customdb"));
    }

    #[test]
    fn srv_service_name_key_is_case_insensitive() {
        let parsed = parse("mongodb+srv://cluster.foo.mongodb.net/?SRVSERVICENAME=mongo").unwrap();
        assert_eq!(parsed.srv_service_name.as_deref(), Some("mongo"));
    }

    #[test]
    fn srv_service_name_empty_value_is_treated_as_absent() {
        // `?srvServiceName=` must not produce an `_._tcp.` query.
        let parsed = parse("mongodb+srv://cluster.foo.mongodb.net/?srvServiceName=").unwrap();
        assert_eq!(parsed.srv_service_name, None);
    }

    #[test]
    fn srv_service_name_on_plain_mongodb_uri_errors() {
        assert_eq!(
            parse("mongodb://host/?srvServiceName=mongodb"),
            Err(ConnectionUriError::SrvServiceNameOnNonSrv {
                value: "mongodb".to_owned()
            })
        );
    }

    #[test]
    fn srv_service_name_with_tls_round_trips_for_srv_scheme() {
        let parsed =
            parse("mongodb+srv://cluster.foo.mongodb.net/?tls=false&srvServiceName=customdb")
                .unwrap();
        assert_eq!(parsed.tls, Some(false));
        assert_eq!(parsed.srv_service_name.as_deref(), Some("customdb"));
    }
}
