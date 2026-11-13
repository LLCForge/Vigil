//! RIPE RIS Live message model and parser.
//!
//! Everything in here handles untrusted feed data: sizes are capped, every field is
//! validated and free-form strings are restricted to a safe character set so they can
//! be printed to a terminal or embedded in alerts without further surprises.

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::Value;
use std::fmt;
use std::net::IpAddr;

/// Largest RIS Live message accepted, in bytes. Real messages are a few KiB.
pub const MAX_MESSAGE_BYTES: usize = 1 << 20;
/// Largest number of prefixes (announced + withdrawn) accepted in one message.
pub const MAX_PREFIXES_PER_MESSAGE: usize = 10_000;
/// Longest AS path accepted.
pub const MAX_PATH_SEGMENTS: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("message is {0} bytes, limit is {MAX_MESSAGE_BYTES}")]
    Oversized(usize),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid field: {0}")]
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> ParseError {
    ParseError::Invalid(msg.into())
}

/// One element of an AS path: a plain ASN or an AS_SET.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum PathSegment {
    As(u32),
    Set(Vec<u32>),
}

/// Origin of a route: the last element of the AS path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Origin {
    As(u32),
    /// The path ends in an AS_SET; the real origin cannot be determined.
    Set(Vec<u32>),
}

impl Origin {
    pub fn asn(&self) -> Option<u32> {
        match self {
            Origin::As(a) => Some(*a),
            Origin::Set(_) => None,
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::As(a) => write!(f, "AS{a}"),
            Origin::Set(set) => {
                let parts: Vec<String> = set.iter().map(|a| format!("AS{a}")).collect();
                write!(f, "{{{}}}", parts.join(","))
            }
        }
    }
}

/// A validated BGP UPDATE as seen by one RIS peer.
#[derive(Debug, Clone)]
pub struct RisUpdate {
    pub collector: String,
    pub peer: IpAddr,
    pub peer_asn: u32,
    pub timestamp: DateTime<Utc>,
    pub path: Vec<PathSegment>,
    pub origin: Option<Origin>,
    pub announced: Vec<IpNet>,
    pub withdrawn: Vec<IpNet>,
}

impl RisUpdate {
    /// Neighbour of the origin in the AS path (prepending ignored); `None` when the
    /// path is just the origin or the neighbour is an AS_SET.
    pub fn upstream(&self) -> Option<u32> {
        let Some(PathSegment::As(origin)) = self.path.last() else {
            return None;
        };
        match self
            .path
            .iter()
            .rev()
            .find(|seg| **seg != PathSegment::As(*origin))?
        {
            PathSegment::As(a) => Some(*a),
            PathSegment::Set(_) => None,
        }
    }

    /// AS path rendered as `64496 64511 {64500,64509}`.
    pub fn path_string(&self) -> String {
        self.path
            .iter()
            .map(|seg| match seg {
                PathSegment::As(a) => a.to_string(),
                PathSegment::Set(s) => {
                    let parts: Vec<String> = s.iter().map(u32::to_string).collect();
                    format!("{{{}}}", parts.join(","))
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug)]
pub enum RisMessage {
    Update(RisUpdate),
    /// `ris_error` sent by the server; the text is sanitised.
    Error(String),
    /// Anything else (pong, subscription acks, non-UPDATE messages).
    Other,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    data: Option<Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AsnField {
    Num(u32),
    Str(String),
}

#[derive(Deserialize)]
struct RawAnnouncement {
    #[serde(default)]
    prefixes: Vec<String>,
}

#[derive(Deserialize)]
struct RawUpdate {
    timestamp: f64,
    peer: String,
    peer_asn: AsnField,
    host: String,
    #[serde(default)]
    path: Vec<PathSegment>,
    #[serde(default)]
    announcements: Vec<RawAnnouncement>,
    #[serde(default)]
    withdrawals: Vec<String>,
}

/// Parse one RIS Live text frame.
pub fn parse_message(text: &str) -> Result<RisMessage, ParseError> {
    if text.len() > MAX_MESSAGE_BYTES {
        return Err(ParseError::Oversized(text.len()));
    }
    let env: Envelope = serde_json::from_str(text)?;
    match env.kind.as_str() {
        "ris_message" => {}
        "ris_error" => {
            let msg = env
                .data
                .as_ref()
                .and_then(|d| d.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Ok(RisMessage::Error(sanitize_text(msg)));
        }
        _ => return Ok(RisMessage::Other),
    }
    let data = env.data.ok_or_else(|| invalid("missing data"))?;
    if data.get("type").and_then(Value::as_str) != Some("UPDATE") {
        return Ok(RisMessage::Other);
    }
    let raw: RawUpdate = serde_json::from_value(data)?;

    if !valid_collector(&raw.host) {
        return Err(invalid("host"));
    }
    let peer: IpAddr = raw.peer.parse().map_err(|_| invalid("peer"))?;
    let peer_asn = match raw.peer_asn {
        AsnField::Num(n) => n,
        AsnField::Str(s) => s.parse().map_err(|_| invalid("peer_asn"))?,
    };
    let timestamp = parse_timestamp(raw.timestamp)?;
    if raw.path.len() > MAX_PATH_SEGMENTS {
        return Err(invalid("path too long"));
    }

    let total: usize = raw
        .announcements
        .iter()
        .map(|a| a.prefixes.len())
        .sum::<usize>()
        + raw.withdrawals.len();
    if total > MAX_PREFIXES_PER_MESSAGE {
        return Err(invalid("too many prefixes"));
    }
    let announced = raw
        .announcements
        .iter()
        .flat_map(|a| a.prefixes.iter())
        .map(|p| parse_prefix(p))
        .collect::<Result<Vec<_>, _>>()?;
    let withdrawn = raw
        .withdrawals
        .iter()
        .map(|p| parse_prefix(p))
        .collect::<Result<Vec<_>, _>>()?;

    let origin = match raw.path.last() {
        None => None,
        Some(PathSegment::As(a)) => Some(Origin::As(*a)),
        Some(PathSegment::Set(set)) => {
            if set.is_empty() {
                return Err(invalid("empty AS_SET"));
            }
            let mut set = set.clone();
            set.sort_unstable();
            set.dedup();
            Some(Origin::Set(set))
        }
    };
    if origin.is_none() && !announced.is_empty() {
        return Err(invalid("announcement without AS path"));
    }

    Ok(RisMessage::Update(RisUpdate {
        collector: raw.host,
        peer,
        peer_asn,
        timestamp,
        path: raw.path,
        origin,
        announced,
        withdrawn,
    }))
}

fn parse_prefix(s: &str) -> Result<IpNet, ParseError> {
    s.parse::<IpNet>()
        .map(|n| n.trunc())
        .map_err(|_| invalid("prefix"))
}

pub fn parse_timestamp(ts: f64) -> Result<DateTime<Utc>, ParseError> {
    // Anything outside 1970..5138 is garbage, not a BGP timestamp.
    if !ts.is_finite() || !(0.0..1e11).contains(&ts) {
        return Err(invalid("timestamp"));
    }
    DateTime::from_timestamp_millis((ts * 1000.0) as i64).ok_or_else(|| invalid("timestamp"))
}

pub fn valid_collector(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Keep printable ASCII only and cap the length; used for server-supplied text.
pub fn sanitize_text(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(text: &str) -> RisUpdate {
        match parse_message(text).expect("parse") {
            RisMessage::Update(u) => u,
            other => panic!("expected update, got {other:?}"),
        }
    }

    #[test]
    fn parses_valid_update() {
        let u = update(
            r#"{"type":"ris_message","data":{"timestamp":1794556800.25,"peer":"192.0.2.1","peer_asn":"64496","id":"x","host":"rrc00","type":"UPDATE","path":[64496,64500],"origin":"igp","announcements":[{"next_hop":"192.0.2.1","prefixes":["198.51.100.0/24","2001:db8:100::/48"]}],"withdrawals":["203.0.113.0/24"]}}"#,
        );
        assert_eq!(u.collector, "rrc00");
        assert_eq!(u.peer_asn, 64496);
        assert_eq!(u.origin, Some(Origin::As(64500)));
        assert_eq!(u.announced.len(), 2);
        assert_eq!(
            u.withdrawn,
            vec!["203.0.113.0/24".parse::<IpNet>().unwrap()]
        );
        assert_eq!(u.timestamp.timestamp_millis(), 1_794_556_800_250);
        assert_eq!(u.path_string(), "64496 64500");
        assert_eq!(u.upstream(), Some(64496));
    }

    #[test]
    fn upstream_skips_prepends_and_sets() {
        let mut u = update(
            r#"{"type":"ris_message","data":{"timestamp":1,"peer":"192.0.2.1","peer_asn":"64496","host":"rrc00","type":"UPDATE","path":[64496,64497,64500,64500,64500],"announcements":[{"prefixes":["198.51.100.0/24"]}]}}"#,
        );
        assert_eq!(u.upstream(), Some(64497));
        u.path = vec![PathSegment::As(64500), PathSegment::As(64500)];
        assert_eq!(u.upstream(), None);
        u.path = vec![PathSegment::Set(vec![64501]), PathSegment::As(64500)];
        assert_eq!(u.upstream(), None);
    }

    #[test]
    fn numeric_peer_asn_and_host_bits_are_normalised() {
        let u = update(
            r#"{"type":"ris_message","data":{"timestamp":1,"peer":"2001:db8::1","peer_asn":64497,"host":"rrc21","type":"UPDATE","path":[64497,64501],"announcements":[{"prefixes":["198.51.100.7/24"]}]}}"#,
        );
        assert_eq!(u.peer_asn, 64497);
        assert_eq!(u.announced[0].to_string(), "198.51.100.0/24");
    }

    #[test]
    fn as_set_origin_is_flagged_not_guessed() {
        let u = update(
            r#"{"type":"ris_message","data":{"timestamp":1,"peer":"192.0.2.1","peer_asn":"64496","host":"rrc00","type":"UPDATE","path":[64496,[64509,64500,64509]],"announcements":[{"prefixes":["198.51.100.0/24"]}]}}"#,
        );
        assert_eq!(u.origin, Some(Origin::Set(vec![64500, 64509])));
        assert_eq!(u.origin.as_ref().and_then(Origin::asn), None);
        assert_eq!(u.path_string(), "64496 {64509,64500,64509}");
    }

    #[test]
    fn withdrawal_only_message_has_no_origin() {
        let u = update(
            r#"{"type":"ris_message","data":{"timestamp":1,"peer":"192.0.2.1","peer_asn":"64496","host":"rrc00","type":"UPDATE","path":[],"announcements":[],"withdrawals":["198.51.100.0/24"]}}"#,
        );
        assert!(u.origin.is_none());
        assert_eq!(u.withdrawn.len(), 1);
    }

    #[test]
    fn malformed_messages_are_rejected() {
        let cases = [
            "not json",
            r#"{"type":"ris_message"}"#,
            r#"{"type":"ris_message","data":{"type":"UPDATE","timestamp":"x"}}"#,
            r#"{"type":"ris_message","data":{"timestamp":1,"peer":"bogus","peer_asn":"1","host":"rrc00","type":"UPDATE","path":[1]}}"#,
            r#"{"type":"ris_message","data":{"timestamp":1,"peer":"192.0.2.1","peer_asn":"1","host":"rrc00\u001b[31m","type":"UPDATE","path":[1]}}"#,
            r#"{"type":"ris_message","data":{"timestamp":1,"peer":"192.0.2.1","peer_asn":"1","host":"rrc00","type":"UPDATE","path":[1],"announcements":[{"prefixes":["300.0.0.0/8"]}]}}"#,
            r#"{"type":"ris_message","data":{"timestamp":1,"peer":"192.0.2.1","peer_asn":"1","host":"rrc00","type":"UPDATE","path":[],"announcements":[{"prefixes":["198.51.100.0/24"]}]}}"#,
            r#"{"type":"ris_message","data":{"timestamp":-5,"peer":"192.0.2.1","peer_asn":"1","host":"rrc00","type":"UPDATE","path":[1]}}"#,
            r#"{"type":"ris_message","data":{"timestamp":1,"peer":"192.0.2.1","peer_asn":"1","host":"rrc00","type":"UPDATE","path":[1,[]],"announcements":[{"prefixes":["198.51.100.0/24"]}]}}"#,
        ];
        for c in cases {
            assert!(parse_message(c).is_err(), "should reject: {c}");
        }
    }

    #[test]
    fn oversized_message_is_rejected_before_parsing() {
        let big = format!(
            r#"{{"type":"ris_message","pad":"{}"}}"#,
            "a".repeat(MAX_MESSAGE_BYTES)
        );
        assert!(matches!(parse_message(&big), Err(ParseError::Oversized(_))));
    }

    #[test]
    fn non_update_and_errors() {
        assert!(matches!(
            parse_message(r#"{"type":"pong","data":null}"#).unwrap(),
            RisMessage::Other
        ));
        assert!(matches!(
            parse_message(r#"{"type":"ris_message","data":{"type":"KEEPALIVE"}}"#).unwrap(),
            RisMessage::Other
        ));
        match parse_message(r#"{"type":"ris_error","data":{"message":"bad\nprefix"}}"#).unwrap() {
            RisMessage::Error(m) => assert_eq!(m, "badprefix"),
            other => panic!("unexpected {other:?}"),
        }
    }
}
