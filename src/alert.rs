//! Vigil's route alert model, its plain-text rendering (stdout of `vigil replay`)
//! and the conversion to the shared `llcforge.alert.v1` schema.

use chrono::{DateTime, SecondsFormat, Utc};
use ipnet::IpNet;
use llcforge_alert::Severity;
use serde::Serialize;

/// Tool name used in every alert id and in the Prometheus `tool` label.
pub const TOOL: &str = "vigil";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    OriginHijack,
    SubPrefixHijack,
    Moas,
    AmbiguousOrigin,
    Squatting,
    ScrubbingOrigin,
    UnexpectedUpstream,
}

impl AlertKind {
    pub fn label(self) -> &'static str {
        match self {
            AlertKind::OriginHijack => "ORIGIN HIJACK",
            AlertKind::SubPrefixHijack => "SUB-PREFIX HIJACK",
            AlertKind::Moas => "MOAS",
            AlertKind::AmbiguousOrigin => "AMBIGUOUS ORIGIN (AS_SET)",
            AlertKind::Squatting => "SQUATTING",
            AlertKind::ScrubbingOrigin => "SCRUBBING PROVIDER ORIGIN",
            AlertKind::UnexpectedUpstream => "UNEXPECTED UPSTREAM",
        }
    }

    /// `kind` in the shared alert schema.
    pub fn as_str(self) -> &'static str {
        match self {
            AlertKind::OriginHijack => "origin_hijack",
            AlertKind::SubPrefixHijack => "sub_prefix_hijack",
            AlertKind::Moas => "moas",
            AlertKind::AmbiguousOrigin => "ambiguous_origin",
            AlertKind::Squatting => "squatting",
            AlertKind::ScrubbingOrigin => "scrubbing_origin",
            AlertKind::UnexpectedUpstream => "unexpected_upstream",
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            AlertKind::OriginHijack | AlertKind::SubPrefixHijack | AlertKind::Squatting => {
                Severity::Critical
            }
            AlertKind::Moas
            | AlertKind::AmbiguousOrigin
            | AlertKind::ScrubbingOrigin
            | AlertKind::UnexpectedUpstream => Severity::Warning,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteAlert {
    pub kind: AlertKind,
    /// Prefix as announced.
    pub prefix: IpNet,
    /// Watched prefix that covers it.
    pub watched: IpNet,
    /// Alert routing resource: the watched prefix, or `<group>/<prefix>`.
    pub resource: String,
    /// Offending origin (`AS64511`), AS_SET (`{AS64500,AS64509}`), for MOAS all
    /// origins seen at once (`AS64500, AS64511`), for an unexpected upstream
    /// `AS64500 via AS64499`.
    pub origin: String,
    /// Single offending (or, for upstream alerts, legitimate) origin ASN.
    pub origin_asn: Option<u32>,
    /// Neighbour of the origin, for unexpected-upstream alerts.
    pub upstream: Option<u32>,
    pub expected_origins: Vec<u32>,
    pub expected_upstreams: Vec<u32>,
    /// Distinct peers that reported the route during the aggregation window.
    pub peers: usize,
    pub collectors: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub sample_path: String,
    /// RPKI validity from Notary, when enrichment is configured and answered in time.
    pub rpki: Option<String>,
    /// `AS64511 EXAMPLE-NET (NL)` lines from AS name enrichment.
    pub as_info: Vec<String>,
    /// The condition cleared (sent with the same id as the original alert).
    pub resolved: bool,
}

impl RouteAlert {
    /// Stable alert id: the same (kind, prefix, origin) always maps to the same id.
    pub fn id(&self) -> String {
        format!(
            "{TOOL}:{}:{}:{}",
            self.kind.as_str(),
            self.prefix,
            self.origin.replace(' ', "")
        )
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // short-lived, almost always the Route variant
pub enum Alert {
    Route(RouteAlert),
    FeedDown { feed: String, since: DateTime<Utc> },
    FeedRestored { feed: String, down_secs: i64 },
}

fn ts(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn asns(v: &[u32]) -> String {
    v.iter()
        .map(|a| format!("AS{a}"))
        .collect::<Vec<_>>()
        .join(", ")
}

impl Alert {
    /// Multi-line plain-text rendering used by `vigil replay` / `vigil replay-mrt`.
    pub fn text(&self) -> String {
        match self {
            Alert::Route(r) => {
                let head = if r.resolved { "RESOLVED" } else { "ALERT" };
                let mut s = format!(
                    "{head} {} {}\n  origin      {} (expected {})\n  watched     {}\n  seen by     {} peer(s) on {} collector(s): {}\n  first seen  {}\n  path        {}",
                    r.kind.label(),
                    r.prefix,
                    r.origin,
                    if r.expected_origins.is_empty() { "none: dormant space".into() } else { asns(&r.expected_origins) },
                    r.watched,
                    r.peers,
                    r.collectors.len(),
                    r.collectors.join(", "),
                    ts(&r.first_seen),
                    r.sample_path,
                );
                if !r.expected_upstreams.is_empty() && r.kind == AlertKind::UnexpectedUpstream {
                    s.push_str(&format!(
                        "\n  upstreams   expected {}",
                        asns(&r.expected_upstreams)
                    ));
                }
                if let Some(state) = &r.rpki {
                    s.push_str(&format!("\n  rpki        {state}"));
                }
                for line in &r.as_info {
                    s.push_str(&format!("\n  as          {line}"));
                }
                s
            }
            Alert::FeedDown { feed, since } => {
                format!("ALERT FEED DOWN {feed}\n  down since  {}", ts(since))
            }
            Alert::FeedRestored { feed, down_secs } => {
                format!("NOTICE FEED RESTORED {feed}\n  was down    {down_secs}s")
            }
        }
    }

    /// Conversion to the shared `llcforge.alert.v1` schema.
    pub fn to_kit(&self) -> llcforge_alert::Alert {
        use llcforge_alert::Alert as K;
        match self {
            Alert::Route(r) => {
                let title = if r.resolved {
                    format!("{} cleared: {}", r.kind.label(), r.prefix)
                } else {
                    format!("{}: {} from {}", r.kind.label(), r.prefix, r.origin)
                };
                let mut a = K::new(TOOL, r.kind.as_str(), r.kind.severity(), title)
                    .resource(r.resource.clone())
                    .id(r.id())
                    .summary(format!(
                        "Seen by {} peer(s) on {} collector(s).",
                        r.peers,
                        r.collectors.len()
                    ))
                    .field("prefix", r.prefix)
                    .field("watched", r.watched)
                    .field("origin", &r.origin)
                    .field("expected_origins", asns(&r.expected_origins))
                    .field("collectors", r.collectors.join(", "))
                    .field("path", &r.sample_path)
                    .first_seen(r.first_seen)
                    .resolved(r.resolved)
                    .link("RIPEstat", format!("https://stat.ripe.net/{}", r.prefix));
                if let Some(u) = r.upstream {
                    a = a.field("upstream", format!("AS{u}"));
                }
                if !r.expected_upstreams.is_empty() {
                    a = a.field("expected_upstreams", asns(&r.expected_upstreams));
                }
                if let Some(state) = &r.rpki {
                    a = a.field("rpki", state);
                }
                for line in &r.as_info {
                    a = a.field("as", line);
                }
                a
            }
            Alert::FeedDown { feed, since } => K::new(
                TOOL,
                "feed_down",
                Severity::Warning,
                format!("Feed {feed} is down"),
            )
            .resource(feed.clone())
            .field("down_since", ts(since))
            .first_seen(*since),
            Alert::FeedRestored { feed, down_secs } => K::new(
                TOOL,
                "feed_down",
                Severity::Warning,
                format!("Feed {feed} restored"),
            )
            .resource(feed.clone())
            .field("was_down_secs", down_secs)
            .resolved(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RouteAlert {
        RouteAlert {
            kind: AlertKind::OriginHijack,
            prefix: "198.51.100.0/24".parse().unwrap(),
            watched: "198.51.100.0/24".parse().unwrap(),
            resource: "customer-a/198.51.100.0/24".into(),
            origin: "AS64511".into(),
            origin_asn: Some(64511),
            upstream: None,
            expected_origins: vec![64500],
            expected_upstreams: vec![],
            peers: 2,
            collectors: vec!["<b>evil</b>".into()],
            first_seen: DateTime::from_timestamp(1_794_556_800, 0).unwrap(),
            sample_path: "64496 & 64511".into(),
            rpki: Some("invalid".into()),
            as_info: vec!["AS64511 EXAMPLE-NET (NL)".into()],
            resolved: false,
        }
    }

    #[test]
    fn kit_alert_has_stable_id_resource_and_raw_fields() {
        let a = Alert::Route(sample()).to_kit();
        assert_eq!(a.id, "vigil:origin_hijack:198.51.100.0/24:AS64511");
        assert_eq!(a.tool, "vigil");
        assert_eq!(a.kind, "origin_hijack");
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.resource.as_deref(), Some("customer-a/198.51.100.0/24"));
        // Escaping is the sinks' job: values are carried verbatim.
        assert!(a.fields.iter().any(|f| f.value == "<b>evil</b>"));
        assert!(a
            .fields
            .iter()
            .any(|f| f.key == "rpki" && f.value == "invalid"));

        let mut r = sample();
        r.resolved = true;
        let resolved = Alert::Route(r).to_kit();
        assert_eq!(resolved.id, a.id, "resolution reuses the id");
        assert!(resolved.resolved);
    }

    #[test]
    fn text_rendering_and_json_shape() {
        let alert = Alert::Route(sample());
        let t = alert.text();
        assert!(t.starts_with("ALERT ORIGIN HIJACK 198.51.100.0/24"));
        assert!(t.contains("rpki        invalid"));
        assert!(t.contains("as          AS64511 EXAMPLE-NET (NL)"));
        let json = serde_json::to_value(&alert).unwrap();
        assert_eq!(json["event"], "route");
        assert_eq!(json["kind"], "origin_hijack");
        let down = Alert::FeedRestored {
            feed: "ris-live".into(),
            down_secs: 5,
        }
        .to_kit();
        assert_eq!(down.id, "vigil:feed_down:ris-live");
        assert!(down.resolved);
    }
}
