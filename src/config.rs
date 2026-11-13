//! TOML configuration, validated at load time. Secrets are only ever read from
//! environment variables named in the config.

use crate::matcher::{Exception, Matcher, ScrubbingMode, Watched, BUILTIN_SCRUBBING_ASNS};
use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use llcforge_beacon::config::SinkKind;
use llcforge_beacon::{AlertsConfig, HealthConfig, LogFormat, SilencesConfig, SinkConfig};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const DEFAULT_RIS_LIVE_URL: &str = "wss://ris-live.ripe.net/v1/ws/?client=llcforge-vigil";
pub const DEFAULT_RIPESTAT_URL: &str = "https://stat.ripe.net";
pub const DEFAULT_BGPKIT_BROKER: &str = "https://api.bgpkit.com/v3/broker/search";
pub const DEFAULT_ROUTEVIEWS_BROKER: &str = "stream.routeviews.org:9092";
const MAX_CONFIG_BYTES: u64 = 1 << 20;
/// Most watched prefixes (static plus ASN-derived); each is one RIS Live subscription.
pub const MAX_PREFIXES: usize = 1000;
const MAX_ASNS: usize = 50;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// State directory (alert queue, silences, incidents). Platform default if unset.
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub feeds: FeedsConfig,
    #[serde(default)]
    pub detection: DetectionConfig,
    #[serde(default, rename = "prefix")]
    pub prefixes: Vec<PrefixConfig>,
    #[serde(default, rename = "asn")]
    pub asns: Vec<AsnConfig>,
    #[serde(default, rename = "exception")]
    pub exceptions: Vec<ExceptionConfig>,
    #[serde(default)]
    pub ripestat: RipestatConfig,
    #[serde(default)]
    pub enrich: EnrichConfig,
    #[serde(default)]
    pub visibility: VisibilityConfig,
    pub event_horizon: Option<EventHorizonConfig>,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub silences: SilencesConfig,
    #[serde(default)]
    pub health: HealthConfig,
    /// Legacy `[metrics] listen`; same listener as `[health] listen`.
    pub metrics: Option<MetricsConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default)]
    pub format: LogFormat,
    #[serde(default = "default_level")]
    pub level: String,
    pub filter: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Text,
            level: default_level(),
            filter: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedsConfig {
    #[serde(default = "default_true")]
    pub ris_live: bool,
    #[serde(default = "default_ris_url")]
    pub ris_live_url: String,
    #[serde(default = "default_grace")]
    pub feed_down_grace_secs: u64,
    pub routeviews_kafka: Option<KafkaConfig>,
    pub bgpkit: Option<BgpkitConfig>,
}

impl Default for FeedsConfig {
    fn default() -> Self {
        Self {
            ris_live: true,
            ris_live_url: default_ris_url(),
            feed_down_grace_secs: default_grace(),
            routeviews_kafka: None,
            bgpkit: None,
        }
    }
}

/// RouteViews (or any OpenBMP-compatible) Kafka stream of raw BMP messages.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KafkaConfig {
    #[serde(default = "default_kafka_brokers")]
    pub brokers: Vec<String>,
    /// Topic globs, e.g. `routeviews.amsix.*.bmp_raw`.
    pub topics: Vec<String>,
    #[serde(default = "default_max_topics")]
    pub max_topics: usize,
    #[serde(default = "default_topic_refresh")]
    pub topic_refresh_secs: u64,
}

/// MRT update files discovered through the BGPKIT broker.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpkitConfig {
    #[serde(default = "default_bgpkit_broker")]
    pub broker_url: String,
    /// Collector ids as the broker names them (`rrc00`, `route-views2`, ...).
    pub collectors: Vec<String>,
    #[serde(default = "default_bgpkit_poll")]
    pub poll_secs: u64,
    /// Hosts MRT files may be downloaded from (suffix match).
    #[serde(default = "default_archive_hosts")]
    pub allowed_hosts: Vec<String>,
    #[serde(default = "default_max_download")]
    pub max_file_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionConfig {
    #[serde(default = "default_window")]
    pub aggregation_window_secs: u64,
    #[serde(default = "default_dedup")]
    pub dedup_secs: u64,
    /// A fired alert is resolved after its route has been gone this long.
    #[serde(default = "default_resolve")]
    pub resolve_after_secs: u64,
    #[serde(default)]
    pub scrubbing: ScrubbingMode,
    /// Replaces the built-in scrubbing provider list when set.
    pub scrubbing_asns: Option<Vec<u32>>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            aggregation_window_secs: default_window(),
            dedup_secs: default_dedup(),
            resolve_after_secs: default_resolve(),
            scrubbing: ScrubbingMode::default(),
            scrubbing_asns: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixConfig {
    pub prefix: String,
    #[serde(default)]
    pub origins: Vec<u32>,
    pub max_length: Option<u8>,
    #[serde(default)]
    pub upstreams: Vec<u32>,
    /// Registered but unannounced: any announcement is squatting.
    #[serde(default)]
    pub dormant: bool,
    pub group: Option<String>,
}

/// Watch every prefix an AS originates (fetched from RIPEstat, refreshed).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsnConfig {
    pub asn: u32,
    /// Other legitimate origins for these prefixes (e.g. a sibling AS).
    #[serde(default)]
    pub extra_origins: Vec<u32>,
    #[serde(default)]
    pub upstreams: Vec<u32>,
    pub group: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionConfig {
    pub origin: u32,
    pub prefix: Option<String>,
    pub until: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RipestatConfig {
    #[serde(default = "default_ripestat")]
    pub base_url: String,
    #[serde(default = "default_ripestat_timeout")]
    pub timeout_ms: u64,
    /// How often `[[asn]]` prefix lists are refreshed.
    #[serde(default = "default_asn_refresh")]
    pub asn_refresh_secs: u64,
}

impl Default for RipestatConfig {
    fn default() -> Self {
        Self {
            base_url: default_ripestat(),
            timeout_ms: default_ripestat_timeout(),
            asn_refresh_secs: default_asn_refresh(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichConfig {
    pub notary: Option<NotaryConfig>,
    pub asnames: Option<AsNamesConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryConfig {
    pub url: String,
    #[serde(default = "default_notary_timeout")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsNamesConfig {
    /// Look names up on RIPEstat (as-overview + rir-stats-country), cached.
    #[serde(default = "default_true")]
    pub ripestat: bool,
    /// Local CSV `asn,name,country` consulted first.
    pub file: Option<PathBuf>,
    #[serde(default = "default_notary_timeout")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisibilityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_vis_poll")]
    pub poll_secs: u64,
    /// Alert when fewer than this share of RIS full-feed peers see a prefix.
    #[serde(default = "default_min_ratio")]
    pub min_ratio: f64,
}

impl Default for VisibilityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_secs: default_vis_poll(),
            min_ratio: default_min_ratio(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventHorizonConfig {
    pub url: String,
    pub token_env: Option<String>,
    #[serde(default = "default_eh_poll")]
    pub poll_secs: u64,
    /// Alert when a blackhole is not seen by any RIS peer this long after creation.
    #[serde(default = "default_eh_grace")]
    pub grace_secs: u64,
    #[serde(default = "default_notary_timeout")]
    pub timeout_ms: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Bearer token for `/v1/visibility` and `/v1/incidents`; open when unset.
    pub token_env: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub listen: SocketAddr,
}

fn default_level() -> String {
    "info".into()
}
fn default_ris_url() -> String {
    DEFAULT_RIS_LIVE_URL.to_string()
}
fn default_grace() -> u64 {
    120
}
fn default_window() -> u64 {
    10
}
fn default_dedup() -> u64 {
    3600
}
fn default_resolve() -> u64 {
    600
}
fn default_notary_timeout() -> u64 {
    1500
}
fn default_true() -> bool {
    true
}
fn default_kafka_brokers() -> Vec<String> {
    vec![DEFAULT_ROUTEVIEWS_BROKER.into()]
}
fn default_max_topics() -> usize {
    200
}
fn default_topic_refresh() -> u64 {
    600
}
fn default_bgpkit_broker() -> String {
    DEFAULT_BGPKIT_BROKER.into()
}
fn default_bgpkit_poll() -> u64 {
    300
}
pub fn default_archive_hosts() -> Vec<String> {
    vec!["routeviews.org".into(), "ripe.net".into()]
}
fn default_max_download() -> u64 {
    512 << 20
}
fn default_ripestat() -> String {
    DEFAULT_RIPESTAT_URL.into()
}
fn default_ripestat_timeout() -> u64 {
    10_000
}
fn default_asn_refresh() -> u64 {
    3600
}
fn default_vis_poll() -> u64 {
    900
}
fn default_min_ratio() -> f64 {
    0.5
}
fn default_eh_poll() -> u64 {
    60
}
fn default_eh_grace() -> u64 {
    300
}

fn parse_net(s: &str, what: &str) -> Result<IpNet> {
    let net: IpNet = s
        .parse()
        .with_context(|| format!("{what}: `{s}` is not a valid prefix"))?;
    ensure!(
        net == net.trunc(),
        "{what}: `{s}` has host bits set (did you mean {}?)",
        net.trunc()
    );
    Ok(net)
}

pub fn check_url(url: &str, schemes: &[&str], what: &str) -> Result<()> {
    ensure!(
        schemes.iter().any(|s| url.starts_with(&format!("{s}://"))),
        "{what}: URL must start with one of {schemes:?}"
    );
    ensure!(
        url.len() <= 2048 && !url.chars().any(char::is_whitespace),
        "{what}: invalid URL"
    );
    Ok(())
}

fn check_env_name(name: &str, what: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "{what} must be an environment variable name"
    );
    Ok(())
}

fn check_group(g: &Option<String>) -> Result<()> {
    if let Some(g) = g {
        ensure!(
            !g.is_empty()
                && g.len() <= 64
                && g.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "group `{g}` must be 1-64 characters of [A-Za-z0-9._-]"
        );
    }
    Ok(())
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        ensure!(meta.len() <= MAX_CONFIG_BYTES, "config file is too large");
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid config {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let raw: toml::Table = toml::from_str(text)?;
        if let Some(alerts) = raw.get("alerts").and_then(|v| v.as_table()) {
            for old in ["stdout", "telegram", "webhook"] {
                ensure!(
                    !alerts.contains_key(old),
                    "[alerts] {old} is the pre-0.2 format; declare outputs as [[alerts.sink]] \
                     entries (type = \"stdout\" | \"telegram\" | \"webhook\" | ...), see README"
                );
            }
        }
        let mut cfg: Config = raw.try_into()?;
        cfg.validate()?;
        if cfg.alerts.sinks.is_empty() {
            // Preserve the historical default: alerts go to stdout.
            cfg.alerts.sinks.push(SinkConfig {
                common: Default::default(),
                kind: SinkKind::Stdout(Default::default()),
            });
        }
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        self.matcher()?;
        ensure!(
            !self.prefixes.is_empty() || !self.asns.is_empty(),
            "at least one [[prefix]] or [[asn]] is required"
        );
        check_url(
            &self.feeds.ris_live_url,
            &["wss", "ws"],
            "feeds.ris_live_url",
        )?;
        ensure!(
            (10..=86_400).contains(&self.feeds.feed_down_grace_secs),
            "feeds.feed_down_grace_secs must be between 10 and 86400"
        );
        if let Some(k) = &self.feeds.routeviews_kafka {
            ensure!(
                !k.brokers.is_empty() && k.brokers.len() <= 16,
                "feeds.routeviews_kafka.brokers: 1-16 entries"
            );
            for b in &k.brokers {
                ensure!(
                    b.len() <= 256
                        && b.rsplit_once(':')
                            .is_some_and(|(_, p)| p.parse::<u16>().is_ok()),
                    "feeds.routeviews_kafka.brokers: `{b}` must be host:port"
                );
            }
            ensure!(
                !k.topics.is_empty() && k.topics.len() <= 64,
                "feeds.routeviews_kafka.topics: 1-64 globs"
            );
            ensure!(
                (1..=2000).contains(&k.max_topics),
                "feeds.routeviews_kafka.max_topics must be between 1 and 2000"
            );
            ensure!(
                (60..=86_400).contains(&k.topic_refresh_secs),
                "feeds.routeviews_kafka.topic_refresh_secs must be between 60 and 86400"
            );
        }
        if let Some(b) = &self.feeds.bgpkit {
            check_url(&b.broker_url, &["https", "http"], "feeds.bgpkit.broker_url")?;
            ensure!(
                !b.collectors.is_empty() && b.collectors.len() <= 64,
                "feeds.bgpkit.collectors: 1-64 entries"
            );
            for c in &b.collectors {
                ensure!(
                    !c.is_empty()
                        && c.len() <= 64
                        && c.bytes()
                            .all(|x| x.is_ascii_alphanumeric() || matches!(x, b'-' | b'_' | b'.')),
                    "feeds.bgpkit.collectors: invalid collector `{c}`"
                );
            }
            ensure!(
                (60..=86_400).contains(&b.poll_secs),
                "feeds.bgpkit.poll_secs must be between 60 and 86400"
            );
            ensure!(
                !b.allowed_hosts.is_empty(),
                "feeds.bgpkit.allowed_hosts must not be empty"
            );
            ensure!(
                (1 << 20..=4 << 30).contains(&b.max_file_bytes),
                "feeds.bgpkit.max_file_bytes must be between 1 MiB and 4 GiB"
            );
        }
        ensure!(
            (1..=300).contains(&self.detection.aggregation_window_secs),
            "detection.aggregation_window_secs must be between 1 and 300"
        );
        ensure!(
            self.detection.dedup_secs <= 7 * 86_400,
            "detection.dedup_secs must be at most 604800"
        );
        ensure!(
            (10..=7 * 86_400).contains(&self.detection.resolve_after_secs),
            "detection.resolve_after_secs must be between 10 and 604800"
        );
        ensure!(
            self.asns.len() <= MAX_ASNS,
            "at most {MAX_ASNS} [[asn]] entries"
        );
        for a in &self.asns {
            ensure!(a.asn != 0, "[[asn]]: AS0 is not valid");
            check_group(&a.group)?;
        }
        check_url(
            &self.ripestat.base_url,
            &["https", "http"],
            "ripestat.base_url",
        )?;
        ensure!(
            (500..=60_000).contains(&self.ripestat.timeout_ms),
            "ripestat.timeout_ms must be between 500 and 60000"
        );
        ensure!(
            (300..=7 * 86_400).contains(&self.ripestat.asn_refresh_secs),
            "ripestat.asn_refresh_secs must be between 300 and 604800"
        );
        if let Some(n) = &self.enrich.notary {
            check_url(&n.url, &["http", "https"], "enrich.notary.url")?;
            ensure!(
                (100..=10_000).contains(&n.timeout_ms),
                "enrich.notary.timeout_ms must be between 100 and 10000"
            );
        }
        if let Some(n) = &self.enrich.asnames {
            ensure!(
                (100..=10_000).contains(&n.timeout_ms),
                "enrich.asnames.timeout_ms must be between 100 and 10000"
            );
        }
        ensure!(
            (60..=86_400).contains(&self.visibility.poll_secs),
            "visibility.poll_secs must be between 60 and 86400"
        );
        ensure!(
            self.visibility.min_ratio > 0.0 && self.visibility.min_ratio <= 1.0,
            "visibility.min_ratio must be in (0, 1]"
        );
        if let Some(e) = &self.event_horizon {
            check_url(&e.url, &["http", "https"], "event_horizon.url")?;
            if let Some(t) = &e.token_env {
                check_env_name(t, "event_horizon.token_env")?;
            }
            ensure!(
                (10..=3600).contains(&e.poll_secs),
                "event_horizon.poll_secs must be between 10 and 3600"
            );
            ensure!(
                (30..=86_400).contains(&e.grace_secs),
                "event_horizon.grace_secs must be between 30 and 86400"
            );
            ensure!(
                (100..=10_000).contains(&e.timeout_ms),
                "event_horizon.timeout_ms must be between 100 and 10000"
            );
        }
        if let Some(t) = &self.api.token_env {
            check_env_name(t, "api.token_env")?;
        }
        if let (Some(h), Some(m)) = (self.health.listen, &self.metrics) {
            ensure!(
                h == m.listen,
                "[metrics] listen and [health] listen differ; use [health] listen only"
            );
        }
        Ok(())
    }

    /// Address of the management listener (`/metrics`, health, APIs), if enabled.
    pub fn listen(&self) -> Option<SocketAddr> {
        self.health
            .listen
            .or_else(|| self.metrics.as_ref().map(|m| m.listen))
    }

    pub fn data_dir(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(|| llcforge_beacon::default_data_dir(crate::alert::TOOL))
    }

    /// Statically configured watched prefixes.
    pub fn watched(&self) -> Result<Vec<Watched>> {
        ensure!(
            self.prefixes.len() <= MAX_PREFIXES,
            "at most {MAX_PREFIXES} prefixes are supported"
        );
        let mut seen = HashSet::new();
        let mut watched = Vec::with_capacity(self.prefixes.len());
        for p in &self.prefixes {
            let net = parse_net(&p.prefix, "prefix")?;
            ensure!(seen.insert(net), "prefix {net} is listed twice");
            ensure!(
                p.dormant || !p.origins.is_empty(),
                "prefix {net}: origins must not be empty (or set dormant = true)"
            );
            ensure!(
                !p.origins.contains(&0) && !p.upstreams.contains(&0),
                "prefix {net}: AS0 is not a valid origin or upstream"
            );
            check_group(&p.group)?;
            let max_length = p.max_length.unwrap_or(net.prefix_len());
            if max_length < net.prefix_len() || max_length > net.max_prefix_len() {
                bail!(
                    "prefix {net}: max_length must be between {} and {}",
                    net.prefix_len(),
                    net.max_prefix_len()
                );
            }
            watched.push(Watched {
                prefix: net,
                origins: p.origins.clone(),
                max_length,
                upstreams: p.upstreams.clone(),
                dormant: p.dormant,
                group: p.group.clone(),
            });
        }
        Ok(watched)
    }

    pub fn exceptions(&self) -> Result<Vec<Exception>> {
        let mut exceptions = Vec::with_capacity(self.exceptions.len());
        for e in &self.exceptions {
            ensure!(e.origin != 0, "exception: AS0 is not a valid origin");
            let prefix = e
                .prefix
                .as_deref()
                .map(|p| parse_net(p, "exception.prefix"))
                .transpose()?;
            let until = DateTime::parse_from_rfc3339(&e.until)
                .with_context(|| format!("exception.until `{}` is not RFC 3339", e.until))?
                .with_timezone(&Utc);
            exceptions.push(Exception {
                origin: e.origin,
                prefix,
                until,
            });
        }
        Ok(exceptions)
    }

    pub fn scrubbing_asns(&self) -> Vec<u32> {
        self.detection
            .scrubbing_asns
            .clone()
            .unwrap_or_else(|| BUILTIN_SCRUBBING_ASNS.iter().map(|(a, _)| *a).collect())
    }

    /// Build a matcher from the static prefixes plus `extra` (ASN-derived) ones;
    /// static entries win on duplicates. Fails on any invalid prefix or exception.
    pub fn matcher_with(&self, extra: &[Watched]) -> Result<Matcher> {
        let mut watched = self.watched()?;
        let mut seen: HashSet<IpNet> = watched.iter().map(|w| w.prefix).collect();
        for w in extra {
            if watched.len() >= MAX_PREFIXES {
                tracing::warn!(
                    "watch list capped at {MAX_PREFIXES} prefixes; ASN-derived prefixes dropped"
                );
                break;
            }
            if seen.insert(w.prefix) {
                watched.push(w.clone());
            }
        }
        Ok(Matcher::new(watched, self.exceptions()?)
            .with_scrubbing(self.detection.scrubbing, self.scrubbing_asns()))
    }

    /// Matcher for the static configuration only.
    pub fn matcher(&self) -> Result<Matcher> {
        self.matcher_with(&[])
    }

    /// Fail early if a secret named in the config is missing.
    pub fn check_secrets(&self) -> Result<()> {
        let mut vars: Vec<&str> = Vec::new();
        if let Some(t) = &self.api.token_env {
            vars.push(t);
        }
        if let Some(t) = self
            .event_horizon
            .as_ref()
            .and_then(|e| e.token_env.as_deref())
        {
            vars.push(t);
        }
        for v in vars {
            llcforge_beacon::env_secret(v)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[[prefix]]
prefix = "198.51.100.0/24"
origins = [64500]
"#;

    #[test]
    fn minimal_config_gets_defaults() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.feeds.ris_live_url, DEFAULT_RIS_LIVE_URL);
        assert!(c.feeds.ris_live);
        assert_eq!(c.detection.aggregation_window_secs, 10);
        assert_eq!(c.detection.scrubbing, ScrubbingMode::Warn);
        assert_eq!(c.alerts.sinks.len(), 1, "stdout sink by default");
        assert_eq!(c.matcher().unwrap().watched()[0].max_length, 24);
        assert!(c.listen().is_none());
        assert!(c.scrubbing_asns().contains(&32787));
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../vigil.example.toml");
        let c = Config::parse(text).unwrap();
        assert!(c.prefixes.len() >= 2);
        assert!(c.watched().unwrap().iter().any(|w| w.dormant));
        assert!(c.listen().is_some());
    }

    #[test]
    fn asn_only_config_and_extra_prefixes() {
        let c = Config::parse("[[asn]]\nasn = 64500\ngroup = \"core\"").unwrap();
        assert!(c.matcher().unwrap().watched().is_empty());
        let extra = vec![Watched::new(
            "192.0.2.0/24".parse().unwrap(),
            vec![64500],
            24,
        )];
        assert_eq!(c.matcher_with(&extra).unwrap().watched().len(), 1);
    }

    #[test]
    fn rejects_bad_configs() {
        let bad = [
            "",
            "[[prefix]]\nprefix = \"198.51.100.1/24\"\norigins = [64500]",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = []",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]\nmax_length = 33",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]\nmax_length = 16",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]\n[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64501]",
            "[feeds]\nrouteviews_bmp = true\n[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]\n[[exception]]\norigin = 64505\nuntil = \"tomorrow\"",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]\n[alerts.webhook]\nurl = \"https://hooks.example.net/x\"",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]\ngroup = \"a b\"",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]\n[event_horizon]\nurl = \"file:///etc/passwd\"",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]\n[visibility]\nmin_ratio = 1.5",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]\n[feeds.routeviews_kafka]\ntopics = [\"x\"]\nbrokers = [\"nohost\"]",
            "[[prefix]]\nprefix = \"198.51.100.0/24\"\norigins = [64500]\n[api]\ntoken_env = \"A B\"",
            "[[asn]]\nasn = 0",
        ];
        for b in bad {
            assert!(Config::parse(b).is_err(), "should reject:\n{b}");
        }
    }
}
