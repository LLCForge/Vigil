//! Process-wide counters rendered in the Prometheus text format. Served on the
//! management listener (`GET /metrics`, see `api`) together with the
//! llcforge-beacon dispatcher metrics.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn set(&self, v: u64) {
        self.0.store(v, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

pub static RIS_MESSAGES: Counter = Counter::new();
pub static RIS_MALFORMED: Counter = Counter::new();
pub static RIS_OVERSIZED: Counter = Counter::new();
pub static RIS_RECONNECTS: Counter = Counter::new();
pub static RIS_CONNECTED: Counter = Counter::new();
pub static RIS_LAG_MS: Counter = Counter::new();
pub static KAFKA_MESSAGES: Counter = Counter::new();
pub static KAFKA_MALFORMED: Counter = Counter::new();
pub static KAFKA_UPDATES: Counter = Counter::new();
pub static KAFKA_PARTITIONS: Counter = Counter::new();
pub static MRT_FILES: Counter = Counter::new();
pub static MRT_FAILURES: Counter = Counter::new();
pub static ALERTS: Counter = Counter::new();
pub static ALERTS_SUPPRESSED: Counter = Counter::new();
pub static SIGHTINGS_DROPPED: Counter = Counter::new();
pub static OPEN_INCIDENTS: Counter = Counter::new();
pub static WATCHED_PREFIXES: Counter = Counter::new();
pub static ENRICH_FAILURES: Counter = Counter::new();

pub fn render() -> String {
    let counters: [(&str, &str, &str, &Counter); 17] = [
        (
            "vigil_ris_messages_total",
            "counter",
            "RIS Live frames received",
            &RIS_MESSAGES,
        ),
        (
            "vigil_ris_malformed_total",
            "counter",
            "RIS Live messages dropped as malformed",
            &RIS_MALFORMED,
        ),
        (
            "vigil_ris_oversized_total",
            "counter",
            "RIS Live messages dropped as oversized",
            &RIS_OVERSIZED,
        ),
        (
            "vigil_ris_reconnects_total",
            "counter",
            "RIS Live connections lost",
            &RIS_RECONNECTS,
        ),
        (
            "vigil_ris_connected",
            "gauge",
            "1 while the RIS Live session is up",
            &RIS_CONNECTED,
        ),
        (
            "vigil_kafka_messages_total",
            "counter",
            "Kafka BMP records received",
            &KAFKA_MESSAGES,
        ),
        (
            "vigil_kafka_malformed_total",
            "counter",
            "Kafka records that were not valid OpenBMP/BMP",
            &KAFKA_MALFORMED,
        ),
        (
            "vigil_kafka_updates_total",
            "counter",
            "Route updates decoded from Kafka BMP Route Monitoring messages",
            &KAFKA_UPDATES,
        ),
        (
            "vigil_kafka_partitions",
            "gauge",
            "Kafka partitions being consumed",
            &KAFKA_PARTITIONS,
        ),
        (
            "vigil_mrt_files_total",
            "counter",
            "MRT update files processed from the BGPKIT broker",
            &MRT_FILES,
        ),
        (
            "vigil_mrt_failures_total",
            "counter",
            "MRT update files that failed to download or parse",
            &MRT_FAILURES,
        ),
        ("vigil_alerts_total", "counter", "Alerts emitted", &ALERTS),
        (
            "vigil_alerts_suppressed_total",
            "counter",
            "Sightings suppressed by dedup",
            &ALERTS_SUPPRESSED,
        ),
        (
            "vigil_sightings_dropped_total",
            "counter",
            "Sightings dropped because a state table was full",
            &SIGHTINGS_DROPPED,
        ),
        (
            "vigil_open_incidents",
            "gauge",
            "Route alerts waiting for resolution",
            &OPEN_INCIDENTS,
        ),
        (
            "vigil_watched_prefixes",
            "gauge",
            "Prefixes under watch (static and ASN-derived)",
            &WATCHED_PREFIXES,
        ),
        (
            "vigil_enrich_failures_total",
            "counter",
            "Notary or AS-name lookups without an answer",
            &ENRICH_FAILURES,
        ),
    ];
    let mut out = String::new();
    for (name, kind, help, c) in counters {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {}",
            c.get()
        );
    }
    let _ = writeln!(
        out,
        "# HELP vigil_ris_lag_seconds Age of the newest RIS Live message when received\n# TYPE vigil_ris_lag_seconds gauge\nvigil_ris_lag_seconds {:.3}",
        RIS_LAG_MS.get() as f64 / 1000.0
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_series_once() {
        let m = render();
        for name in [
            "vigil_ris_messages_total",
            "vigil_kafka_partitions",
            "vigil_open_incidents",
            "vigil_ris_lag_seconds",
        ] {
            assert_eq!(m.matches(&format!("# TYPE {name} ")).count(), 1, "{name}");
        }
    }
}
