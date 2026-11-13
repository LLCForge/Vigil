//! Turns RIS updates into aggregated, deduplicated route alerts, and resolves
//! them once the condition has cleared.
//!
//! Sightings of the same `(kind, prefix, origin)` are grouped for a short window so
//! one alert reports how many peers and collectors saw it. After an alert fires, the
//! same key stays quiet for the dedup period. A fired alert stays "open" until no
//! tracked peer carries the offending route for `resolve_after`; then a resolution
//! with the same id is emitted.

use crate::alert::{AlertKind, RouteAlert};
use crate::matcher::{Matcher, Verdict, Watched};
use crate::ris::{Origin, RisUpdate};
use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

/// Most announced prefixes tracked for MOAS detection and resolution.
const MAX_TRACKED_PREFIXES: usize = 65_536;
/// Most alert groups waiting for their window to close.
const MAX_PENDING: usize = 10_000;
/// Most fired alerts waiting for resolution.
const MAX_OPEN: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    kind: AlertKind,
    prefix: IpNet,
    origin: String,
}

struct Group {
    watched: Watched,
    origin_asn: Option<u32>,
    upstream: Option<u32>,
    first_seen: DateTime<Utc>,
    opened_at: DateTime<Utc>,
    peers: BTreeSet<IpAddr>,
    collectors: BTreeSet<String>,
    sample_path: String,
}

/// An alert that fired and is waiting for its condition to clear.
struct Open {
    alert: RouteAlert,
    inactive_since: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteState {
    origin: Origin,
    upstream: Option<u32>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DetectorStats {
    /// Sightings ignored because the same alert fired within the dedup period.
    pub suppressed: u64,
    /// Sightings dropped because a state table was full.
    pub dropped: u64,
}

pub struct Detector {
    matcher: Matcher,
    window: Duration,
    dedup: Duration,
    resolve_after: Duration,
    pending: HashMap<Key, Group>,
    recent: HashMap<Key, DateTime<Utc>>,
    open: HashMap<Key, Open>,
    /// Current route per (prefix, collector, peer), for MOAS and resolution.
    routes: HashMap<IpNet, HashMap<(String, IpAddr), RouteState>>,
    /// Active Event Horizon blackholes: our own more-specifics, not hijacks.
    blackholes: HashSet<IpNet>,
    pub stats: DetectorStats,
}

fn verdict_kind(v: Verdict) -> Option<AlertKind> {
    match v {
        Verdict::Ok | Verdict::Excepted => None,
        Verdict::OriginHijack => Some(AlertKind::OriginHijack),
        Verdict::SubPrefixHijack => Some(AlertKind::SubPrefixHijack),
        Verdict::Ambiguous => Some(AlertKind::AmbiguousOrigin),
        Verdict::Squat => Some(AlertKind::Squatting),
        Verdict::Scrubbing => Some(AlertKind::ScrubbingOrigin),
    }
}

impl Detector {
    pub fn new(matcher: Matcher, window: Duration, dedup: Duration) -> Self {
        Self {
            matcher,
            window,
            dedup,
            resolve_after: Duration::seconds(600),
            pending: HashMap::new(),
            recent: HashMap::new(),
            open: HashMap::new(),
            routes: HashMap::new(),
            blackholes: HashSet::new(),
            stats: DetectorStats::default(),
        }
    }

    /// A fired alert is resolved once its condition has been absent this long.
    pub fn with_resolve_after(mut self, d: Duration) -> Self {
        self.resolve_after = d;
        self
    }

    /// Apply new timing parameters (config reload).
    pub fn configure(&mut self, window: Duration, dedup: Duration, resolve_after: Duration) {
        self.window = window;
        self.dedup = dedup;
        self.resolve_after = resolve_after;
    }

    pub fn matcher(&self) -> &Matcher {
        &self.matcher
    }

    /// Swap the watch list (config reload, ASN refresh). Routes no longer
    /// covered by any watched prefix are dropped.
    pub fn set_matcher(&mut self, matcher: Matcher) {
        self.matcher = matcher;
        let m = &self.matcher;
        self.routes.retain(|p, _| m.lookup(p).is_some());
    }

    pub fn set_blackholes(&mut self, nets: HashSet<IpNet>) {
        self.blackholes = nets;
    }

    /// Finding for one route: (kind, origin label).
    fn finding(
        &self,
        w: &Watched,
        p: &IpNet,
        route: &RouteState,
        now: DateTime<Utc>,
    ) -> Option<(AlertKind, String)> {
        let verdict = self.matcher.evaluate(w, p, &route.origin, now);
        if verdict == Verdict::SubPrefixHijack
            && self.blackholes.contains(p)
            && route.origin.asn().is_some_and(|a| w.origins.contains(&a))
        {
            return None; // our own RTBH more-specific
        }
        if let Some(kind) = verdict_kind(verdict) {
            return Some((kind, route.origin.to_string()));
        }
        match (verdict, route.upstream) {
            (Verdict::Ok, Some(u)) if !w.upstreams.is_empty() && !w.upstreams.contains(&u) => {
                Some((
                    AlertKind::UnexpectedUpstream,
                    format!("{} via AS{u}", route.origin),
                ))
            }
            _ => None,
        }
    }

    /// MOAS label for `p` if several origins are present and one of them is bad.
    fn moas(&self, w: &Watched, p: &IpNet, now: DateTime<Utc>) -> Option<String> {
        if w.dormant {
            return None;
        }
        let origins: BTreeSet<&Origin> = self.routes.get(p)?.values().map(|r| &r.origin).collect();
        let any_bad = origins
            .iter()
            .any(|o| verdict_kind(self.matcher.evaluate(w, p, o, now)).is_some());
        (origins.len() >= 2 && any_bad).then(|| {
            origins
                .iter()
                .map(|o| o.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })
    }

    /// Feed one update; `now` drives window and exception expiry.
    pub fn observe(&mut self, u: &RisUpdate, now: DateTime<Utc>) {
        let peer_key = (u.collector.clone(), u.peer);
        for p in &u.withdrawn {
            if let Some(peers) = self.routes.get_mut(p) {
                peers.remove(&peer_key);
                if peers.is_empty() {
                    self.routes.remove(p);
                }
            }
        }
        let Some(origin) = &u.origin else { return };
        let route = RouteState {
            origin: origin.clone(),
            upstream: u.upstream(),
        };

        for p in &u.announced {
            let Some(w) = self.matcher.lookup(p).cloned() else {
                continue;
            };
            if let Some((kind, label)) = self.finding(&w, p, &route, now) {
                self.sight(kind, *p, label, origin.asn(), route.upstream, &w, u, now);
            }

            if self.routes.len() >= MAX_TRACKED_PREFIXES && !self.routes.contains_key(p) {
                self.stats.dropped += 1;
                continue;
            }
            self.routes
                .entry(*p)
                .or_default()
                .insert(peer_key.clone(), route.clone());
            if let Some(label) = self.moas(&w, p, now) {
                self.sight(AlertKind::Moas, *p, label, None, None, &w, u, now);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn sight(
        &mut self,
        kind: AlertKind,
        prefix: IpNet,
        origin: String,
        origin_asn: Option<u32>,
        upstream: Option<u32>,
        w: &Watched,
        u: &RisUpdate,
        now: DateTime<Utc>,
    ) {
        let key = Key {
            kind,
            prefix,
            origin,
        };
        if self.recent.get(&key).is_some_and(|t| now - *t < self.dedup) {
            self.stats.suppressed += 1;
            return;
        }
        if !self.pending.contains_key(&key) && self.pending.len() >= MAX_PENDING {
            self.stats.dropped += 1;
            tracing::warn!("alert table full, dropping sighting for {prefix}");
            return;
        }
        let g = self.pending.entry(key).or_insert_with(|| Group {
            watched: w.clone(),
            origin_asn,
            upstream,
            first_seen: u.timestamp,
            opened_at: now,
            peers: BTreeSet::new(),
            collectors: BTreeSet::new(),
            sample_path: u.path_string(),
        });
        g.first_seen = g.first_seen.min(u.timestamp);
        g.peers.insert(u.peer);
        g.collectors.insert(u.collector.clone());
    }

    /// Is the condition behind `key` still present in the current routes?
    fn active(&self, key: &Key, now: DateTime<Utc>) -> bool {
        let Some(w) = self.matcher.lookup(&key.prefix) else {
            return false;
        };
        if key.kind == AlertKind::Moas {
            return self.moas(w, &key.prefix, now).is_some();
        }
        self.routes.get(&key.prefix).is_some_and(|peers| {
            peers.values().any(|r| {
                self.finding(w, &key.prefix, r, now)
                    .is_some_and(|(k, l)| k == key.kind && l == key.origin)
            })
        })
    }

    /// Emit groups whose window has closed (all groups when `force`), plus
    /// resolutions of fired alerts whose condition has been gone for
    /// `resolve_after` (never when `force`: shutdown is not a resolution).
    pub fn flush(&mut self, now: DateTime<Utc>, force: bool) -> Vec<RouteAlert> {
        let ready: Vec<Key> = self
            .pending
            .iter()
            .filter(|(_, g)| force || now - g.opened_at >= self.window)
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = Vec::with_capacity(ready.len());
        for key in ready {
            let Some(g) = self.pending.remove(&key) else {
                continue;
            };
            self.recent.insert(key.clone(), now);
            let alert = RouteAlert {
                kind: key.kind,
                prefix: key.prefix,
                watched: g.watched.prefix,
                resource: g.watched.resource(),
                origin: key.origin.clone(),
                origin_asn: g.origin_asn,
                upstream: g.upstream,
                expected_origins: g.watched.origins.clone(),
                expected_upstreams: g.watched.upstreams.clone(),
                peers: g.peers.len(),
                collectors: g.collectors.into_iter().collect(),
                first_seen: g.first_seen,
                sample_path: g.sample_path,
                rpki: None,
                as_info: Vec::new(),
                resolved: false,
            };
            if self.open.len() < MAX_OPEN || self.open.contains_key(&key) {
                self.open.insert(
                    key,
                    Open {
                        alert: alert.clone(),
                        inactive_since: None,
                    },
                );
            }
            out.push(alert);
        }
        if !force {
            let keys: Vec<Key> = self.open.keys().cloned().collect();
            for key in keys {
                let active = self.active(&key, now);
                let Some(o) = self.open.get_mut(&key) else {
                    continue;
                };
                if active {
                    o.inactive_since = None;
                    continue;
                }
                let since = *o.inactive_since.get_or_insert(now);
                if now - since >= self.resolve_after {
                    if let Some(o) = self.open.remove(&key) {
                        let mut r = o.alert;
                        r.resolved = true;
                        self.recent.remove(&key);
                        out.push(r);
                    }
                }
            }
        }
        let dedup = self.dedup;
        self.recent.retain(|_, t| now - *t < dedup);
        out.sort_by(|a, b| (a.first_seen, a.kind).cmp(&(b.first_seen, b.kind)));
        out
    }

    /// Number of fired alerts waiting for resolution.
    pub fn open_count(&self) -> usize {
        self.open.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ris::PathSegment;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_794_556_800 + secs, 0).unwrap()
    }

    fn detector() -> Detector {
        let m = Matcher::new(
            vec![Watched::new(net("198.51.100.0/24"), vec![64500], 24)],
            vec![],
        );
        Detector::new(m, Duration::seconds(10), Duration::seconds(3600))
    }

    fn upd(collector: &str, peer: &str, path: &[u32], prefix: &str, at: i64) -> RisUpdate {
        RisUpdate {
            collector: collector.into(),
            peer: peer.parse().unwrap(),
            peer_asn: path[0],
            timestamp: t(at),
            path: path.iter().map(|a| PathSegment::As(*a)).collect(),
            origin: path.last().map(|a| Origin::As(*a)),
            announced: vec![net(prefix)],
            withdrawn: vec![],
        }
    }

    fn withdraw(collector: &str, peer: &str, prefix: &str, at: i64) -> RisUpdate {
        let mut w = upd(collector, peer, &[64496], prefix, at);
        w.announced.clear();
        w.withdrawn = vec![net(prefix)];
        w.origin = None;
        w
    }

    #[test]
    fn aggregates_peers_within_window_then_dedups() {
        let mut d = detector();
        d.observe(
            &upd("rrc00", "192.0.2.1", &[64496, 64511], "198.51.100.0/24", 0),
            t(0),
        );
        d.observe(
            &upd("rrc21", "192.0.2.2", &[64497, 64511], "198.51.100.0/24", 2),
            t(2),
        );
        d.observe(
            &upd("rrc21", "192.0.2.2", &[64497, 64511], "198.51.100.0/24", 3),
            t(3),
        );
        assert!(d.flush(t(5), false).is_empty(), "window still open");

        let alerts = d.flush(t(10), false);
        assert_eq!(alerts.len(), 1);
        let a = &alerts[0];
        assert_eq!(a.kind, AlertKind::OriginHijack);
        assert_eq!(a.origin, "AS64511");
        assert_eq!(a.peers, 2);
        assert_eq!(a.collectors, vec!["rrc00", "rrc21"]);
        assert_eq!(a.first_seen, t(0));
        assert_eq!(a.resource, "198.51.100.0/24");

        // Same hijack again within the dedup period: suppressed.
        d.observe(
            &upd("rrc25", "192.0.2.3", &[64498, 64511], "198.51.100.0/24", 60),
            t(60),
        );
        assert!(d.flush(t(100), true).is_empty());
        assert_eq!(d.stats.suppressed, 1);

        // After the dedup period it fires again.
        d.observe(
            &upd(
                "rrc25",
                "192.0.2.3",
                &[64498, 64511],
                "198.51.100.0/24",
                4000,
            ),
            t(4000),
        );
        assert_eq!(d.flush(t(4000), true).len(), 1);
    }

    #[test]
    fn moas_requires_concurrent_origins_and_respects_withdrawals() {
        let mut d = detector();
        d.observe(
            &upd("rrc00", "192.0.2.1", &[64496, 64500], "198.51.100.0/24", 0),
            t(0),
        );
        assert!(d.flush(t(20), true).is_empty(), "legitimate origin only");

        d.observe(
            &withdraw("rrc00", "192.0.2.1", "198.51.100.0/24", 21),
            t(21),
        );
        d.observe(
            &upd("rrc21", "192.0.2.2", &[64497, 64511], "198.51.100.0/24", 22),
            t(22),
        );
        let kinds: Vec<_> = d.flush(t(40), true).into_iter().map(|a| a.kind).collect();
        assert_eq!(
            kinds,
            vec![AlertKind::OriginHijack],
            "legit route was withdrawn"
        );

        d.observe(
            &upd("rrc00", "192.0.2.1", &[64496, 64500], "198.51.100.0/24", 50),
            t(50),
        );
        let alerts = d.flush(t(60), true);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::Moas);
        assert_eq!(alerts[0].origin, "AS64500, AS64511");
    }

    #[test]
    fn unwatched_prefixes_are_ignored() {
        let mut d = detector();
        d.observe(
            &upd("rrc00", "192.0.2.1", &[64496, 64511], "203.0.113.0/24", 0),
            t(0),
        );
        assert!(d.flush(t(100), true).is_empty());
        assert!(d.routes.is_empty());
    }

    #[test]
    fn hijack_resolves_after_withdrawal_and_can_fire_again() {
        let mut d = detector().with_resolve_after(Duration::seconds(60));
        d.observe(
            &upd("rrc00", "192.0.2.1", &[64496, 64511], "198.51.100.0/24", 0),
            t(0),
        );
        assert_eq!(d.flush(t(10), false).len(), 1);
        assert_eq!(d.open_count(), 1);
        assert!(d.flush(t(100), false).is_empty(), "still announced");

        d.observe(
            &withdraw("rrc00", "192.0.2.1", "198.51.100.0/24", 110),
            t(110),
        );
        assert!(d.flush(t(120), false).is_empty(), "resolve_after not over");
        let resolved = d.flush(t(181), false);
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved);
        assert_eq!(resolved[0].origin, "AS64511");
        assert_eq!(d.open_count(), 0);

        // Recurrence after resolution alerts again despite the dedup period.
        d.observe(
            &upd(
                "rrc00",
                "192.0.2.1",
                &[64496, 64511],
                "198.51.100.0/24",
                200,
            ),
            t(200),
        );
        let again = d.flush(t(210), false);
        assert_eq!(again.len(), 1);
        assert!(!again[0].resolved);
    }

    #[test]
    fn unexpected_upstream_and_blackhole_exemption() {
        let mut w = Watched::new(net("198.51.100.0/24"), vec![64500], 24);
        w.upstreams = vec![64496];
        let mut d = Detector::new(
            Matcher::new(vec![w], vec![]),
            Duration::seconds(10),
            Duration::seconds(3600),
        );
        d.observe(
            &upd(
                "rrc00",
                "192.0.2.1",
                &[64497, 64496, 64500],
                "198.51.100.0/24",
                0,
            ),
            t(0),
        );
        assert!(d.flush(t(20), true).is_empty(), "expected upstream");
        d.observe(
            &upd(
                "rrc00",
                "192.0.2.2",
                &[64497, 64499, 64500, 64500],
                "198.51.100.0/24",
                1,
            ),
            t(1),
        );
        let a = d.flush(t(20), true);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, AlertKind::UnexpectedUpstream);
        assert_eq!(a[0].origin, "AS64500 via AS64499");
        assert_eq!(a[0].upstream, Some(64499));

        d.set_blackholes([net("198.51.100.7/32")].into_iter().collect());
        d.observe(
            &upd("rrc00", "192.0.2.1", &[64496, 64500], "198.51.100.7/32", 30),
            t(30),
        );
        assert!(
            d.flush(t(50), true).is_empty(),
            "own RTBH /32 is not a hijack"
        );
        d.observe(
            &upd("rrc00", "192.0.2.1", &[64496, 64511], "198.51.100.7/32", 31),
            t(31),
        );
        assert_eq!(d.flush(t(50), true)[0].kind, AlertKind::SubPrefixHijack);
    }
}
