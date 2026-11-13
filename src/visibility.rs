//! Prefix visibility: share of RIS full-feed peers that carry each watched
//! prefix. The authoritative number is polled from RIPEstat routing-status;
//! between polls, live withdrawals (and re-announcements) by individual peers
//! adjust it so a sudden loss is noticed without waiting for the next poll.

use crate::alert::TOOL;
use crate::matcher::Watched;
use crate::ripestat::Visibility;
use crate::ris::RisUpdate;
use chrono::{DateTime, SecondsFormat, Utc};
use ipnet::IpNet;
use llcforge_alert::{Alert, Severity};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Mutex;

/// Most per-peer withdrawals remembered per prefix between polls.
const MAX_DOWN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Snapshot {
    pub prefix: String,
    pub peers_seeing: u32,
    pub peers_total: u32,
    pub ratio: f64,
    pub as_of: String,
}

struct Entry {
    resource: String,
    polled: Option<Visibility>,
    as_of: DateTime<Utc>,
    /// Peers that withdrew the exact prefix since the last poll.
    down: HashSet<(String, IpAddr)>,
    alerted: bool,
}

impl Entry {
    fn current(&self) -> Option<(u32, u32)> {
        let v = self.polled?;
        let lost = u32::try_from(self.down.len()).unwrap_or(u32::MAX);
        Some((v.seeing.saturating_sub(lost), v.total))
    }
}

pub struct VisibilityTracker {
    min_ratio: f64,
    entries: Mutex<BTreeMap<IpNet, Entry>>,
}

fn ratio(seeing: u32, total: u32) -> f64 {
    if total == 0 {
        0.0
    } else {
        f64::from(seeing) / f64::from(total)
    }
}

impl VisibilityTracker {
    pub fn new(min_ratio: f64) -> Self {
        Self {
            min_ratio,
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<IpNet, Entry>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Track exactly these prefixes (dormant space is never tracked).
    pub fn set_prefixes(&self, watched: &[Watched]) {
        let mut e = self.lock();
        let keep: BTreeMap<IpNet, String> = watched
            .iter()
            .filter(|w| !w.dormant)
            .map(|w| (w.prefix, w.resource()))
            .collect();
        e.retain(|p, _| keep.contains_key(p));
        for (p, resource) in keep {
            e.entry(p)
                .and_modify(|x| x.resource = resource.clone())
                .or_insert(Entry {
                    resource,
                    polled: None,
                    as_of: Utc::now(),
                    down: HashSet::new(),
                    alerted: false,
                });
        }
    }

    pub fn prefixes(&self) -> Vec<IpNet> {
        self.lock().keys().copied().collect()
    }

    /// Alert transition for an entry, if its threshold state changed.
    fn evaluate(&self, prefix: &IpNet, e: &mut Entry) -> Option<Alert> {
        let (seeing, total) = e.current()?;
        if total == 0 {
            return None;
        }
        let r = ratio(seeing, total);
        let low = r < self.min_ratio;
        if low == e.alerted {
            return None;
        }
        e.alerted = low;
        let title = if low {
            format!("Visibility loss: {prefix} seen by {seeing}/{total} RIS peers")
        } else {
            format!("Visibility restored: {prefix} seen by {seeing}/{total} RIS peers")
        };
        Some(
            Alert::new(TOOL, "visibility_loss", Severity::Warning, title)
                .resource(e.resource.clone())
                .id(format!("{TOOL}:visibility_loss:{prefix}"))
                .field("prefix", prefix)
                .field("peers_seeing", seeing)
                .field("peers_total", total)
                .field("ratio", format!("{r:.3}"))
                .field("threshold", format!("{:.3}", self.min_ratio))
                .link("RIPEstat", format!("https://stat.ripe.net/{prefix}"))
                .resolved(!low),
        )
    }

    /// Apply a RIPEstat measurement (resets the live delta).
    pub fn apply_poll(&self, prefix: &IpNet, v: Visibility, at: DateTime<Utc>) -> Option<Alert> {
        let mut entries = self.lock();
        let e = entries.get_mut(prefix)?;
        e.polled = Some(v);
        e.as_of = at;
        e.down.clear();
        self.evaluate(prefix, e)
    }

    /// Live adjustment from a feed update touching a tracked prefix exactly.
    pub fn observe(&self, u: &RisUpdate) -> Vec<Alert> {
        let mut out = Vec::new();
        let mut entries = self.lock();
        let peer = (u.collector.clone(), u.peer);
        for (p, withdrawn) in u
            .withdrawn
            .iter()
            .map(|p| (p, true))
            .chain(u.announced.iter().map(|p| (p, false)))
        {
            let Some(e) = entries.get_mut(p) else {
                continue;
            };
            let changed = if withdrawn {
                e.down.len() < MAX_DOWN && e.down.insert(peer.clone())
            } else {
                e.down.remove(&peer)
            };
            if changed {
                e.as_of = u.timestamp;
                out.extend(self.evaluate(p, e));
            }
        }
        out
    }

    pub fn snapshot(&self, prefix: &IpNet) -> Option<Snapshot> {
        let entries = self.lock();
        let e = entries.get(prefix)?;
        let (seeing, total) = e.current()?;
        Some(Snapshot {
            prefix: prefix.to_string(),
            peers_seeing: seeing,
            peers_total: total,
            ratio: ratio(seeing, total),
            as_of: e.as_of.to_rfc3339_opts(SecondsFormat::Secs, true),
        })
    }

    pub fn render_prometheus(&self, out: &mut String) {
        let entries = self.lock();
        out.push_str("# HELP vigil_visibility_ratio Share of RIS full-feed peers seeing the prefix\n# TYPE vigil_visibility_ratio gauge\n");
        for (p, e) in entries.iter() {
            if let Some((s, t)) = e.current() {
                let _ = writeln!(
                    out,
                    "vigil_visibility_ratio{{prefix=\"{p}\"}} {:.4}",
                    ratio(s, t)
                );
            }
        }
        out.push_str("# HELP vigil_visibility_peers_seeing RIS full-feed peers seeing the prefix\n# TYPE vigil_visibility_peers_seeing gauge\n");
        for (p, e) in entries.iter() {
            if let Some((s, _)) = e.current() {
                let _ = writeln!(out, "vigil_visibility_peers_seeing{{prefix=\"{p}\"}} {s}");
            }
        }
        out.push_str("# HELP vigil_visibility_peers_total RIS full-feed peers of the address family\n# TYPE vigil_visibility_peers_total gauge\n");
        for (p, e) in entries.iter() {
            if let Some((_, t)) = e.current() {
                let _ = writeln!(out, "vigil_visibility_peers_total{{prefix=\"{p}\"}} {t}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ris::{Origin, PathSegment};

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn upd(peer: &str, withdraw: bool) -> RisUpdate {
        RisUpdate {
            collector: "rrc00".into(),
            peer: peer.parse().unwrap(),
            peer_asn: 64496,
            timestamp: Utc::now(),
            path: vec![PathSegment::As(64496), PathSegment::As(64500)],
            origin: (!withdraw).then_some(Origin::As(64500)),
            announced: if withdraw {
                vec![]
            } else {
                vec![net("198.51.100.0/24")]
            },
            withdrawn: if withdraw {
                vec![net("198.51.100.0/24")]
            } else {
                vec![]
            },
        }
    }

    #[test]
    fn poll_live_adjustment_alert_and_resolution() {
        let t = VisibilityTracker::new(0.5);
        let mut dormant = Watched::new(net("203.0.113.0/24"), vec![], 24);
        dormant.dormant = true;
        t.set_prefixes(&[
            Watched::new(net("198.51.100.0/24"), vec![64500], 24),
            dormant,
        ]);
        assert_eq!(t.prefixes(), vec![net("198.51.100.0/24")]);
        assert!(
            t.snapshot(&net("198.51.100.0/24")).is_none(),
            "not polled yet"
        );

        let p = net("198.51.100.0/24");
        assert!(t
            .apply_poll(
                &p,
                Visibility {
                    seeing: 3,
                    total: 4
                },
                Utc::now()
            )
            .is_none());
        let s = t.snapshot(&p).unwrap();
        assert_eq!((s.peers_seeing, s.peers_total), (3, 4));
        assert!((s.ratio - 0.75).abs() < 1e-9);

        assert!(
            t.observe(&upd("192.0.2.1", true)).is_empty(),
            "2/4 is not < 0.5"
        );
        let a = t.observe(&upd("192.0.2.2", true));
        assert_eq!(a.len(), 1);
        assert!(!a[0].resolved);
        assert_eq!(a[0].id, "vigil:visibility_loss:198.51.100.0/24");
        assert!(
            t.observe(&upd("192.0.2.2", true)).is_empty(),
            "same peer twice"
        );

        let r = t.observe(&upd("192.0.2.2", false));
        assert_eq!(r.len(), 1);
        assert!(r[0].resolved);

        let mut m = String::new();
        t.render_prometheus(&mut m);
        assert!(m.contains("vigil_visibility_peers_seeing{prefix=\"198.51.100.0/24\"} 2"));
    }
}
