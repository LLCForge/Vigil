//! Verifies that Event Horizon's remotely triggered blackholes are actually
//! visible outside: polls `GET /v1/blackholes`, subscribes the /32 and /128
//! routes on the live feed, and asks the RIPEstat looking glass. A blackhole no
//! RIS peer carries `grace_secs` after it was created raises
//! `blackhole_not_visible`; it resolves once a peer sees it (or it is removed).

use crate::alert::TOOL;
use crate::config::EventHorizonConfig;
use crate::outlet::Outlet;
use crate::ripestat::{read_json, RipeStat};
use crate::ris::RisUpdate;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use llcforge_alert::{Alert, Severity};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

const MAX_BLACKHOLES: usize = 1000;
const MAX_BODY: usize = 4 << 20;

struct Entry {
    created: DateTime<Utc>,
    live: HashSet<(String, IpAddr)>,
    alerted: bool,
}

#[derive(Default)]
pub struct BlackholeTracker {
    entries: Mutex<HashMap<IpNet, Entry>>,
}

fn host_net(ip: IpAddr) -> IpNet {
    IpNet::from(ip) // /32 or /128
}

/// Active, non-dry-run blackholes from an Event Horizon `/v1/blackholes` body.
pub fn parse_blackholes(v: &Value) -> Result<Vec<(IpNet, DateTime<Utc>)>> {
    let list = v
        .get("blackholes")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("response has no `blackholes` array"))?;
    Ok(list
        .iter()
        .filter(|e| e.get("dry_run").and_then(Value::as_bool) != Some(true))
        .filter_map(|e| {
            let ip: IpAddr = e.get("ip")?.as_str()?.parse().ok()?;
            let created = e
                .get("created_at")
                .and_then(Value::as_i64)
                .and_then(|s| DateTime::from_timestamp(s, 0))
                .unwrap_or_else(Utc::now);
            Some((host_net(ip), created))
        })
        .take(MAX_BLACKHOLES)
        .collect())
}

impl BlackholeTracker {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpNet, Entry>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn prefixes(&self) -> HashSet<IpNet> {
        self.lock().keys().copied().collect()
    }

    /// Replace the active set; returns resolutions for removed, alerted entries.
    pub fn set_active(&self, active: &[(IpNet, DateTime<Utc>)]) -> Vec<Alert> {
        let mut e = self.lock();
        let keep: HashSet<IpNet> = active.iter().map(|(p, _)| *p).collect();
        let mut out = Vec::new();
        e.retain(|p, x| {
            let k = keep.contains(p);
            if !k && x.alerted {
                out.push(alert(p, false, 0, "removed from Event Horizon"));
            }
            k
        });
        for (p, created) in active {
            e.entry(*p).or_insert(Entry {
                created: *created,
                live: HashSet::new(),
                alerted: false,
            });
        }
        out
    }

    /// Live feed sightings of the exact blackhole routes.
    pub fn observe(&self, u: &RisUpdate) -> Vec<Alert> {
        let mut entries = self.lock();
        if entries.is_empty() {
            return Vec::new();
        }
        let peer = (u.collector.clone(), u.peer);
        let mut out = Vec::new();
        for p in &u.withdrawn {
            if let Some(e) = entries.get_mut(p) {
                e.live.remove(&peer);
            }
        }
        for p in &u.announced {
            if let Some(e) = entries.get_mut(p) {
                if e.live.len() < 4096 {
                    e.live.insert(peer.clone());
                }
                if e.alerted {
                    e.alerted = false;
                    out.push(alert(p, false, e.live.len(), "seen on the live feed"));
                }
            }
        }
        out
    }

    /// Blackholes old enough to be checked.
    pub fn due(&self, now: DateTime<Utc>, grace: Duration) -> Vec<IpNet> {
        self.lock()
            .iter()
            .filter(|(_, e)| now - e.created >= grace)
            .map(|(p, _)| *p)
            .collect()
    }

    /// Combine the looking-glass count with live sightings.
    pub fn apply_check(&self, p: &IpNet, looking_glass_peers: usize) -> Option<Alert> {
        let mut entries = self.lock();
        let e = entries.get_mut(p)?;
        let seen = looking_glass_peers.max(e.live.len());
        let missing = seen == 0;
        if missing == e.alerted {
            return None;
        }
        e.alerted = missing;
        Some(if missing {
            alert(p, true, 0, "no RIS peer carries it")
        } else {
            alert(p, false, seen, "visible")
        })
    }
}

fn alert(p: &IpNet, firing: bool, peers: usize, why: &str) -> Alert {
    let title = if firing {
        format!("Blackhole {p} is not visible outside: {why}")
    } else {
        format!("Blackhole {p}: {why}")
    };
    Alert::new(TOOL, "blackhole_not_visible", Severity::Warning, title)
        .resource(p.to_string())
        .field("prefix", p)
        .field("ris_peers", peers)
        .link("RIPEstat", format!("https://stat.ripe.net/{p}"))
        .resolved(!firing)
}

/// Poll loop; publishes the active set (for subscriptions and the hijack
/// exemption) through `active_tx`. Runs until the task is aborted.
pub async fn run(
    cfg: EventHorizonConfig,
    client: reqwest::Client,
    ripestat: RipeStat,
    tracker: Arc<BlackholeTracker>,
    outlet: Outlet,
    active_tx: watch::Sender<HashSet<IpNet>>,
) {
    let token = cfg
        .token_env
        .as_deref()
        .and_then(|v| llcforge_alert::env_secret(v).ok());
    let url = format!("{}/v1/blackholes", cfg.url.trim_end_matches('/'));
    let timeout = std::time::Duration::from_millis(cfg.timeout_ms);
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(cfg.poll_secs));
    loop {
        tick.tick().await;
        let fetch = async {
            let mut req = client.get(&url);
            if let Some(t) = &token {
                req = req.bearer_auth(t);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| anyhow!(e.without_url()))?
                .error_for_status()
                .map_err(|e| anyhow!(e.without_url()))?;
            parse_blackholes(&read_json(resp, MAX_BODY).await?)
        };
        let active = match tokio::time::timeout(timeout, fetch).await {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "Event Horizon poll failed");
                continue;
            }
            Err(_) => {
                tracing::warn!("Event Horizon poll timed out");
                continue;
            }
        };
        for a in tracker.set_active(&active) {
            outlet.send_kit(a);
        }
        active_tx.send_if_modified(|cur| {
            let new = tracker.prefixes();
            let changed = *cur != new;
            *cur = new;
            changed
        });
        for p in tracker.due(Utc::now(), Duration::seconds(cfg.grace_secs as i64)) {
            match ripestat.looking_glass_peers(&p).await {
                Ok(n) => {
                    if let Some(a) = tracker.apply_check(&p, n) {
                        outlet.send_kit(a);
                    }
                }
                Err(e) => tracing::debug!(prefix = %p, error = %e, "looking-glass check failed"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ris::{Origin, PathSegment};
    use serde_json::json;

    #[test]
    fn parses_event_horizon_list() {
        let v = json!({"blackholes":[
            {"ip":"198.51.100.7","reason":"x","source":"api","created_at":1794556800,"expires_at":1794560400,"dry_run":false,"propagation":{"status":"unknown"}},
            {"ip":"2001:db8::7","created_at":1794556800,"dry_run":false},
            {"ip":"198.51.100.8","dry_run":true},
            {"ip":"not-an-ip"}
        ]});
        let l = parse_blackholes(&v).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].0.to_string(), "198.51.100.7/32");
        assert_eq!(l[1].0.to_string(), "2001:db8::7/128");
        assert!(parse_blackholes(&json!([1])).is_err());
    }

    #[test]
    fn missing_then_seen_then_removed() {
        let t = BlackholeTracker::default();
        let p: IpNet = "198.51.100.7/32".parse().unwrap();
        let created = DateTime::from_timestamp(1_794_556_800, 0).unwrap();
        assert!(t.set_active(&[(p, created)]).is_empty());
        assert!(t.due(created, Duration::seconds(300)).is_empty());
        assert_eq!(
            t.due(created + Duration::seconds(300), Duration::seconds(300)),
            vec![p]
        );

        let a = t.apply_check(&p, 0).unwrap();
        assert!(!a.resolved);
        assert_eq!(a.id, "vigil:blackhole_not_visible:198.51.100.7/32");
        assert!(t.apply_check(&p, 0).is_none());

        let u = RisUpdate {
            collector: "rrc00".into(),
            peer: "192.0.2.1".parse().unwrap(),
            peer_asn: 64496,
            timestamp: created,
            path: vec![PathSegment::As(64496), PathSegment::As(64500)],
            origin: Some(Origin::As(64500)),
            announced: vec![p],
            withdrawn: vec![],
        };
        let r = t.observe(&u);
        assert_eq!(r.len(), 1);
        assert!(r[0].resolved);
        assert!(t.apply_check(&p, 0).is_none(), "live sighting counts");

        t.apply_check(&p, 0);
        let mut w = u.clone();
        w.announced.clear();
        w.withdrawn = vec![p];
        t.observe(&w);
        assert!(t.apply_check(&p, 0).is_some());
        let gone = t.set_active(&[]);
        assert_eq!(gone.len(), 1);
        assert!(gone[0].resolved);
    }
}
