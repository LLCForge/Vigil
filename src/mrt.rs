//! MRT (RFC 6396) update files through the pure-Rust `bgpkit-parser`: local
//! files, RIPE RIS archive replay for a date range, and near-real-time
//! updates discovered through the BGPKIT broker.

use crate::config::BgpkitConfig;
use crate::feed::{FeedEvent, Outage};
use crate::matcher::{Matcher, Watched};
use crate::ripestat::read_json;
use crate::ris::{
    parse_timestamp, valid_collector, Origin, PathSegment, RisUpdate, MAX_PATH_SEGMENTS,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use bgpkit_parser::models::{AsPathSegment, ElemType};
use bgpkit_parser::{BgpElem, BgpkitParser};
use chrono::{DateTime, Duration, DurationRound, Utc};
use ipnet::IpNet;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, watch};

pub const FEED_NAME: &str = "bgpkit";
/// Default RIPE RIS raw data archive.
pub const RIS_ARCHIVE: &str = "https://data.ris.ripe.net";
/// Longest replay range (one week of 5-minute files).
pub const MAX_REPLAY_FILES: usize = 7 * 24 * 12;
const MAX_SEEN_URLS: usize = 10_000;

/// Convert one bgpkit element to Vigil's update model. `None` for elements
/// that cannot be represented (no usable AS path on an announcement).
pub fn elem_to_update(e: &BgpElem, collector: &str) -> Option<RisUpdate> {
    let timestamp = parse_timestamp(e.timestamp).ok()?;
    let prefix: IpNet = e.prefix.prefix.trunc();
    let mut u = RisUpdate {
        collector: collector.to_string(),
        peer: e.peer_ip,
        peer_asn: e.peer_asn.to_u32(),
        timestamp,
        path: Vec::new(),
        origin: None,
        announced: Vec::new(),
        withdrawn: Vec::new(),
    };
    if e.elem_type == ElemType::WITHDRAW {
        u.withdrawn.push(prefix);
        return Some(u);
    }
    for seg in &e.as_path.as_ref()?.segments {
        match seg {
            AsPathSegment::AsSequence(v) => {
                u.path.extend(v.iter().map(|a| PathSegment::As(a.to_u32())))
            }
            AsPathSegment::AsSet(v) => u
                .path
                .push(PathSegment::Set(v.iter().map(|a| a.to_u32()).collect())),
            // Confederation segments are local to the confederation; not part of the origin.
            AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_) => {}
        }
        if u.path.len() > MAX_PATH_SEGMENTS {
            return None;
        }
    }
    u.origin = match u.path.last()? {
        PathSegment::As(a) => Some(Origin::As(*a)),
        PathSegment::Set(s) if s.is_empty() => return None,
        PathSegment::Set(s) => {
            let mut s = s.clone();
            s.sort_unstable();
            s.dedup();
            Some(Origin::Set(s))
        }
    };
    u.announced.push(prefix);
    Some(u)
}

/// Collector label safe for alerts (`route-views2`, `rrc00`).
pub fn collector_label(raw: &str) -> String {
    let s: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(64)
        .collect();
    if valid_collector(&s) {
        s
    } else {
        "mrt".into()
    }
}

/// Wrap `reader` in the right decompressor, sniffing gzip / bzip2 magic bytes.
pub fn decompress<'a, R: Read + 'a>(reader: R) -> Result<Box<dyn Read + 'a>> {
    let mut r = BufReader::new(reader);
    let head = r.fill_buf()?;
    Ok(if head.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::MultiGzDecoder::new(r))
    } else if head.starts_with(b"BZh") {
        Box::new(bzip2::read::MultiBzDecoder::new(r))
    } else {
        Box::new(r)
    })
}

/// Parse an MRT stream and call `f` for every element covered by `keep`.
/// Returns the number of elements read. Malformed records are skipped by the parser.
pub fn read_updates<R: Read>(
    reader: R,
    collector: &str,
    keep: &dyn Fn(&IpNet) -> bool,
    f: &mut dyn FnMut(RisUpdate),
) -> Result<u64> {
    let mut n = 0u64;
    for e in BgpkitParser::from_reader(decompress(reader)?) {
        n += 1;
        if keep(&e.prefix.prefix.trunc()) {
            if let Some(u) = elem_to_update(&e, collector) {
                f(u);
            }
        }
    }
    Ok(n)
}

/// RIS archive update files (5-minute granularity) covering `[from, to)`.
pub fn ris_archive_urls(
    base: &str,
    collector: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<String>> {
    ensure!(from < to, "--from must be before --to");
    ensure!(
        collector.len() <= 16 && collector.bytes().all(|b| b.is_ascii_alphanumeric()),
        "invalid RIS collector `{collector}` (e.g. rrc00)"
    );
    let step = Duration::minutes(5);
    let mut t = from.duration_trunc(step)?;
    let mut out = Vec::new();
    while t < to {
        ensure!(
            out.len() < MAX_REPLAY_FILES,
            "range too long: at most {MAX_REPLAY_FILES} files (7 days)"
        );
        out.push(format!(
            "{}/{collector}/{}/updates.{}.gz",
            base.trim_end_matches('/'),
            t.format("%Y.%m"),
            t.format("%Y%m%d.%H%M")
        ));
        t += step;
    }
    Ok(out)
}

/// Only http(s) URLs whose host is (a subdomain of) an allowed host.
pub fn url_allowed(url: &str, allowed: &[String]) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else {
        return false;
    };
    let Some(host) = u.host_str() else {
        return false;
    };
    matches!(u.scheme(), "http" | "https")
        && allowed
            .iter()
            .any(|a| host == a || host.ends_with(&format!(".{a}")))
}

/// Stream `url` into a temporary file under `dir`, at most `max` bytes.
pub async fn download(
    client: &reqwest::Client,
    url: &str,
    dir: &Path,
    max: u64,
) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!(e.without_url()))?
        .error_for_status()
        .map_err(|e| anyhow!(e.without_url()))?;
    if resp.content_length().is_some_and(|l| l > max) {
        bail!("file larger than {max} bytes");
    }
    let path = dir.join(format!(
        "vigil-mrt-{}-{}.tmp",
        std::process::id(),
        fastrand::u64(..)
    ));
    let result = async {
        let mut f = std::fs::File::create(&path)?;
        let mut total = 0u64;
        while let Some(chunk) = resp.chunk().await.map_err(|e| anyhow!(e.without_url()))? {
            total += chunk.len() as u64;
            ensure!(total <= max, "file larger than {max} bytes");
            f.write_all(&chunk)?;
        }
        f.flush()?;
        Ok(())
    }
    .await;
    if let Err(e) = result {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}

/// Filter built from the current watch list (covering lookup).
pub fn coverage(prefixes: &[IpNet]) -> Matcher {
    Matcher::new(
        prefixes
            .iter()
            .map(|p| Watched::new(*p, vec![], p.prefix_len()))
            .collect(),
        vec![],
    )
}

/// One update file reported by the BGPKIT broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerItem {
    pub url: String,
    pub collector: String,
    pub ts_start: DateTime<Utc>,
}

pub fn parse_broker(v: &Value) -> Result<Vec<BrokerItem>> {
    let data = v
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("broker response without data"))?;
    let mut out: Vec<BrokerItem> = data
        .iter()
        .filter(|i| i.get("data_type").and_then(Value::as_str) == Some("updates"))
        .filter_map(|i| {
            let url = i.get("url")?.as_str()?.to_string();
            let collector = collector_label(i.get("collector_id")?.as_str()?);
            let ts = i.get("ts_start")?.as_str()?;
            let ts_start = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S")
                .ok()?
                .and_utc();
            (url.len() <= 2048).then_some(BrokerItem {
                url,
                collector,
                ts_start,
            })
        })
        .collect();
    out.sort_by_key(|i| i.ts_start);
    Ok(out)
}

async fn query_broker(
    client: &reqwest::Client,
    cfg: &BgpkitConfig,
    collector: &str,
    since: DateTime<Utc>,
) -> Result<Vec<BrokerItem>> {
    let fmt = |t: DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let req = client.get(&cfg.broker_url).query(&[
        ("collector_id", collector.to_string()),
        ("data_type", "updates".to_string()),
        ("ts_start", fmt(since)),
        ("ts_end", fmt(Utc::now())),
        ("page_size", "100".to_string()),
    ]);
    let resp = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let r = req
            .send()
            .await
            .map_err(|e| anyhow!(e.without_url()))?
            .error_for_status()
            .map_err(|e| anyhow!(e.without_url()))?;
        read_json(r, 4 << 20).await
    })
    .await
    .map_err(|_| anyhow!("broker query timed out"))??;
    parse_broker(&resp)
}

/// Poll the BGPKIT broker, download new update files and feed their updates.
pub async fn run_broker_feed(
    cfg: BgpkitConfig,
    client: reqwest::Client,
    tmp_dir: PathBuf,
    prefixes: watch::Receiver<Vec<IpNet>>,
    grace: std::time::Duration,
    tx: mpsc::Sender<FeedEvent>,
) {
    let mut outage = Outage::new(FEED_NAME, grace);
    // Archives publish files with a delay; start an hour back, then follow the
    // newest file start per collector (the broker returns overlapping files, `seen` dedups).
    let start = Utc::now() - Duration::hours(1);
    let mut since: std::collections::HashMap<String, DateTime<Utc>> =
        cfg.collectors.iter().map(|c| (c.clone(), start)).collect();
    let mut seen: VecDeque<String> = VecDeque::new();
    let mut seen_set: HashSet<String> = HashSet::new();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(cfg.poll_secs));
    loop {
        tick.tick().await;
        let mut items = Vec::new();
        let mut failed = false;
        for c in &cfg.collectors {
            let from = since.get(c).copied().unwrap_or(start);
            match query_broker(&client, &cfg, c, from).await {
                Ok(mut v) => {
                    if let Some(last) = v.iter().map(|i| i.ts_start).max() {
                        since.insert(c.clone(), last.max(from));
                    }
                    items.append(&mut v);
                }
                Err(e) => {
                    failed = true;
                    tracing::warn!(collector = %c, error = %e, "BGPKIT broker query failed");
                }
            }
        }
        let ev = if failed { outage.fail() } else { outage.ok() };
        for ev in ev {
            if tx.send(ev).await.is_err() {
                return;
            }
        }
        for item in items {
            if seen_set.contains(&item.url) {
                continue;
            }
            if !url_allowed(&item.url, &cfg.allowed_hosts) {
                tracing::warn!(url = %item.url, "broker returned a URL outside allowed_hosts; skipped");
                continue;
            }
            if seen.len() >= MAX_SEEN_URLS {
                if let Some(old) = seen.pop_front() {
                    seen_set.remove(&old);
                }
            }
            seen.push_back(item.url.clone());
            seen_set.insert(item.url.clone());

            let path = match download(&client, &item.url, &tmp_dir, cfg.max_file_bytes).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(url = %item.url, error = %e, "MRT download failed");
                    crate::metrics::MRT_FAILURES.inc();
                    continue;
                }
            };
            let filter = coverage(&prefixes.borrow());
            let tx2 = tx.clone();
            let collector = item.collector.clone();
            let p2 = path.clone();
            let parsed = tokio::task::spawn_blocking(move || -> Result<u64> {
                let f = std::fs::File::open(&p2)?;
                let keep = |p: &IpNet| filter.lookup(p).is_some();
                read_updates(f, &collector, &keep, &mut |u| {
                    let _ = tx2.blocking_send(FeedEvent::Update(Box::new(u)));
                })
            })
            .await;
            let _ = std::fs::remove_file(&path);
            match parsed {
                Ok(Ok(n)) => {
                    crate::metrics::MRT_FILES.inc();
                    tracing::info!(url = %item.url, elements = n, "MRT update file processed");
                }
                Ok(Err(e)) => {
                    crate::metrics::MRT_FAILURES.inc();
                    tracing::warn!(url = %item.url, error = %e, "MRT parse failed");
                }
                Err(e) => {
                    crate::metrics::MRT_FAILURES.inc();
                    tracing::error!(url = %item.url, error = %e, "MRT parser task failed");
                }
            }
            if tx.is_closed() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgpkit_parser::models::{AsPath, Asn, NetworkPrefix};
    use serde_json::json;

    fn elem(ty: ElemType, path: Option<AsPath>) -> BgpElem {
        BgpElem {
            timestamp: 1_794_556_800.5,
            elem_type: ty,
            peer_ip: "192.0.2.1".parse().unwrap(),
            peer_asn: Asn::new_32bit(64496),
            prefix: NetworkPrefix::new("198.51.100.0/24".parse().unwrap(), None),
            as_path: path,
            ..Default::default()
        }
    }

    #[test]
    fn converts_announcements_sets_and_withdrawals() {
        let p = AsPath::from_sequence([64496, 64511]);
        let u = elem_to_update(&elem(ElemType::ANNOUNCE, Some(p)), "route-views2").unwrap();
        assert_eq!(u.origin, Some(Origin::As(64511)));
        assert_eq!(u.path_string(), "64496 64511");
        assert_eq!(u.announced[0].to_string(), "198.51.100.0/24");
        assert_eq!(u.timestamp.timestamp_millis(), 1_794_556_800_500);

        let set = AsPath::from_segments(vec![
            AsPathSegment::sequence([64496]),
            AsPathSegment::set([64509, 64500]),
        ]);
        let u = elem_to_update(&elem(ElemType::ANNOUNCE, Some(set)), "rrc00").unwrap();
        assert_eq!(u.origin, Some(Origin::Set(vec![64500, 64509])));

        assert!(elem_to_update(&elem(ElemType::ANNOUNCE, None), "rrc00").is_none());
        let w = elem_to_update(&elem(ElemType::WITHDRAW, None), "rrc00").unwrap();
        assert!(w.origin.is_none());
        assert_eq!(w.withdrawn.len(), 1);
    }

    #[test]
    fn archive_urls_cover_range_and_are_bounded() {
        let from = "2026-11-01T00:03:00Z".parse().unwrap();
        let to = "2026-11-01T00:15:00Z".parse().unwrap();
        let u = ris_archive_urls(RIS_ARCHIVE, "rrc00", from, to).unwrap();
        assert_eq!(
            u,
            vec![
                "https://data.ris.ripe.net/rrc00/2026.11/updates.20261101.0000.gz",
                "https://data.ris.ripe.net/rrc00/2026.11/updates.20261101.0005.gz",
                "https://data.ris.ripe.net/rrc00/2026.11/updates.20261101.0010.gz",
            ]
        );
        let far = "2026-12-01T00:00:00Z".parse().unwrap();
        assert!(ris_archive_urls(RIS_ARCHIVE, "rrc00", from, far).is_err());
        assert!(ris_archive_urls(RIS_ARCHIVE, "../x", from, to).is_err());
        assert!(ris_archive_urls(RIS_ARCHIVE, "rrc00", to, from).is_err());
    }

    #[test]
    fn url_allowlist() {
        let allowed = crate::config::default_archive_hosts();
        assert!(url_allowed(
            "http://archive.routeviews.org/bgpdata/2026.11/UPDATES/updates.20261112.0000.bz2",
            &allowed
        ));
        assert!(url_allowed(
            "https://data.ris.ripe.net/rrc00/x.gz",
            &allowed
        ));
        assert!(!url_allowed("https://evilrouteviews.org/x", &allowed));
        assert!(!url_allowed("file:///etc/passwd", &allowed));
        assert!(!url_allowed("http://127.0.0.1/x", &allowed));
    }

    #[test]
    fn parses_broker_response() {
        let v = json!({"data":[
            {"ts_start":"2026-11-12T00:15:00","collector_id":"route-views2","data_type":"updates","url":"http://archive.routeviews.org/b.bz2"},
            {"ts_start":"2026-11-12T00:00:00","collector_id":"route-views2","data_type":"updates","url":"http://archive.routeviews.org/a.bz2"},
            {"ts_start":"2026-11-12T00:00:00","collector_id":"route-views2","data_type":"rib","url":"http://archive.routeviews.org/r.bz2"},
            {"ts_start":"bad","collector_id":"x","data_type":"updates","url":"u"}
        ]});
        let items = parse_broker(&v).unwrap();
        assert_eq!(items.len(), 2);
        assert!(items[0].url.ends_with("a.bz2"));
        assert_eq!(items[0].collector, "route-views2");
    }

    #[test]
    fn garbage_and_compressed_garbage_do_not_panic() {
        let keep = |_: &IpNet| true;
        let mut n = 0;
        for input in [
            vec![0u8; 0],
            vec![0xffu8; 64],
            vec![0x1f, 0x8b, 0, 0],
            b"BZh9garbage".to_vec(),
        ] {
            let _ = read_updates(&input[..], "rrc00", &keep, &mut |_| n += 1);
        }
        assert_eq!(n, 0);
    }
}
