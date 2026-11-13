//! RouteViews BMP stream over Kafka (pure Rust: `rskafka` + `bgpkit-parser`).
//!
//! RouteViews publishes the BMP feed of its collectors as OpenBMP-compatible
//! raw BMP messages, one topic per collector and peer AS
//! (`routeviews.<collector>.<peer-asn>.bmp_raw`, broker
//! `stream.routeviews.org:9092`; see README for how this was verified). Every
//! Kafka record value is an OpenBMP v2 header followed by one BMP message.
//! Route Monitoring messages are turned into updates; everything else is
//! ignored. Consumption starts at the latest offset of each partition (no
//! consumer group, no committed offsets).

use crate::config::KafkaConfig;
use crate::feed::{backoff, FeedEvent, Outage};
use crate::metrics;
use crate::mrt::{collector_label, coverage, elem_to_update};
use crate::ris::RisUpdate;
use anyhow::{anyhow, Result};
use bgpkit_parser::parser::bmp::messages::BmpMessageBody;
use bgpkit_parser::{parse_bmp_msg, parse_openbmp_header, Elementor};
use bytes::Bytes;
use ipnet::IpNet;
use llcforge_beacon::glob_match;
use rskafka::client::partition::{OffsetAt, UnknownTopicHandling};
use rskafka::client::{Client, ClientBuilder};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

pub const FEED_NAME: &str = "routeviews-kafka";
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RECORD_BYTES: usize = 4 << 20;
const FETCH_MAX_BYTES: i32 = 4 << 20;

/// `routeviews.amsix.ams.61955.bmp_raw` -> `routeviews.amsix.ams`.
pub fn topic_collector(topic: &str) -> String {
    let parts: Vec<&str> = topic.split('.').collect();
    let base = if parts.len() > 3 && parts[parts.len() - 1] == "bmp_raw" {
        parts[..parts.len() - 2].join(".")
    } else {
        topic.to_string()
    };
    collector_label(&base)
}

pub fn topic_selected(topic: &str, globs: &[String]) -> bool {
    globs.iter().any(|g| glob_match(g, topic))
}

/// Decode one record value (OpenBMP header + BMP message) into updates.
/// Never panics: the third-party parser runs under `catch_unwind`.
pub fn parse_record(value: &[u8], collector: &str) -> Option<Vec<RisUpdate>> {
    if value.len() > MAX_RECORD_BYTES {
        return None;
    }
    let collector = collector.to_string();
    let data = Bytes::copy_from_slice(value);
    std::panic::catch_unwind(move || {
        let mut data = data;
        let header = parse_openbmp_header(&mut data).ok()?;
        let msg = parse_bmp_msg(&mut data).ok()?;
        let BmpMessageBody::RouteMonitoring(m) = msg.message_body else {
            return Some(Vec::new());
        };
        let pph = msg.per_peer_header?;
        // BMP per-peer timestamp is the event time; the OpenBMP one is collection time.
        let ts = if pph.timestamp > 0.0 {
            pph.timestamp
        } else {
            header.timestamp
        };
        Some(
            Elementor::bgp_to_elems(m.bgp_message, ts, &pph.peer_ip, &pph.peer_asn)
                .iter()
                .filter_map(|e| elem_to_update(e, &collector))
                .collect(),
        )
    })
    .ok()
    .flatten()
}

async fn connect(cfg: &KafkaConfig) -> Result<Client> {
    tokio::time::timeout(
        CALL_TIMEOUT,
        ClientBuilder::new(cfg.brokers.clone())
            .client_id("llcforge-vigil")
            .max_message_size(MAX_RECORD_BYTES * 2)
            .build(),
    )
    .await
    .map_err(|_| anyhow!("Kafka connect timed out"))?
    .map_err(|e| anyhow!("Kafka connect failed: {e}"))
}

/// Topics (with partitions) matching the configured globs, capped.
pub async fn matching_topics(client: &Client, cfg: &KafkaConfig) -> Result<Vec<(String, i32)>> {
    let topics = tokio::time::timeout(CALL_TIMEOUT, client.list_topics())
        .await
        .map_err(|_| anyhow!("Kafka metadata request timed out"))?
        .map_err(|e| anyhow!("Kafka metadata request failed: {e}"))?;
    let mut names: Vec<_> = topics
        .into_iter()
        .filter(|t| topic_selected(&t.name, &cfg.topics))
        .collect();
    names.sort_by(|a, b| a.name.cmp(&b.name));
    if names.len() > cfg.max_topics {
        tracing::warn!(
            matching = names.len(),
            max = cfg.max_topics,
            "more Kafka topics match than max_topics; extra topics ignored"
        );
        names.truncate(cfg.max_topics);
    }
    Ok(names
        .into_iter()
        .flat_map(|t| {
            let name = t.name;
            t.partitions.into_iter().map(move |p| (name.clone(), p))
        })
        .collect())
}

async fn consume_partition(
    client: Arc<Client>,
    topic: String,
    partition: i32,
    mut prefixes: watch::Receiver<Vec<IpNet>>,
    tx: mpsc::Sender<FeedEvent>,
) {
    let collector = topic_collector(&topic);
    let mut filter = coverage(&prefixes.borrow_and_update());
    let mut attempt = 0u32;
    loop {
        let session = async {
            let pc = tokio::time::timeout(
                CALL_TIMEOUT,
                client.partition_client(topic.clone(), partition, UnknownTopicHandling::Retry),
            )
            .await
            .map_err(|_| anyhow!("timed out"))??;
            let mut offset = tokio::time::timeout(CALL_TIMEOUT, pc.get_offset(OffsetAt::Latest))
                .await
                .map_err(|_| anyhow!("timed out"))??;
            loop {
                let (records, _high) = tokio::time::timeout(
                    CALL_TIMEOUT,
                    pc.fetch_records(offset, 1..FETCH_MAX_BYTES, 1000),
                )
                .await
                .map_err(|_| anyhow!("fetch timed out"))??;
                attempt = 0;
                if prefixes.has_changed().unwrap_or(false) {
                    filter = coverage(&prefixes.borrow_and_update());
                }
                for r in records {
                    offset = offset.max(r.offset + 1);
                    metrics::KAFKA_MESSAGES.inc();
                    let Some(value) = r.record.value else {
                        continue;
                    };
                    let Some(updates) = parse_record(&value, &collector) else {
                        metrics::KAFKA_MALFORMED.inc();
                        continue;
                    };
                    for u in updates {
                        metrics::KAFKA_UPDATES.inc();
                        let keep = u
                            .announced
                            .iter()
                            .chain(&u.withdrawn)
                            .any(|p| filter.lookup(p).is_some());
                        if keep && tx.send(FeedEvent::Update(Box::new(u))).await.is_err() {
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                }
            }
        };
        match session.await {
            Ok(()) => return,
            Err(e) => {
                tracing::warn!(topic = %topic, partition, error = %e, "Kafka partition consumer error")
            }
        }
        tokio::time::sleep(backoff(attempt)).await;
        attempt = attempt.saturating_add(1);
    }
}

/// Run the Kafka feed until shutdown.
pub async fn run(
    cfg: KafkaConfig,
    prefixes: watch::Receiver<Vec<IpNet>>,
    grace: Duration,
    tx: mpsc::Sender<FeedEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut outage = Outage::new(FEED_NAME, grace);
    let mut tasks: HashMap<(String, i32), JoinHandle<()>> = HashMap::new();
    let mut client: Option<Arc<Client>> = None;
    let mut attempt = 0u32;
    loop {
        let result = async {
            let c = match &client {
                Some(c) => c.clone(),
                None => {
                    let c = Arc::new(connect(&cfg).await?);
                    client = Some(c.clone());
                    c
                }
            };
            let wanted = matching_topics(&c, &cfg).await?;
            Ok::<_, anyhow::Error>((c, wanted))
        }
        .await;
        let delay = match result {
            Ok((c, wanted)) => {
                attempt = 0;
                tasks.retain(|k, h| {
                    let keep = wanted.contains(k) && !h.is_finished();
                    if !keep {
                        h.abort();
                    }
                    keep
                });
                for k in wanted {
                    if let std::collections::hash_map::Entry::Vacant(slot) = tasks.entry(k) {
                        let (topic, partition) = slot.key().clone();
                        slot.insert(tokio::spawn(consume_partition(
                            c.clone(),
                            topic,
                            partition,
                            prefixes.clone(),
                            tx.clone(),
                        )));
                    }
                }
                metrics::KAFKA_PARTITIONS.set(tasks.len() as u64);
                if tasks.is_empty() {
                    tracing::warn!("no Kafka topic matches feeds.routeviews_kafka.topics");
                } else {
                    tracing::info!(partitions = tasks.len(), "consuming Kafka partitions");
                }
                for ev in outage.ok() {
                    if tx.send(ev).await.is_err() {
                        break;
                    }
                }
                Duration::from_secs(cfg.topic_refresh_secs)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Kafka feed error");
                client = None;
                for ev in outage.fail() {
                    if tx.send(ev).await.is_err() {
                        break;
                    }
                }
                let d = backoff(attempt);
                attempt = attempt.saturating_add(1);
                d
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown.changed() => break,
        }
        if tx.is_closed() {
            break;
        }
    }
    for (_, h) in tasks {
        h.abort();
    }
    metrics::KAFKA_PARTITIONS.set(0);
}

/// `vigil kafka-topics`: list matching topics (configuration helper).
pub async fn list(cfg: &KafkaConfig) -> Result<Vec<(String, i32)>> {
    let c = connect(cfg).await?;
    matching_topics(&c, cfg).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_names_and_globs() {
        assert_eq!(
            topic_collector("routeviews.amsix.ams.61955.bmp_raw"),
            "routeviews.amsix.ams"
        );
        assert_eq!(topic_collector("weird"), "weird");
        let globs = vec!["routeviews.amsix.*.bmp_raw".to_string()];
        assert!(topic_selected("routeviews.amsix.ams.61955.bmp_raw", &globs));
        assert!(!topic_selected("routeviews.linx.6830.bmp_raw", &globs));
    }

    /// OpenBMP v1.7 header + BMP v3 Route Monitoring carrying one UPDATE
    /// (198.51.100.0/24, AS_PATH 64496 64511), built by hand.
    fn sample_record() -> Vec<u8> {
        // BGP UPDATE
        let mut attrs = Vec::new();
        attrs.extend([0x40, 1, 1, 0]); // ORIGIN IGP
        attrs.extend([0x40, 2, 10, 2, 2, 0, 0, 0xfb, 0xf0, 0, 0, 0xfb, 0xff]); // AS_PATH (4-byte)
        attrs.extend([0x40, 3, 4, 192, 0, 2, 1]); // NEXT_HOP
        let nlri = [24u8, 198, 51, 100];
        let mut upd = Vec::new();
        upd.extend([0u8, 0]); // withdrawn len
        upd.extend((attrs.len() as u16).to_be_bytes());
        upd.extend(&attrs);
        upd.extend(nlri);
        let mut bgp = vec![0xffu8; 16];
        bgp.extend(((19 + upd.len()) as u16).to_be_bytes());
        bgp.push(2);
        bgp.extend(&upd);
        // BMP per-peer header (42 bytes)
        let mut pph = vec![0u8, 0]; // type global, flags: IPv4, 4-byte AS
        pph.extend([0u8; 8]); // distinguisher
        pph.extend([0u8; 12]);
        pph.extend([192, 0, 2, 1]); // peer address
        pph.extend(64496u32.to_be_bytes());
        pph.extend([192, 0, 2, 1]); // BGP id
        pph.extend(1_794_556_800u32.to_be_bytes());
        pph.extend(0u32.to_be_bytes());
        let body_len = 6 + pph.len() + bgp.len();
        let mut bmp = vec![3u8];
        bmp.extend((body_len as u32).to_be_bytes());
        bmp.push(0); // Route Monitoring
        bmp.extend(&pph);
        bmp.extend(&bgp);
        // OpenBMP header
        let collector = b"vigil-test";
        let router = b"rv";
        let mut hdr = Vec::new();
        hdr.extend(b"OBMP");
        hdr.extend([1u8, 7]);
        let hdr_len_pos = hdr.len();
        hdr.extend([0u8, 0]); // header length, fixed below
        hdr.extend((bmp.len() as u32).to_be_bytes());
        hdr.push(0x80); // flags: router message, IPv4
        hdr.push(12); // object type BMP_RAW
        hdr.extend(1_794_556_800u32.to_be_bytes());
        hdr.extend(0u32.to_be_bytes());
        hdr.extend([0u8; 16]); // collector hash
        hdr.extend((collector.len() as u16).to_be_bytes());
        hdr.extend(collector);
        hdr.extend([0u8; 16]); // router hash
        let mut ip = vec![0u8; 16];
        ip[..4].copy_from_slice(&[192, 0, 2, 254]);
        hdr.extend(ip);
        hdr.extend((router.len() as u16).to_be_bytes());
        hdr.extend(router);
        hdr.extend(1u32.to_be_bytes()); // row count
        let len = hdr.len() as u16;
        hdr[hdr_len_pos..hdr_len_pos + 2].copy_from_slice(&len.to_be_bytes());
        hdr.extend(&bmp);
        hdr
    }

    #[test]
    fn parses_openbmp_route_monitoring() {
        let updates = parse_record(&sample_record(), "routeviews.test").expect("parse");
        assert_eq!(updates.len(), 1);
        let u = &updates[0];
        assert_eq!(u.announced[0].to_string(), "198.51.100.0/24");
        assert_eq!(u.path_string(), "64496 64511");
        assert_eq!(u.peer_asn, 64496);
        assert_eq!(u.collector, "routeviews.test");
    }

    #[test]
    fn garbage_records_are_rejected_without_panicking() {
        assert!(parse_record(b"", "x").is_none());
        assert!(parse_record(b"OBMP\x01\x07\xff\xff", "x").is_none());
        let mut truncated = sample_record();
        truncated.truncate(truncated.len() - 5);
        assert!(parse_record(&truncated, "x").is_none_or(|v| v.is_empty()));
        for seed in 0..200u64 {
            let mut r = sample_record();
            let mut rng = fastrand::Rng::with_seed(seed);
            for _ in 0..4 {
                let i = rng.usize(..r.len());
                r[i] = rng.u8(..);
            }
            let _ = parse_record(&r, "x");
        }
    }
}
