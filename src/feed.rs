//! RIPE RIS Live WebSocket client: subscribes to every watched prefix (plus
//! more-specifics), follows changes to the watch list on the open session
//! (`ris_subscribe` / `ris_unsubscribe`), reconnects with jittered exponential
//! backoff and reports outages longer than the grace period.

use crate::metrics;
use crate::ris::{parse_message, ParseError, RisMessage, RisUpdate, MAX_MESSAGE_BYTES};
use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use ipnet::IpNet;
use serde_json::json;
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub const FEED_NAME: &str = "ris-live";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const PING_EVERY: Duration = Duration::from_secs(30);
/// No frame at all (data or pong) for this long means the session is dead.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A session must last this long before the backoff resets.
const STABLE_AFTER: Duration = Duration::from_secs(60);

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug)]
pub enum FeedEvent {
    Update(Box<RisUpdate>),
    Down {
        feed: String,
        since: DateTime<Utc>,
    },
    Restored {
        feed: String,
        down_secs: i64,
    },
    /// Session state for readiness (`/readyz`).
    Connected {
        feed: String,
        up: bool,
    },
}

/// Jittered exponential backoff: 1s, 2s, 4s ... capped at 60s, scaled by 50-100%.
pub fn backoff(attempt: u32) -> Duration {
    let base = Duration::from_secs(1u64 << attempt.min(6)).min(BACKOFF_MAX);
    base.mul_f64(0.5 + fastrand::f64() * 0.5)
}

fn sub_message(kind: &str, p: &IpNet) -> Message {
    let sub = json!({
        "type": kind,
        "data": {
            "prefix": p.to_string(),
            "moreSpecific": true,
            "type": "UPDATE",
            "socketOptions": { "includeRaw": false }
        }
    });
    Message::Text(sub.to_string().into())
}

async fn connect(url: &str, prefixes: &BTreeSet<IpNet>) -> Result<Ws> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    let (mut ws, _) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async_with_config(url, Some(config), false),
    )
    .await
    .map_err(|_| anyhow!("connect timed out"))??;
    for p in prefixes {
        ws.send(sub_message("ris_subscribe", p)).await?;
    }
    Ok(ws)
}

/// Read frames until the session fails. Returns `Ok(())` only when the receiver is gone.
async fn pump(
    ws: Ws,
    tx: &mpsc::Sender<FeedEvent>,
    subscribed: &mut BTreeSet<IpNet>,
    prefixes: &mut watch::Receiver<Vec<IpNet>>,
) -> Result<()> {
    let (mut sink, mut stream) = ws.split();
    let mut ping = tokio::time::interval(PING_EVERY);
    let mut last_rx = Instant::now();
    loop {
        tokio::select! {
            changed = prefixes.changed() => {
                if changed.is_err() {
                    return Ok(()); // owner gone: shutting down
                }
                let want: BTreeSet<IpNet> = prefixes.borrow_and_update().iter().copied().collect();
                for p in want.difference(subscribed) {
                    sink.send(sub_message("ris_subscribe", p)).await?;
                }
                for p in subscribed.difference(&want) {
                    sink.send(sub_message("ris_unsubscribe", p)).await?;
                }
                tracing::info!(prefixes = want.len(), "RIS Live subscriptions updated");
                *subscribed = want;
            }
            _ = ping.tick() => {
                sink.send(Message::Text(r#"{"type":"ping"}"#.into())).await?;
            }
            _ = tokio::time::sleep_until(last_rx + IDLE_TIMEOUT) => {
                bail!("no data for {}s", IDLE_TIMEOUT.as_secs());
            }
            frame = stream.next() => {
                let Some(frame) = frame else { bail!("connection closed") };
                last_rx = Instant::now();
                match frame? {
                    Message::Text(text) => {
                        if !handle_text(text.as_str(), tx).await {
                            return Ok(());
                        }
                    }
                    Message::Binary(_) => metrics::RIS_MALFORMED.inc(),
                    Message::Close(_) => bail!("server closed the connection"),
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                }
            }
        }
    }
}

/// Returns false when the receiver has gone away.
async fn handle_text(text: &str, tx: &mpsc::Sender<FeedEvent>) -> bool {
    metrics::RIS_MESSAGES.inc();
    match parse_message(text) {
        Ok(RisMessage::Update(u)) => {
            let lag = (Utc::now() - u.timestamp).num_milliseconds().max(0);
            metrics::RIS_LAG_MS.set(lag as u64);
            tx.send(FeedEvent::Update(Box::new(u))).await.is_ok()
        }
        Ok(RisMessage::Error(msg)) => {
            tracing::warn!(message = %msg, "RIS Live reported an error");
            true
        }
        Ok(RisMessage::Other) => true,
        Err(ParseError::Oversized(n)) => {
            metrics::RIS_OVERSIZED.inc();
            tracing::debug!(bytes = n, "dropped oversized RIS message");
            true
        }
        Err(e) => {
            metrics::RIS_MALFORMED.inc();
            tracing::debug!(error = %e, "dropped malformed RIS message");
            true
        }
    }
}

/// Run the RIS Live client until shutdown is signalled or the receiver closes.
/// `prefixes` is the live watch list (watched prefixes plus blackhole routes).
pub async fn run_ris_live(
    url: String,
    mut prefixes: watch::Receiver<Vec<IpNet>>,
    grace: Duration,
    tx: mpsc::Sender<FeedEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut down_since = (Instant::now(), Utc::now());
    let mut alerted = false;
    let mut attempt = 0u32;
    loop {
        let mut subscribed: BTreeSet<IpNet> =
            prefixes.borrow_and_update().iter().copied().collect();
        let connected = tokio::select! {
            r = connect(&url, &subscribed) => r,
            _ = shutdown.changed() => return,
        };
        match connected {
            Ok(ws) => {
                tracing::info!(prefixes = subscribed.len(), "connected to RIS Live");
                metrics::RIS_CONNECTED.set(1);
                let up = FeedEvent::Connected {
                    feed: FEED_NAME.into(),
                    up: true,
                };
                if tx.send(up).await.is_err() {
                    return;
                }
                if alerted {
                    let down_secs = down_since.0.elapsed().as_secs() as i64;
                    let ev = FeedEvent::Restored {
                        feed: FEED_NAME.into(),
                        down_secs,
                    };
                    if tx.send(ev).await.is_err() {
                        return;
                    }
                    alerted = false;
                }
                let started = Instant::now();
                let result = tokio::select! {
                    r = pump(ws, &tx, &mut subscribed, &mut prefixes) => r,
                    _ = shutdown.changed() => return,
                };
                metrics::RIS_CONNECTED.set(0);
                let down = FeedEvent::Connected {
                    feed: FEED_NAME.into(),
                    up: false,
                };
                if tx.send(down).await.is_err() {
                    return;
                }
                match result {
                    Ok(()) => return,
                    Err(e) => tracing::warn!(error = %e, "RIS Live session lost"),
                }
                metrics::RIS_RECONNECTS.inc();
                down_since = (Instant::now(), Utc::now());
                if started.elapsed() >= STABLE_AFTER {
                    attempt = 0;
                }
            }
            Err(e) => tracing::warn!(error = %e, "RIS Live connect failed"),
        }

        let down_for = down_since.0.elapsed();
        if !alerted && down_for >= grace {
            let ev = FeedEvent::Down {
                feed: FEED_NAME.into(),
                since: down_since.1,
            };
            if tx.send(ev).await.is_err() {
                return;
            }
            alerted = true;
        }
        let mut delay = backoff(attempt);
        attempt = attempt.saturating_add(1);
        if !alerted {
            // Wake up in time to raise FeedDown when the grace period ends.
            delay = delay.min(
                grace
                    .saturating_sub(down_for)
                    .max(Duration::from_millis(100)),
            );
        }
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// Outage bookkeeping for polled / streamed feeds without a session of their
/// own: `Down` after `grace` of continuous failure, `Restored` on recovery.
pub struct Outage {
    feed: &'static str,
    grace: Duration,
    since: Option<(Instant, DateTime<Utc>)>,
    alerted: bool,
}

impl Outage {
    pub fn new(feed: &'static str, grace: Duration) -> Self {
        Self {
            feed,
            grace,
            since: None,
            alerted: false,
        }
    }

    pub fn fail(&mut self) -> Vec<FeedEvent> {
        let (start, at) = *self.since.get_or_insert((Instant::now(), Utc::now()));
        let mut out = vec![FeedEvent::Connected {
            feed: self.feed.into(),
            up: false,
        }];
        if !self.alerted && start.elapsed() >= self.grace {
            self.alerted = true;
            out.push(FeedEvent::Down {
                feed: self.feed.into(),
                since: at,
            });
        }
        out
    }

    pub fn ok(&mut self) -> Vec<FeedEvent> {
        let mut out = vec![FeedEvent::Connected {
            feed: self.feed.into(),
            up: true,
        }];
        if let Some((start, _)) = self.since.take() {
            if std::mem::take(&mut self.alerted) {
                out.push(FeedEvent::Restored {
                    feed: self.feed.into(),
                    down_secs: start.elapsed().as_secs() as i64,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        for attempt in 0..20 {
            let d = backoff(attempt);
            let base = Duration::from_secs(1u64 << attempt.min(6)).min(BACKOFF_MAX);
            assert!(d >= base / 2 && d <= base, "attempt {attempt}: {d:?}");
        }
    }

    #[test]
    fn outage_reports_down_once_then_restored() {
        let mut o = Outage::new("bgpkit", Duration::ZERO);
        let ev = o.fail();
        assert!(matches!(ev.last(), Some(FeedEvent::Down { .. })));
        assert_eq!(
            o.fail().len(),
            1,
            "only the disconnected marker the second time"
        );
        assert!(matches!(o.ok().last(), Some(FeedEvent::Restored { .. })));
        assert_eq!(o.ok().len(), 1);
    }

    #[tokio::test]
    async fn feed_down_fires_after_grace_when_unreachable() {
        let (tx, mut rx) = mpsc::channel(4);
        let (_stop, stop_rx) = watch::channel(false);
        let (_prefixes, prefixes_rx) = watch::channel(vec!["198.51.100.0/24".parse().unwrap()]);
        // Nothing listens on port 9 locally, so every connect fails fast.
        let task = tokio::spawn(run_ris_live(
            "ws://127.0.0.1:9/".into(),
            prefixes_rx,
            Duration::from_millis(300),
            tx,
            stop_rx,
        ));
        let ev = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("FeedDown within timeout");
        assert!(matches!(ev, Some(FeedEvent::Down { .. })));
        task.abort();
    }
}
