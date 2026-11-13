//! `vigil run` / `vigil service run`: wires feeds, the detector, pollers, the
//! management listener and the llcforge-alert dispatcher, and handles reloads.

use crate::alert::{Alert, TOOL};
use crate::api::{self, ApiState};
use crate::asinfo::AsInfo;
use crate::blackhole::{self, BlackholeTracker};
use crate::config::Config;
use crate::detector::Detector;
use crate::feed::{self, FeedEvent};
use crate::incidents::IncidentStore;
use crate::matcher::Watched;
use crate::notary::Notary;
use crate::outlet::{Outlet, Outputs};
use crate::ripestat::RipeStat;
use crate::visibility::VisibilityTracker;
use crate::{kafka, metrics, mrt};
use anyhow::{Context, Result};
use chrono::{Duration as ChronoDuration, Utc};
use ipnet::IpNet;
use llcforge_alert::{
    health_router, reload_router, silences_router, ApiToken, Dispatcher, DispatcherOptions,
    Readiness, ReloadSignal, ServiceSpec, Shutdown, SilenceStore,
};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

pub const SPEC: ServiceSpec = ServiceSpec {
    bin: TOOL,
    display_name: "Vigil",
    description: "Real-time BGP origin hijack detection over public route collector feeds",
};

/// Entry point for `run_foreground` / the Windows service: owns its runtime.
pub fn daemon(config: PathBuf, shutdown: Shutdown) -> Result<()> {
    tokio::runtime::Runtime::new()
        .context("cannot start async runtime")?
        .block_on(run(config, shutdown))
}

pub fn detector(cfg: &Config, extra: &[Watched]) -> Result<Detector> {
    Ok(Detector::new(
        cfg.matcher_with(extra)?,
        ChronoDuration::seconds(cfg.detection.aggregation_window_secs as i64),
        ChronoDuration::seconds(cfg.detection.dedup_secs as i64),
    )
    .with_resolve_after(ChronoDuration::seconds(
        cfg.detection.resolve_after_secs as i64,
    )))
}

fn ripestat(cfg: &Config, client: &reqwest::Client) -> RipeStat {
    RipeStat::new(
        client.clone(),
        &cfg.ripestat.base_url,
        Duration::from_millis(cfg.ripestat.timeout_ms),
    )
}

fn start_dispatcher(
    cfg: &Config,
    data: &Path,
    silences: &Arc<SilenceStore>,
    client: &reqwest::Client,
) -> Result<Dispatcher> {
    Ok(Dispatcher::start(
        &cfg.alerts,
        DispatcherOptions {
            tool: TOOL.into(),
            data_dir: Some(data.to_path_buf()),
            silences: Some(silences.clone()),
            http: Some(client.clone()),
        },
    )?)
}

fn outputs(cfg: &Config, d: &Dispatcher, client: &reqwest::Client) -> Result<Outputs> {
    let notary = cfg
        .enrich
        .notary
        .as_ref()
        .map(|n| Notary::new(client.clone(), &n.url, Duration::from_millis(n.timeout_ms)));
    let asinfo = match &cfg.enrich.asnames {
        Some(a) => Some(Arc::new(AsInfo::new(
            a.file.as_deref(),
            a.ripestat.then(|| ripestat(cfg, client)),
            Duration::from_millis(a.timeout_ms),
        )?)),
        None => None,
    };
    Ok(Outputs {
        handle: d.handle(),
        notary,
        asinfo,
    })
}

/// Keeps `[[asn]]` prefix lists fresh; a failed fetch keeps the previous list.
async fn asn_watcher(
    mut cfg_rx: watch::Receiver<Arc<Config>>,
    client: reqwest::Client,
    tx: watch::Sender<Vec<Watched>>,
) {
    let mut known: BTreeMap<u32, Vec<IpNet>> = BTreeMap::new();
    loop {
        let cfg = cfg_rx.borrow_and_update().clone();
        let rs = ripestat(&cfg, &client);
        let mut watched = Vec::new();
        for a in &cfg.asns {
            match rs.announced_prefixes(a.asn).await {
                Ok(list) => {
                    tracing::info!(asn = a.asn, prefixes = list.len(), "ASN prefixes refreshed");
                    known.insert(a.asn, list);
                }
                Err(e) => tracing::warn!(asn = a.asn, error = %e, "ASN prefix refresh failed"),
            }
            for p in known.get(&a.asn).into_iter().flatten() {
                let mut origins = vec![a.asn];
                origins.extend(&a.extra_origins);
                watched.push(Watched {
                    prefix: *p,
                    origins,
                    max_length: p.prefix_len(),
                    upstreams: a.upstreams.clone(),
                    dormant: false,
                    group: a.group.clone(),
                });
            }
        }
        tx.send_if_modified(|cur| {
            let changed = *cur != watched;
            *cur = watched;
            changed
        });
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(cfg.ripestat.asn_refresh_secs)) => {}
            r = cfg_rx.changed() => if r.is_err() { return },
        }
    }
}

async fn visibility_poller(
    cfg: Arc<Config>,
    client: reqwest::Client,
    tracker: Arc<VisibilityTracker>,
    outlet: Outlet,
) {
    let rs = ripestat(&cfg, &client);
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.visibility.poll_secs));
    loop {
        tick.tick().await;
        for p in tracker.prefixes() {
            match rs.visibility(&p).await {
                Ok(v) => {
                    if let Some(a) = tracker.apply_poll(&p, v, Utc::now()) {
                        outlet.send_kit(a);
                    }
                }
                Err(e) => tracing::debug!(prefix = %p, error = %e, "visibility poll failed"),
            }
            // Be gentle with RIPEstat.
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

struct Core {
    detector: Detector,
    visibility: Arc<VisibilityTracker>,
    blackholes: Arc<BlackholeTracker>,
    outlet: Outlet,
    readiness: Readiness,
    prefix_tx: watch::Sender<Vec<IpNet>>,
}

impl Core {
    fn rebuild(&mut self, cfg: &Config, asn: &[Watched], bh: &HashSet<IpNet>) {
        match cfg.matcher_with(asn) {
            Ok(m) => {
                self.detector.set_matcher(m);
                let secs = |s: u64| ChronoDuration::seconds(s as i64);
                self.detector.configure(
                    secs(cfg.detection.aggregation_window_secs),
                    secs(cfg.detection.dedup_secs),
                    secs(cfg.detection.resolve_after_secs),
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot rebuild the watch list; keeping the old one");
                return;
            }
        }
        self.detector.set_blackholes(bh.clone());
        let watched = self.detector.matcher().watched();
        self.visibility.set_prefixes(watched);
        metrics::WATCHED_PREFIXES.set(watched.len() as u64);
        let mut subs: Vec<IpNet> = watched.iter().map(|w| w.prefix).collect();
        let covered = crate::mrt::coverage(&subs);
        subs.extend(bh.iter().filter(|p| covered.lookup(p).is_none()));
        self.prefix_tx.send_if_modified(|cur| {
            let changed = *cur != subs;
            *cur = subs;
            changed
        });
    }

    fn flush(&mut self, force: bool) {
        for a in self.detector.flush(Utc::now(), force) {
            self.outlet.send_route(a);
        }
        metrics::ALERTS_SUPPRESSED.set(self.detector.stats.suppressed);
        metrics::SIGHTINGS_DROPPED.set(self.detector.stats.dropped);
        metrics::OPEN_INCIDENTS.set(self.detector.open_count() as u64);
    }

    fn event(&mut self, ev: FeedEvent) {
        match ev {
            FeedEvent::Update(u) => {
                self.detector.observe(&u, Utc::now());
                for a in self.visibility.observe(&u) {
                    self.outlet.send_kit(a);
                }
                for a in self.blackholes.observe(&u) {
                    self.outlet.send_kit(a);
                }
            }
            FeedEvent::Down { feed, since } => self.outlet.send(&Alert::FeedDown { feed, since }),
            FeedEvent::Restored { feed, down_secs } => {
                self.outlet.send(&Alert::FeedRestored { feed, down_secs })
            }
            FeedEvent::Connected { feed, up } => self.readiness.set(&feed, up),
        }
    }
}

async fn run(path: PathBuf, mut shutdown: Shutdown) -> Result<()> {
    let cfg = Arc::new(Config::load(&path)?);
    cfg.check_secrets()?;
    let data = cfg.data_dir();
    std::fs::create_dir_all(&data)
        .with_context(|| format!("cannot create data directory {}", data.display()))?;
    let client = crate::http_client()?;
    let silences = Arc::new(SilenceStore::open(cfg.silences.path_or(&data))?);
    let incidents = Arc::new(IncidentStore::open(data.join("incidents.json"))?);
    let readiness = Readiness::new();

    let mut dispatcher = start_dispatcher(&cfg, &data, &silences, &client)?;
    let (out_tx, out_rx) = watch::channel(Arc::new(outputs(&cfg, &dispatcher, &client)?));
    let outlet = Outlet::new(out_rx, incidents.clone());
    let visibility = Arc::new(VisibilityTracker::new(cfg.visibility.min_ratio));
    let blackholes = Arc::new(BlackholeTracker::default());
    let mut reload = ReloadSignal::standard(Some(path.clone()))?;

    // Management listener: /metrics, /healthz, /readyz, /v1/*.
    let mut server = None;
    if let Some(addr) = cfg.listen() {
        let token = cfg
            .api
            .token_env
            .as_deref()
            .map(ApiToken::from_env)
            .transpose()?;
        let state = ApiState {
            visibility: visibility.clone(),
            incidents: incidents.clone(),
            outlet: outlet.clone(),
        };
        let mut admin = health_router(readiness.clone()).merge(api::router(state, token));
        if let Some(var) = &cfg.silences.api_token_env {
            admin = admin.merge(silences_router(silences.clone(), ApiToken::from_env(var)?));
        }
        if let Some(var) = &cfg.health.admin_token_env {
            admin = admin.merge(reload_router(reload.trigger(), ApiToken::from_env(var)?));
        }
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("cannot bind management listener {addr}"))?;
        tracing::info!(%addr, "management listener (metrics, health, API) started");
        let mut sd = shutdown.clone();
        server = Some(tokio::spawn(async move {
            let r = axum::serve(listener, admin)
                .with_graceful_shutdown(async move { sd.wait().await })
                .await;
            if let Err(e) = r {
                tracing::error!(error = %e, "management listener failed");
            }
        }));
    }

    let (cfg_tx, cfg_rx) = watch::channel(cfg.clone());
    let (prefix_tx, prefix_rx) = watch::channel(Vec::<IpNet>::new());
    let (asn_tx, mut asn_rx) = watch::channel(Vec::<Watched>::new());
    let (bh_tx, mut bh_rx) = watch::channel(HashSet::<IpNet>::new());
    let (feed_tx, mut feed_rx) = mpsc::channel::<FeedEvent>(4096);
    let (stop_tx, stop_rx) = watch::channel(false);
    let grace = Duration::from_secs(cfg.feeds.feed_down_grace_secs);

    let mut core = Core {
        detector: detector(&cfg, &[])?,
        visibility: visibility.clone(),
        blackholes: blackholes.clone(),
        outlet: outlet.clone(),
        readiness: readiness.clone(),
        prefix_tx,
    };
    core.rebuild(&cfg, &[], &HashSet::new());

    let mut feeds = Vec::new();
    let mut aux = Vec::new();
    if cfg.feeds.ris_live {
        readiness.register(feed::FEED_NAME);
        feeds.push(tokio::spawn(feed::run_ris_live(
            cfg.feeds.ris_live_url.clone(),
            prefix_rx.clone(),
            grace,
            feed_tx.clone(),
            stop_rx.clone(),
        )));
    }
    if let Some(k) = &cfg.feeds.routeviews_kafka {
        readiness.register(kafka::FEED_NAME);
        feeds.push(tokio::spawn(kafka::run(
            k.clone(),
            prefix_rx.clone(),
            grace,
            feed_tx.clone(),
            stop_rx.clone(),
        )));
    }
    if let Some(b) = &cfg.feeds.bgpkit {
        readiness.register(mrt::FEED_NAME);
        aux.push(tokio::spawn(mrt::run_broker_feed(
            b.clone(),
            client.clone(),
            data.join("tmp"),
            prefix_rx.clone(),
            grace,
            feed_tx.clone(),
        )));
    }
    drop(feed_tx);
    if !cfg.asns.is_empty() {
        aux.push(tokio::spawn(asn_watcher(
            cfg_rx.clone(),
            client.clone(),
            asn_tx,
        )));
    }
    if cfg.visibility.enabled {
        aux.push(tokio::spawn(visibility_poller(
            cfg.clone(),
            client.clone(),
            visibility.clone(),
            outlet.clone(),
        )));
    }
    if let Some(eh) = &cfg.event_horizon {
        aux.push(tokio::spawn(blackhole::run(
            eh.clone(),
            client.clone(),
            ripestat(&cfg, &client),
            blackholes.clone(),
            outlet.clone(),
            bh_tx,
        )));
    }

    let mut core_cfg = cfg_rx.clone();
    let core_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                ev = feed_rx.recv() => match ev {
                    Some(ev) => core.event(ev),
                    None => break,
                },
                _ = tick.tick() => core.flush(false),
                r = core_cfg.changed() => {
                    if r.is_err() { break; }
                    let c = core_cfg.borrow_and_update().clone();
                    let (a, b) = (asn_rx.borrow().clone(), bh_rx.borrow().clone());
                    core.rebuild(&c, &a, &b);
                }
                Ok(()) = asn_rx.changed() => {
                    let c = core_cfg.borrow().clone();
                    let (a, b) = (asn_rx.borrow_and_update().clone(), bh_rx.borrow().clone());
                    core.rebuild(&c, &a, &b);
                }
                Ok(()) = bh_rx.changed() => {
                    let c = core_cfg.borrow().clone();
                    let (a, b) = (asn_rx.borrow().clone(), bh_rx.borrow_and_update().clone());
                    core.rebuild(&c, &a, &b);
                }
            }
        }
        core.flush(true);
    });

    tracing::info!("vigil running; press Ctrl+C to stop");
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            Some(reason) = reload.recv() => {
                tracing::info!(?reason, "reloading configuration");
                let new = match Config::load(&path).and_then(|c| c.check_secrets().map(|_| c)) {
                    Ok(c) => Arc::new(c),
                    Err(e) => {
                        tracing::error!(error = %format!("{e:#}"), "invalid configuration; keeping the old one");
                        continue;
                    }
                };
                match start_dispatcher(&new, &data, &silences, &client)
                    .and_then(|d| outputs(&new, &d, &client).map(|o| (d, o)))
                {
                    Ok((d, o)) => {
                        let _ = out_tx.send(Arc::new(o));
                        std::mem::replace(&mut dispatcher, d)
                            .shutdown(Duration::from_secs(5))
                            .await;
                    }
                    Err(e) => {
                        tracing::error!(error = %format!("{e:#}"), "cannot apply [alerts]; keeping the old outputs");
                    }
                }
                let _ = cfg_tx.send(new);
                tracing::info!("configuration reloaded (feed, listener and data_dir changes need a restart)");
            }
        }
    }

    tracing::info!("shutting down");
    let _ = stop_tx.send(true);
    for t in &aux {
        t.abort();
    }
    // Feeds stop -> detector flushes pending groups -> enrichment drains -> dispatcher drains.
    let drain = async {
        for f in feeds {
            let _ = f.await;
        }
        for t in aux {
            let _ = t.await;
        }
        let _ = core_task.await;
        outlet.drain(Duration::from_secs(5)).await;
    };
    if tokio::time::timeout(Duration::from_secs(15), drain)
        .await
        .is_err()
    {
        tracing::warn!("shutdown timed out; some alerts may not have been delivered");
    }
    drop(cfg_tx);
    dispatcher.shutdown(Duration::from_secs(5)).await;
    if let Some(s) = server {
        let _ = tokio::time::timeout(Duration::from_secs(2), s).await;
    }
    Ok(())
}
