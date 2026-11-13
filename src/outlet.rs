//! Where alerts leave Vigil: optional enrichment (RPKI via Notary, AS names),
//! the incident timeline, then the llcforge-beacon dispatcher. Enrichment runs in
//! its own task with a hard timeout per lookup, so it never stalls detection.

use crate::alert::{Alert, RouteAlert};
use crate::asinfo::AsInfo;
use crate::incidents::IncidentStore;
use crate::metrics;
use crate::notary::Notary;
use llcforge_beacon::AlertHandle;
use std::sync::Arc;
use tokio::sync::{watch, Semaphore};

/// Replaced as a whole on config reload.
pub struct Outputs {
    pub handle: AlertHandle,
    pub notary: Option<Notary>,
    pub asinfo: Option<Arc<AsInfo>>,
}

#[derive(Clone)]
pub struct Outlet {
    outputs: watch::Receiver<Arc<Outputs>>,
    incidents: Arc<IncidentStore>,
    slots: Arc<Semaphore>,
}

impl Outlet {
    pub fn new(outputs: watch::Receiver<Arc<Outputs>>, incidents: Arc<IncidentStore>) -> Self {
        Self {
            outputs,
            incidents,
            slots: Arc::new(Semaphore::new(32)),
        }
    }

    /// Wait (bounded) for in-flight enrichment tasks to hand their alerts over.
    pub async fn drain(&self, timeout: std::time::Duration) {
        let _ = tokio::time::timeout(timeout, self.slots.acquire_many(32)).await;
    }

    pub fn outputs(&self) -> Arc<Outputs> {
        self.outputs.borrow().clone()
    }

    /// Record and dispatch a finished alert (never blocks).
    pub fn send_kit(&self, a: llcforge_beacon::Alert) {
        metrics::ALERTS.inc();
        self.incidents.record(&a);
        self.outputs().handle.send(a);
    }

    pub fn send(&self, a: &Alert) {
        match a {
            Alert::Route(r) => self.send_route(r.clone()),
            other => self.send_kit(other.to_kit()),
        }
    }

    /// Enrich in the background, then dispatch.
    pub fn send_route(&self, mut r: RouteAlert) {
        let out = self.outputs();
        if out.notary.is_none() && out.asinfo.is_none() {
            self.send_kit(Alert::Route(r).to_kit());
            return;
        }
        let me = self.clone();
        let slots = self.slots.clone();
        tokio::spawn(async move {
            let _permit = slots.acquire_owned().await;
            enrich(&out, &mut r).await;
            me.send_kit(Alert::Route(r).to_kit());
        });
    }
}

/// Fill RPKI state and AS names; every lookup is individually time-boxed.
pub async fn enrich(out: &Outputs, r: &mut RouteAlert) {
    let rpki = async {
        match (&out.notary, r.origin_asn) {
            (Some(n), Some(asn)) => {
                let s = n.validity(&r.prefix, asn).await;
                if s.is_none() {
                    metrics::ENRICH_FAILURES.inc();
                }
                s
            }
            _ => None,
        }
    };
    let names = async {
        let Some(info) = &out.asinfo else {
            return Vec::new();
        };
        let mut lines = Vec::new();
        for asn in r.origin_asn.into_iter().chain(r.upstream) {
            match info.lookup(asn).await {
                Some(m) => lines.push(m.label(asn)),
                None => metrics::ENRICH_FAILURES.inc(),
            }
        }
        lines
    };
    let (rpki, names) = tokio::join!(rpki, names);
    r.rpki = rpki;
    r.as_info = names;
}
