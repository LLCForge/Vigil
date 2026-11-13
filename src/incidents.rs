//! Incident timeline: every alert id becomes an incident with an ordered list
//! of events (raised, re-raised, resolved). Persisted as one JSON file with an
//! atomic replace, bounded in incidents and events per incident.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use llcforge_alert::{Alert, Severity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_INCIDENTS: usize = 1000;
const MAX_EVENTS: usize = 100;
const MAX_FILE_BYTES: u64 = 32 << 20;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub at: DateTime<Utc>,
    pub severity: Severity,
    pub resolved: bool,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub kind: String,
    pub resource: Option<String>,
    pub opened_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub events: Vec<Event>,
}

impl Incident {
    pub fn is_open(&self) -> bool {
        self.resolved_at.is_none()
    }
}

pub struct IncidentStore {
    path: Option<PathBuf>,
    items: Mutex<Vec<Incident>>,
}

impl IncidentStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            items: Mutex::new(Vec::new()),
        }
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let items = Self::read(&path)?;
        Ok(Self {
            path: Some(path),
            items: Mutex::new(items),
        })
    }

    /// Read a store file (missing file = empty).
    pub fn read(path: &Path) -> Result<Vec<Incident>> {
        match std::fs::metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
            Ok(m) => anyhow::ensure!(m.len() <= MAX_FILE_BYTES, "{} is too large", path.display()),
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("corrupt {}", path.display()))
    }

    /// Record an alert that was handed to the dispatcher.
    pub fn record(&self, a: &Alert) {
        let snapshot = {
            let mut items = self.items.lock().unwrap_or_else(|p| p.into_inner());
            let at = Utc::now();
            let event = Event {
                at,
                severity: a.severity,
                resolved: a.resolved,
                title: a.title.chars().take(512).collect(),
            };
            match items.iter_mut().rev().find(|i| i.id == a.id && i.is_open()) {
                Some(i) => {
                    if i.events.len() >= MAX_EVENTS {
                        i.events.remove(1); // keep the opening event
                    }
                    i.events.push(event);
                    if a.resolved {
                        i.resolved_at = Some(at);
                    }
                }
                None if a.resolved => return, // nothing open to resolve
                None => {
                    if items.len() >= MAX_INCIDENTS {
                        // Drop the oldest resolved incident, else the oldest one.
                        let idx = items.iter().position(|i| !i.is_open()).unwrap_or(0);
                        items.remove(idx);
                    }
                    items.push(Incident {
                        id: a.id.clone(),
                        kind: a.kind.clone(),
                        resource: a.resource.clone(),
                        opened_at: a.first_seen.min(at),
                        resolved_at: None,
                        events: vec![event],
                    });
                }
            }
            items.clone()
        };
        if let Some(path) = &self.path {
            if let Err(e) = write_atomic(path, &snapshot) {
                tracing::warn!(error = %e, "cannot persist incident timeline");
            }
        }
    }

    pub fn list(&self, open_only: bool) -> Vec<Incident> {
        let items = self.items.lock().unwrap_or_else(|p| p.into_inner());
        items
            .iter()
            .rev()
            .filter(|i| !open_only || i.is_open())
            .cloned()
            .collect()
    }
}

fn write_atomic(path: &Path, items: &[Incident]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(items)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Human-readable timeline for `vigil incidents`.
pub fn render(items: &[Incident]) -> String {
    let ts = |t: &DateTime<Utc>| t.format("%Y-%m-%d %H:%M:%SZ").to_string();
    let mut out = String::new();
    for i in items {
        let state = match &i.resolved_at {
            Some(t) => format!("resolved {}", ts(t)),
            None => "OPEN".into(),
        };
        out.push_str(&format!(
            "{}  [{state}]  opened {}\n",
            i.id,
            ts(&i.opened_at)
        ));
        for e in &i.events {
            let what = if e.resolved {
                "resolved".to_string()
            } else {
                e.severity.to_string()
            };
            out.push_str(&format!("  {}  {what:<8}  {}\n", ts(&e.at), e.title));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(resolved: bool) -> Alert {
        Alert::new(
            "vigil",
            "origin_hijack",
            Severity::Critical,
            "ORIGIN HIJACK",
        )
        .resource("198.51.100.0/24")
        .resolved(resolved)
    }

    #[test]
    fn opens_appends_resolves_and_persists() {
        let dir = std::env::temp_dir().join(format!("vigil-inc-{}", std::process::id()));
        let path = dir.join("incidents.json");
        let store = IncidentStore::open(&path).unwrap();
        store.record(&alert(true)); // resolution without an incident: ignored
        assert!(store.list(false).is_empty());
        store.record(&alert(false));
        store.record(&alert(false));
        assert_eq!(store.list(true).len(), 1);
        store.record(&alert(true));
        let all = store.list(false);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].events.len(), 3);
        assert!(!all[0].is_open());
        assert!(store.list(true).is_empty());

        let reread = IncidentStore::read(&path).unwrap();
        assert_eq!(reread, all);
        assert!(render(&reread).contains("resolved"));
        store.record(&alert(false));
        assert_eq!(store.list(false).len(), 2, "recurrence is a new incident");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn bounded_incidents_and_events() {
        let store = IncidentStore::in_memory();
        for i in 0..MAX_INCIDENTS + 5 {
            store.record(&Alert::new("vigil", "x", Severity::Info, "t").resource(format!("r{i}")));
        }
        assert_eq!(store.list(false).len(), MAX_INCIDENTS);
        for _ in 0..MAX_EVENTS + 5 {
            store.record(&alert(false));
        }
        let i = store
            .list(false)
            .into_iter()
            .find(|i| i.kind == "origin_hijack")
            .unwrap();
        assert_eq!(i.events.len(), MAX_EVENTS);
    }
}
