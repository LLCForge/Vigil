//! AS holder name and registration country for alerts: a local CSV file
//! (`asn,name,country`) first, then RIPEstat, cached with a TTL and a size cap.

use crate::ripestat::RipeStat;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(24 * 3600);
const NEGATIVE_TTL: Duration = Duration::from_secs(600);
const MAX_CACHE: usize = 50_000;
const MAX_FILE_BYTES: u64 = 64 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsMeta {
    pub name: Option<String>,
    pub country: Option<String>,
}

impl AsMeta {
    /// `AS64511 EXAMPLE-NET (NL)`.
    pub fn label(&self, asn: u32) -> String {
        let mut s = format!("AS{asn}");
        if let Some(n) = &self.name {
            s.push(' ');
            s.push_str(n);
        }
        if let Some(c) = &self.country {
            s.push_str(&format!(" ({c})"));
        }
        s
    }
}

pub struct AsInfo {
    file: HashMap<u32, AsMeta>,
    ripestat: Option<RipeStat>,
    timeout: Duration,
    cache: Mutex<HashMap<u32, (Option<AsMeta>, Instant)>>,
}

fn clean(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Parse `asn,name,country` lines (`#` comments, optional `AS` prefix, name may
/// not contain commas; country optional). Bad lines are skipped.
pub fn parse_names(text: &str) -> HashMap<u32, AsMeta> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, ',');
        let Some(asn) = parts
            .next()
            .map(|a| a.trim().trim_start_matches("AS").trim_start_matches("as"))
            .and_then(|a| a.parse::<u32>().ok())
        else {
            continue;
        };
        let name = parts
            .next()
            .map(|n| clean(n, 120))
            .filter(|n| !n.is_empty());
        let country = parts
            .next()
            .map(|c| c.trim().to_ascii_uppercase())
            .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()));
        out.insert(asn, AsMeta { name, country });
    }
    out
}

impl AsInfo {
    pub fn new(file: Option<&Path>, ripestat: Option<RipeStat>, timeout: Duration) -> Result<Self> {
        let file = match file {
            Some(p) => {
                let len = std::fs::metadata(p)
                    .with_context(|| format!("cannot read {}", p.display()))?
                    .len();
                anyhow::ensure!(len <= MAX_FILE_BYTES, "{} is too large", p.display());
                parse_names(
                    &std::fs::read_to_string(p)
                        .with_context(|| format!("cannot read {}", p.display()))?,
                )
            }
            None => HashMap::new(),
        };
        Ok(Self {
            file,
            ripestat,
            timeout,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Never takes longer than the configured timeout; `None` when unknown.
    pub async fn lookup(&self, asn: u32) -> Option<AsMeta> {
        if let Some(m) = self.file.get(&asn) {
            return Some(m.clone());
        }
        {
            let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((m, at)) = cache.get(&asn) {
                let ttl = if m.is_some() { TTL } else { NEGATIVE_TTL };
                if at.elapsed() < ttl {
                    return m.clone();
                }
            }
        }
        let rs = self.ripestat.as_ref()?;
        let fetched = tokio::time::timeout(self.timeout, async {
            let (name, country) = tokio::join!(rs.holder(asn), rs.country(asn));
            match (name, country) {
                (Err(e), Err(_)) => {
                    tracing::debug!(asn, error = %e, "AS name lookup failed");
                    None
                }
                (n, c) => Some(AsMeta {
                    name: n.ok().flatten(),
                    country: c.ok().flatten(),
                }),
            }
        })
        .await
        .ok()
        .flatten();
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= MAX_CACHE {
            cache.clear(); // shortcut: wholesale eviction; an LRU is not worth it at this size
        }
        cache.insert(asn, (fetched.clone(), Instant::now()));
        fetched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names_file() {
        let m = parse_names(
            "# asn,name,country\nAS64511,EXAMPLE-NET Example Networks,nl\n64512,ONLY-NAME\nbogus,x,y\n64513,,ZZZ\n",
        );
        assert_eq!(
            m[&64511].label(64511),
            "AS64511 EXAMPLE-NET Example Networks (NL)"
        );
        assert_eq!(m[&64512].label(64512), "AS64512 ONLY-NAME");
        assert_eq!(m[&64513].label(64513), "AS64513");
        assert_eq!(m.len(), 3);
    }

    #[tokio::test]
    async fn file_hit_and_unknown_without_ripestat() {
        let dir = std::env::temp_dir().join(format!("vigil-asinfo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("names.csv");
        std::fs::write(&f, "64511,EXAMPLE-NET,NL\n").unwrap();
        let info = AsInfo::new(Some(&f), None, Duration::from_millis(100)).unwrap();
        assert_eq!(
            info.lookup(64511).await.unwrap().name.as_deref(),
            Some("EXAMPLE-NET")
        );
        assert_eq!(info.lookup(64512).await, None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
