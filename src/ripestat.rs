//! Small RIPEstat Data API client (routing-status, announced-prefixes,
//! as-overview, rir-stats-country, looking-glass). Every call is time-boxed and
//! the response body is size-capped; parsers are pure functions for tests.

use anyhow::{anyhow, bail, Result};
use ipnet::IpNet;
use serde_json::Value;
use std::time::Duration;

/// Largest RIPEstat response read (looking-glass for a busy prefix is ~1 MiB).
const MAX_BODY: usize = 8 << 20;
const MAX_PREFIXES_PER_ASN: usize = 5000;

#[derive(Clone)]
pub struct RipeStat {
    client: reqwest::Client,
    base: String,
    timeout: Duration,
}

/// Visibility of one prefix among RIS full-feed peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Visibility {
    pub seeing: u32,
    pub total: u32,
}

/// Read a JSON body of at most `max` bytes.
pub async fn read_json(resp: reqwest::Response, max: usize) -> Result<Value> {
    if resp.content_length().is_some_and(|l| l > max as u64) {
        bail!("response too large");
    }
    let mut resp = resp;
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| anyhow!(e.without_url()))? {
        if buf.len() + chunk.len() > max {
            bail!("response too large");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&buf)?)
}

impl RipeStat {
    pub fn new(client: reqwest::Client, base: &str, timeout: Duration) -> Self {
        Self {
            client,
            base: base.trim_end_matches('/').to_string(),
            timeout,
        }
    }

    async fn call(&self, endpoint: &str, resource: &str) -> Result<Value> {
        let req = async {
            let resp = self
                .client
                .get(format!("{}/data/{endpoint}/data.json", self.base))
                .query(&[("resource", resource), ("sourceapp", "llcforge-vigil")])
                .send()
                .await
                .map_err(|e| anyhow!(e.without_url()))?
                .error_for_status()
                .map_err(|e| anyhow!(e.without_url()))?;
            read_json(resp, MAX_BODY).await
        };
        tokio::time::timeout(self.timeout, req)
            .await
            .map_err(|_| anyhow!("RIPEstat {endpoint} timed out"))?
    }

    pub async fn visibility(&self, prefix: &IpNet) -> Result<Visibility> {
        parse_visibility(
            &self.call("routing-status", &prefix.to_string()).await?,
            prefix,
        )
    }

    pub async fn announced_prefixes(&self, asn: u32) -> Result<Vec<IpNet>> {
        parse_announced(&self.call("announced-prefixes", &format!("AS{asn}")).await?)
    }

    pub async fn holder(&self, asn: u32) -> Result<Option<String>> {
        Ok(parse_holder(
            &self.call("as-overview", &format!("AS{asn}")).await?,
        ))
    }

    pub async fn country(&self, asn: u32) -> Result<Option<String>> {
        Ok(parse_country(
            &self.call("rir-stats-country", &format!("AS{asn}")).await?,
        ))
    }

    /// Number of RIS peers carrying exactly `prefix` (looking-glass).
    pub async fn looking_glass_peers(&self, prefix: &IpNet) -> Result<usize> {
        parse_looking_glass(
            &self.call("looking-glass", &prefix.to_string()).await?,
            prefix,
        )
    }
}

fn data(v: &Value) -> Result<&Value> {
    if v.get("status").and_then(Value::as_str) != Some("ok") {
        bail!("RIPEstat returned a non-ok status");
    }
    v.get("data")
        .ok_or_else(|| anyhow!("RIPEstat response without data"))
}

pub fn parse_visibility(v: &Value, prefix: &IpNet) -> Result<Visibility> {
    let fam = if prefix.addr().is_ipv4() { "v4" } else { "v6" };
    let vis = data(v)?
        .get("visibility")
        .and_then(|x| x.get(fam))
        .ok_or_else(|| anyhow!("routing-status without visibility.{fam}"))?;
    let num = |k: &str| {
        vis.get(k)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| anyhow!("routing-status: bad {k}"))
    };
    let (seeing, total) = (num("ris_peers_seeing")?, num("total_ris_peers")?);
    if seeing > total {
        bail!("routing-status: seeing > total");
    }
    Ok(Visibility { seeing, total })
}

pub fn parse_announced(v: &Value) -> Result<Vec<IpNet>> {
    let list = data(v)?
        .get("prefixes")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("announced-prefixes without prefixes"))?;
    let mut out: Vec<IpNet> = list
        .iter()
        .filter_map(|p| p.get("prefix")?.as_str()?.parse::<IpNet>().ok())
        .map(|n| n.trunc())
        .take(MAX_PREFIXES_PER_ASN)
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// Printable ASCII only, capped; holder names land in alerts.
fn clean(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn parse_holder(v: &Value) -> Option<String> {
    let h = clean(data(v).ok()?.get("holder")?.as_str()?, 120);
    (!h.is_empty()).then_some(h)
}

pub fn parse_country(v: &Value) -> Option<String> {
    let loc = data(v)
        .ok()?
        .get("located_resources")?
        .as_array()?
        .first()?
        .get("location")?
        .as_str()?;
    (loc.len() == 2 && loc.bytes().all(|b| b.is_ascii_uppercase())).then(|| loc.to_string())
}

pub fn parse_looking_glass(v: &Value, prefix: &IpNet) -> Result<usize> {
    let rrcs = data(v)?
        .get("rrcs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("looking-glass without rrcs"))?;
    Ok(rrcs
        .iter()
        .filter_map(|r| r.get("peers")?.as_array())
        .flatten()
        .filter(|p| {
            p.get("prefix")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<IpNet>().ok())
                .is_some_and(|n| n.trunc() == *prefix)
        })
        .count())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_routing_status() {
        let v = json!({"status":"ok","data":{"visibility":{"v4":{"ris_peers_seeing":300,"total_ris_peers":320},"v6":{"ris_peers_seeing":0,"total_ris_peers":0}}}});
        let p: IpNet = "198.51.100.0/24".parse().unwrap();
        assert_eq!(
            parse_visibility(&v, &p).unwrap(),
            Visibility {
                seeing: 300,
                total: 320
            }
        );
        let bad = json!({"status":"ok","data":{"visibility":{"v4":{"ris_peers_seeing":3,"total_ris_peers":2}}}});
        assert!(parse_visibility(&bad, &p).is_err());
        assert!(parse_visibility(&json!({"status":"error"}), &p).is_err());
    }

    #[test]
    fn parses_announced_holder_country_and_looking_glass() {
        let v = json!({"status":"ok","data":{"prefixes":[{"prefix":"198.51.100.0/24"},{"prefix":"2001:db8::/32"},{"prefix":"bogus"},{"prefix":"198.51.100.0/24"}]}});
        assert_eq!(parse_announced(&v).unwrap().len(), 2);
        let h = json!({"status":"ok","data":{"holder":"EXAMPLE-NET \u{1b}[31mExample\n"}});
        assert_eq!(parse_holder(&h).as_deref(), Some("EXAMPLE-NET [31mExample"));
        let c = json!({"status":"ok","data":{"located_resources":[{"location":"NL"}]}});
        assert_eq!(parse_country(&c).as_deref(), Some("NL"));
        let c = json!({"status":"ok","data":{"located_resources":[{"location":"<b>"}]}});
        assert_eq!(parse_country(&c), None);
        let lg = json!({"status":"ok","data":{"rrcs":[{"peers":[{"prefix":"198.51.100.7/32"},{"prefix":"198.51.100.0/24"}]},{"peers":[{"prefix":"198.51.100.7/32"}]}]}});
        assert_eq!(
            parse_looking_glass(&lg, &"198.51.100.7/32".parse().unwrap()).unwrap(),
            2
        );
    }
}
