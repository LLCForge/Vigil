//! Optional RPKI enrichment through a Notary instance.
//!
//! Tolerant by design: any error, timeout or unexpected body yields `None` and the
//! alert goes out without RPKI state.

use ipnet::IpNet;
use serde_json::Value;
use std::time::Duration;

const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct Notary {
    client: reqwest::Client,
    base: String,
    timeout: Duration,
}

impl Notary {
    pub fn new(client: reqwest::Client, url: &str, timeout: Duration) -> Self {
        Self {
            client,
            base: url.trim_end_matches('/').to_string(),
            timeout,
        }
    }

    /// RPKI validity of `(prefix, asn)`, or `None` if Notary did not answer in time.
    pub async fn validity(&self, prefix: &IpNet, asn: u32) -> Option<String> {
        let request = async {
            let resp = self
                .client
                .get(format!("{}/v1/validity", self.base))
                .query(&[("prefix", prefix.to_string()), ("asn", asn.to_string())])
                .send()
                .await
                .map_err(|e| anyhow::anyhow!(e.without_url()))?
                .error_for_status()
                .map_err(|e| anyhow::anyhow!(e.without_url()))?;
            let v = crate::ripestat::read_json(resp, MAX_BODY_BYTES).await?;
            Ok::<_, anyhow::Error>(extract_state(&v))
        };
        match tokio::time::timeout(self.timeout, request).await {
            Ok(Ok(state)) => state,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "notary lookup failed");
                None
            }
            Err(_) => {
                tracing::warn!("notary lookup timed out");
                None
            }
        }
    }
}

/// Pull a validity state out of a response. Notary's contract field `state`
/// (`valid|invalid|not_found`) is preferred; older Notary builds and other
/// validators are still understood through `{"validity": ..}`,
/// `{"validity": {"state": ..}}` and Routinator's
/// `{"validated_route": {"validity": {"state": ..}}}`. `"stale": true` (VRP
/// data out of date) is appended as ` (stale)`.
pub fn extract_state(v: &Value) -> Option<String> {
    let candidates = [
        v.get("state"),
        v.get("validity"),
        v.get("validity").and_then(|x| x.get("state")),
        v.pointer("/validated_route/validity/state"),
    ];
    let raw = candidates.into_iter().flatten().find_map(Value::as_str)?;
    // Allowlist so a hostile response cannot inject markup into alerts.
    let ok = !raw.is_empty()
        && raw.len() <= 32
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if !ok {
        return None;
    }
    let state = raw.to_ascii_lowercase();
    Some(if v.get("stale").and_then(Value::as_bool) == Some(true) {
        format!("{state} (stale)")
    } else {
        state
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_known_shapes() {
        assert_eq!(
            extract_state(&json!({"state": "Valid"})).as_deref(),
            Some("valid")
        );
        assert_eq!(
            extract_state(&json!({"validity": "invalid"})).as_deref(),
            Some("invalid")
        );
        assert_eq!(
            extract_state(&json!({"validity": {"state": "not-found"}})).as_deref(),
            Some("not-found")
        );
        assert_eq!(
            extract_state(&json!({"validated_route": {"validity": {"state": "invalid"}}}))
                .as_deref(),
            Some("invalid")
        );
    }

    #[test]
    fn prefers_contract_state_field_and_reports_stale() {
        assert_eq!(
            extract_state(&json!({"state": "not_found", "validity": "legacy", "stale": false}))
                .as_deref(),
            Some("not_found")
        );
        assert_eq!(
            extract_state(&json!({"state": "invalid", "stale": true})).as_deref(),
            Some("invalid (stale)")
        );
    }

    #[test]
    fn rejects_unknown_or_hostile_values() {
        assert_eq!(extract_state(&json!({"foo": 1})), None);
        assert_eq!(extract_state(&json!({"state": "<b>valid</b>"})), None);
        assert_eq!(extract_state(&json!({"state": 3})), None);
    }

    #[tokio::test]
    async fn unreachable_notary_returns_none_within_timeout() {
        // Port 9 on localhost is closed on CI runners; either way the timeout bounds it.
        let n = Notary::new(
            reqwest::Client::new(),
            "http://127.0.0.1:9/",
            Duration::from_millis(300),
        );
        let start = std::time::Instant::now();
        assert_eq!(
            n.validity(&"198.51.100.0/24".parse().unwrap(), 64511).await,
            None
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
