//! Read-only HTTP API on the management listener:
//!
//! * `GET /metrics` — Vigil and llcforge-alert metrics (Prometheus text).
//! * `GET /v1/visibility?prefix=<p>` — `{"prefix","peers_seeing","peers_total","ratio","as_of"}`.
//! * `GET /v1/incidents[?open=true]` — incident timeline.
//!
//! `/v1/*` takes an optional bearer token (`[api] token_env`). Health, silences
//! and reload routes come from llcforge-alert and are merged by `main`.

use crate::incidents::IncidentStore;
use crate::metrics;
use crate::outlet::Outlet;
use crate::visibility::VisibilityTracker;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use ipnet::IpNet;
use llcforge_alert::ApiToken;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiState {
    pub visibility: Arc<VisibilityTracker>,
    pub incidents: Arc<IncidentStore>,
    pub outlet: Outlet,
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

async fn metrics_handler(State(s): State<ApiState>) -> Response {
    let mut body = metrics::render();
    s.visibility.render_prometheus(&mut body);
    s.outlet
        .outputs()
        .handle
        .metrics()
        .render_prometheus(&mut body);
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

#[derive(Deserialize)]
struct VisibilityQuery {
    prefix: Option<String>,
}

async fn visibility(State(s): State<ApiState>, Query(q): Query<VisibilityQuery>) -> Response {
    let Some(raw) = q.prefix else {
        return error(StatusCode::BAD_REQUEST, "missing prefix parameter");
    };
    if raw.len() > 64 {
        return error(StatusCode::BAD_REQUEST, "invalid prefix");
    }
    let Ok(p) = raw.parse::<IpNet>() else {
        return error(StatusCode::BAD_REQUEST, "invalid prefix");
    };
    match s.visibility.snapshot(&p.trunc()) {
        Some(snap) => Json(snap).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            "prefix is not tracked or not measured yet",
        ),
    }
}

#[derive(Deserialize)]
struct IncidentsQuery {
    open: Option<bool>,
}

async fn incidents(State(s): State<ApiState>, Query(q): Query<IncidentsQuery>) -> Response {
    let open = q.open.unwrap_or(false);
    Json(json!({ "incidents": s.incidents.list(open) })).into_response()
}

pub fn router(state: ApiState, token: Option<ApiToken>) -> Router {
    let mut v1 = Router::new()
        .route("/v1/visibility", get(visibility))
        .route("/v1/incidents", get(incidents));
    if let Some(t) = token {
        v1 = v1.layer(axum::middleware::from_fn_with_state(
            t,
            llcforge_alert::auth::require_bearer,
        ));
    }
    Router::new()
        .route("/metrics", get(metrics_handler))
        .merge(v1)
        .layer(DefaultBodyLimit::max(1024))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outlet::Outputs;
    use crate::ripestat::Visibility;
    use axum::body::Body;
    use axum::http::Request;
    use chrono::Utc;
    use llcforge_alert::AlertHandle;
    use tower::ServiceExt;

    fn state() -> ApiState {
        let (_tx, rx) = tokio::sync::watch::channel(Arc::new(Outputs {
            handle: AlertHandle::disabled("vigil"),
            notary: None,
            asinfo: None,
        }));
        let incidents = Arc::new(IncidentStore::in_memory());
        let visibility = Arc::new(VisibilityTracker::new(0.5));
        let p: IpNet = "198.51.100.0/24".parse().unwrap();
        visibility.set_prefixes(&[crate::matcher::Watched::new(p, vec![64500], 24)]);
        visibility.apply_poll(
            &p,
            Visibility {
                seeing: 300,
                total: 320,
            },
            Utc::now(),
        );
        ApiState {
            visibility,
            outlet: Outlet::new(rx, incidents.clone()),
            incidents,
        }
    }

    async fn call(app: &Router, path: &str, token: Option<&str>) -> (StatusCode, String) {
        let mut req = Request::get(path);
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let st = resp.status();
        let b = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (st, String::from_utf8_lossy(&b).into_owned())
    }

    #[tokio::test]
    async fn visibility_contract_metrics_and_errors() {
        let app = router(state(), None);
        let (st, body) = call(&app, "/v1/visibility?prefix=198.51.100.0/24", None).await;
        assert_eq!(st, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["prefix"], "198.51.100.0/24");
        assert_eq!(v["peers_seeing"], 300);
        assert_eq!(v["peers_total"], 320);
        assert!((v["ratio"].as_f64().unwrap() - 0.9375).abs() < 1e-9);
        assert!(v["as_of"].as_str().unwrap().ends_with('Z'));

        assert_eq!(
            call(&app, "/v1/visibility", None).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&app, "/v1/visibility?prefix=bogus", None).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&app, "/v1/visibility?prefix=203.0.113.0/24", None)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let (st, m) = call(&app, "/metrics", None).await;
        assert_eq!(st, StatusCode::OK);
        assert!(m.contains("vigil_ris_messages_total"));
        assert!(m.contains("vigil_visibility_ratio{prefix=\"198.51.100.0/24\"}"));
        assert_eq!(call(&app, "/nope", None).await.0, StatusCode::NOT_FOUND);
        let (st, inc) = call(&app, "/v1/incidents?open=true", None).await;
        assert_eq!(st, StatusCode::OK);
        assert!(inc.contains("\"incidents\":[]"));
    }

    #[tokio::test]
    async fn bearer_token_protects_v1_only() {
        let token = ApiToken::new("correct-horse-battery-staple-0123456789").unwrap();
        let app = router(state(), Some(token));
        let path = "/v1/visibility?prefix=198.51.100.0/24";
        assert_eq!(call(&app, path, None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            call(&app, path, Some("wrong")).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, path, Some("correct-horse-battery-staple-0123456789"))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(call(&app, "/metrics", None).await.0, StatusCode::OK);
    }
}
