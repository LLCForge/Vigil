//! Vigil: real-time BGP origin hijack detection over public route collector
//! feeds (RIPE RIS Live, RouteViews BMP over Kafka, MRT updates via BGPKIT).
#![deny(unsafe_code)]

pub mod alert;
pub mod api;
pub mod asinfo;
pub mod blackhole;
pub mod config;
pub mod daemon;
pub mod detector;
pub mod feed;
pub mod incidents;
pub mod kafka;
pub mod matcher;
pub mod metrics;
pub mod mrt;
pub mod notary;
pub mod outlet;
pub mod replay;
pub mod ripestat;
pub mod ris;
pub mod visibility;

use std::time::Duration;

/// Shared outbound HTTP client: rustls, no redirects, bounded timeouts.
pub fn http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("vigil/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(900)) // MRT downloads; API calls have their own shorter timeouts
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
