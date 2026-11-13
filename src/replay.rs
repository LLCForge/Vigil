//! Offline replay: saved RIS Live messages (one JSON message per line) and MRT
//! update files (local, or downloaded from the RIS archive for a date range).

use crate::alert::Alert;
use crate::detector::Detector;
use crate::ris::{parse_message, ParseError, RisMessage, RisUpdate};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::io::BufRead;

#[derive(Debug, Default)]
pub struct ReplayReport {
    pub lines: u64,
    pub updates: u64,
    pub malformed: u64,
    pub oversized: u64,
    pub alerts: Vec<Alert>,
}

/// Drives a detector with message timestamps as the clock so results are
/// deterministic.
pub struct Replayer<'a> {
    detector: &'a mut Detector,
    clock: Option<DateTime<Utc>>,
    pub report: ReplayReport,
}

impl<'a> Replayer<'a> {
    pub fn new(detector: &'a mut Detector) -> Self {
        Self {
            detector,
            clock: None,
            report: ReplayReport::default(),
        }
    }

    pub fn update(&mut self, u: &RisUpdate) {
        self.report.updates += 1;
        let now = self.clock.map_or(u.timestamp, |c| u.timestamp.max(c));
        self.clock = Some(now);
        self.detector.observe(u, now);
        self.report.alerts.extend(
            self.detector
                .flush(now, false)
                .into_iter()
                .map(Alert::Route),
        );
    }

    /// Flush whatever is still pending and return the report.
    pub fn finish(mut self) -> ReplayReport {
        if let Some(now) = self.clock {
            self.report
                .alerts
                .extend(self.detector.flush(now, true).into_iter().map(Alert::Route));
        }
        self.report
    }
}

/// Feed every RIS Live JSON line through the detector.
pub fn replay<R: BufRead>(reader: R, detector: &mut Detector) -> Result<ReplayReport> {
    let mut r = Replayer::new(detector);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        r.report.lines += 1;
        match parse_message(&line) {
            Ok(RisMessage::Update(u)) => r.update(&u),
            Ok(RisMessage::Error(_) | RisMessage::Other) => {}
            Err(ParseError::Oversized(_)) => r.report.oversized += 1,
            Err(_) => r.report.malformed += 1,
        }
    }
    Ok(r.finish())
}
