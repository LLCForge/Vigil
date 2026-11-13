use std::io::Cursor;
use vigil::alert::{Alert, AlertKind};
use vigil::config::Config;
use vigil::detector::Detector;
use vigil::replay::replay;

fn detector() -> Detector {
    let cfg = Config::parse(include_str!("../vigil.example.toml")).expect("example config");
    vigil::daemon::detector(&cfg, &[]).expect("detector")
}

#[test]
fn sample_file_produces_expected_alerts() {
    let sample = include_str!("../examples/ris-sample.jsonl");
    let report = replay(Cursor::new(sample), &mut detector()).expect("replay");

    assert_eq!(report.lines, 13);
    assert_eq!(report.updates, 10);
    assert_eq!(report.malformed, 1);
    assert_eq!(report.oversized, 0);

    let routes: Vec<_> = report
        .alerts
        .iter()
        .map(|a| match a {
            Alert::Route(r) => r,
            other => panic!("unexpected alert {other:?}"),
        })
        .collect();
    let summary: Vec<_> = routes
        .iter()
        .map(|r| (r.kind, r.prefix.to_string(), r.origin.clone()))
        .collect();
    assert_eq!(
        summary,
        vec![
            // The example config expects upstreams AS64496/AS64497 for this prefix.
            (
                AlertKind::UnexpectedUpstream,
                "198.51.100.0/24".into(),
                "AS64500 via AS64498".into()
            ),
            // 192.0.2.0/24 is dormant (registered, unannounced) in the example config.
            (
                AlertKind::Squatting,
                "192.0.2.0/24".into(),
                "AS64503".into()
            ),
            (
                AlertKind::OriginHijack,
                "198.51.100.0/24".into(),
                "AS64511".into()
            ),
            (
                AlertKind::Moas,
                "198.51.100.0/24".into(),
                "AS64500, AS64511".into()
            ),
            (
                AlertKind::SubPrefixHijack,
                "198.51.100.128/25".into(),
                "AS64510".into()
            ),
            (
                AlertKind::AmbiguousOrigin,
                "2001:db8:100::/48".into(),
                "{AS64500,AS64509}".into()
            ),
        ]
    );

    let hijack = routes[2];
    assert_eq!(hijack.peers, 3);
    assert_eq!(hijack.collectors, vec!["rrc00", "rrc21", "rrc25"]);
    assert_eq!(hijack.expected_origins, vec![64500]);
    assert_eq!(hijack.first_seen.timestamp(), 1_794_556_830);
    assert!(Alert::Route(hijack.clone())
        .text()
        .contains("ORIGIN HIJACK 198.51.100.0/24"));
    assert_eq!(hijack.resource, "core/198.51.100.0/24");
    assert!(routes.iter().all(|r| !r.resolved));
    let kit = Alert::Route(hijack.clone()).to_kit();
    assert_eq!(kit.id, "vigil:origin_hijack:198.51.100.0/24:AS64511");
    assert_eq!(kit.severity, llcforge_beacon::Severity::Critical);
}

#[test]
fn oversized_and_garbage_lines_are_counted_not_fatal() {
    let big = format!(
        "{{\"type\":\"ris_message\",\"pad\":\"{}\"}}",
        "x".repeat(2 << 20)
    );
    let input = format!("{big}\n\nnot json\n{{\"type\":\"pong\",\"data\":null}}\n");
    let report = replay(Cursor::new(input), &mut detector()).expect("replay");
    assert_eq!(report.lines, 3);
    assert_eq!(report.oversized, 1);
    assert_eq!(report.malformed, 1);
    assert!(report.alerts.is_empty());
}

#[test]
fn squatting_sample_reports_dormant_space() {
    let sample = include_str!("../examples/ris-squat.jsonl");
    let report = replay(Cursor::new(sample), &mut detector()).expect("replay");
    assert_eq!(report.updates, 2);
    assert_eq!(report.alerts.len(), 1);
    let Alert::Route(r) = &report.alerts[0] else {
        panic!("expected a route alert");
    };
    assert_eq!(r.kind, AlertKind::Squatting);
    assert_eq!(r.peers, 2);
    assert!(r.expected_origins.is_empty());
}
