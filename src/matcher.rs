//! Longest-prefix matching of announcements against watched prefixes, and the
//! origin / max-length policy check.

use crate::ris::Origin;
use chrono::{DateTime, Utc};
use ipnet::IpNet;

/// A prefix under watch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watched {
    pub prefix: IpNet,
    /// Origins allowed to announce the prefix (and more-specifics up to `max_length`).
    pub origins: Vec<u32>,
    /// Longest prefix length that may legitimately be announced.
    pub max_length: u8,
    /// Expected upstreams (neighbour of the origin in the AS path); empty = not checked.
    pub upstreams: Vec<u32>,
    /// Registered but intentionally unannounced space: any announcement is squatting.
    pub dormant: bool,
    /// Prefix group used for alert routing (`resource = "<group>/<prefix>"`).
    pub group: Option<String>,
}

impl Watched {
    /// Plain watched prefix (no upstream check, announced, no group).
    pub fn new(prefix: IpNet, origins: Vec<u32>, max_length: u8) -> Self {
        Self {
            prefix,
            origins,
            max_length,
            upstreams: Vec::new(),
            dormant: false,
            group: None,
        }
    }

    /// Alert `resource`: the watched prefix, prefixed with its group when set.
    pub fn resource(&self) -> String {
        match &self.group {
            Some(g) => format!("{g}/{}", self.prefix),
            None => self.prefix.to_string(),
        }
    }
}

/// How origins that belong to a known DDoS scrubbing provider are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScrubbingMode {
    /// Report as `scrubbing_origin` (warning) instead of a critical hijack.
    #[default]
    Warn,
    /// Treat as an exception (no alert).
    Allow,
    /// No special treatment: a scrubbing provider is a hijacker like any other.
    Off,
}

/// Built-in DDoS scrubbing / mitigation provider ASNs that may originate a
/// customer's prefixes during an attack (holder names checked against RIPEstat
/// as-overview on 2026-11-13). Override with `detection.scrubbing_asns`.
pub const BUILTIN_SCRUBBING_ASNS: &[(u32, &str)] = &[
    (13335, "Cloudflare (Magic Transit)"),
    (19551, "Imperva / Incapsula"),
    (19905, "Vercara (UltraDDoS Protect)"),
    (32787, "Akamai Prolexic"),
    (55002, "F5 Silverline (Defense.Net)"),
];

/// Time-boxed permission for an extra origin, e.g. a DDoS scrubbing provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exception {
    pub origin: u32,
    /// Limit the exception to this prefix and its more-specifics; `None` means all.
    pub prefix: Option<IpNet>,
    pub until: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// Origin is not allowed, but an active exception covers it.
    Excepted,
    OriginHijack,
    SubPrefixHijack,
    /// Origin is an AS_SET; flagged instead of guessed.
    Ambiguous,
    /// Announcement of registered but unannounced (dormant) space.
    Squat,
    /// Origin is a known scrubbing provider (mode `warn`).
    Scrubbing,
}

#[derive(Default)]
struct Node {
    child: [Option<usize>; 2],
    value: Option<usize>,
}

/// Binary trie keyed on the top `len` bits of a 128-bit address.
struct Trie {
    nodes: Vec<Node>,
}

impl Trie {
    fn new() -> Self {
        Self {
            nodes: vec![Node::default()],
        }
    }

    fn bit(key: u128, i: u8) -> usize {
        ((key >> (127 - u32::from(i))) & 1) as usize
    }

    fn insert(&mut self, key: u128, len: u8, value: usize) {
        let mut n = 0;
        for i in 0..len {
            let b = Self::bit(key, i);
            n = match self.nodes[n].child[b] {
                Some(c) => c,
                None => {
                    self.nodes.push(Node::default());
                    let c = self.nodes.len() - 1;
                    self.nodes[n].child[b] = Some(c);
                    c
                }
            };
        }
        self.nodes[n].value = Some(value);
    }

    fn longest(&self, key: u128, len: u8) -> Option<usize> {
        let mut n = 0;
        let mut best = self.nodes[0].value;
        for i in 0..len {
            match self.nodes[n].child[Self::bit(key, i)] {
                Some(c) => n = c,
                None => break,
            }
            if self.nodes[n].value.is_some() {
                best = self.nodes[n].value;
            }
        }
        best
    }
}

fn key(net: &IpNet) -> u128 {
    match net {
        IpNet::V4(n) => u128::from(u32::from(n.network())) << 96,
        IpNet::V6(n) => u128::from(n.network()),
    }
}

pub struct Matcher {
    v4: Trie,
    v6: Trie,
    watched: Vec<Watched>,
    exceptions: Vec<Exception>,
    scrubbing: Vec<u32>,
    scrubbing_mode: ScrubbingMode,
}

impl Matcher {
    pub fn new(watched: Vec<Watched>, exceptions: Vec<Exception>) -> Self {
        let mut v4 = Trie::new();
        let mut v6 = Trie::new();
        for (i, w) in watched.iter().enumerate() {
            let trie = match w.prefix {
                IpNet::V4(_) => &mut v4,
                IpNet::V6(_) => &mut v6,
            };
            trie.insert(key(&w.prefix), w.prefix.prefix_len(), i);
        }
        Self {
            v4,
            v6,
            watched,
            exceptions,
            scrubbing: Vec::new(),
            scrubbing_mode: ScrubbingMode::Off,
        }
    }

    /// Enable scrubbing-provider handling for `asns`.
    pub fn with_scrubbing(mut self, mode: ScrubbingMode, asns: Vec<u32>) -> Self {
        self.scrubbing_mode = mode;
        self.scrubbing = asns;
        self
    }

    pub fn watched(&self) -> &[Watched] {
        &self.watched
    }

    /// Most specific watched prefix covering `prefix`, if any.
    pub fn lookup(&self, prefix: &IpNet) -> Option<&Watched> {
        let trie = match prefix {
            IpNet::V4(_) => &self.v4,
            IpNet::V6(_) => &self.v6,
        };
        trie.longest(key(prefix), prefix.prefix_len())
            .map(|i| &self.watched[i])
    }

    fn excepted(&self, prefix: &IpNet, origin: u32, now: DateTime<Utc>) -> bool {
        self.exceptions.iter().any(|e| {
            e.origin == origin && e.until > now && e.prefix.is_none_or(|p| p.contains(prefix))
        })
    }

    /// Judge an announcement of `prefix` (covered by `w`) with `origin`.
    pub fn evaluate(
        &self,
        w: &Watched,
        prefix: &IpNet,
        origin: &Origin,
        now: DateTime<Utc>,
    ) -> Verdict {
        let scrubber = origin.asn().is_some_and(|a| {
            self.scrubbing_mode != ScrubbingMode::Off
                && !w.origins.contains(&a)
                && self.scrubbing.contains(&a)
        });
        let excepted = origin.asn().is_some_and(|a| self.excepted(prefix, a, now))
            || (scrubber && self.scrubbing_mode == ScrubbingMode::Allow);
        if w.dormant {
            return if excepted {
                Verdict::Excepted
            } else {
                Verdict::Squat
            };
        }
        // Too specific is suspicious whatever the origin: a forged origin is the
        // classic way to hide a sub-prefix hijack.
        if prefix.prefix_len() > w.max_length {
            return if excepted {
                Verdict::Excepted
            } else {
                Verdict::SubPrefixHijack
            };
        }
        match origin {
            Origin::Set(_) => Verdict::Ambiguous,
            Origin::As(a) if w.origins.contains(a) => Verdict::Ok,
            Origin::As(_) if excepted => Verdict::Excepted,
            Origin::As(_) if scrubber => Verdict::Scrubbing,
            Origin::As(_) => Verdict::OriginHijack,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn matcher(exceptions: Vec<Exception>) -> Matcher {
        Matcher::new(
            vec![
                Watched::new(net("198.51.100.0/24"), vec![64500], 24),
                Watched::new(net("198.51.0.0/16"), vec![64501], 20),
                Watched::new(net("2001:db8:100::/48"), vec![64500, 64501], 56),
            ],
            exceptions,
        )
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 13, 8, 0, 0).unwrap()
    }

    #[test]
    fn longest_match_v4_and_v6() {
        let m = matcher(vec![]);
        assert_eq!(
            m.lookup(&net("198.51.100.128/25")).unwrap().prefix,
            net("198.51.100.0/24")
        );
        assert_eq!(
            m.lookup(&net("198.51.7.0/24")).unwrap().prefix,
            net("198.51.0.0/16")
        );
        assert!(m.lookup(&net("198.0.0.0/8")).is_none());
        assert!(m.lookup(&net("203.0.113.0/24")).is_none());
        assert_eq!(
            m.lookup(&net("2001:db8:100:ff00::/56")).unwrap().prefix,
            net("2001:db8:100::/48")
        );
        assert!(m.lookup(&net("2001:db8:200::/48")).is_none());
        // An IPv4 key must never match in the IPv6 trie.
        assert!(m.lookup(&net("::/0")).is_none());
    }

    #[test]
    fn origin_and_max_length_rules() {
        let m = matcher(vec![]);
        let w = m.lookup(&net("198.51.100.0/24")).unwrap();
        let p = net("198.51.100.0/24");
        assert_eq!(m.evaluate(w, &p, &Origin::As(64500), now()), Verdict::Ok);
        assert_eq!(
            m.evaluate(w, &p, &Origin::As(64511), now()),
            Verdict::OriginHijack
        );
        assert_eq!(
            m.evaluate(w, &p, &Origin::Set(vec![64500, 64509]), now()),
            Verdict::Ambiguous
        );
        let sub = net("198.51.100.0/25");
        assert_eq!(
            m.evaluate(w, &sub, &Origin::As(64511), now()),
            Verdict::SubPrefixHijack
        );
        assert_eq!(
            m.evaluate(w, &sub, &Origin::As(64500), now()),
            Verdict::SubPrefixHijack
        );

        let w6 = m.lookup(&net("2001:db8:100::/52")).unwrap();
        let p6 = net("2001:db8:100::/52");
        assert_eq!(m.evaluate(w6, &p6, &Origin::As(64501), now()), Verdict::Ok);
        assert_eq!(
            m.evaluate(w6, &p6, &Origin::As(64511), now()),
            Verdict::OriginHijack
        );
        let p6_long = net("2001:db8:100::/64");
        assert_eq!(
            m.evaluate(w6, &p6_long, &Origin::As(64500), now()),
            Verdict::SubPrefixHijack
        );
    }

    #[test]
    fn exceptions_apply_until_expiry_and_only_to_their_prefix() {
        let until = now() + chrono::Duration::hours(1);
        let m = matcher(vec![Exception {
            origin: 64505,
            prefix: Some(net("198.51.100.0/24")),
            until,
        }]);
        let w = m.lookup(&net("198.51.100.0/24")).unwrap();
        let p = net("198.51.100.0/24");
        assert_eq!(
            m.evaluate(w, &p, &Origin::As(64505), now()),
            Verdict::Excepted
        );
        assert_eq!(
            m.evaluate(w, &net("198.51.100.0/25"), &Origin::As(64505), now()),
            Verdict::Excepted
        );
        assert_eq!(
            m.evaluate(w, &p, &Origin::As(64505), until),
            Verdict::OriginHijack
        );

        let w16 = m.lookup(&net("198.51.7.0/24")).unwrap();
        assert_eq!(
            m.evaluate(w16, &net("198.51.0.0/16"), &Origin::As(64505), now()),
            Verdict::OriginHijack
        );
    }

    #[test]
    fn dormant_space_and_scrubbing_providers() {
        let mut dormant = Watched::new(net("203.0.113.0/24"), vec![], 24);
        dormant.dormant = true;
        let m = Matcher::new(
            vec![
                dormant,
                Watched::new(net("198.51.100.0/24"), vec![64500], 24),
            ],
            vec![],
        )
        .with_scrubbing(ScrubbingMode::Warn, vec![64520]);
        let d = m.lookup(&net("203.0.113.0/25")).unwrap();
        assert_eq!(
            m.evaluate(d, &net("203.0.113.0/25"), &Origin::As(64500), now()),
            Verdict::Squat
        );
        let w = m.lookup(&net("198.51.100.0/24")).unwrap();
        let p = net("198.51.100.0/24");
        assert_eq!(
            m.evaluate(w, &p, &Origin::As(64520), now()),
            Verdict::Scrubbing
        );
        assert_eq!(
            m.evaluate(w, &p, &Origin::As(64511), now()),
            Verdict::OriginHijack
        );
        let allow =
            Matcher::new(vec![w.clone()], vec![]).with_scrubbing(ScrubbingMode::Allow, vec![64520]);
        assert_eq!(
            allow.evaluate(w, &p, &Origin::As(64520), now()),
            Verdict::Excepted
        );
        let mut grouped = w.clone();
        grouped.group = Some("customer-a".into());
        assert_eq!(grouped.resource(), "customer-a/198.51.100.0/24");
    }

    #[test]
    fn global_exception_covers_every_prefix() {
        let m = matcher(vec![Exception {
            origin: 64505,
            prefix: None,
            until: now() + chrono::Duration::minutes(5),
        }]);
        let w = m.lookup(&net("2001:db8:100::/48")).unwrap();
        assert_eq!(
            m.evaluate(w, &net("2001:db8:100::/48"), &Origin::As(64505), now()),
            Verdict::Excepted
        );
    }
}
