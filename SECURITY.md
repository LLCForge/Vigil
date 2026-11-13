# Security Policy

Vigil runs close to network infrastructure, so we take security reports seriously and appreciate responsible disclosure.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| `main` branch | Yes (best effort) |
| Older releases | No, please upgrade |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for security problems.**

Report privately through GitHub Security Advisories:

1. Go to [https://github.com/LLCForge/Vigil/security/advisories/new](https://github.com/LLCForge/Vigil/security/advisories/new).
2. Describe the issue, affected version or commit, and steps to reproduce.
3. Include a proof of concept if you have one. Strip any real customer data, IP addresses or credentials from captures and logs.

What to expect:

- Acknowledgement within **3 business days**.
- An initial assessment and severity rating within **10 business days**.
- A fix or mitigation plan, coordinated disclosure date, and credit in the advisory (unless you prefer to stay anonymous).

## In scope

- Remote crash or memory exhaustion via crafted feed messages (RIS Live JSON, Kafka OpenBMP/BMP records, MRT files) or crafted responses from RIPEstat, the BGPKIT broker, Notary or Event Horizon.
- Injection into alert messages via attacker-controlled feed or API fields (AS names, collector names, RPKI states).
- Downloading from hosts outside `feeds.bgpkit.allowed_hosts`, or any other server-side request forgery through broker-supplied URLs.
- Authentication bypass on the management listener (`/v1/visibility`, `/v1/incidents` with `[api] token_env`, `/v1/silences`, `POST /v1/reload`).
- Detection bypass (a hijack of a watched prefix that Vigil should flag but does not).
- Dependency vulnerabilities that are reachable from Vigil's code paths.

## Out of scope

- Vulnerabilities in third-party services or protocols themselves (report those upstream).
- Issues that require an attacker to already control the host or the config file.
- Denial of service by volumetric flooding of the network the tool runs on.

## Attack surface

| Surface | Exposure | Mitigation |
|---|---|---|
| Management listener (`[health] listen`) | `/metrics`, `/healthz`, `/readyz` unauthenticated; `/v1/visibility`, `/v1/incidents` read-only | Disabled unless configured; bind to 127.0.0.1 (container: pod network only); optional bearer token for `/v1/*` (constant-time compare); 1 KiB body limit. |
| `/v1/silences`, `POST /v1/reload` | Can mute alerts / reload config | Mounted only when their token variables are set. |
| RouteViews Kafka | Plaintext, unauthenticated public stream; anyone on path can inject records | Records capped at 4 MiB, decoder isolated with `catch_unwind`, only updates for watched space are used. Treat Kafka-only findings as public-feed evidence, like RIS. |
| BGPKIT broker / MRT downloads | Third-party URLs | Host allowlist, http(s) only, no redirects, size cap, temporary file always removed. |
| RIPEstat, Notary, Event Horizon responses | Third-party / sibling data in alerts | Size caps, time limits, value allowlists; failures never block alerts. Event Horizon token from environment only. |
| On-disk state (`data_dir`) | Alert queue, silences, incident timeline | Created by the service user; systemd unit uses `StateDirectory` with mode 0750 and `UMask=0077`. |

## Hardening recommendations

- Run as an unprivileged user; grant only the capabilities the tool needs.
- Bind management and API listeners to localhost or a management network.
- Keep secrets in environment variables or your secret manager, never in the config file or in version control.
