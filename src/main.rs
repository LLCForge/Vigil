use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use llcforge_beacon::cli::{run_silence_command, ServiceCommand, SilenceCommand};
use llcforge_beacon::{init_logging, run_service_command, LogFormat};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use vigil::config::Config;
use vigil::daemon::{self, SPEC};
use vigil::incidents::{self, IncidentStore};
use vigil::replay::{replay, Replayer};
use vigil::{kafka, mrt};

#[derive(Parser)]
#[command(
    name = "vigil",
    version,
    about = "Real-time BGP origin hijack detection over public route collector feeds"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, short, global = true, default_value = "vigil.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Watch the configured feeds and send alerts until stopped.
    Run,
    /// Validate the configuration (and required environment variables) and exit.
    CheckConfig,
    /// Run saved RIS Live messages (JSON lines) through the detector offline.
    Replay {
        /// File with one RIS Live message per line.
        file: PathBuf,
    },
    /// Replay MRT update files: local files, or a RIS archive date range.
    ReplayMrt {
        /// Local MRT files (gzip, bzip2 or uncompressed).
        files: Vec<PathBuf>,
        /// RIS collector to download from (e.g. rrc00); requires --from and --to.
        #[arg(long)]
        collector: Option<String>,
        /// Start of the range (RFC 3339).
        #[arg(long)]
        from: Option<DateTime<Utc>>,
        /// End of the range (RFC 3339, exclusive).
        #[arg(long)]
        to: Option<DateTime<Utc>>,
        /// RIS raw data archive base URL.
        #[arg(long, default_value = mrt::RIS_ARCHIVE)]
        archive: String,
    },
    /// Show the incident timeline recorded by `vigil run`.
    Incidents {
        /// Only incidents that are still open.
        #[arg(long)]
        open: bool,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List Kafka topics matched by [feeds.routeviews_kafka].
    KafkaTopics,
    /// Manage silences (maintenance windows).
    Silence {
        #[command(subcommand)]
        cmd: SilenceCommand,
    },
    /// Install, uninstall or run as a system service.
    Service {
        #[command(subcommand)]
        cmd: ServiceCommand,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    // Log settings come from the config when it is readable; errors surface below.
    let (format, level, filter) = match Config::load(&cli.config) {
        Ok(c) => (c.log.format, c.log.level, c.log.filter),
        Err(_) => (LogFormat::Text, "info".to_string(), None),
    };
    // rskafka logs every partition connection at info; keep that out of the default log.
    let level = format!("{level},rskafka=warn");
    if let Err(e) = init_logging(format, &level, filter.as_deref()) {
        eprintln!("error: {e:#}");
        return std::process::ExitCode::FAILURE;
    }
    let result = match cli.command {
        Command::Run => llcforge_beacon::service::run_foreground(cli.config, daemon::daemon),
        Command::CheckConfig => check_config(&cli.config),
        Command::Replay { file } => run_replay(&cli.config, &file),
        Command::ReplayMrt {
            files,
            collector,
            from,
            to,
            archive,
        } => run_replay_mrt(&cli.config, files, collector, from, to, &archive),
        Command::Incidents { open, json } => show_incidents(&cli.config, open, json),
        Command::KafkaTopics => kafka_topics(&cli.config),
        Command::Silence { cmd } => Config::load(&cli.config)
            .and_then(|c| run_silence_command(cmd, &c.silences.path_or(&c.data_dir()))),
        Command::Service { cmd } => {
            run_service_command(&SPEC, cmd.into_action(cli.config), daemon::daemon)
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn check_config(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    cfg.check_secrets()?;
    let feeds: Vec<&str> = [
        cfg.feeds.ris_live.then_some("ris-live"),
        cfg.feeds
            .routeviews_kafka
            .as_ref()
            .map(|_| "routeviews-kafka"),
        cfg.feeds.bgpkit.as_ref().map(|_| "bgpkit"),
    ]
    .into_iter()
    .flatten()
    .collect();
    println!(
        "config OK: {} prefix(es), {} ASN(s), {} exception(s), {} alert sink(s), feeds: {}",
        cfg.prefixes.len(),
        cfg.asns.len(),
        cfg.exceptions.len(),
        cfg.alerts.sinks.len(),
        if feeds.is_empty() {
            "none".into()
        } else {
            feeds.join(", ")
        }
    );
    Ok(())
}

fn print_report(what: &str, r: &vigil::replay::ReplayReport, extra: &str) {
    for a in &r.alerts {
        println!("{}\n", a.text());
    }
    println!(
        "{what}: {extra}{} updates, {} malformed, {} oversized, {} alert(s)",
        r.updates,
        r.malformed,
        r.oversized,
        r.alerts.len()
    );
}

fn run_replay(config: &Path, file: &Path) -> Result<()> {
    let cfg = Config::load(config)?;
    let mut det = daemon::detector(&cfg, &[])?;
    let f = std::fs::File::open(file).with_context(|| format!("cannot open {}", file.display()))?;
    let report = replay(BufReader::new(f), &mut det)?;
    print_report("replay", &report, &format!("{} messages, ", report.lines));
    Ok(())
}

fn run_replay_mrt(
    config: &Path,
    files: Vec<PathBuf>,
    collector: Option<String>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    archive: &str,
) -> Result<()> {
    let cfg = Config::load(config)?;
    let mut det = daemon::detector(&cfg, &[])?;
    let filter = mrt::coverage(
        &det.matcher()
            .watched()
            .iter()
            .map(|w| w.prefix)
            .collect::<Vec<_>>(),
    );
    let in_range = |t: DateTime<Utc>| from.is_none_or(|f| t >= f) && to.is_none_or(|e| t < e);
    let keep = |p: &IpNet| filter.lookup(p).is_some();
    let mut rep = Replayer::new(&mut det);
    let (mut done, mut missing, mut elements) = (0usize, 0usize, 0u64);
    let mut feed_file = |rep: &mut Replayer, f: std::fs::File, label: &str| -> Result<()> {
        elements += mrt::read_updates(f, label, &keep, &mut |u| {
            if in_range(u.timestamp) {
                rep.update(&u);
            }
        })?;
        Ok(())
    };
    for path in &files {
        let f =
            std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let label = collector
            .as_deref()
            .map_or_else(|| "mrt".to_string(), mrt::collector_label);
        feed_file(&mut rep, f, &label)?;
        done += 1;
    }
    if files.is_empty() {
        let (Some(c), Some(from), Some(to)) = (collector.as_deref(), from, to) else {
            anyhow::bail!("give MRT files, or --collector with --from and --to");
        };
        vigil::config::check_url(archive, &["https", "http"], "--archive")?;
        let urls = mrt::ris_archive_urls(archive, c, from, to)?;
        let rt = tokio::runtime::Runtime::new()?;
        let client = vigil::http_client()?;
        let tmp = std::env::temp_dir();
        for url in &urls {
            match rt.block_on(mrt::download(&client, url, &tmp, 1 << 30)) {
                Ok(p) => {
                    let r = std::fs::File::open(&p)
                        .map_err(anyhow::Error::from)
                        .and_then(|f| feed_file(&mut rep, f, &mrt::collector_label(c)));
                    let _ = std::fs::remove_file(&p);
                    r.with_context(|| format!("cannot parse {url}"))?;
                    done += 1;
                }
                Err(e) => {
                    missing += 1;
                    tracing::warn!(%url, error = %format!("{e:#}"), "skipping file");
                }
            }
        }
    }
    let report = rep.finish();
    let missing = if missing > 0 {
        format!(", {missing} missing")
    } else {
        String::new()
    };
    print_report(
        "replay-mrt",
        &report,
        &format!("{done} file(s){missing}, {elements} elements, "),
    );
    Ok(())
}

fn show_incidents(config: &Path, open: bool, json: bool) -> Result<()> {
    let cfg = Config::load(config)?;
    let mut items = IncidentStore::read(&cfg.data_dir().join("incidents.json"))?;
    items.reverse();
    items.retain(|i| !open || i.is_open());
    if json {
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else if items.is_empty() {
        println!("no incidents");
    } else {
        print!("{}", incidents::render(&items));
    }
    Ok(())
}

fn kafka_topics(config: &Path) -> Result<()> {
    let cfg = Config::load(config)?;
    let k = cfg
        .feeds
        .routeviews_kafka
        .context("[feeds.routeviews_kafka] is not configured")?;
    let topics = tokio::runtime::Runtime::new()?.block_on(kafka::list(&k))?;
    let names: std::collections::BTreeSet<&str> = topics.iter().map(|(t, _)| t.as_str()).collect();
    for t in &names {
        println!("{t}");
    }
    println!("{} topic(s), {} partition(s)", names.len(), topics.len());
    Ok(())
}
