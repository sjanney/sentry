// SPDX-License-Identifier: Apache-2.0
use std::{path::Path, time::Duration};

#[cfg(target_os = "linux")]
use std::{io::Write, path::PathBuf};

#[cfg(target_os = "linux")]
use std::{thread, time::Instant};

use sentry_daemon::capability::KernelPreflight;

fn capture_lifecycle(object_path: &Path, duration: Duration) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use sentry_daemon::{EventIngestor, kernel_events::ProcessEventReader};

        let mut reader =
            ProcessEventReader::load(object_path).map_err(|error| error.to_string())?;
        let mut ingestor = EventIngestor::new(16_384);
        println!("capture-lifecycle: ready");
        std::io::stdout()
            .flush()
            .map_err(|error| error.to_string())?;
        let deadline = Instant::now() + duration;
        let mut total = sentry_daemon::kernel_events::KernelDrain::default();
        while Instant::now() < deadline {
            let drain = reader.drain(&mut ingestor, 1_024);
            total.read = total.read.saturating_add(drain.read);
            total.accepted = total.accepted.saturating_add(drain.accepted);
            total.dropped = total.dropped.saturating_add(drain.dropped);
            total.malformed = total.malformed.saturating_add(drain.malformed);
            total.redaction_rejected = total
                .redaction_rejected
                .saturating_add(drain.redaction_rejected);
            total.sequence_exhausted = total
                .sequence_exhausted
                .saturating_add(drain.sequence_exhausted);
            total.exec = total.exec.saturating_add(drain.exec);
            total.fork = total.fork.saturating_add(drain.fork);
            total.exit = total.exit.saturating_add(drain.exit);
            if drain.read == 0 {
                thread::sleep(Duration::from_millis(10));
            }
        }
        println!(
            "capture-lifecycle: read={} accepted={} exec={} fork={} exit={} dropped={} malformed={} redaction-rejected={} sequence-exhausted={}",
            total.read,
            total.accepted,
            total.exec,
            total.fork,
            total.exit,
            total.dropped,
            total.malformed,
            total.redaction_rejected,
            total.sequence_exhausted,
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (object_path, duration);
        Err("capture-lifecycle requires Linux".to_owned())
    }
}

#[cfg(target_os = "linux")]
fn parse_credential_rule(
    argument: &str,
) -> Result<sentry_daemon::kernel_events::CredentialRule, String> {
    use sentry_daemon::{CredentialClass, kernel_events::CredentialRule};

    let (class, path) = argument
        .split_once('=')
        .ok_or_else(|| "credential rule must be CLASS=PATH".to_owned())?;
    if path.is_empty() {
        return Err("credential rule path cannot be empty".to_owned());
    }
    let class = match class {
        "ssh_key" => CredentialClass::SshKey,
        "cloud_credential" => CredentialClass::CloudCredential,
        "dotenv" => CredentialClass::DotEnv,
        "keyring" => CredentialClass::Keyring,
        "token_cache" => CredentialClass::TokenCache,
        _ => return Err(format!("unknown credential class: {class}")),
    };
    Ok(CredentialRule {
        path: PathBuf::from(path),
        class,
    })
}

fn capture_filesystem(
    object_path: &Path,
    duration: Duration,
    rule_arguments: &[String],
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use sentry_daemon::{
            EventIngestor, FileAccessOutcome, ObservedTarget,
            kernel_events::{FilesystemDrain, FilesystemEventReader},
        };
        use std::{thread, time::Instant};

        let rules = rule_arguments
            .iter()
            .map(|argument| parse_credential_rule(argument))
            .collect::<Result<Vec<_>, _>>()?;
        let mut reader =
            FilesystemEventReader::load(object_path, &rules).map_err(|error| error.to_string())?;
        let mut ingestor = EventIngestor::new(16_384);
        println!("capture-filesystem: ready rules={}", rules.len());
        std::io::stdout()
            .flush()
            .map_err(|error| error.to_string())?;
        let deadline = Instant::now() + duration;
        let mut total = FilesystemDrain::default();
        while Instant::now() < deadline {
            let (drain, observations) = reader.drain(&mut ingestor, 1_024);
            total.read = total.read.saturating_add(drain.read);
            total.accepted = total.accepted.saturating_add(drain.accepted);
            total.attempted = total.attempted.saturating_add(drain.attempted);
            total.succeeded = total.succeeded.saturating_add(drain.succeeded);
            total.denied = total.denied.saturating_add(drain.denied);
            total.dropped = total.dropped.saturating_add(drain.dropped);
            total.malformed = total.malformed.saturating_add(drain.malformed);
            total.sequence_exhausted = total
                .sequence_exhausted
                .saturating_add(drain.sequence_exhausted);
            for observation in observations {
                let ObservedTarget::Credential(class) = observation.target else {
                    continue;
                };
                let class = match class {
                    sentry_daemon::CredentialClass::SshKey => "ssh_key",
                    sentry_daemon::CredentialClass::CloudCredential => "cloud_credential",
                    sentry_daemon::CredentialClass::DotEnv => "dotenv",
                    sentry_daemon::CredentialClass::Keyring => "keyring",
                    sentry_daemon::CredentialClass::TokenCache => "token_cache",
                };
                let outcome = match observation.outcome {
                    FileAccessOutcome::Attempted => "attempted".to_owned(),
                    FileAccessOutcome::Succeeded => "succeeded".to_owned(),
                    FileAccessOutcome::Denied { errno } => format!("denied:{errno}"),
                };
                let identity = observation
                    .identity
                    .expect("kernel file event has identity");
                println!(
                    "filesystem-event: class={class} outcome={outcome} device={} inode={}",
                    identity.device, identity.inode
                );
            }
            if drain.read == 0 {
                thread::sleep(Duration::from_millis(10));
            }
        }
        println!(
            "capture-filesystem: read={} accepted={} attempted={} succeeded={} denied={} dropped={} malformed={} sequence-exhausted={}",
            total.read,
            total.accepted,
            total.attempted,
            total.succeeded,
            total.denied,
            total.dropped,
            total.malformed,
            total.sequence_exhausted,
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (object_path, duration, rule_arguments);
        Err("capture-filesystem requires Linux".to_owned())
    }
}

fn capture_connections(
    object_path: &Path,
    cgroup_path: &Path,
    duration: Duration,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use sentry_daemon::{
            ConnectionTarget, DnsEvidenceCache, EventIngestor,
            kernel_events::{ConnectionDrain, ConnectionEventReader},
        };

        let mut reader = ConnectionEventReader::load(object_path, cgroup_path)
            .map_err(|error| error.to_string())?;
        let mut ingestor = EventIngestor::new(16_384);
        let mut dns = DnsEvidenceCache::new(1_024);
        println!("capture-connections: ready");
        std::io::stdout()
            .flush()
            .map_err(|error| error.to_string())?;
        let deadline = Instant::now() + duration;
        let mut total = ConnectionDrain::default();
        while Instant::now() < deadline {
            let (drain, observations) = reader.drain(&mut ingestor, &mut dns, 1, 1_024);
            total.read = total.read.saturating_add(drain.read);
            total.accepted = total.accepted.saturating_add(drain.accepted);
            total.tcp = total.tcp.saturating_add(drain.tcp);
            total.udp = total.udp.saturating_add(drain.udp);
            total.ipv4 = total.ipv4.saturating_add(drain.ipv4);
            total.ipv6 = total.ipv6.saturating_add(drain.ipv6);
            total.unknown = total.unknown.saturating_add(drain.unknown);
            total.correlated = total.correlated.saturating_add(drain.correlated);
            total.dropped = total.dropped.saturating_add(drain.dropped);
            total.malformed = total.malformed.saturating_add(drain.malformed);
            total.sequence_exhausted = total
                .sequence_exhausted
                .saturating_add(drain.sequence_exhausted);
            for observation in observations {
                let target = match observation.target {
                    ConnectionTarget::UnknownDestination => "unknown",
                    ConnectionTarget::DnsCorrelated { .. } => "dns_correlated",
                };
                println!(
                    "connection-event: protocol={:?} destination={} port={} target={target}",
                    observation.protocol, observation.destination, observation.port
                );
            }
            if drain.read == 0 {
                thread::sleep(Duration::from_millis(10));
            }
        }
        println!(
            "capture-connections: read={} accepted={} tcp={} udp={} ipv4={} ipv6={} unknown={} correlated={} dropped={} malformed={} sequence-exhausted={}",
            total.read,
            total.accepted,
            total.tcp,
            total.udp,
            total.ipv4,
            total.ipv6,
            total.unknown,
            total.correlated,
            total.dropped,
            total.malformed,
            total.sequence_exhausted,
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (object_path, cgroup_path, duration);
        Err("capture-connections requires Linux".to_owned())
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "capture-connections")
    {
        let (Some(object), Some(cgroup), Some(duration)) =
            (arguments.get(2), arguments.get(3), arguments.get(4))
        else {
            eprintln!(
                "usage: sentryd capture-connections <BPF-object> <cgroup-path> <duration-ms>"
            );
            std::process::exit(2);
        };
        let duration_ms = duration.parse::<u64>().unwrap_or_else(|_| {
            eprintln!("duration-ms must be an unsigned integer");
            std::process::exit(2);
        });
        if let Err(error) = capture_connections(
            Path::new(object),
            Path::new(cgroup),
            Duration::from_millis(duration_ms),
        ) {
            eprintln!("capture-connections failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "capture-filesystem")
    {
        let (Some(object), Some(duration)) = (arguments.get(2), arguments.get(3)) else {
            eprintln!(
                "usage: sentryd capture-filesystem <BPF-object> <duration-ms> CLASS=PATH [...]"
            );
            std::process::exit(2);
        };
        let duration_ms = duration.parse::<u64>().unwrap_or_else(|_| {
            eprintln!("duration-ms must be an unsigned integer");
            std::process::exit(2);
        });
        if let Err(error) = capture_filesystem(
            Path::new(object),
            Duration::from_millis(duration_ms),
            &arguments[4..],
        ) {
            eprintln!("capture-filesystem failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "capture-lifecycle" || argument == "capture-exec")
    {
        let Some(object) = arguments.get(2) else {
            eprintln!("usage: sentryd capture-lifecycle <BPF-object> [duration-ms]");
            std::process::exit(2);
        };
        let duration_ms = arguments
            .get(3)
            .map_or(Ok(1_000_u64), |value| value.parse::<u64>())
            .unwrap_or_else(|_| {
                eprintln!("duration-ms must be an unsigned integer");
                std::process::exit(2);
            });
        if let Err(error) = capture_lifecycle(Path::new(object), Duration::from_millis(duration_ms))
        {
            eprintln!("capture-lifecycle failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    println!("sentryd {}", env!("CARGO_PKG_VERSION"));
    if std::env::consts::OS != "linux" {
        println!("host: unsupported (Linux required)");
        return;
    }
    let preflight = KernelPreflight::inspect(std::path::Path::new("/"));
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").map_or_else(
        |_| "unavailable".to_owned(),
        |release| release.trim().to_owned(),
    );
    println!("kernel: {kernel}");
    println!("arch: {}", std::env::consts::ARCH);
    println!("btf: {} (preflight)", preflight.btf_readable);
    println!(
        "bpf-lsm: {} (preflight; attachment unverified)",
        preflight.bpf_lsm_active
    );
    println!(
        "cgroup-v2: {} (preflight; attachment unverified)",
        preflight.cgroup_v2_available
    );
}
