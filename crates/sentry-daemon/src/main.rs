// SPDX-License-Identifier: Apache-2.0
use std::{path::Path, time::Duration};

#[cfg(target_os = "linux")]
use std::{thread, time::Instant};

use sentry_daemon::capability::KernelPreflight;

fn capture_exec(object_path: &Path, duration: Duration) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use sentry_daemon::{EventIngestor, kernel_events::ExecEventReader};

        let mut reader = ExecEventReader::load(object_path).map_err(|error| error.to_string())?;
        let mut ingestor = EventIngestor::new(16_384);
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
            if drain.read == 0 {
                thread::sleep(Duration::from_millis(10));
            }
        }
        println!(
            "capture-exec: read={} accepted={} dropped={} malformed={} redaction-rejected={} sequence-exhausted={}",
            total.read,
            total.accepted,
            total.dropped,
            total.malformed,
            total.redaction_rejected,
            total.sequence_exhausted,
        );
        return Ok(());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (object_path, duration);
        Err("capture-exec requires Linux".to_owned())
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "capture-exec")
    {
        let Some(object) = arguments.get(2) else {
            eprintln!("usage: sentryd capture-exec <BPF-object> [duration-ms]");
            std::process::exit(2);
        };
        let duration_ms = arguments
            .get(3)
            .map_or(Ok(1_000_u64), |value| value.parse::<u64>())
            .unwrap_or_else(|_| {
                eprintln!("duration-ms must be an unsigned integer");
                std::process::exit(2);
            });
        if let Err(error) = capture_exec(Path::new(object), Duration::from_millis(duration_ms)) {
            eprintln!("capture-exec failed: {error}");
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
