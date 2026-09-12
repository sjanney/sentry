// SPDX-License-Identifier: Apache-2.0
use sentry_daemon::capability::KernelPreflight;

fn main() {
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
