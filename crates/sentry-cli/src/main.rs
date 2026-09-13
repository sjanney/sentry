// SPDX-License-Identifier: Apache-2.0
use std::process;

use sentry_cli::{
    Capability, CliError, CommandOutcome, capabilities, run_command,
    run_command_with_seccomp_socket_deny,
};
use sentry_daemon::audit::{self, AuditEvent, AuditLog};
use sentry_daemon::capability::KernelPreflight;
use sentry_daemon::process_snapshot::{SnapshotError, snapshot_process_tree};
use sentry_policy::{
    Destination, ObservationTrust, RunCompleteness, RunObservation, TaintMask,
    compiler::{
        KernelCapability, KernelPolicyLimits, PolicyMode, PolicySpec, compile_kernel_policy,
        load_policy_spec_json, validate_seccomp_fallback,
    },
    merge_profile, render_policy_candidate,
};
use std::collections::BTreeSet;

const USAGE: &str = "usage: sentry <run|observe> -- <command> [args...] | enforce --policy PATH -- <command> [args...] | generate --run-id ID --workspace PATH --domain DOMAIN | dry-run (--allow-domain DOMAIN --domain DOMAIN | --allow-cidr CIDR --ip IP) [--secret] | attach <pid> | capabilities | audit verify <path> [--checkpoint-sequence N --checkpoint-hash HEX]";

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result: Result<CommandOutcome, String> = match arguments.first().map(String::as_str) {
        Some("run") => {
            let command = if arguments.get(1).is_some_and(|argument| argument == "--") {
                &arguments[2..]
            } else {
                &arguments[1..]
            };
            if std::env::consts::OS == "linux" {
                run_command(command).map_err(|error| render_error(&error))
            } else {
                Err(render_error(&CliError::UnsupportedHost))
            }
        }
        Some("observe") => observe_command(&arguments[1..]),
        Some("enforce") => enforce_command(&arguments[1..]),
        Some("attach") => attach_command(&arguments[1..]),
        Some("capabilities") => capabilities(std::env::consts::OS)
            .map(|capabilities| {
                let preflight = KernelPreflight::inspect(std::path::Path::new("/"));
                let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").map_or_else(
                    |_| "unavailable".to_owned(),
                    |release| release.trim().to_owned(),
                );
                println!("kernel: {kernel}");
                println!("arch: {}", std::env::consts::ARCH);
                println!(
                    "btf: {} (preflight)",
                    if preflight.btf_readable {
                        "present"
                    } else {
                        "missing"
                    }
                );
                println!(
                    "bpf-lsm: {} (preflight; attachment unverified)",
                    if preflight.bpf_lsm_active {
                        "active"
                    } else {
                        "inactive"
                    }
                );
                println!(
                    "cgroup-v2: {} (preflight; attachment unverified)",
                    if preflight.cgroup_v2_available {
                        "present"
                    } else {
                        "missing"
                    }
                );
                for capability in capabilities {
                    println!("{}", render_capability(capability));
                }
                CommandOutcome::Exited(0)
            })
            .map_err(|error| render_error(&error)),
        Some("audit") if arguments.get(1).map(String::as_str) == Some("verify") => {
            verify_audit(&arguments[2..])
        }
        Some("dry-run") => dry_run(&arguments[1..]),
        Some("generate") => generate_candidate(&arguments[1..]),
        Some("--help" | "help") => {
            println!("{USAGE}");
            Ok(CommandOutcome::Exited(0))
        }
        Some("--version" | "version") => {
            println!("sentry {}", env!("CARGO_PKG_VERSION"));
            Ok(CommandOutcome::Exited(0))
        }
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(CommandOutcome::Exited(code)) => process::exit(code),
        Ok(CommandOutcome::Signaled(signal)) => terminate_with_signal(signal),
        Err(message) => {
            eprintln!("sentry: {message}");
            process::exit(2);
        }
    }
}

fn enforce_command(arguments: &[String]) -> Result<CommandOutcome, String> {
    if std::env::consts::OS != "linux" {
        return Err(render_error(&CliError::UnsupportedHost));
    }
    if arguments.len() < 4 || arguments[0] != "--policy" || arguments[2] != "--" {
        return Err("enforce requires --policy PATH -- COMMAND".to_owned());
    }
    let input = std::fs::read_to_string(&arguments[1])
        .map_err(|error| format!("could not read fallback policy: {error}"))?;
    let policy = load_policy_spec_json(&input)
        .map_err(|error| format!("fallback policy is not valid JSON: {error}"))?;
    validate_seccomp_fallback(&policy)
        .map_err(|error| format!("fallback policy rejected: {error:?}"))?;
    run_command_with_seccomp_socket_deny(&arguments[3..]).map_err(|error| render_error(&error))
}

fn verify_audit(arguments: &[String]) -> Result<CommandOutcome, String> {
    let path = arguments
        .first()
        .ok_or_else(|| "audit verify requires a log path".to_owned())?;
    let mut sequence = None;
    let mut hash = None;
    let mut index = 1;
    while index < arguments.len() {
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| "audit verify checkpoint options require a value".to_owned())?;
        match arguments[index].as_str() {
            "--checkpoint-sequence" => {
                sequence = Some(value.parse::<u64>().map_err(|_| {
                    "checkpoint sequence must be a non-negative integer".to_owned()
                })?);
            }
            "--checkpoint-hash" => {
                hash = Some(parse_hash(value)?);
            }
            _ => return Err("unknown audit verify option".to_owned()),
        }
        index += 2;
    }
    let checkpoint = match (sequence, hash) {
        (None, None) => None,
        (Some(sequence), Some(hash)) => Some(audit::AuditCheckpoint { sequence, hash }),
        _ => return Err("checkpoint sequence and hash must be provided together".to_owned()),
    };
    let verified = audit::verify(std::path::Path::new(path), checkpoint.as_ref())
        .map_err(|error| render_audit_error(&error))?;
    match verified {
        Some(checkpoint) => println!(
            "verified audit sequence {} hash {}",
            checkpoint.sequence,
            hex(&checkpoint.hash)
        ),
        None => println!("verified empty audit log"),
    }
    Ok(CommandOutcome::Exited(0))
}

fn parse_hash(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("checkpoint hash must contain exactly 64 hex characters".to_owned());
    }
    let mut hash = [0; 32];
    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "checkpoint hash must contain only hex characters".to_owned())?;
    }
    Ok(hash)
}

fn attach_command(arguments: &[String]) -> Result<CommandOutcome, String> {
    if std::env::consts::OS != "linux" {
        return Err(render_error(&CliError::UnsupportedHost));
    }
    if arguments.len() != 1 {
        return Err("attach requires exactly one PID".to_owned());
    }
    let pid = arguments
        .first()
        .ok_or(CliError::InvalidPid)
        .and_then(|pid| pid.parse().map_err(|_| CliError::InvalidPid))
        .map_err(|error| render_error(&error))?;
    let snapshot =
        snapshot_process_tree(std::path::Path::new("/proc"), pid).map_err(|error| match error {
            SnapshotError::InvalidPid => render_error(&CliError::InvalidPid),
            SnapshotError::RootUnavailable => "attach target exited or is inaccessible".to_owned(),
            SnapshotError::RootChanged | SnapshotError::InconsistentTree => {
                "attach target changed during snapshot; retry the attach".to_owned()
            }
        })?;
    println!(
        "attach snapshot: root={} start_ticks={} processes={} skipped={} coverage=partial",
        snapshot.root.tgid,
        snapshot.root.start_time_ticks,
        snapshot.processes.len(),
        snapshot.skipped_processes
    );
    Ok(CommandOutcome::Exited(0))
}

fn generate_candidate(arguments: &[String]) -> Result<CommandOutcome, String> {
    let mut run_id = None;
    let mut workspace = None;
    let mut domain = None;
    let mut index = 0;
    while index < arguments.len() {
        let value = arguments
            .get(index + 1)
            .cloned()
            .ok_or_else(|| "generate options require a value".to_owned())?;
        match arguments[index].as_str() {
            "--run-id" => run_id = Some(value),
            "--workspace" => workspace = Some(value),
            "--domain" => domain = Some(value),
            _ => return Err("unknown generate option".to_owned()),
        }
        index += 2;
    }
    let run_id = run_id.ok_or_else(|| "generate requires --run-id ID".to_owned())?;
    let workspace = workspace.ok_or_else(|| "generate requires --workspace PATH".to_owned())?;
    let domain = domain.ok_or_else(|| "generate requires --domain DOMAIN".to_owned())?;
    let profile = merge_profile([RunObservation {
        run_id,
        completeness: RunCompleteness::Complete,
        trust: ObservationTrust::Trusted,
        workspace_paths: BTreeSet::from([workspace]),
        domains: BTreeSet::from([domain]),
        credential_classes: BTreeSet::new(),
    }])
    .map_err(|error| format!("profile generation failed: {error:?}"))?;
    print!("{}", render_policy_candidate(&profile));
    Ok(CommandOutcome::Exited(0))
}

fn dry_run(arguments: &[String]) -> Result<CommandOutcome, String> {
    let mut allowed = None;
    let mut allowed_cidr = None;
    let mut domain = None;
    let mut ip = None;
    let mut secret = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--allow-domain" => {
                index += 1;
                allowed = arguments.get(index).cloned();
            }
            "--allow-cidr" => {
                index += 1;
                allowed_cidr = arguments.get(index).cloned();
            }
            "--domain" => {
                index += 1;
                domain = arguments.get(index).cloned();
            }
            "--ip" => {
                index += 1;
                ip = arguments.get(index).cloned();
            }
            "--secret" => secret = true,
            _ => return Err("unknown dry-run option".to_owned()),
        }
        index += 1;
    }
    if allowed.is_none() && allowed_cidr.is_none() {
        return Err("dry-run requires --allow-domain DOMAIN or --allow-cidr CIDR".to_owned());
    }
    let domain = domain.as_deref();
    if allowed.is_some() && domain.is_none() {
        return Err("--allow-domain requires --domain DOMAIN".to_owned());
    }
    if allowed_cidr.is_some() && ip.is_none() {
        return Err("--allow-cidr requires --ip IP".to_owned());
    }
    let ip = ip
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| "--ip requires a valid IP address".to_owned())?;
    let capabilities = BTreeSet::from([
        KernelCapability::BpfLsm,
        KernelCapability::CgroupV2,
        KernelCapability::DnsObservation,
    ]);
    let policy = PolicySpec {
        schema_version: 1,
        policy_version: 1,
        mode: PolicyMode::DryRun,
        default_deny: true,
        deny_untrusted_egress: true,
        allowed_domains: allowed.into_iter().collect(),
        allowed_cidrs: allowed_cidr.into_iter().collect(),
        required_capabilities: capabilities.clone(),
    };
    let compiled = compile_kernel_policy(
        &policy,
        &capabilities,
        KernelPolicyLimits {
            max_domains: 16,
            max_cidrs: 16,
            max_serialized_bytes: 4096,
        },
    )
    .map_err(|error| format!("dry-run policy error: {error:?}"))?;
    let verdict = compiled.dry_run_egress(
        TaintMask {
            secret,
            untrusted_input: false,
        },
        Destination {
            ip,
            domain,
            dns_observed: domain.is_some(),
            ttl_valid: true,
            same_execution_domain: true,
        },
    );
    println!(
        "policy_hash={} would_deny={} rule_id={:?} explanation={}",
        verdict.policy_hash, verdict.would_deny, verdict.rule_id, verdict.explanation
    );
    Ok(CommandOutcome::Exited(0))
}

fn observe_command(arguments: &[String]) -> Result<CommandOutcome, String> {
    if std::env::consts::OS != "linux" {
        return Err(render_error(&CliError::UnsupportedHost));
    }
    let Some((flag, remainder)) = arguments.split_first() else {
        return Err("observe requires --audit-log PATH -- COMMAND".to_owned());
    };
    if flag != "--audit-log" || remainder.len() < 3 || remainder[1] != "--" {
        return Err("observe requires --audit-log PATH -- COMMAND".to_owned());
    }
    let run_id = format!("observe-{}", process::id());
    let mut log = AuditLog::open(&remainder[0]).map_err(|error| render_audit_error(&error))?;
    log.append(&AuditEvent {
        sequence: 1,
        run_id: run_id.clone(),
        policy_version: 0,
        policy_hash: 0,
        decision: "observe_started".to_owned(),
        rule_id: None,
        target_class: "command".to_owned(),
    })
    .map_err(|error| render_audit_error(&error))?;
    let outcome = run_command(&remainder[2..]).map_err(|error| render_error(&error))?;
    log.append(&AuditEvent {
        sequence: 2,
        run_id,
        policy_version: 0,
        policy_hash: 0,
        decision: match outcome {
            CommandOutcome::Exited(_) => "command_exited".to_owned(),
            CommandOutcome::Signaled(_) => "command_signaled".to_owned(),
        },
        rule_id: None,
        target_class: "command".to_owned(),
    })
    .map_err(|error| render_audit_error(&error))?;
    Ok(outcome)
}

fn render_audit_error(error: &audit::AuditError) -> String {
    format!("audit verification failed: {error:?}")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

fn terminate_with_signal(signal: i32) -> ! {
    let process_id = process::id().to_string();
    let signal_number = signal.to_string();
    let _ = process::Command::new("kill")
        .args(["-s", &signal_number, &process_id])
        .status();
    process::exit(128 + signal)
}

fn render_capability(capability: Capability) -> &'static str {
    match capability {
        Capability::ObserverUnavailable => "observer: unavailable (eBPF integration pending)",
        Capability::AttachSnapshotOnly => {
            "attach: partial process snapshot only (live sensor integration pending)"
        }
    }
}

fn render_error(error: &CliError) -> String {
    match error {
        CliError::MissingCommand => "a command is required".to_owned(),
        CliError::InvalidPid => "attach requires a non-zero numeric PID".to_owned(),
        CliError::UnsupportedHost => "this MVP supports Linux hosts only".to_owned(),
        CliError::Spawn(kind) => format!("could not start command: {kind}"),
        CliError::SeccompSetup(detail) => format!("could not install seccomp fallback: {detail}"),
    }
}
