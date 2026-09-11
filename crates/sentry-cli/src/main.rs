// SPDX-License-Identifier: Apache-2.0
use std::process;

use sentry_cli::{Capability, CliError, CommandOutcome, attach, capabilities, run_command};
use sentry_daemon::audit::{self, AuditEvent, AuditLog};
use sentry_policy::{
    Destination, TaintMask,
    compiler::{
        KernelCapability, KernelPolicyLimits, PolicyMode, PolicySpec, compile_kernel_policy,
    },
};
use std::collections::BTreeSet;

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
        Some("attach") => arguments
            .get(1)
            .ok_or(CliError::InvalidPid)
            .and_then(|pid| pid.parse().map_err(|_| CliError::InvalidPid))
            .and_then(|pid| attach(pid, std::env::consts::OS))
            .map(|()| CommandOutcome::Exited(0))
            .map_err(|error| render_error(&error)),
        Some("capabilities") => capabilities(std::env::consts::OS)
            .map(|capabilities| {
                for capability in capabilities {
                    println!("{}", render_capability(capability));
                }
                CommandOutcome::Exited(0)
            })
            .map_err(|error| render_error(&error)),
        Some("audit") if arguments.get(1).map(String::as_str) == Some("verify") => arguments
            .get(2)
            .ok_or_else(|| "audit verify requires a log path".to_owned())
            .and_then(|path| audit::verify(std::path::Path::new(path), None).map_err(|error| render_audit_error(&error)))
            .map(|checkpoint| {
                match checkpoint {
                    Some(checkpoint) => println!("verified audit sequence {} hash {}", checkpoint.sequence, hex(&checkpoint.hash)),
                    None => println!("verified empty audit log"),
                }
                CommandOutcome::Exited(0)
            }),
        Some("dry-run") => dry_run(&arguments[1..]),
        Some("--version" | "version") => {
            println!("sentry {}", env!("CARGO_PKG_VERSION"));
            Ok(CommandOutcome::Exited(0))
        }
        _ => Err(
            "usage: sentry <run|observe> -- <command> [args...] | dry-run --allow-domain DOMAIN --domain DOMAIN [--secret] | attach <pid> | capabilities | audit verify <path>"
                .to_owned(),
        ),
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

fn dry_run(arguments: &[String]) -> Result<CommandOutcome, String> {
    let mut allowed = None;
    let mut domain = None;
    let mut secret = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--allow-domain" => {
                index += 1;
                allowed = arguments.get(index).cloned();
            }
            "--domain" => {
                index += 1;
                domain = arguments.get(index).cloned();
            }
            "--secret" => secret = true,
            _ => return Err("unknown dry-run option".to_owned()),
        }
        index += 1;
    }
    let allowed = allowed.ok_or_else(|| "dry-run requires --allow-domain DOMAIN".to_owned())?;
    let domain = domain.ok_or_else(|| "dry-run requires --domain DOMAIN".to_owned())?;
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
        allowed_domains: BTreeSet::from([allowed]),
        allowed_cidrs: BTreeSet::new(),
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
            domain: Some(&domain),
            dns_observed: true,
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
        Capability::AttachUnavailable => {
            "attach: unavailable (process attachment integration pending)"
        }
    }
}

fn render_error(error: &CliError) -> String {
    match error {
        CliError::MissingCommand => "a command is required".to_owned(),
        CliError::InvalidPid => "attach requires a numeric PID".to_owned(),
        CliError::UnsupportedHost => "this MVP supports Linux hosts only".to_owned(),
        CliError::AttachUnavailable { pid } => {
            format!("attach to PID {pid} is not available in this MVP; use run or observe")
        }
        CliError::Spawn(kind) => format!("could not start command: {kind}"),
    }
}
