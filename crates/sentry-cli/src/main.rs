// SPDX-License-Identifier: Apache-2.0
use std::process;

use sentry_cli::{Capability, CliError, CommandOutcome, attach, capabilities, run_command};
use sentry_daemon::audit;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result: Result<CommandOutcome, String> = match arguments.first().map(String::as_str) {
        Some("run" | "observe") => {
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
        Some("--version" | "version") => {
            println!("sentry {}", env!("CARGO_PKG_VERSION"));
            Ok(CommandOutcome::Exited(0))
        }
        _ => Err(
            "usage: sentry <run|observe> -- <command> [args...] | attach <pid> | capabilities | audit verify <path>"
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
