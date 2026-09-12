// SPDX-License-Identifier: Apache-2.0
use std::{io, os::unix::process::ExitStatusExt, process::Command};

#[derive(Debug, Eq, PartialEq)]
pub enum CliError {
    MissingCommand,
    InvalidPid,
    UnsupportedHost,
    Spawn(io::ErrorKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    ObserverUnavailable,
    AttachSnapshotOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandOutcome {
    Exited(i32),
    Signaled(i32),
}

#[must_use]
pub fn host_supported(os: &str) -> bool {
    os == "linux"
}

/// Runs a command and reports its exit status or terminating signal.
///
/// # Errors
///
/// Returns `MissingCommand` when no program is supplied and `Spawn` when the
/// operating system cannot start it.
pub fn run_command(command: &[String]) -> Result<CommandOutcome, CliError> {
    let (program, arguments) = command.split_first().ok_or(CliError::MissingCommand)?;
    let status = Command::new(program)
        .args(arguments)
        .status()
        .map_err(|error| CliError::Spawn(error.kind()))?;
    Ok(status.code().map_or_else(
        || CommandOutcome::Signaled(status.signal().unwrap_or(0)),
        CommandOutcome::Exited,
    ))
}

/// # Errors
///
/// Returns `UnsupportedHost` when the host cannot run the Linux MVP.
pub fn capabilities(os: &str) -> Result<[Capability; 2], CliError> {
    if !host_supported(os) {
        return Err(CliError::UnsupportedHost);
    }
    Ok([
        Capability::ObserverUnavailable,
        Capability::AttachSnapshotOnly,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_command_preserves_nonzero_exit_status() {
        let command = vec!["sh".to_owned(), "-c".to_owned(), "exit 23".to_owned()];
        assert_eq!(run_command(&command), Ok(CommandOutcome::Exited(23)));
    }

    #[test]
    fn wrapped_command_reports_terminating_signal() {
        let command = vec!["sh".to_owned(), "-c".to_owned(), "kill -TERM $$".to_owned()];
        assert_eq!(run_command(&command), Ok(CommandOutcome::Signaled(15)));
    }

    #[test]
    fn missing_commands_and_unsupported_hosts_are_typed_errors() {
        assert_eq!(run_command(&[]), Err(CliError::MissingCommand));
        assert!(!host_supported("macos"));
        assert_eq!(capabilities("windows"), Err(CliError::UnsupportedHost));
    }

    #[test]
    fn linux_host_is_supported() {
        assert!(host_supported("linux"));
    }
}
