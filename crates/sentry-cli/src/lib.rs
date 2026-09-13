// SPDX-License-Identifier: Apache-2.0
use std::{io, os::unix::process::ExitStatusExt, process::Command};

#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, convert::TryInto, os::unix::process::CommandExt};

#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

#[derive(Debug, Eq, PartialEq)]
pub enum CliError {
    MissingCommand,
    InvalidPid,
    UnsupportedHost,
    Spawn(io::ErrorKind),
    SeccompSetup(String),
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

/// Installs the Linux seccomp fallback and replaces this process with the
/// supplied command. The filter returns `EPERM` from `socket(2)` and is
/// inherited across `exec`.
///
/// This is deliberately narrower than network-egress enforcement. It does not
/// control inherited descriptors or other ways a process may acquire a socket.
///
/// # Errors
///
/// Returns `MissingCommand`, `UnsupportedHost`, or a typed setup/exec error.
pub fn run_command_with_seccomp_socket_deny(
    command: &[String],
) -> Result<CommandOutcome, CliError> {
    let (program, arguments) = command.split_first().ok_or(CliError::MissingCommand)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (program, arguments);
        Err(CliError::UnsupportedHost)
    }
    #[cfg(target_os = "linux")]
    {
        let filter = socket_deny_filter()?;
        seccompiler::apply_filter(&filter)
            .map_err(|error| CliError::SeccompSetup(error.to_string()))?;
        eprintln!("sentry: enforcement_path=seccomp_socket_deny scope=socket(2)_only");
        let error = Command::new(program).args(arguments).exec();
        Err(CliError::Spawn(error.kind()))
    }
}

#[cfg(target_os = "linux")]
fn socket_deny_filter() -> Result<BpfProgram, CliError> {
    let architecture = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|error| CliError::SeccompSetup(error.to_string()))?;
    SeccompFilter::new(
        BTreeMap::from([(libc::SYS_socket, Vec::new())]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM.cast_unsigned()),
        architecture,
    )
    .and_then(TryInto::try_into)
    .map_err(|error| CliError::SeccompSetup(error.to_string()))
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

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_socket_deny_filter_compiles_for_the_host_architecture() {
        assert!(!socket_deny_filter().unwrap().is_empty());
    }
}
