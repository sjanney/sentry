// SPDX-License-Identifier: Apache-2.0
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub run_id: String,
    pub policy_version: u64,
    pub policy_hash: u64,
    pub decision: String,
    pub rule_id: Option<String>,
    /// A redacted category only; never a raw sensitive pathname or content.
    pub target_class: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditCheckpoint {
    pub sequence: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditError {
    Io(io::ErrorKind),
    Malformed { line: usize },
    Sequence { line: usize },
    PreviousHash { line: usize },
    Hash { line: usize },
}
impl From<io::Error> for AuditError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

pub struct AuditLog {
    path: std::path::PathBuf,
    last: Option<AuditCheckpoint>,
}

impl AuditLog {
    /// Opens a log and discards only an incomplete, unterminated final write.
    ///
    /// # Errors
    /// Returns an I/O or integrity error for any complete invalid record.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, AuditError> {
        let path = path.into();
        let last = recover(&path)?;
        Ok(Self { path, last })
    }

    /// Appends one canonical SHA-256 chained redacted event.
    ///
    /// # Errors
    /// Returns an error for a non-monotonic sequence or I/O failure.
    pub fn append(&mut self, event: &AuditEvent) -> Result<AuditCheckpoint, AuditError> {
        if self
            .last
            .as_ref()
            .is_some_and(|last| event.sequence <= last.sequence)
        {
            return Err(AuditError::Sequence { line: 0 });
        }
        let previous = self.last.as_ref().map_or([0; 32], |last| last.hash);
        let body = canonical_body(event, &previous);
        let hash = digest(body.as_bytes());
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(format!("{body}|{}\n", hex(&hash)).as_bytes())?;
        file.sync_data()?;
        let checkpoint = AuditCheckpoint {
            sequence: event.sequence,
            hash,
        };
        self.last = Some(checkpoint.clone());
        Ok(checkpoint)
    }
}

/// Independently reusable verifier for all complete records and a trusted checkpoint.
///
/// # Errors
/// Returns a typed integrity or I/O error.
pub fn verify(
    path: &Path,
    checkpoint: Option<&AuditCheckpoint>,
) -> Result<Option<AuditCheckpoint>, AuditError> {
    verify_bytes(&fs::read(path)?, checkpoint)
}

fn recover(path: &Path) -> Result<Option<AuditCheckpoint>, AuditError> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    if !bytes.ends_with(b"\n") {
        let complete_length = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        let complete = &bytes[..complete_length];
        fs::write(path, complete)?;
        return verify_bytes(complete, None);
    }
    verify_bytes(&bytes, None)
}

fn verify_bytes(
    bytes: &[u8],
    checkpoint: Option<&AuditCheckpoint>,
) -> Result<Option<AuditCheckpoint>, AuditError> {
    let text = std::str::from_utf8(bytes).map_err(|_| AuditError::Malformed { line: 0 })?;
    let mut prior = checkpoint.map_or([0; 32], |value| value.hash);
    let mut sequence = checkpoint.map_or(0, |value| value.sequence);
    let mut result = checkpoint.cloned();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let (body, written) = line
            .rsplit_once('|')
            .ok_or(AuditError::Malformed { line: line_number })?;
        let fields: Vec<_> = body.split('|').collect();
        if fields.len() != 9 || fields[0] != "v1" {
            return Err(AuditError::Malformed { line: line_number });
        }
        let current: u64 = fields[1]
            .parse()
            .map_err(|_| AuditError::Malformed { line: line_number })?;
        if current <= sequence {
            return Err(AuditError::Sequence { line: line_number });
        }
        if unhex32(fields[8]) != Some(prior) {
            return Err(AuditError::PreviousHash { line: line_number });
        }
        let hash = digest(body.as_bytes());
        if unhex32(written) != Some(hash) {
            return Err(AuditError::Hash { line: line_number });
        }
        prior = hash;
        sequence = current;
        result = Some(AuditCheckpoint { sequence, hash });
    }
    Ok(result)
}

fn canonical_body(event: &AuditEvent, previous: &[u8; 32]) -> String {
    format!(
        "v1|{}|{}|{}|{:016x}|{}|{}|{}|{}",
        event.sequence,
        hex(event.run_id.as_bytes()),
        event.policy_version,
        event.policy_hash,
        hex(event.decision.as_bytes()),
        event
            .rule_id
            .as_deref()
            .map_or("-".to_owned(), |value| hex(value.as_bytes())),
        hex(event.target_class.as_bytes()),
        hex(previous)
    )
}
fn digest(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}
fn hex(input: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
fn unhex32(input: &str) -> Option<[u8; 32]> {
    if input.len() != 64 {
        return None;
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(sequence: u64) -> AuditEvent {
        AuditEvent {
            sequence,
            run_id: "run-7".to_owned(),
            policy_version: 2,
            policy_hash: 9,
            decision: "would_deny".to_owned(),
            rule_id: Some("secret_taint".to_owned()),
            target_class: "credential:ssh_key".to_owned(),
        }
    }
    fn path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("sentry-audit-{name}-{}", std::process::id()))
    }
    #[test]
    fn chain_detects_corruption_reorder_and_checkpoint_deletion() {
        let path = path("chain");
        let mut log = AuditLog::open(&path).unwrap();
        let first = event(1);
        let second = event(2);
        let _first = log.append(&first).unwrap();
        let final_checkpoint = log.append(&second).unwrap();
        assert!(verify(&path, None).is_ok());
        let original = fs::read(&path).unwrap();
        let mut corrupt = original.clone();
        corrupt[10] ^= 1;
        fs::write(&path, &corrupt).unwrap();
        assert!(matches!(verify(&path, None), Err(AuditError::Hash { .. })));
        let lines: Vec<_> = std::str::from_utf8(&original).unwrap().lines().collect();
        fs::write(&path, format!("{}\n{}\n", lines[1], lines[0])).unwrap();
        assert!(matches!(
            verify(&path, None),
            Err(AuditError::PreviousHash { .. } | AuditError::Sequence { .. })
        ));
        fs::write(&path, format!("{}\n", lines[1])).unwrap();
        assert!(matches!(
            verify(&path, Some(&final_checkpoint)),
            Err(AuditError::Sequence { .. })
        ));
        let _ = fs::remove_file(path);
    }
    #[test]
    fn open_recovers_unterminated_tail() {
        let path = path("tail");
        let mut log = AuditLog::open(&path).unwrap();
        let first = event(1);
        let checkpoint = log.append(&first).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"v1|partial")
            .unwrap();
        assert_eq!(AuditLog::open(&path).unwrap().last, Some(checkpoint));
        let _ = fs::remove_file(path);
    }
}
