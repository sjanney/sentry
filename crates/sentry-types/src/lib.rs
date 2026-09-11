// SPDX-License-Identifier: Apache-2.0
#![no_std]

pub const EVENT_ABI_VERSION: u16 = 1;
pub const EVENT_HEADER_SIZE: usize = 48;
pub const EVENT_HEADER_SIZE_U32: u32 = 48;
pub const MAX_EVENT_BYTES: u32 = 4096;
pub const KERNEL_RING_BUFFER_BYTES: u32 = 1 << 20;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    Exec = 1,
    Fork = 2,
    Exit = 3,
    FileOpen = 4,
    Connect = 5,
    DnsResolution = 6,
    EnforcementDecision = 7,
    Dropped = 8,
}

impl TryFrom<u8> for EventKind {
    type Error = HeaderDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Exec),
            2 => Ok(Self::Fork),
            3 => Ok(Self::Exit),
            4 => Ok(Self::FileOpen),
            5 => Ok(Self::Connect),
            6 => Ok(Self::DnsResolution),
            7 => Ok(Self::EnforcementDecision),
            8 => Ok(Self::Dropped),
            _ => Err(HeaderDecodeError::UnknownKind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderDecodeError {
    TooShort,
    UnsupportedVersion,
    UnknownKind,
    InvalidLength,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventHeader {
    pub version: u16,
    pub kind: EventKind,
    pub flags: u8,
    pub event_size: u32,
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub run_id: u64,
    pub tgid: u32,
    pub tid: u32,
    pub parent_tgid: u32,
    pub reserved: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub run_id: u64,
    pub tgid: u32,
    pub tid: u32,
    pub parent_tgid: u32,
}

impl EventHeader {
    #[must_use]
    pub const fn new(
        kind: EventKind,
        event_size: u32,
        sequence: u64,
        timestamp_ns: u64,
        process: ProcessIdentity,
    ) -> Self {
        Self {
            version: EVENT_ABI_VERSION,
            kind,
            flags: 0,
            event_size,
            sequence,
            timestamp_ns,
            run_id: process.run_id,
            tgid: process.tgid,
            tid: process.tid,
            parent_tgid: process.parent_tgid,
            reserved: 0,
        }
    }

    #[must_use]
    pub fn encode(self) -> [u8; EVENT_HEADER_SIZE] {
        let mut bytes = [0; EVENT_HEADER_SIZE];
        bytes[0..2].copy_from_slice(&self.version.to_le_bytes());
        bytes[2] = self.kind as u8;
        bytes[3] = self.flags;
        bytes[4..8].copy_from_slice(&self.event_size.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.run_id.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.tgid.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.tid.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.parent_tgid.to_le_bytes());
        bytes[44..48].copy_from_slice(&self.reserved.to_le_bytes());
        bytes
    }

    /// # Errors
    ///
    /// Returns an error for truncated, incompatible, unknown-kind, or
    /// out-of-bounds event headers.
    pub fn decode(bytes: &[u8]) -> Result<Self, HeaderDecodeError> {
        if bytes.len() < EVENT_HEADER_SIZE {
            return Err(HeaderDecodeError::TooShort);
        }
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        if version != EVENT_ABI_VERSION {
            return Err(HeaderDecodeError::UnsupportedVersion);
        }
        let event_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if !(EVENT_HEADER_SIZE_U32..=MAX_EVENT_BYTES).contains(&event_size)
            || event_size as usize > bytes.len()
        {
            return Err(HeaderDecodeError::InvalidLength);
        }
        Ok(Self {
            version,
            kind: EventKind::try_from(bytes[2])?,
            flags: bytes[3],
            event_size,
            sequence: read_u64(bytes, 8)?,
            timestamp_ns: read_u64(bytes, 16)?,
            run_id: read_u64(bytes, 24)?,
            tgid: read_u32(bytes, 32)?,
            tid: read_u32(bytes, 36)?,
            parent_tgid: read_u32(bytes, 40)?,
            reserved: read_u32(bytes, 44)?,
        })
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, HeaderDecodeError> {
    let field: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(HeaderDecodeError::TooShort)?
        .try_into()
        .map_err(|_| HeaderDecodeError::TooShort)?;
    Ok(u32::from_le_bytes(field))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, HeaderDecodeError> {
    let field: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or(HeaderDecodeError::TooShort)?
        .try_into()
        .map_err(|_| HeaderDecodeError::TooShort)?;
    Ok(u64::from_le_bytes(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    fn header() -> EventHeader {
        EventHeader::new(
            EventKind::Exec,
            EVENT_HEADER_SIZE_U32,
            12,
            34,
            ProcessIdentity {
                run_id: 56,
                tgid: 78,
                tid: 90,
                parent_tgid: 0,
            },
        )
    }

    #[test]
    fn header_layout_is_fixed() {
        assert_eq!(size_of::<EventHeader>(), EVENT_HEADER_SIZE);
        assert_eq!(EVENT_HEADER_SIZE, 48);
    }

    #[test]
    fn header_round_trips_as_little_endian() {
        assert_eq!(EventHeader::decode(&header().encode()), Ok(header()));
    }

    #[test]
    fn malformed_headers_are_rejected() {
        assert_eq!(EventHeader::decode(&[]), Err(HeaderDecodeError::TooShort));
        let mut bytes = header().encode();
        bytes[0] = 2;
        assert_eq!(
            EventHeader::decode(&bytes),
            Err(HeaderDecodeError::UnsupportedVersion)
        );
        let mut bytes = header().encode();
        bytes[2] = 99;
        assert_eq!(
            EventHeader::decode(&bytes),
            Err(HeaderDecodeError::UnknownKind)
        );
        let mut bytes = header().encode();
        bytes[4..8].copy_from_slice(&(MAX_EVENT_BYTES + 1).to_le_bytes());
        assert_eq!(
            EventHeader::decode(&bytes),
            Err(HeaderDecodeError::InvalidLength)
        );
    }
}
