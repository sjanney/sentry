// SPDX-License-Identifier: Apache-2.0
#![no_std]

pub const EVENT_ABI_VERSION: u16 = 1;
pub const EVENT_HEADER_SIZE: usize = 48;
pub const EVENT_HEADER_SIZE_U32: u32 = 48;
pub const FILE_OPEN_EVENT_SIZE: usize = 72;
pub const FILE_OPEN_EVENT_SIZE_U32: u32 = 72;
pub const CONNECT_EVENT_SIZE: usize = 72;
pub const CONNECT_EVENT_SIZE_U32: u32 = 72;
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
    InvalidFlags,
    NonzeroReserved,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialClass {
    SshKey = 1,
    CloudCredential = 2,
    DotEnv = 3,
    Keyring = 4,
    TokenCache = 5,
}

impl TryFrom<u8> for CredentialClass {
    type Error = FileOpenDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SshKey),
            2 => Ok(Self::CloudCredential),
            3 => Ok(Self::DotEnv),
            4 => Ok(Self::Keyring),
            5 => Ok(Self::TokenCache),
            _ => Err(FileOpenDecodeError::UnknownCredentialClass),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileAccessStatus {
    Attempted = 1,
    Succeeded = 2,
    Denied = 3,
}

impl TryFrom<u8> for FileAccessStatus {
    type Error = FileOpenDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Attempted),
            2 => Ok(Self::Succeeded),
            3 => Ok(Self::Denied),
            _ => Err(FileOpenDecodeError::UnknownStatus),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileOpenDecodeError {
    Header(HeaderDecodeError),
    WrongKind,
    InvalidLength,
    UnknownCredentialClass,
    UnknownStatus,
    NonzeroReserved,
    InvalidErrno,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    Ipv4 = 4,
    Ipv6 = 6,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkProtocol {
    Tcp = 6,
    Udp = 17,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectDecodeError {
    Header(HeaderDecodeError),
    WrongKind,
    InvalidLength,
    UnknownFamily,
    UnknownProtocol,
    NonzeroReserved,
    NoncanonicalIpv4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectEvent {
    pub header: EventHeader,
    pub family: AddressFamily,
    pub protocol: NetworkProtocol,
    pub port: u16,
    pub address: [u8; 16],
}

impl ConnectEvent {
    #[must_use]
    pub fn encode(self) -> [u8; CONNECT_EVENT_SIZE] {
        let mut bytes = [0; CONNECT_EVENT_SIZE];
        bytes[..EVENT_HEADER_SIZE].copy_from_slice(&self.header.encode());
        bytes[48] = self.family as u8;
        bytes[49] = self.protocol as u8;
        bytes[52..54].copy_from_slice(&self.port.to_le_bytes());
        bytes[56..72].copy_from_slice(&self.address);
        bytes
    }

    /// # Errors
    ///
    /// Returns an error unless the input is the exact canonical connect record.
    pub fn decode(bytes: &[u8]) -> Result<Self, ConnectDecodeError> {
        let header = EventHeader::decode(bytes).map_err(ConnectDecodeError::Header)?;
        if header.kind != EventKind::Connect {
            return Err(ConnectDecodeError::WrongKind);
        }
        if bytes.len() != CONNECT_EVENT_SIZE || header.event_size != CONNECT_EVENT_SIZE_U32 {
            return Err(ConnectDecodeError::InvalidLength);
        }
        if bytes[50] != 0 || bytes[51] != 0 || bytes[54] != 0 || bytes[55] != 0 {
            return Err(ConnectDecodeError::NonzeroReserved);
        }
        let family = match bytes[48] {
            4 => AddressFamily::Ipv4,
            6 => AddressFamily::Ipv6,
            _ => return Err(ConnectDecodeError::UnknownFamily),
        };
        let protocol = match bytes[49] {
            6 => NetworkProtocol::Tcp,
            17 => NetworkProtocol::Udp,
            _ => return Err(ConnectDecodeError::UnknownProtocol),
        };
        let mut address = [0; 16];
        address.copy_from_slice(&bytes[56..72]);
        if family == AddressFamily::Ipv4 && address[4..].iter().any(|byte| *byte != 0) {
            return Err(ConnectDecodeError::NoncanonicalIpv4);
        }
        Ok(Self {
            header,
            family,
            protocol,
            port: u16::from_le_bytes([bytes[52], bytes[53]]),
            address,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileOpenEvent {
    pub header: EventHeader,
    pub credential_class: CredentialClass,
    pub status: FileAccessStatus,
    pub errno: i32,
    pub device: u64,
    pub inode: u64,
}

impl FileOpenEvent {
    #[must_use]
    pub fn encode(self) -> [u8; FILE_OPEN_EVENT_SIZE] {
        let mut bytes = [0; FILE_OPEN_EVENT_SIZE];
        bytes[..EVENT_HEADER_SIZE].copy_from_slice(&self.header.encode());
        bytes[48] = self.credential_class as u8;
        bytes[49] = self.status as u8;
        bytes[52..56].copy_from_slice(&self.errno.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.device.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.inode.to_le_bytes());
        bytes
    }

    /// # Errors
    ///
    /// Returns an error when the record is not an exact, canonical file-open
    /// event. Successful and attempted records require errno zero; denied
    /// records require a positive errno.
    pub fn decode(bytes: &[u8]) -> Result<Self, FileOpenDecodeError> {
        let header = EventHeader::decode(bytes).map_err(FileOpenDecodeError::Header)?;
        if header.kind != EventKind::FileOpen {
            return Err(FileOpenDecodeError::WrongKind);
        }
        if bytes.len() != FILE_OPEN_EVENT_SIZE || header.event_size != FILE_OPEN_EVENT_SIZE_U32 {
            return Err(FileOpenDecodeError::InvalidLength);
        }
        if bytes[50] != 0 || bytes[51] != 0 {
            return Err(FileOpenDecodeError::NonzeroReserved);
        }
        let credential_class = CredentialClass::try_from(bytes[48])?;
        let status = FileAccessStatus::try_from(bytes[49])?;
        let errno = i32::from_le_bytes(
            bytes[52..56]
                .try_into()
                .map_err(|_| FileOpenDecodeError::InvalidLength)?,
        );
        match status {
            FileAccessStatus::Denied if errno <= 0 => {
                return Err(FileOpenDecodeError::InvalidErrno);
            }
            FileAccessStatus::Attempted | FileAccessStatus::Succeeded if errno != 0 => {
                return Err(FileOpenDecodeError::InvalidErrno);
            }
            _ => {}
        }
        Ok(Self {
            header,
            credential_class,
            status,
            errno,
            device: read_u64(bytes, 56).map_err(FileOpenDecodeError::Header)?,
            inode: read_u64(bytes, 64).map_err(FileOpenDecodeError::Header)?,
        })
    }
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
            || event_size as usize != bytes.len()
        {
            return Err(HeaderDecodeError::InvalidLength);
        }
        if bytes[3] != 0 {
            return Err(HeaderDecodeError::InvalidFlags);
        }
        if read_u32(bytes, 44)? != 0 {
            return Err(HeaderDecodeError::NonzeroReserved);
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
        let mut bytes = header().encode();
        bytes[3] = 1;
        assert_eq!(
            EventHeader::decode(&bytes),
            Err(HeaderDecodeError::InvalidFlags)
        );
        let mut bytes = header().encode();
        bytes[44..48].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            EventHeader::decode(&bytes),
            Err(HeaderDecodeError::NonzeroReserved)
        );
        let mut bytes = header().encode().to_vec();
        bytes.push(0);
        assert_eq!(
            EventHeader::decode(&bytes),
            Err(HeaderDecodeError::InvalidLength)
        );
    }

    fn file_open(status: FileAccessStatus, errno: i32) -> FileOpenEvent {
        FileOpenEvent {
            header: EventHeader::new(
                EventKind::FileOpen,
                FILE_OPEN_EVENT_SIZE_U32,
                0,
                99,
                ProcessIdentity {
                    run_id: 0,
                    tgid: 10,
                    tid: 11,
                    parent_tgid: 0,
                },
            ),
            credential_class: CredentialClass::SshKey,
            status,
            errno,
            device: 12,
            inode: 13,
        }
    }

    #[test]
    fn file_open_event_round_trips_without_a_path_or_content_field() {
        let event = file_open(FileAccessStatus::Denied, 13);
        assert_eq!(FileOpenEvent::decode(&event.encode()), Ok(event));
        assert_eq!(size_of::<FileOpenEvent>(), FILE_OPEN_EVENT_SIZE);
        assert_eq!(FILE_OPEN_EVENT_SIZE, 72);
    }

    #[test]
    fn file_open_event_rejects_noncanonical_outcomes() {
        let mut bytes = file_open(FileAccessStatus::Succeeded, 0).encode();
        bytes[50] = 1;
        assert_eq!(
            FileOpenEvent::decode(&bytes),
            Err(FileOpenDecodeError::NonzeroReserved)
        );

        let bytes = file_open(FileAccessStatus::Succeeded, 13).encode();
        assert_eq!(
            FileOpenEvent::decode(&bytes),
            Err(FileOpenDecodeError::InvalidErrno)
        );
        let bytes = file_open(FileAccessStatus::Denied, 0).encode();
        assert_eq!(
            FileOpenEvent::decode(&bytes),
            Err(FileOpenDecodeError::InvalidErrno)
        );
    }

    fn connect(family: AddressFamily, protocol: NetworkProtocol) -> ConnectEvent {
        let mut address = [0; 16];
        match family {
            AddressFamily::Ipv4 => address[..4].copy_from_slice(&[127, 0, 0, 1]),
            AddressFamily::Ipv6 => {
                address.copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            }
        }
        ConnectEvent {
            header: EventHeader::new(
                EventKind::Connect,
                CONNECT_EVENT_SIZE_U32,
                0,
                101,
                ProcessIdentity {
                    run_id: 0,
                    tgid: 20,
                    tid: 21,
                    parent_tgid: 0,
                },
            ),
            family,
            protocol,
            port: 443,
            address,
        }
    }

    #[test]
    fn connect_events_cover_both_families_and_protocols() {
        for event in [
            connect(AddressFamily::Ipv4, NetworkProtocol::Tcp),
            connect(AddressFamily::Ipv4, NetworkProtocol::Udp),
            connect(AddressFamily::Ipv6, NetworkProtocol::Tcp),
            connect(AddressFamily::Ipv6, NetworkProtocol::Udp),
        ] {
            assert_eq!(ConnectEvent::decode(&event.encode()), Ok(event));
        }
    }

    #[test]
    fn connect_events_reject_reserved_and_noncanonical_address_bytes() {
        let mut bytes = connect(AddressFamily::Ipv4, NetworkProtocol::Tcp).encode();
        bytes[54] = 1;
        assert_eq!(
            ConnectEvent::decode(&bytes),
            Err(ConnectDecodeError::NonzeroReserved)
        );
        let mut bytes = connect(AddressFamily::Ipv4, NetworkProtocol::Tcp).encode();
        bytes[71] = 1;
        assert_eq!(
            ConnectEvent::decode(&bytes),
            Err(ConnectDecodeError::NoncanonicalIpv4)
        );
    }
}
