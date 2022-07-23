//! Internet layer: Internet Protocol message header construction

use crate::{IpV4Addr, Protocol, DSCP};

use byte_struct::*;
use modular_bitfield::prelude::*;
use static_assertions::const_assert;
use ufmt::derive::uDebug;

const_assert!(IpV4Header::BYTE_LEN == 20);

/// IPV4 header per IETF-RFC-791.
/// See https://en.wikipedia.org/wiki/IPv4.
#[derive(ByteStruct, Clone, Copy, uDebug, Debug, PartialEq, Eq)]
#[byte_struct_be]
pub struct IpV4Header {
    /// Combined version and header length info in a single byte
    pub version_and_header_length: VersionAndHeaderLength,
    /// Type of Service / Differentiated-Service
    pub dscp: DSCP,
    /// Total length including header and data
    pub total_length: u16,
    /// Mostly-legacy id field
    pub identification: u16,
    /// Mostly-legacy packet fragmentation info
    pub fragmentation: Fragmentation,
    /// TTL counter
    pub time_to_live: u8,
    /// Transport-layer protocol
    pub protocol: Protocol,
    /// CRC checksum
    pub checksum: u16,
    /// Source IP address
    pub src_ipaddr: IpV4Addr,
    /// Destination IP address
    pub dst_ipaddr: IpV4Addr,
}

impl IpV4Header {
    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0_u8; Self::BYTE_LEN];
        self.write_bytes(&mut bytes);
        bytes
    }
}

/// IPV4 frame with header and data.
/// Data should be sized in a multiple of 4 bytes.
#[derive(Clone, Copy, uDebug, Debug, PartialEq, Eq)]
pub struct IpV4Frame<T>
where
    T: ByteStruct,
{
    /// IP header
    pub header: IpV4Header,
    /// Data such as a UDP header; should be some multiple of 4 bytes (32-bit words)
    pub data: T,
}

impl<T> ByteStructLen for IpV4Frame<T>
where
    T: ByteStruct,
{
    const BYTE_LEN: usize = IpV4Header::BYTE_LEN + T::BYTE_LEN;
}

impl<T> ByteStruct for IpV4Frame<T>
where
    T: ByteStruct,
{
    fn read_bytes(bytes: &[u8]) -> Self {
        IpV4Frame::<T> {
            header: IpV4Header::read_bytes(&bytes[0..IpV4Header::BYTE_LEN]),
            data: T::read_bytes(&bytes[IpV4Header::BYTE_LEN..]),
        }
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        self.header.write_bytes(&mut bytes[0..IpV4Header::BYTE_LEN]);
        self.data.write_bytes(&mut bytes[IpV4Header::BYTE_LEN..]);
    }
}

impl<T> IpV4Frame<T>
where
    T: ByteStruct,
{
    fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0_u8; Self::BYTE_LEN];
        self.write_bytes(&mut bytes);
        bytes
    }
}

/// Fragmentation flags and offset info
#[bitfield(bits = 16)]
#[derive(Clone, Copy, uDebug, Debug, Default, PartialEq, Eq)]
pub struct Fragmentation {
    unused: B1,
    /// Flag for routers to drop packets instead of fragmenting
    pub do_not_fragment: B1,
    /// Flag that there are more fragments coming
    pub more_fragments: B1,
    /// Where we are in a set of fragments
    pub offset: B13,
}

impl ByteStructLen for Fragmentation {
    const BYTE_LEN: usize = 2;
}

impl ByteStruct for Fragmentation {
    fn read_bytes(bytes: &[u8]) -> Self {
        // All bit patterns are valid, so this will never error
        let mut bytes_to_read = [0_u8; Fragmentation::BYTE_LEN];
        bytes_to_read.copy_from_slice(&bytes[0..=1]);
        Fragmentation::from_bytes(bytes_to_read)
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        let bytes_to_write = self.into_bytes();
        bytes[0] = bytes_to_write[0];
        bytes[1] = bytes_to_write[1];
    }
}

/// Combined IP version and header length in a single byte.
#[bitfield(bits = 8)]
#[derive(Clone, Copy, uDebug, Debug, Default, PartialEq, Eq)]
pub struct VersionAndHeaderLength {
    /// IP version number
    pub version: B4,
    /// Length of IP header in 32-bit words (usually 5 words, or 20 bytes)
    pub header_length: B4,
}

impl ByteStructLen for VersionAndHeaderLength {
    const BYTE_LEN: usize = 1;
}

impl ByteStruct for VersionAndHeaderLength {
    fn read_bytes(bytes: &[u8]) -> Self {
        // All bit patterns are valid, so this will never error
        VersionAndHeaderLength::from_bytes([bytes[0]])
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        bytes[0] = self.into_bytes()[0];
    }
}
