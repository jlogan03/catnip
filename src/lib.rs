//! Ethernet comms

#![no_std]
#![allow(dead_code)]
#![deny(missing_docs)]
#![feature(generic_const_exprs)]
#![feature(test)]

// While Deref implementations are usually a bad sign, we're only using them for
// a #[repr(transparent)] newtype here in order to avoid reimplementing array indexing.
use core::ops::{Deref, DerefMut};

#[cfg(feature = "panic_never")]
use panic_never as _;

pub use byte_struct::{ByteStruct, ByteStructLen};
pub use modular_bitfield;
pub use ufmt::{uDebug, uDisplay, uWrite, derive::uDebug};

pub mod arp; // Address Resolution Protocol - technically an internet layer
pub mod enet; // Link Layer
pub mod ip; // Internet layer
pub mod udp; // Transport layer // Address Resolution Protocol - not a distinct layer, but required for IP and UDP to function on most networks

pub use arp::*;
pub use enet::*;
pub use ip::*;
pub use udp::*;

/// Newtype for byte arrays in order to be able to implement traits on them
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

impl<const N: usize> Deref for ByteArray<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for ByteArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> ByteStructLen for ByteArray<N> {
    const BYTE_LEN: usize = N;
}

impl<const N: usize> ByteStruct for ByteArray<N> {
    fn read_bytes(bytes: &[u8]) -> Self {
        let mut out = [0_u8; N];
        out.copy_from_slice(&bytes[0..N]);
        ByteArray(out)
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        for i in 0..N {
            bytes[i] = self[i];
        }
    }
}

impl<const N: usize> ByteArray<N> {
    /// Convert to big-endian byte array
    pub fn to_be_bytes(&self) -> [u8; N] {
        *self.deref()
    }
}

impl uDebug for ByteArray<4> {
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: uWrite + ?Sized,
    {
        <[u8; 4] as uDebug>::fmt(&self, f)
    }
}

impl uDebug for ByteArray<6> {
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: uWrite + ?Sized,
    {
        <[u8; 6] as uDebug>::fmt(&self, f)
    }
}

/// Standard 6-byte MAC address
///
/// Split 24/24 format, Block ID | Device ID
///
/// Locally-administered addresses are [0x02, ...], [0x06, ...], [0x0A, ...], [0x0E, ...]
pub type MacAddr = ByteArray<6>;

impl MacAddr {
    /// New from bytes
    pub fn new(v: [u8; 6]) -> Self {
        ByteArray(v)
    }

    /// Broadcast address (all ones)
    pub const BROADCAST: MacAddr = ByteArray([0xFF_u8; 6]);

    /// Any address (all zeroes)
    pub const ANY: MacAddr = ByteArray([0x0_u8; 6]);
}

/// IPV4 Address as bytes
pub type IpV4Addr = ByteArray<4>;

impl IpV4Addr {
    /// New from bytes
    pub fn new(v: [u8; 4]) -> Self {
        ByteArray(v)
    }

    /// Broadcast address (all ones)
    pub const BROADCAST: IpV4Addr = ByteArray([0xFF_u8; 4]);

    /// Any address (all zeroes)
    pub const ANY: IpV4Addr = ByteArray([0x0_u8; 4]);
}

/// EtherType tag values (incomplete list - there are many more not implemented here)
///
/// See https://en.wikipedia.org/wiki/EtherType
#[derive(Clone, Copy, uDebug, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum EtherType {
    /// IPV4
    IPV4 = 0x0800,
    /// ARP
    ARP = 0x0806,
    /// VLAN - if this tag is encountered, then this is not the real ethertype field, and we're reading an 802.1Q VLAN tag instead
    VLAN = 0x8100,
    /// IPV6
    IPV6 = 0x86DD,
    /// EtherCat
    EtherCat = 0x88A4,
    /// Precision Time Protocol
    PTP = 0x88A7,
    /// Catch-all for uncommon types not handled here
    Unimplemented,
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            x if x == EtherType::ARP as u16 => EtherType::ARP,
            x if x == EtherType::EtherCat as u16 => EtherType::EtherCat,
            x if x == EtherType::IPV4 as u16 => EtherType::IPV4,
            x if x == EtherType::IPV6 as u16 => EtherType::IPV6,
            x if x == EtherType::PTP as u16 => EtherType::PTP,
            x if x == EtherType::VLAN as u16 => EtherType::VLAN,
            _ => EtherType::Unimplemented,
        }
    }
}

impl ByteStructLen for EtherType {
    const BYTE_LEN: usize = 2;
}

impl ByteStruct for EtherType {
    fn read_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 2 {
            return EtherType::Unimplemented;
        } else {
            let mut bytes_read = [0_u8; 2];
            bytes_read.copy_from_slice(&bytes[0..=1]);
            return EtherType::from(u16::from_be_bytes(bytes_read));
        }
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        if bytes.len() >= 2 {
            let bytes_to_write = (*self as u16).to_be_bytes();
            bytes[0] = bytes_to_write[0];
            bytes[1] = bytes_to_write[1];
        } else {
            // Do nothing - no bytes to write
        }
    }
}

impl EtherType {
    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        (*self as u16).to_be_bytes()
    }
}

/// Common choices of transport-layer protocols and their IP header values.
///
/// There are many more protocols not listed here -
/// see https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
#[derive(Clone, Copy, uDebug, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Protocol {
    /// Transmission Control Protocol
    TCP = 0x06,
    /// User Datagram Protocol
    UDP = 0x11,
    /// Unimplemented
    Unimplemented,
}

impl ByteStructLen for Protocol {
    const BYTE_LEN: usize = 1;
}

impl ByteStruct for Protocol {
    fn read_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 1 {
            return Protocol::Unimplemented;
        } else {
            return match bytes[0] {
                x if x == (Protocol::TCP as u8) => Protocol::TCP,
                x if x == (Protocol::UDP as u8) => Protocol::UDP,
                _ => Protocol::Unimplemented,
            };
        }
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        if bytes.len() >= 1 {
            bytes[0] = *self as u8;
        } else {
            // Do nothing - no bytes to write
        }
    }
}

impl Protocol {
    fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        (*self as u8).to_be_bytes()
    }
}

/// Type-of-Service for networks with differentiated services.
///
/// See https://en.wikipedia.org/wiki/Differentiated_services.
#[derive(Clone, Copy, uDebug, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DSCP {
    /// Standard is almost always fine
    Standard = 0,
    /// Realtime is rarely used
    Realtime = 32 << 2,
    /// Catch-all for the many other kinds or invalid bit patterns
    Unimplemented,
}

impl ByteStructLen for DSCP {
    const BYTE_LEN: usize = 1;
}

impl ByteStruct for DSCP {
    fn read_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 1 {
            return DSCP::Unimplemented;
        } else {
            return match bytes[0] {
                x if x == (DSCP::Standard as u8) => DSCP::Standard,
                x if x == (DSCP::Realtime as u8) => DSCP::Realtime,
                _ => DSCP::Unimplemented,
            };
        }
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        if bytes.len() >= 1 {
            bytes[0] = *self as u8;
        } else {
            // Do nothing - no bytes to write
        }
    }
}

impl DSCP {
    fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        (*self as u8).to_be_bytes()
    }
}

/// Calculate IP checksum per IETF-RFC-768
/// following implementation guide in IETF-RFC-1071 section 4.1 .
/// See https://datatracker.ietf.org/doc/html/rfc1071#section-4 .
pub fn calc_ip_checksum(data: &[u8]) -> u16 {
    let n: usize = data.len();
    let mut sum: i32 = 0;
    let mut i: usize = 0;
    let mut count: usize = n;
    while count > 1 {
        // Combine bytes to form u16; cast to u32; add to sum
        let bytes: [u8; 2] = [data[i], data[i + 1]];
        sum = sum + u16::from_be_bytes(bytes) as i32;

        count = count - 2;
        i = i + 2;
    }

    // There may be a single byte left; it is paired with 0 (just add the byte)
    if count > 0 {
        sum = sum + data[n - 1] as i32;
    };

    // Fold 32-bit accumulator into 16 bits
    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Take one's complement
    let checksum: u16 = (!sum) as u16;

    return checksum;
}
