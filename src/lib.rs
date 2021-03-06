//! A no-std, panic-never, heapless, minimally-featured UDP/IP stack for bare-metal.
//! Intended for fixed-time data acquisition and controls on LAN.
//!
//! This crate currently relies on the nightly channel, and as a result, may break regularly
//! until the required features stabilize.
//!
//! Makes use of const generic expressions to provide flexibility in, 
//! and guaranteed correctness of, lengths of headers and data segments without an allocator.
//!
//! This library is under active development; major functionality is yet to 
//! be implemented and I'm sure some bugs are yet to be found.
//! 
//! ```rust
//! use catnip::*;
//!
//! // Some made-up data with two 32-bit words' worth of bytes and some arbitrary addresses
//! let data: ByteArray<8> = ByteArray([0, 1, 2, 3, 4, 5, 6, 7]);
//!
//! // Build frame
//! let frame = EthernetFrame::<IpV4Frame<UdpFrame<ByteArray<8>>>> {
//!     header: EthernetHeader {
//!         dst_macaddr: MacAddr::BROADCAST,
//!         src_macaddr: MacAddr::new([0x02, 0xAF, 0xFF, 0x1A, 0xE5, 0x3C]),
//!         ethertype: EtherType::IpV4,
//!     },
//!     data: IpV4Frame::<UdpFrame<ByteArray<8>>> {
//!         header: IpV4Header {
//!             version_and_header_length: VersionAndHeaderLength::new().with_version(4).with_header_length((IpV4Header::BYTE_LEN / 4) as u8),
//!             dscp: DSCP::Standard,
//!             total_length: IpV4Frame::<UdpFrame<ByteArray<8>>>::BYTE_LEN as u16,
//!             identification: 0,
//!             fragmentation: Fragmentation::default(),
//!             time_to_live: 10,
//!             protocol: Protocol::Udp,
//!             checksum: 0,
//!             src_ipaddr: IpV4Addr::new([10, 0, 0, 120]),
//!             dst_ipaddr: IpV4Addr::new([10, 0, 0, 121]),
//!         },
//!         data: UdpFrame::<ByteArray<8>> {
//!             header: UdpHeader {
//!                 src_port: 8123,
//!                 dst_port: 8125,
//!                 length: UdpFrame::<ByteArray<8>>::BYTE_LEN as u16,
//!                 checksum: 0,
//!             },
//!             data: data,
//!         },
//!     },
//!     checksum: 0_u32,
//! };
//!
//! // Reduce to bytes
//! let bytes = frame.to_be_bytes();
//!
//! // Parse from bytes
//! let frame_parsed = EthernetFrame::<IpV4Frame<UdpFrame<ByteArray<8>>>>::read_bytes(&bytes);
//! assert_eq!(frame_parsed, frame);
//! ```

#![no_std]
#![allow(dead_code)]
#![deny(missing_docs)]
#![feature(generic_const_exprs)]
#![feature(test)]

#[cfg(feature = "panic_never")]
use panic_never as _;

pub use byte_struct::{ByteStruct, ByteStructLen};
pub use modular_bitfield;
pub use ufmt::{uDebug, uDisplay, uWrite, derive::uDebug};

pub mod arp; // Address Resolution Protocol - not a distinct layer (between link and transport), but required for IP and Udp to function on most networks
pub mod enet; // Link Layer
pub mod ip; // Internet layer
pub mod udp; // Transport layer

pub use arp::*;
pub use enet::*;
pub use ip::*;
pub use udp::*;

/// Newtype for [u8; N] in order to be able to implement traits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

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
            bytes[i] = self.0[i];
        }
    }
}

impl<const N: usize> ByteArray<N> {
    /// Convert to big-endian byte array
    pub fn to_be_bytes(&self) -> [u8; N] {
        self.0
    }
}

impl uDebug for ByteArray<4> {
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: uWrite + ?Sized,
    {
        <[u8; 4] as uDebug>::fmt(&self.0, f)
    }
}

impl uDebug for ByteArray<6> {
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: uWrite + ?Sized,
    {
        <[u8; 6] as uDebug>::fmt(&self.0, f)
    }
}

/// Standard 6-byte MAC address.
/// Split 24/24 format, Block ID | Device ID .
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

/// IPV4 address as bytes
pub type IpV4Addr = ByteArray<4>;

impl IpV4Addr {
    /// New from bytes
    pub fn new(v: [u8; 4]) -> Self {
        ByteArray(v)
    }

    /// Broadcast address (all ones)
    pub const BROADCAST: IpV4Addr = ByteArray([0xFF_u8; 4]);

    /// LAN broadcast address (all ones)
    pub const BROADCAST_LOCAL: IpV4Addr = ByteArray([0x0, 0x0, 0x0, 0xFF]);

    /// Any address (all zeroes)
    pub const ANY: IpV4Addr = ByteArray([0x0_u8; 4]);
}

/// Common choices of transport-layer protocols and their IP header values.
/// There are many more protocols not listed here.
/// See <https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers>.
#[derive(Clone, Copy, uDebug, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Protocol {
    /// Transmission Control Protocol
    Tcp = 0x06,
    /// User Datagram Protocol
    Udp = 0x11,
    /// Unimplemented
    Unimplemented,
}

impl ByteStructLen for Protocol {
    const BYTE_LEN: usize = 1;
}

impl ByteStruct for Protocol {
    fn read_bytes(bytes: &[u8]) -> Self {
        return match bytes[0] {
            x if x == (Protocol::Tcp as u8) => Protocol::Tcp,
            x if x == (Protocol::Udp as u8) => Protocol::Udp,
            _ => Protocol::Unimplemented,
        };
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        bytes[0] = *self as u8;
    }
}

impl Protocol {
    fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        (*self as u8).to_be_bytes()
    }
}

/// Type-of-Service for networks with differentiated services.
/// See <https://en.wikipedia.org/wiki/Differentiated_services>.
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
        return match bytes[0] {
            x if x == (DSCP::Standard as u8) => DSCP::Standard,
            x if x == (DSCP::Realtime as u8) => DSCP::Realtime,
            _ => DSCP::Unimplemented,
        };
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        bytes[0] = *self as u8;
    }
}

impl DSCP {
    fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        (*self as u8).to_be_bytes()
    }
}

/// Calculate IP checksum per IETF-RFC-768
/// following implementation guide in IETF-RFC-1071 section 4.1 .
/// See <https://datatracker.ietf.org/doc/html/rfc1071#section-4> .
/// This function is provided for convenience and is not used directly.
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
