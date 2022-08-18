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
pub use ufmt::{derive::uDebug, uDebug, uDisplay, uWrite};

pub mod enet; // Link Layer
pub mod ip; // Internet layer
pub mod udp; // Transport layer

pub mod arp; // Address Resolution Protocol - not a distinct layer (between link and transport), but required for IP and UDP to function on most networks.
pub mod dhcp; // Dynamic Host Configuration Protocol - for negotiating an IP address from a router/switch. Uses UDP.

pub use arp::*;
pub use dhcp::*;
pub use enet::*;
pub use ip::*;
pub use udp::*;

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

/// Derive To/From with an added "Unknown" variant catch-all for converting
/// from numerical values that do not match a valid variant in order to
/// avoid either panicking or cumbersome error handling.
///
/// Yoinked shamelessly (with some modification) from smoltcp.
#[macro_export]
macro_rules! enum_with_unknown {
    (
        $( #[$enum_attr:meta] )*
        pub enum $name:ident($ty:ty) {
            $(
              $( #[$variant_attr:meta] )*
              $variant:ident = $value:expr
            ),+ $(,)?
        }
    ) => {
        #[derive(Debug, uDebug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        $( #[$enum_attr] )*
        pub enum $name {
            $(
              $( #[$variant_attr] )*
              $variant
            ),*,
            /// Catch-all for values that do not match a variant
            Unknown($ty)
        }

        impl ::core::convert::From<$ty> for $name {
            fn from(value: $ty) -> Self {
                match value {
                    $( $value => $name::$variant ),*,
                    other => $name::Unknown(other)
                }
            }
        }

        impl ::core::convert::From<$name> for $ty {
            fn from(value: $name) -> Self {
                match value {
                    $( $name::$variant => $value ),*,
                    $name::Unknown(other) => other
                }
            }
        }
    }
}

/// Calculate IP checksum per IETF-RFC-768
/// following implementation guide in IETF-RFC-1071 section 4.1 .
/// See <https://datatracker.ietf.org/doc/html/rfc1071#section-4> .
/// This function is provided for convenience and is not used directly.
pub fn calc_ip_checksum(data: &[u8]) -> u16 {
    // Partial calc
    let sum = calc_ip_checksum_incomplete(data);
    // Fold and flip
    let checksum = calc_ip_checksum_finalize(sum);

    checksum
}

/// Finalize an IP checksum by folding the accumulator from an [i32]
/// to a [u16] and taking the one's complement
pub fn calc_ip_checksum_finalize(sum: u32) -> u16 {
    // Copy to avoid mutating the input, which may be used for something else
    // since some checksums relate to overlapping data
    let mut sum = sum;

    // Fold 32-bit accumulator into 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Convert to u16 and take bitwise complement
    let checksum = !(sum as u16);

    checksum
}

/// Calculate an IP checksum on incomplete data
/// returning the unfolded accumulator as [i32]
/// 
/// This is a slowish method by about a factor of 2-4.
/// It would be faster to case pairs of bytes to u16,
/// but this method avoids generating panic branches in slice operations.
pub fn calc_ip_checksum_incomplete(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i: usize = 0;

    for x in data {
        if i % 2 == 0 {
            sum += (*x as u32) << 8;
        } else {
            sum += *x as u32;
        };

        i += 1;
    }

    sum
}

#[cfg(test)]
mod test {

    use crate::*;
    extern crate std;
    use std::*;

    #[test]
    fn test_calc_ip_checksum() -> () {
        let src_ipaddr: IpV4Addr = IpV4Addr::new([10, 0, 0, 1]);
        let dst_ipaddr: IpV4Addr = IpV4Addr::new([10, 0, 0, 2]);
        let mut sample_ipv4_header = IpV4Header {
            version_and_header_length: VersionAndHeaderLength::new()
                .with_version(4)
                .with_header_length((IpV4Header::BYTE_LEN / 4) as u8),
            dscp: DSCP::Standard,
            total_length: IpV4Frame::<UdpFrame<ByteArray<8>>>::BYTE_LEN as u16,
            identification: 0,
            fragmentation: Fragmentation::default(),
            time_to_live: 10,
            protocol: Protocol::Udp,
            checksum: 0,
            src_ipaddr: src_ipaddr,
            dst_ipaddr: dst_ipaddr,
        };
        let checksum_pre = calc_ip_checksum(&sample_ipv4_header.to_be_bytes());
        sample_ipv4_header.checksum = checksum_pre;
        let checksum_post = calc_ip_checksum(&sample_ipv4_header.to_be_bytes());

        assert!(checksum_post == 0)
    }
}
