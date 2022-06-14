//! Ethernet comms

#![no_std]
#![allow(dead_code)]
#![deny(missing_docs)]
#![feature(generic_const_exprs)]
#![feature(test)]

#[cfg(feature = "panic_never")]
use panic_never as _;

pub mod arp;
pub mod enet; // Link Layer
pub mod ip; // Internet layer
pub mod udp; // Transport layer // Address Resolution Protocol - not a distinct layer, but required for IP and UDP to function on most networks

pub use enet::EtherType;
pub use ip::{Flags, Protocol, Version, DSCP};

// All protocols' headers, data, and frames must be able to convert to byte array
// in order to be consumed by EMAC/PHY drivers for transmission
// TODO: bring this impl back in once const generic exprs in trait bounds no longer break the compiler
// pub trait Transportable<const N: usize> {
//     /// Length of byte representation
//     const LENGTH: usize = N;
//     /// Get length of byte representation
//     fn len(&self) -> usize {
//         Self::LENGTH
//     }
//     /// Convert to big-endian (network) byte array
//     fn to_be_bytes(&self) -> [u8; N];
// }

/// MAC Addresses & methods for converting between common formats
///
/// Locally-administered addresses are [0x02, ...], [0x06, ...], [0x0A, ...], [0x0E, ...]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct MACAddr {
    /// Split 24/24 format, Block ID | Device ID
    pub value: [u8; 6],
}

impl MACAddr {
    /// Formalize a MAC address from bytes
    pub fn new(value: [u8; 6]) -> Self {
        return MACAddr { value: value };
    }
}

/// IPV4 Address as bytes
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct IPV4Addr {
    /// 4-byte IP address
    pub value: [u8; 4],
}

impl IPV4Addr {
    /// Formalize a IPV4 address from bytes
    pub fn new(value: [u8; 4]) -> Self {
        return IPV4Addr { value: value };
    }
}

/// IP and UDP require their data to be a multiple of 4 bytes (32-bit words)
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct Data<const Q: usize>
where
    [u8; 4 * Q]:,
{
    /// Byte array of data
    pub value: [u8; 4 * Q],
}

impl<const Q: usize> Data<Q>
where
    [u8; 4 * Q]:,
{
    /// Length of byte representation
    const LENGTH: usize = 4 * Q;

    /// Get length of byte representation
    fn len(&self) -> usize {
        Self::LENGTH
    }

    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; 4 * Q] {
        self.value
    }
}

/// Calculate IP checksum per IETF-RFC-768
///
/// following implementation guide in IETF-RFC-1071 section 4.1
///
/// https://datatracker.ietf.org/doc/html/rfc1071#section-4
///
/// using a section of a byte array
#[cfg(feature = "crc")]
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

/// Return blank checksum; real checksum must be calculated by hardware
#[cfg(not(feature = "crc"))]
pub fn calc_ip_checksum(data: &[u8]) -> u16 {
    0_u16
}

#[cfg(test)]
mod tests {

    extern crate std;
    use std::println;

    use crate::{calc_ip_checksum, ip::IPV4Header};

    /// Test cyclic redundancy check following example from https://www.thegeekstuff.com/2012/05/ip-header-checksum/
    #[test]
    #[cfg(feature = "crc")]
    fn test_calc_ip_checksum() -> () {
        // Sample header with pre-calculated checksum: 4500 003c 1c46 4000 4006 b1e6 ac10 0a63 ac10 0a0c
        let ipheader_example_16: &[u16; 10] = &[
            0x4500_u16, 0x003c_u16, 0x1c46_u16, 0x4000_u16, 0x4006_u16, 0xb1e6_u16, 0xac10_u16,
            0x0a63_u16, 0xac10_u16, 0x0a0c_u16,
        ];
        let header: IPV4Header<0> = IPV4Header::<0>::from_16bit_words(ipheader_example_16);

        // Expected outputs
        let checksum_expected = ipheader_example_16[5]; // The example already has a checksum in place
        let cyclic_checksum_expected: u16 = 0; // If the calculated checksum is already in place, should sum to 0

        // Make sure that the checksum over the header that already includes a checksum comes out correct
        let cyclic_checksum = calc_ip_checksum(&header.value);
        assert_eq!(cyclic_checksum, cyclic_checksum_expected);
        println!("Cyclic Checksum: {:x}", cyclic_checksum);

        // Make sure that the checksum over the header with the existing checksum removed also comes out correct
        let mut ipheader_example_16_modified_checksum = ipheader_example_16.clone();
        ipheader_example_16_modified_checksum[5] = 0_u16; // Erase existing checksum
        let header: IPV4Header<0> =
            IPV4Header::<0>::from_16bit_words(&ipheader_example_16_modified_checksum);
        let checksum = calc_ip_checksum(&header.value);
        assert_eq!(checksum, checksum_expected);

        // Make sure it errors if a value is changed
        ipheader_example_16_modified_checksum[5] = 1_u16;
        let header: IPV4Header<0> =
            IPV4Header::<0>::from_16bit_words(&ipheader_example_16_modified_checksum);
        let checksum = calc_ip_checksum(&header.value);
        assert_ne!(checksum, 0_u16);

        // Make sure it works for odd-numbered Options length
        let ipheader_16_extended: &[u16; 12] = &[
            0x4500_u16, 0x003c_u16, 0x1c46_u16, 0x4000_u16, 0x4006_u16, 0_u16, 0xac10_u16,
            0x0a63_u16, 0xac10_u16, 0x0a0c_u16, 0x0F00_u16, 0_u16,
        ];
        let mut header: IPV4Header<1> = IPV4Header::<1>::from_16bit_words(&ipheader_16_extended);
        header.header_checksum(); // Apply checksum value
        let cyclic_check = calc_ip_checksum(&header.value);
        assert_eq!(cyclic_check, 0_u16);
    }
}
