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

// use modular_bitfield::Specifier;
pub use byte_struct::*;

pub mod arp; // Address Resolution Protocol - midlayer between internet and transport
pub mod enet; // Link Layer
pub mod ip; // Internet layer
pub mod udp; // Transport layer // Address Resolution Protocol - not a distinct layer, but required for IP and UDP to function on most networks

pub use enet::EtherType;
pub use ip::Protocol;

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

/// MAC Addresses & methods for converting between common formats
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

    // extern crate std;
    // use std::println;

    use crate::{calc_ip_checksum, ip::IpV4Header};

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
        // println!("Cyclic Checksum: {:x}", cyclic_checksum);

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
