//! Ethernet comms

#![no_std]
#![warn(dead_code)]
#![deny(missing_docs)]
#![feature(generic_const_exprs)]

pub mod ip; // Internet layer
pub mod udp; // Transport layer

/// MAC Addresses & methods for converting between common formats
/// Locally-administered addresses are [0x02, ...], [0x06, ...], [0x0A, ...], [0x0E, ...]
pub enum MACAddress {
    /// Split 24/24 format, Block ID | Device ID
    Split24_24(&'static mut [u8; 6]),
    /// Split 32/16 format
    Split32_16(&'static mut [u8; 6]),
}

impl MACAddress {}

/// Calculate IP checksum per IETF-RFC-768
/// following implementation guide in IETF-RFC-1071 section 4.1
/// https://datatracker.ietf.org/doc/html/rfc1071#section-4
/// using a section of a byte array
pub fn calc_checksum(data: &[u8]) -> u16 {
    let n: usize = data.len();
    let mut sum: i32 = 0;
    let mut i: usize = 0;
    let mut count: usize = n;
    while count > 1 {
        // Combine bytes to form u16; cast to u32; add to sum
        let bytes: [u8; 2] = [data[i], data[i + 1]];
        sum = sum + u16::from_be_bytes(bytes) as i32;

        count = count - 1;
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

#[cfg(test)]
mod tests {

    use crate::ip::*;

    /// Following example from https://www.thegeekstuff.com/2012/05/ip-header-checksum/
    #[test]
    fn test_calc_checksum() -> () {
        // Sample header with zero checksum: 4500 003c 1c46 4000 4006 b1e6 ac10 0a63 ac10 0a0c
        let mut ipheader_example_16: &[u16; 10] = &[
            0x4500_u16, 0x003c_u16, 0x1c46_u16, 0x4000_u16, 0x4006_u16, 0xb1e6_u16, 0xac10_u16,
            0x0a63_u16, 0xac10_u16, 0x0a0c_u16,
        ];

        // Convert words to bytes
        let mut ipheader_example_8: [u8; 20] = [0_u8; 20];
        for (i, v) in ipheader_example_16.iter().enumerate() {
            let bytes: [u8; 2] = v.to_be_bytes();
            ipheader_example_8[i] = bytes[0];
            ipheader_example_8[i + 1] = bytes[1];
        }

        let header: IPV4Header<0_usize> = IPV4Header {
            header: ipheader_example_8,
        };
    }
}
