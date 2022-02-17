//! Ethernet comms

#![feature(generic_const_exprs)]


pub mod ip; // Internet layer
pub mod udp; // Transport layer



/// MAC Addresses & methods for converting between common formats
/// Locally-administered addresses are [0x02, ...], [0x06, ...], [0x0A, ...], [0x0E, ...]
pub struct MACAddress {
    addr: &'static mut [u8; 6],
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
    while i < n {
        // Combine bytes to form u16; cast to u32; add to sum
        let bytes: [u8; 2] = [data[i], data[i + 1]];
        sum = sum + u16::from_be_bytes(bytes) as i32;

        i = i + 2;
    }

    // If there is a byte left, it is paired with 0 (just add the byte)
    if i == n {
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
fn test() -> () {
    
}