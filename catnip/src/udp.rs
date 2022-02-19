//! User Datagram Protocol

use crate::ip::IPV4Header;
use crate::Transportable;

/// UDP datagram header structure like
///
/// value [0] source port [u16]
///
/// value [1] destination port [u16]
///
/// value [2] total length in bytes [u16], header + data
///
/// value [3] checksum [u16]
#[derive(Clone, Copy, Debug)]
struct UDPHeader {
    value: [u16; 4],
}

impl UDPHeader {
    pub fn new() -> UDPHeader {
        // Start a blank header
        let header: UDPHeader = UDPHeader { value: [0_u16; 4] };

        header
    }
}

impl Transportable<8> for UDPHeader {
    /// Pack into big-endian (network) byte array
    fn to_be_bytes(&self) -> [u8; 8] {
        let mut header_bytes = [0_u8; 8];
        for (i, v) in self.value.iter().enumerate() {
            let bytes: [u8; 2] = v.to_be_bytes();
            header_bytes[2 * i] = bytes[0];
            header_bytes[2 * i + 1] = bytes[1];
        }

        header_bytes
    }
}

/// IP message frame for UDP protocol
///
/// N is size of UDP Data in 32-bit words
///
/// M is size of IP Options in 32-bit words
#[derive(Clone, Copy, Debug)]
struct UDPFrame<'a, const N: usize, const M: usize>
where
    [u8; 4 * N + 20]:,
    [u8; 4 * M]:,
{
    ip_header: IPV4Header<'a, N>,
    udp_header: UDPHeader,
    udp_data: [u8; 4 * M],
}

impl<'a, const N: usize, const M: usize> UDPFrame<'a, N, M>
where
    [u8; 4 * M]:,
    [u8; 4 * N + 20]:,
    [u8; 4 * N + 20 + 4 * M + 8]:, // Required for Transportable trait
{
    pub fn finalize(mut self) -> Self {
        // Set IP frame length and header checksum
        let ip_length: u16 = self.to_be_bytes().len() as u16;
        // self.ip_header = self.ip_header.header_checksum();

        // Set UDP data length

        // Set UDP header checksum

        self
    }
}

impl<'a, const N: usize, const M: usize> Transportable<{ 4 * M + 20 + 4 * N + 8 }>
    for UDPFrame<'a, N, M>
where
    [u8; 4 * M]:,
    [u8; 4 * N + 20]:,
    [u8; 4 * N + 20 + 4 * M + 8]:,
{
    /// Pack into big-endian (network) byte array
    fn to_be_bytes(&self) -> [u8; 4 * M + 20 + 4 * N + 8] {
        // Pack a byte array with IP header, UDP header, and UDP data
        let mut bytes = [0_u8; 4 * M + 20 + 4 * N + 8];
        let mut i = 0;
        for v in self.ip_header.to_be_bytes().iter() {
            bytes[i] = *v;
            i = i + 1;
        }
        for v in self.udp_header.to_be_bytes().iter() {
            bytes[i] = *v;
            i = i + 1;
        }
        for v in self.udp_data.iter() {
            bytes[i] = *v;
            i = i + 1;
        }

        bytes
    }
}
