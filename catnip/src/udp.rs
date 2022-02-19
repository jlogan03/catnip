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
struct UDPFrame<'a, const N: usize, const M: usize>
where
    [u8; 4 * N]:,
    [u8; 4 * M + 20]:,
{
    ip_header: IPV4Header<'a, M>,
    udp_header: UDPHeader,
    udp_data: [u8; 4 * N],
}

impl<'a, const N: usize, const M: usize> UDPFrame<'a, N, M>
where
    [u8; 4 * N]:,
    [u8; 4 * M + 20]:,
    [u8; 4 * M + 20 + 4 * N + 8]:,
{
    pub fn set_ip_length(mut self) -> Self
    {
        let ip_length: u16 = self.to_be_bytes().len() as u16;
        self.ip_header = self.ip_header.total_length(ip_length);

        self
    }

    pub fn set_ip_checksum(mut self) -> Self {
        self
    }

    pub fn set_udp_checksum(mut self) -> Self {
        self
    }

    pub fn set_udp_length(mut self) -> Self {
        self
    }
}

impl<'a, const N: usize, const M: usize> Transportable<{ 4 * M + 20 + 4 * N + 8 }>
    for UDPFrame<'_, N, M>
where
    [u8; 4 * N]:,
    [u8; 4 * M + 20]:,
    [u8; 4 * M + 20 + 4 * N + 8]:,
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
