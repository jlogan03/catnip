//! User Datagram Protocol

use crate::ip::IPV4Header;
use crate::{calc_ip_checksum, Transportable, Data};

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
pub struct UDPHeader {
    value: [u16; 4],
}

impl UDPHeader {
    /// Start a header with src and dst ports populated
    /// 
    /// Length and checksum will be populated later
    pub fn new(src_port: u16, dst_port: u16) -> UDPHeader {
        let header: UDPHeader = UDPHeader { value: [src_port, dst_port, 0, 0] };

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
/// N is size of IP Options in 32-bit words
///
/// M is size of UDP Data in 32-bit words
#[derive(Clone, Copy, Debug)]
pub struct UDPPacket<'a, const N: usize, const M: usize>
where
    [u8; 4 * N + 20]:,
    [u8; 4 * M]:,
{
    /// IPV4 packet header
    pub ip_header: IPV4Header<'a, N>,
    /// UDP datagram header
    pub udp_header: UDPHeader,
    /// Data to transmit; bytes in some multiple of 32 bit words
    pub udp_data: Data<M>,
}

impl<'a, const N: usize, const M: usize> UDPPacket<'a, N, M>
where
    [u8; 4 * M]:,
    [u8; 4 * N + 20]:,
    [u8; 4 * N + 20 + 4 * M + 8]:, // Required for Transportable trait
{
    /// Set values that require the complete packet (length, checksums)
    ///
    /// TODO: use IPV4Header's methods to set its values once the missing bounds error is fixed
    pub fn finalize(mut self) -> Self {
        // Set IP frame length
        let ip_length: u16 = self.to_be_bytes().len() as u16;
        // self.ip_header = self.ip_header.total_length(ip_length);
        let bytes: [u8; 2] = ip_length.to_be_bytes();
        self.ip_header.value[2] = bytes[0];
        self.ip_header.value[3] = bytes[1];

        // Set IP header checksum
        // Clear old
        self.ip_header.value[10] = 0;
        self.ip_header.value[11] = 0;
        // Apply new
        let checksum = calc_ip_checksum(&self.ip_header.value);
        let bytes: [u8; 2] = checksum.to_be_bytes();
        self.ip_header.value[10] = bytes[0];
        self.ip_header.value[11] = bytes[1];

        // Set UDP data length in bytes
        self.udp_header.value[2] = (self.udp_data.value.len() + 2 * self.udp_header.value.len()) as u16;

        // Zero-out UDP checksum because it is redundant with ethernet checksum & prone to overflow
        // // Set UDP header checksum, summing up the parts of the "pseudoheader"
        // // See https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv4_pseudo_header
        // Clear old
        self.udp_header.value[3] = 0;
        // // Apply new
        // let mut udp_checksum: u16 = 0_u16;
        // udp_checksum = udp_checksum + calc_checksum(&self.ip_header.value[12..20]); // src, dst ipaddrs
        // let protocol_bytes: [u8; 2] = (self.ip_header.value[9] as u16).to_be_bytes();
        // udp_checksum = udp_checksum + calc_checksum(&protocol_bytes); // Protocol with zero-padding
        // udp_checksum = udp_checksum + calc_checksum(&self.udp_header.to_be_bytes()); // UDP header
        // udp_checksum = udp_checksum + calc_checksum(&self.udp_data); // The actual data
        // self.udp_header.value[3] = udp_checksum;

        self
    }
}

impl<'a, const N: usize, const M: usize> Transportable<{ 4 * N + 20 + 4 * M + 8 }>
    for UDPPacket<'a, N, M>
where
    [u8; 4 * M]:,
    [u8; 4 * N + 20]:,
    [u8; 4 * N + 20 + 4 * M + 8]:,
{
    /// Pack into big-endian (network) byte array
    fn to_be_bytes(&self) -> [u8; 4 * N + 20 + 4 * M + 8] {
        // Pack a byte array with IP header, UDP header, and UDP data
        let mut bytes = [0_u8; 4 * N + 20 + 4 * M + 8];
        let mut i = 0;
        for v in self.ip_header.to_be_bytes() {
            bytes[i] = v;
            i = i + 1;
        }
        for v in self.udp_header.to_be_bytes() {
            bytes[i] = v;
            i = i + 1;
        }
        for v in self.udp_data.value {
            bytes[i] = v;
            i = i + 1;
        }

        bytes
    }
}

#[cfg(test)]
mod test {
    // use super::{UDPHeader, UDPPacket};

    // #[test]
    // fn test_udp_header() {
    //     // Parse and replicate example header from https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:the-internet/xcae6f4a7ff015e7d:transporting-packets/a/user-datagram-protocol-udp
    //     let example_header: [u16; 4] = [
    //         0b00010101_00001001,
    //         0b0001010_100001001,
    //         0b00000000_00000100,
    //         0b10110100_11010000,
    //     ];
    //     let example_data: [u8; 4] = [0b01001000, 0b01101111, 0b01101100, 0b01100001];
    //     // let mut example_u16: [u16; 4] = [0_u16; 4];
    //     // for i in 0..4 {
    //     //     let bytes: [u8; 2] = [example_bytes[2*i], example_bytes[2*i + 1]];
    //     //     example_u16[i] = u16::from_be_bytes(bytes);
    //     // }
    //     let example_header: UDPHeader = UDPHeader {
    //         value: example_header,
    //     };
    //     let example_packet: UDPPacket<0, 1> = UDPPacket {
    //         ip_header: crate::ip::IPV4Header::new(),
    //         udp_header: example_header,
    //         udp_data: example_data,
    //     };

    // }
}
