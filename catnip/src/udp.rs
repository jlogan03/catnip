//! User Datagram Protocol

use crate::ip::IPV4Header;
use crate::{calc_ip_checksum, Data};

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
        let header: UDPHeader = UDPHeader {
            value: [src_port, dst_port, 0, 0],
        };

        header
    }

    /// Length of byte representation
    const LENGTH: usize = 8;

    /// Get length of byte representation
    fn len(&self) -> usize {
        Self::LENGTH
    }

    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; 8] {
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
pub struct UDPPacket<const N: usize, const M: usize>
where
    [u8; 4 * N + 20]:,
    [u8; 4 * M]:,
{
    /// IPV4 packet header
    pub ip_header: IPV4Header<N>,
    /// UDP datagram header
    pub udp_header: UDPHeader,
    /// Data to transmit; bytes in some multiple of 32 bit words
    pub udp_data: Data<M>,
}

impl<const N: usize, const M: usize> UDPPacket<N, M>
where
    [u8; 4 * M]:,
    [u8; 4 * N + 20]:,
    [u8; 4 * N + 20 + 4 * M + 8]:, // Required for Transportable trait
    // UDPPacket<'a, N, M>: Transportable<{ 4 * N + 20 + 4 * M + 8 }>,
{
    /// Build a UDP packet and populate the components that depend on the combined data
    ///
    /// N is size of IP Options in 32-bit words
    ///
    /// M is size of UDP Data in 32-bit words
    pub fn new(
        ip_header: IPV4Header<N>,
        udp_header: UDPHeader,
        udp_data: Data<M>,
    ) -> UDPPacket<N, M> {
        let mut udppacket: UDPPacket<N, M> = UDPPacket::<N, M> {
            ip_header: ip_header,
            udp_header: udp_header,
            udp_data: udp_data,
        };

        // Set IP frame length
        let ip_length: u16 = udppacket.len() as u16;
        let ip_length_bytes: [u8; 2] = ip_length.to_be_bytes();
        udppacket.ip_header.value[2] = ip_length_bytes[0];
        udppacket.ip_header.value[3] = ip_length_bytes[1];

        // Set IP header checksum
        let checksum: u16 = calc_ip_checksum(&udppacket.ip_header.value);
        let checksum_bytes: [u8; 2] = checksum.to_be_bytes();
        udppacket.ip_header.value[10] = checksum_bytes[0];
        udppacket.ip_header.value[11] = checksum_bytes[1];

        // Set UDP packet length in bytes
        udppacket.udp_header.value[2] =
            (udp_data.len() + udp_header.len()) as u16;

        // Zero-out UDP checksum because it is redundant with ethernet checksum & prone to overflow
        udppacket.udp_header.value[3] = 0;

        udppacket
    }

    /// Length of byte representation
    pub const LENGTH: usize = 4 * N + 20 + 4 * M + 8;

    /// Length of instance's byte representation
    pub fn len(&self) -> usize {
        4 * N + 20 + 4 * M + 8
    }

    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; 4 * N + 20 + 4 * M + 8] {
        // Pack a byte array with IP header, UDP header, and UDP data
        let mut bytes = [0_u8; 4 * N + 20 + 4 * M + 8];
        let mut i = 0;
        for v in self.ip_header.value {
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
