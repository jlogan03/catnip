//! User Datagram Protocol

use crate::ip::{self, IPV4Header, Protocol, Version};
use crate::{calc_ip_checksum, Data, IPV4Addr};

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

/// Parse a UDP header from bytes
pub fn parse_header_bytes(bytes: &[u8; 8]) -> (u16, u16, u16, u16) {
    let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let total_length = u16::from_be_bytes([bytes[4], bytes[5]]);
    let checksum = u16::from_be_bytes([bytes[6], bytes[7]]);

    (src_port, dst_port, total_length, checksum)
}

/// IPV4 message frame for UDP protocol.
///
/// N is size of IP Options in 32-bit words.
///
/// M is size of UDP Data in 32-bit words.
#[derive(Clone, Debug)]
pub struct UDPPacket<const N: usize, const M: usize>
where
    // [u8; 4 * N + 20]:,
    [u8; 4 * M]:,
    [u8; 4 * N + 20]:,
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
    /// Build a UDP packet and populate the components that depend on the combined data.
    ///
    /// N is size of IP Options in 32-bit words.
    ///
    /// M is size of UDP Data in 32-bit words.
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
        let ip_length: u16 = (4 * N + 20 + 4 * M + 8) as u16;
        let ip_length_bytes: [u8; 2] = ip_length.to_be_bytes();
        udppacket.ip_header.value[2] = ip_length_bytes[0];
        udppacket.ip_header.value[3] = ip_length_bytes[1];

        // Set IP header checksum
        let checksum: u16 = calc_ip_checksum(&udppacket.ip_header.value);
        let checksum_bytes: [u8; 2] = checksum.to_be_bytes();
        udppacket.ip_header.value[10] = checksum_bytes[0];
        udppacket.ip_header.value[11] = checksum_bytes[1];

        // Set UDP packet length in bytes
        udppacket.udp_header.value[2] = (&udppacket.udp_data.len() + udp_header.len()) as u16;

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

/// Attempt to parse and IPV4 UDP packet components from bytes.
///
/// Checks if this is, in fact, an IPV4 UDP packet and will error otherwise.
pub fn parse_packet_bytes(
    bytes: &[u8],
) -> Result<
    (
        &[u8],
        &[u8],
        IPV4Addr,
        u16,
        IPV4Addr,
        u16,
        Version,
        Protocol,
        u16,
        u16,
    ),
    &str,
> {
    let p = bytes.len();

    // Check if there is enough data for an IP header
    if p < 20 {
        return Err("Inadequate data for IP header");
    };

    // Parse the IP header assuming there are no options bytes, then check listed header length
    let mut header_bytes = [0_u8; 20];
    header_bytes.copy_from_slice(&bytes[0..20]);

    let (
        version,
        protocol,
        src_ipaddr,
        dst_ipaddr,
        header_length,
        total_length,
        _, // assume no Options for now
        identification,
    ) = ip::parse_header_bytes::<0>(&header_bytes);

    let header_length = header_length as usize * 4;  // Convert to bytes from words

    // Make sure the length field matches reality
    if p != total_length as usize {
        return Err("Packet length does not match total length");
    };

    // If there is an IP Options segment, parse it as a chunk but do not interpret
    let options: &[u8];
    if p < header_length as usize {
        // Do we have enough for the full header including Options?
        return Err("IP header length exceeds data size");
    } else {
        options = &bytes[20..header_length as usize] // May be zero-size
    }

    // Check what protocol defines the structure of the payload
    match protocol {
        Protocol::UDP => (),
        _ => return Err("Unimplemented protocol"), // Other protocols not implemented
    };

    // Check IP version
    match version {
        Version::V4 => (),
        _ => return Err("Unimplemented IP version"), // IPV6 not implemented yet
    };

    // This is an IPV4 UDP packet
    // Slice the UDP portion
    let bytes = &bytes[header_length as usize..];
    let p = bytes.len();

    // Parse the UDP header
    if p < 8 {
        // Make sure there is at least a full header worth of data left
        return Err("Inadequate data for UDP header");
    }
    let mut header_bytes = [0_u8; 8];
    header_bytes.copy_from_slice(&bytes[0..8]);
    let (src_port, dst_port, _, checksum) = parse_header_bytes(&header_bytes);

    // Extract UDP data
    let data = &bytes[8..];

    Ok((
        data, options, src_ipaddr, src_port, dst_ipaddr, dst_port, version, protocol, checksum, identification
    ))
}
