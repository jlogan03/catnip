//! Internet Protocol message header construction

use crate::{calc_ip_checksum, IPV4Addr};

/// IPV4 header per IETF-RFC-791
///
/// https://en.wikipedia.org/wiki/IPv4
///
/// first 32-bit word
///
/// value [0] Version [4 bits], Header Length [4 bits]
///
/// value [1] Type-of-Service/IP Precedence/DSCP
///
/// value [2:3] Total Length [u16] in bytes
///
/// second 32-bit word
///
/// value [4:5] Identification [u16]
///
/// value [6:7] Flags [3 bits], Fragmentation Offset [13 bits]
///
/// third 32-bit word
///
/// value [8] Time-to-Live
///
/// value [9] Protocol
///
/// value [10:11] Checksum [u16]
///
/// fourth 32-bit word
///
/// value [12:15] Source IP Address
///
/// fifth 32-bit word
///
/// value [16:19] Destination IP Address
///
/// N is number of 32-bit words to reserve for the Options section
#[derive(Clone, Debug)]
pub struct IPV4Header<const N: usize>
where
    [u8; 4 * N + 20]:,
{
    /// The actual content of the header as bytes
    pub value: [u8; 4 * N + 20],
}

impl<const N: usize> IPV4Header<N>
where
    [u8; 4 * N + 20]:,
{
    /// Start from some sensible defaults
    pub fn new() -> Self {
        // Start a blank header and apply some sensible defaults
        let mut header = IPV4Header {
            value: [0_u8; 4 * N + 20],
        };
        header
            .version(Version::V4)
            .header_length({ 5 + N } as u8)
            .dscp(DSCP::Standard)
            .ttl(100)
            .protocol(Protocol::UDP);

        header
    }

    /// Set version
    pub fn version(&mut self, v: Version) -> &mut Self {
        self.value[0] = self.value[0] & 0b0000_1111; // Clear existing
        self.value[0] = self.value[0] | v as u8; // Apply new
        self
    }

    /// Set header length (in 32-bit words)
    pub fn header_length(&mut self, v: u8) -> &mut Self {
        self.value[0] = self.value[0] & 0b1111_0000; // Clear existing
        self.value[0] = self.value[0] | v as u8; // Apply new
        self
    }

    /// Set DSCP (first 6 bits of second byte)
    pub fn dscp(&mut self, v: DSCP) -> &mut Self {
        self.value[1] = self.value[1] & 0b00000011; // Clear existing
        self.value[1] = self.value[1] | v as u8; // Apply new
        self
    }

    /// Set total length of packet (header + body) in bytes
    pub fn total_length(&mut self, v: u16) -> &mut Self {
        // Split into two bytes
        let bytes: [u8; 2] = v.to_be_bytes();

        // Apply new
        self.value[2] = bytes[0];
        self.value[3] = bytes[1];

        self
    }

    /// Set identification
    pub fn identification(&mut self, v: u16) -> &mut Self {
        let bytes = v.to_be_bytes();
        self.value[4] = bytes[0];
        self.value[5] = bytes[1];

        self
    }

    /// Set fragmentation flags
    pub fn flags(&mut self, v: Flags) -> &mut Self {
        match v {
            Flags::Clear => {
                // Clear old if requested
                self.value[6] = self.value[6] & Flags::Clear as u8;
            }
            _ => {
                // Apply new otherwise
                self.value[6] = self.value[6] | v as u8;
            }
        }

        self
    }

    /// Set fragmentation offset
    pub fn frag_offs(&mut self, v: u16) -> &mut Self {
        // Clip to 13 bits and split into bytes
        let v: u16 = v & 0b0001_1111_1111_1111;
        let bytes: [u8; 2] = v.to_be_bytes();
        // Clear old
        self.value[6] = self.value[6] & 0b1110_000;
        self.value[7] = 0u8;
        // Apply new
        self.value[6] = self.value[6] | bytes[0];
        self.value[7] = self.value[7] | bytes[1];

        self
    }

    /// Set Time-to-Live counter (number of bounces allowed)
    /// This counter decrements at each router and drops the packet at 0
    pub fn ttl(&mut self, v: u8) -> &mut Self {
        self.value[8] = v;

        self
    }

    /// Set protocol
    pub fn protocol(&mut self, v: Protocol) -> &mut Self {
        self.value[9] = v as u8;

        self
    }

    /// Calculate and set checksum
    pub fn header_checksum(&mut self) -> &mut Self {
        // Clear old
        self.value[10] = 0;
        self.value[11] = 0;
        // Apply new
        let checksum = calc_ip_checksum(&self.value);
        let bytes = checksum.to_be_bytes();
        self.value[10] = bytes[0];
        self.value[11] = bytes[1];

        self
    }

    /// Set source IP address
    pub fn src_ipaddr(&mut self, v: IPV4Addr) -> &mut Self {
        for i in 0..4_usize {
            self.value[12 + i] = v.value[i];
        }

        self
    }

    /// Set destination IP address
    pub fn dst_ipaddr(&mut self, v: IPV4Addr) -> &mut Self {
        for i in 0..4_usize {
            self.value[16 + i] = v.value[i];
        }

        self
    }

    /// Make from 16-bit words
    pub fn from_16bit_words<const M: usize>(header16: &[u16; 2 * M + 10]) -> IPV4Header<M>
    where
        [u8; 4 * M + 20]:,
    {
        // Convert words to bytes
        let mut header8: [u8; 4 * M + 20] = [0_u8; 4 * M + 20];
        for (i, v) in header16.iter().enumerate() {
            let bytes: [u8; 2] = v.to_be_bytes();
            header8[2 * i] = bytes[0];
            header8[2 * i + 1] = bytes[1];
        }

        let header: IPV4Header<M> = IPV4Header { value: header8 };

        header
    }

    /// Make from 16-bit words
    pub fn from_32bit_words<const M: usize>(header32: &[u32; M + 5]) -> IPV4Header<M>
    where
        [u8; 4 * M + 20]:,
    {
        // Convert words to bytes
        let mut header8: [u8; 4 * M + 20] = [0_u8; 4 * M + 20];
        for (i, v) in header32.iter().enumerate() {
            let bytes: [u8; 4] = v.to_be_bytes();
            for j in 0..4 {
                header8[4 * i + j] = bytes[j];
            }
        }

        let header: IPV4Header<M> = IPV4Header { value: header8 };

        header
    }

    /// Length of byte representation
    const LENGTH: usize = 4 * N + 20;

    /// Get length of byte representation
    fn len(&self) -> usize {
        Self::LENGTH
    }

    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; 4 * N + 20] {
        self.value
    }
}

/// Parse (some) fields from big-endian (network) byte array
pub fn parse_header_bytes<const N: usize>(
    bytes: &[u8; 4 * N + 20],
) -> (Version, Protocol, IPV4Addr, IPV4Addr, u8, u16, [u8; 4 * N], u16) {
    let version = match bytes[0] & 0b1111_0000 {
        x if x == Version::V4 as u8 => Version::V4,
        x if x == Version::V6 as u8 => Version::V6,
        _ => Version::Unimplemented, // Default to IPV4 if the version field is invalid
    };

    let header_length: u8 = bytes[0] & 0b0000_1111;

    let mut total_length_bytes = [0_u8; 2];
    total_length_bytes.copy_from_slice(&bytes[2..4]);
    let total_length: u16 = u16::from_be_bytes(total_length_bytes);

    let mut src_ipaddr_bytes = [0_u8; 4];
    src_ipaddr_bytes.copy_from_slice(&bytes[12..16]);
    let src_ipaddr = IPV4Addr {
        value: src_ipaddr_bytes,
    };

    let mut dst_ipaddr_bytes = [0_u8; 4];
    dst_ipaddr_bytes.copy_from_slice(&bytes[16..20]);
    let dst_ipaddr = IPV4Addr {
        value: dst_ipaddr_bytes,
    };

    let protocol = match bytes[9] {
        x if x == Protocol::TCP as u8 => Protocol::TCP,
        x if x == Protocol::UDP as u8 => Protocol::UDP,
        _ => Protocol::Unimplemented,
    };

    let mut identification_bytes = [0_u8; 2];
    identification_bytes.copy_from_slice(&bytes[4..6]);
    let identification = u16::from_be_bytes(identification_bytes);


    let mut options = [0_u8; 4 * N];
    if N > 0 {
        options.copy_from_slice(&bytes[20..4 * N + 20]);
    }

    return (
        version,
        protocol,
        src_ipaddr,
        dst_ipaddr,
        header_length,
        total_length,
        options,
        identification,
    );
}

/// Common choices of transport-layer protocols
///
/// and their IP header values.
///
/// There are many more protocols not listed here -
///
/// see https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    /// Transmission Control Protocol
    TCP = 0x06,
    /// User Datagram Protocol
    UDP = 0x11,
    /// Catch-all for unimplemented identifiers
    Unimplemented = 0,
}

/// IP version bit mask
#[derive(Clone, Copy, Debug)]
pub enum Version {
    /// IPV4
    V4 = 0b0100_0000,
    /// IPV6
    V6 = 0b0110_0000,
    /// Unimplemented
    Unimplemented = 0
}

/// https://en.wikipedia.org/wiki/Differentiated_services
///
/// Priority 2 is low-latency class
#[derive(Clone, Copy, Debug)]
pub enum DSCP {
    /// Default traffic
    Standard = 0,
    ///
    NetworkControl = 48 << 2,
    ///
    Telephony = 46 << 2,
    ///
    Signaling = 40 << 2,
    ///
    Realtime = 32 << 2,
    ///
    BroadcastVideo = 24 << 2,
    ///
    OAM = 16 << 2,
    ///
    LowPriority = 8 << 2,
    /// Low drop, priority 1
    AF11 = 10 << 2,
    /// Med drop, priority 1
    AF12 = 12 << 2,
    /// High drop, priority 1
    AF13 = 14 << 2,
    /// Low drop, priority 2
    AF21 = 18 << 2,
    /// Med drop, priority 2
    AF22 = 20 << 2,
    /// High drop, priority 2
    AF23 = 22 << 2,
    /// Low drop, priority 3
    AF31 = 26 << 2,
    /// Med drop, priority 3
    AF32 = 28 << 2,
    /// High drop, priority 3
    AF33 = 30 << 2,
}

/// Fragmentation flags
#[derive(Clone, Copy, Debug)]
pub enum Flags {
    /// Do not fragment
    DF = 1 << 6,
    /// More fragments       
    MF = 1 << 5,
    /// Helper for clearing flags
    Clear = 0b0001_1111,
}
