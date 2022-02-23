//! Ethernet II protocol per IEEE 802.3
//! Diagram at https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II

use crate::{MACAddr};

/// Combined preamble and start-frame delimiter because they are never changed or separated
const PREAMBLE: [u8; 8] = [
    0b1010_1010,
    0b1010_1010,
    0b1010_1010,
    0b1010_1010,
    0b1010_1010,
    0b1010_1010,
    0b1010_1010,
    0b1010_1011,
];

/// Standard 96-bit inter-packet gap
const IPG: [u8; 12] = [0; 12];

/// Header for Ethernet II frame like
///
/// value [0:5] src macaddr
///
/// value [6:11] dst macaddr  ([0xFF_u8; 6] when payload is IP packet)
///
/// value [12:13] ethertype
#[derive(Clone, Copy, Debug)]
pub struct EthernetHeader {
    /// The header structure in bytes
    pub value: [u8; 14],
}

impl EthernetHeader {
    /// Make a complete ethernet frame header with the specified values
    ///
    /// If no destination MAC address is given, defaults to Broadcast value (always used when payload is IP packet)
    pub fn new(
        src_macaddr: MACAddr,
        dst_macaddr: Option<MACAddr>,
        ethertype: EtherType,
    ) -> EthernetHeader {
        let dst_macaddr = match dst_macaddr {
            Some(x) => x,
            None => MACAddr {
                value: [0xFF_u8; 6],
            },
        };

        let header = EthernetHeader { value: [0_u8; 14] }
            .src_macaddr(&src_macaddr.value)
            .dst_macaddr(&dst_macaddr.value)
            .ethertype(ethertype)
            .finalize();

        header
    }

    /// Set source mac address
    pub fn src_macaddr(&mut self, v: &[u8; 6]) -> &mut Self {
        for i in 0..6 {
            self.value[i] = v[i];
        }

        self
    }

    /// Set destination mac address
    pub fn dst_macaddr(&mut self, v: &[u8; 6]) -> &mut Self {
        for i in 0..6 {
            self.value[i + 5] = v[i];
        }

        self
    }

    /// Set ethernet service type
    pub fn ethertype(&mut self, v: EtherType) -> &mut Self {
        let bytes: [u8; 2] = (v as u16).to_be_bytes();
        self.value[12] = bytes[0];
        self.value[13] = bytes[1];

        self
    }

    /// Dereference to prevent droppage
    pub fn finalize(&mut self) -> Self {
        *self
    }

    /// Length of byte representation
    const LENGTH: usize = 14;

    /// Get length of byte representation
    pub fn len(&self) -> usize {
        Self::LENGTH
    }

    /// Pack into big-endian (network) byte array
    fn to_be_bytes(&self) -> [u8; 14] {
        self.value
    }
}


/// Ethernet II frame (variable parts of a packet)
///
/// P is length of data's byte representation
#[derive(Clone, Copy, Debug)]
pub struct EthernetFrame<const P: usize> {
    /// Ethernet frame header
    pub header: EthernetHeader,
    /// Ethernet payload (likely some kind of IP packet)
    pub payload: [u8; P],
}

impl<const P: usize> EthernetFrame<P> {
    /// Generate new, complete frame from components
    pub fn new(header: EthernetHeader, payload: [u8; P]) -> Self {
        let enetframe: EthernetFrame<P> = EthernetFrame {
            header: header,
            payload: payload,
        };

        enetframe
    }

    /// Length of byte representation
    const LENGTH: usize = P + 14;

    /// Get length of byte representation
    pub fn len(&self) -> usize {
        Self::LENGTH
    }

    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; P + 14] {
        let mut bytes: [u8; P + 14] = [0_u8; P + 14];
        let mut i = 0;
        for v in self.header.value {
            bytes[i] = v;
            i = i + 1;
        }
        for v in self.payload {
            bytes[i] = v;
            i = i + 1;
        }

        bytes
    }
}


/// Ethernet II packet (including preamble, start-frame delimiter, and interpacket gap)
#[derive(Clone, Copy, Debug)]
pub struct EthernetPacket<const P: usize> {
    frame: EthernetFrame<P>,
}

impl<const P: usize> EthernetPacket<P> {
    /// Build a new packet from a frame
    pub fn new(frame: EthernetFrame<P>) -> Self {
        EthernetPacket { frame: frame }
    }

    /// Length of byte representation
    const LENGTH: usize = P + 14 + 24;

    /// Get length of byte representation
    pub fn len(&self) -> usize {
        Self::LENGTH
    }

    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; P + 14 + 24] {
        // Initialize output
        let mut bytes = [0_u8; P + 14 + 24];

        // Calculate CRC32 checksum over ethernet frame
        // TODO: this could be done faster using either a persistent Hasher
        // or a CRC32 peripheral
        let frame_bytes: [u8; P + 14] = self.frame.to_be_bytes();
        let checksum: u32 = crc32fast::hash(&frame_bytes);
        let checksum_bytes: [u8; 4] = checksum.to_be_bytes();

        let mut i = 0;
        for v in PREAMBLE {
            // Clock-sync preamble and start-frame delimiter
            bytes[i] = v;
            i = i + 1;
        }
        for v in self.frame.to_be_bytes() {
            // Data
            bytes[i] = v;
            i = i + 1;
        }
        for v in checksum_bytes {
            // Checksum
            bytes[i] = v;
            i = i + 1;
        }
        for v in IPG {
            // Inter-packet gap
            bytes[i] = v;
            i = i + 1;
        }

        bytes
    }
}


/// EtherType tag values (incomplete list - there are many more not implemented here)
///
/// See https://en.wikipedia.org/wiki/EtherType
#[derive(Clone, Copy, Debug)]
pub enum EtherType {
    /// IPV4
    IPV4 = 0x0800,
    /// ARP
    ARP = 0x0806,
    /// VLAN
    VLAN = 0x8100,
    /// IPV6
    IPV6 = 0x86DD,
    /// EtherCat
    EtherCat = 0x88A4,
    /// Precision Time Protocol
    PTP = 0x88A7,
}
