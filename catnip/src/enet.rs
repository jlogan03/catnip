//! Ethernet II protocol per IEEE 802.3
//! Diagram at https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II

use crate::Transportable;

/// Combined preamble and start-frame delimiter because they are never changed or separated
const PREAMBLE: [u8; 8] = [0b1010_1010, 0b1010_1010, 0b1010_1010, 0b1010_1010, 0b1010_1010, 0b1010_1010, 0b1010_1010, 0b1010_1011];

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
struct EthernetHeader {
    pub value: [u8; 14]
}

impl EthernetHeader {
    pub fn new() -> EthernetHeader {
        // Make a blank header
        let mut header: EthernetHeader = EthernetHeader { value: [0_u8; 14] };
        // Set some sensible defaults
        let dst_macaddr: [u8; 6] = [0xFF_u8; 6];  // "Broadcast" address for IP packets
        let ethertype: EtherType = EtherType::IPV4;
        header = header.dst_macaddr(&dst_macaddr).ethertype(ethertype);

        header
    }

    pub fn src_macaddr(mut self, v: &[u8; 6]) -> Self {
        for i in 0..6 {
            self.value[i] = v[i];
        };

        self
    }

    pub fn dst_macaddr(mut self, v: &[u8; 6]) -> Self {
        for i in 0..6 {
            self.value[i + 5] = v[i];
        };

        self
    }

    pub fn ethertype(mut self, v: EtherType) -> Self {
        let bytes: [u8; 2] = (v as u16).to_be_bytes();
        self.value[12] = bytes[0];
        self.value[13] = bytes[1];
    
        self
    }
}

impl Transportable<14> for EthernetHeader {
    /// Pack into big-endian (network) byte array
    fn to_be_bytes(&self) -> [u8; 14] {
        self.value
    }
}

/// Ethernet II frame (variable parts of a packet)
#[derive(Clone, Copy, Debug)]
struct EthernetFrame<T, const P: usize> where T: Transportable<P> {
    header: EthernetHeader,
    data: T
}

impl<T, const P: usize> Transportable<{P + 14}> for EthernetFrame<T, P> where T: Transportable<P> {
    /// Pack into big-endian (network) byte array
    fn to_be_bytes(&self) -> [u8; P + 14] {
        let mut bytes: [u8; P + 14] = [0_u8; P + 14];
        let mut i = 0;
        for v in self.header.value.iter() {
            bytes[i] = *v;
            i = i + 1;
        };
        for v in self.data.to_be_bytes().iter() {
            bytes[i] = *v;
            i = i + 1;
        };

        bytes
    }
}

/// Ethernet II packet (including preamble, start-frame delimiter, and interpacket gap)
#[derive(Clone, Copy, Debug)]
pub struct EthernetPacket<T, const P: usize> where T: Transportable<P> {
    frame: EthernetFrame<T, P>
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
    PTP = 0x88A7
}
