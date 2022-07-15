//! Link layer: Ethernet II protocol
//!
//! Diagram at https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II

use crate::MacAddr;

use byte_struct::*;

#[cfg(feature = "crc")]
use crc32fast;

/// Header for Ethernet II frame like
///
/// value [0:5] src macaddr
///
/// value [6:11] dst macaddr  ([0xFF_u8; 6] when payload is IP packet)
///
/// value [12:13] ethertype
#[derive(ByteStruct, Clone, Copy, Debug)]
pub struct EthernetHeader {
    /// The header structure in bytes
    pub src_macaddr: MacAddr,
    pub dst_macaddr: MacAddr,
    pub ethertype: EtherType,
}

/// Ethernet frame around arbitrary data
#[derive(Clone, Copy, Debug)]
pub struct EthernetFrame<T>
where
    T: ByteStruct,
{
    header: EthernetHeader,
    data: T,
    checksum: u32,
}

impl<T> ByteStructLen for EthernetFrame<T>
where
    T: ByteStruct,
{
    const BYTE_LEN: usize = EthernetHeader::BYTE_LEN + T::BYTE_LEN + 4;
}

impl<T> ByteStruct for EthernetFrame<T>
where
    T: ByteStruct,
{
    fn read_bytes(bytes: &[u8]) -> Self {
        let mut checksum_bytes = [0_u8; 4];
        checksum_bytes.copy_from_slice(&bytes[Self::BYTE_LEN - 4..Self::BYTE_LEN]);
        EthernetFrame::<T> {
            header: EthernetHeader::read_bytes(&bytes[0..EthernetHeader::BYTE_LEN]),
            data: T::read_bytes(&bytes[EthernetHeader::BYTE_LEN..Self::BYTE_LEN - 4]),
            checksum: u32::from_be_bytes(checksum_bytes),
        }
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        self.header
            .write_bytes(&mut bytes[0..EthernetHeader::BYTE_LEN]);
        self.data
            .write_bytes(&mut bytes[EthernetHeader::BYTE_LEN..Self::BYTE_LEN - 4]);
        let checksum_bytes = self.checksum.to_be_bytes();
        for i in 0..4 {
            bytes[Self::BYTE_LEN - 4 + i] = checksum_bytes[i];
        }
    }
}

/// EtherType tag values (incomplete list - there are many more not implemented here)
///
/// See https://en.wikipedia.org/wiki/EtherType
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum EtherType {
    /// IPV4
    IPV4 = 0x0800,
    /// ARP
    ARP = 0x0806,
    /// VLAN - if this tag is encountered, then this is not the real ethertype field, and we're reading an 802.1Q VLAN tag instead
    VLAN = 0x8100,
    /// IPV6
    IPV6 = 0x86DD,
    /// EtherCat
    EtherCat = 0x88A4,
    /// Precision Time Protocol
    PTP = 0x88A7,
    /// Catch-all for uncommon types not handled here
    Unimplemented,
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            x if x == EtherType::ARP as u16 => EtherType::ARP,
            x if x == EtherType::EtherCat as u16 => EtherType::EtherCat,
            x if x == EtherType::IPV4 as u16 => EtherType::IPV4,
            x if x == EtherType::IPV6 as u16 => EtherType::IPV6,
            x if x == EtherType::PTP as u16 => EtherType::PTP,
            x if x == EtherType::VLAN as u16 => EtherType::VLAN,
            _ => EtherType::Unimplemented,
        }
    }
}

impl ByteStructLen for EtherType {
    const BYTE_LEN: usize = 2;
}

impl ByteStruct for EtherType {
    fn read_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 2 {
            return EtherType::Unimplemented;
        } else {
            let mut bytes_read = [0_u8; 2];
            bytes_read.copy_from_slice(&bytes[0..=1]);
            return EtherType::from(u16::from_be_bytes(bytes_read));
        }
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        if bytes.len() >= 2 {
            let bytes_to_write = (*self as u16).to_be_bytes();
            bytes[0] = bytes_to_write[0];
            bytes[1] = bytes_to_write[1];
        } else {
            // Do nothing - no bytes to write
        }
    }
}

// Calculate ethernet checksum in software
// #[cfg(feature = "crc")]
// pub fn calc_enet_checksum(&self, frame_bytes: &[u8; (4 * N + 20) + (4 * M) + 14 + 8 + 4]) -> u32 {
//     let checksum: u32 = crc32fast::hash(frame_bytes);
//     checksum
// }

// Add blank checksum; real checksum will be generated by hardware
// #[cfg(not(feature = "crc"))]
// pub fn calc_enet_checksum(&self, _: &[u8; (4 * N + 20) + (4 * M) + 14 + 8 + 4]) -> u32 {
//     let checksum: u32 = 0;
//     checksum
// }
