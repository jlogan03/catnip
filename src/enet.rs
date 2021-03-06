//! Link layer: Ethernet II protocol.
//! See <https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II>.

use crate::MacAddr;

use byte_struct::*;
use ufmt::derive::uDebug;
use static_assertions::const_assert;

// In general, this could be 18 bytes for a 802.1Q tagged vlan,
// but that is not supported here because tagged vlan is spammy and unsecure.
const_assert!(EthernetHeader::BYTE_LEN == 14);

/// Header for Ethernet II frame
#[derive(ByteStruct, Clone, Copy, uDebug, Debug, PartialEq, Eq)]
#[byte_struct_be]
pub struct EthernetHeader {
    /// Destination MAC address
    pub dst_macaddr: MacAddr,
    /// Source MAC address
    pub src_macaddr: MacAddr,
    /// Type of content (IpV4, IpV6, Arp, Ptp, etc)
    pub ethertype: EtherType,
}

impl EthernetHeader {
    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0_u8; Self::BYTE_LEN];
        self.write_bytes(&mut bytes);
        bytes
    }
}

/// Ethernet frame around arbitrary data
#[derive(Clone, Copy, uDebug, Debug, PartialEq, Eq)]
pub struct EthernetFrame<T>
where
    T: ByteStruct,
{
    /// Ethernet header
    pub header: EthernetHeader,
    /// Data payload (probably and IP frame or Arp message)
    pub data: T,
    /// CRC checksum. Must be present, but zeroed-out s.t. it can be calculated by hardware.
    pub checksum: u32,
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

impl<T> EthernetFrame<T>
where
    T: ByteStruct,
{
    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0_u8; Self::BYTE_LEN];
        self.write_bytes(&mut bytes);
        bytes
    }
}

/// EtherType tag values (incomplete list - there are many more not implemented here).
/// See <https://en.wikipedia.org/wiki/EtherType>.
#[derive(Clone, Copy, uDebug, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum EtherType {
    /// Internet protocol version 4
    IpV4 = 0x0800,
    /// Address resolution protocol
    Arp = 0x0806,
    /// Tagged virtual LAN - if this tag is encountered, then this is not the real ethertype field, and we're reading an 802.1Q Vlan tag instead
    /// This crate does not support tagged Vlan, which is a trust-based and inefficient system. Untagged Vlan should be used instead.
    Vlan = 0x8100,
    /// Internet protocol version 6
    IpV6 = 0x86DD,
    /// EtherCat
    EtherCat = 0x88A4,
    /// Precision Time Protocol
    Ptp = 0x88A7,
    /// Catch-all for uncommon types not handled here
    Unimplemented = 0x0,
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            x if x == EtherType::Arp as u16 => EtherType::Arp,
            x if x == EtherType::EtherCat as u16 => EtherType::EtherCat,
            x if x == EtherType::IpV4 as u16 => EtherType::IpV4,
            x if x == EtherType::IpV6 as u16 => EtherType::IpV6,
            x if x == EtherType::Ptp as u16 => EtherType::Ptp,
            x if x == EtherType::Vlan as u16 => EtherType::Vlan,
            _ => EtherType::Unimplemented,
        }
    }
}

impl ByteStructLen for EtherType {
    const BYTE_LEN: usize = 2;
}

impl ByteStruct for EtherType {
    fn read_bytes(bytes: &[u8]) -> Self {
        let mut bytes_read = [0_u8; 2];
        bytes_read.copy_from_slice(&bytes[0..=1]);
        return EtherType::from(u16::from_be_bytes(bytes_read));
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        let bytes_to_write = (*self as u16).to_be_bytes();
        bytes[0] = bytes_to_write[0];
        bytes[1] = bytes_to_write[1];
    }
}

impl EtherType {
    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        (*self as u16).to_be_bytes()
    }
}
