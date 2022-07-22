//! Address Resolution Protocol implementation with generation of requests and responses to received requests.
//!
//! ARP is not a distinct network abstraction layer, but is still required for most networks to function
//! because socket abstractions frequently require an ARP request and response to be completed before sending data
//! even if the router is actually going to be handling the association between MAC addresses and IP addresses,
//! so resolving the target's MAC address is not explicitly necessary.
//!
//! This is a noisy process, but on a statically-addressed network, it will ideally only occur once
//! during network initialization or if a host resets its network drivers and needs to re-connect.
//! In practice, most systems send out ARP requests about once per second.
//!
//! This process is not useful on a statically-addressed network, but on a mixed statically-and-dynamically-addressed network, it can help
//! in the case where the target device does exist on the network, but has not yet sent a packet and does not have an entry in the
//! router/switch's MAC address table. In that case, the broadcasted ARP request will still reach that device and produce a response,
//! which will be noted by the router/switch and allow its MAC address table entry to be populated.
//!
//! It can also be useful for networks with not-smart network switches where the hosts have to self-assemble the addressing space,
//! because ARP allows each host on the network to poll the others to check if an address is already taken before assigning
//! that address to itself. The success of that method requires that all devices on the network be configured to respond to ARP requests,
//! which is not necessarily the case.

use crate::*;

use ufmt::derive::uDebug;
use byte_struct::*;
use static_assertions::const_assert;

const_assert!(ArpPayload::BYTE_LEN == 46);  // Make sure the ARP frame is at least sized for the minimum ethernet payload

/// An ARP request or response with IPV4 addresses and standard MAC addresses.
/// Assumes 6-byte standard MAC addresses and 4-byte IPV4 addresses; this function can't be as general as the parser
/// because we need to know the size of the output at compile time.
/// See https://en.wikipedia.org/wiki/Address_Resolution_Protocol .
///
/// Hardware type is 1 for ethernet.
#[derive(ByteStruct, Clone, Copy, uDebug, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[byte_struct_be]
pub struct ArpPayload {
    /// Hardware type (1 for ethernet)
    pub htype: u16,
    /// Protocol type (same as ethertype from ethernet header)
    pub ptype: ProtocolType,
    /// Hardware address length (6 for standard MAC)
    pub hlen: u8,
    /// Protocol address length (4 for IPV4)
    pub plen: u8,
    /// ARP operation type
    pub operation: ArpOperation,
    /// Source MAC address
    pub src_mac: MacAddr,
    /// Source IP address
    pub src_ipaddr: IpV4Addr,
    /// Destination MAC address
    pub dst_mac: MacAddr,
    /// Destination IP address
    pub dst_ipaddr: IpV4Addr,
    /// Pad to minimum frame size
    _pad0: u128,
    _pad1: u16
}

impl ArpPayload {
    /// Create a new ARP payload for IPV4 on ethernet
    pub fn new(
        src_mac: MacAddr,
        src_ipaddr: IpV4Addr,
        dst_mac: MacAddr,
        dst_ipaddr: IpV4Addr,
        operation: ArpOperation,
    ) -> Self {
        ArpPayload {
            htype: 1,  // Always on ethernet
            ptype: ProtocolType::IpV4,  // Always resolving an IPV4 address
            hlen: 6,
            plen: 4,
            operation: operation,
            src_mac: src_mac,
            src_ipaddr: src_ipaddr,
            dst_mac: dst_mac,
            dst_ipaddr: dst_ipaddr,
            _pad0: 0,
            _pad1: 0
        }
    }

    /// Convert to big-endian byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0_u8; Self::BYTE_LEN];
        self.write_bytes(&mut bytes);
        bytes
    }
}

/// ARP request or response flag values
#[derive(Clone, Copy, uDebug, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ArpOperation {
    /// This is a request to confirm target IP address and acquire associated MAC address
    Request = 1,
    /// This is a response to confirm our IP address and provide associated MAC address
    Response = 2,
    /// Invalid operation
    Unimplemented,
}

impl From<u16> for ArpOperation {
    fn from(value: u16) -> Self {
        match value {
            x if x == ArpOperation::Request as u16 => ArpOperation::Request,
            x if x == ArpOperation::Response as u16 => ArpOperation::Response,
            _ => ArpOperation::Unimplemented,
        }
    }
}

impl ByteStructLen for ArpOperation {
    const BYTE_LEN: usize = 2;
}

impl ByteStruct for ArpOperation {
    fn read_bytes(bytes: &[u8]) -> Self {
        let mut bytes_read = [0_u8; 2];
        bytes_read.copy_from_slice(&bytes[0..=1]);
        return ArpOperation::from(u16::from_be_bytes(bytes_read));
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        let bytes_to_write = self.to_be_bytes();
        bytes[0] = bytes_to_write[0];
        bytes[1] = bytes_to_write[1];
    }
}

impl ArpOperation {
    /// Convert to big-endian byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        (*self as u16).to_be_bytes()
    }
}

/// Protocol Type flags are the same as EtherType but must be reimplemented to avoid run-time recursion
///
/// See https://en.wikipedia.org/wiki/EtherType
#[derive(Clone, Copy, uDebug, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ProtocolType {
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

impl From<u16> for ProtocolType {
    fn from(value: u16) -> Self {
        match value {
            x if x == ProtocolType::Arp as u16 => ProtocolType::Arp,
            x if x == ProtocolType::EtherCat as u16 => ProtocolType::EtherCat,
            x if x == ProtocolType::IpV4 as u16 => ProtocolType::IpV4,
            x if x == ProtocolType::IpV6 as u16 => ProtocolType::IpV6,
            x if x == ProtocolType::Ptp as u16 => ProtocolType::Ptp,
            x if x == ProtocolType::Vlan as u16 => ProtocolType::Vlan,
            _ => ProtocolType::Unimplemented,
        }
    }
}

impl ByteStructLen for ProtocolType {
    const BYTE_LEN: usize = 2;
}

impl ByteStruct for ProtocolType {
    fn read_bytes(bytes: &[u8]) -> Self {
        let mut bytes_read = [0_u8; 2];
        bytes_read.copy_from_slice(&bytes[0..=1]);
        return ProtocolType::from(u16::from_be_bytes(bytes_read));
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        let bytes_to_write = (*self as u16).to_be_bytes();
        bytes[0] = bytes_to_write[0];
        bytes[1] = bytes_to_write[1];
    }
}

impl ProtocolType {
    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        (*self as u16).to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an ARP message and make sure the parser returns the same values from the input
    #[test]
    fn test_serialization_loop() -> () {
        let msg = ArpPayload::new(
            MacAddr::new([7_u8; 6]),
            IpV4Addr::new([8_u8; 4]),
            MacAddr::new([9_u8; 6]),
            IpV4Addr::new([10_u8; 4]),
            ArpOperation::Request,
        );
        // Serialize
        let bytes: [u8; 64] = msg.to_be_bytes();
        // Deserialize
        let msg_parsed = ArpPayload::read_bytes(&bytes);

        assert_eq!(msg, msg_parsed);
    }
}
