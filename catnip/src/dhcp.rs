//! Dynamic Host Configuration Protocol for IPV4
//!
//! Call-response structure used by a router to assign IP addresses to devices on a local network.
//!
//! https://datatracker.ietf.org/doc/html/rfc2131#page-22

use crate::{EtherType, IPV4Addr, MACAddr};
use core::mem::size_of;

const Cookie: u32 = 0x63_82_53_63;
const ServerPort: u16 = 67;
const ClientPort: u16 = 68;

/// The fixed-length part of the DHCP payload. The options section can vary in length, but only the first portion is important.
///
/// C-ordered, packed, and aligned to 1 byte in order to support direct conversion to byte array.
#[repr(C, packed(1))]
struct DHCPFixedPayload {
    op: DHCPOperation,
    /// Hardware type always 1 for ethernet
    htype: u8,
    /// Hardware address length always 6 bytes for standard mac address
    hlen: u8,
    /// Legacy field, always 0
    hops: u8,
    /// Transaction ID; assigned by router
    xid: u32,
    /// Seconds elapsed since client started transaction
    secs: u16,
    /// Broadcast flag; 1 for broadcast, 0 for unicast
    flags: u16,
    /// Client IP Address; only used for renewal, otherwise zero
    ciaddr: IPV4Addr,
    /// Your IP Address; usually the one you are requesting to lease
    yiaddr: IPV4Addr,
    /// Server IP Address; usually the closest router or network switch
    siaddr: IPV4Addr,
    /// Gateway IP Address
    giaddr: IPV4Addr,
    /// Client (your) hardware address. Actual field is 16 bytes; we only use 6 for standard MAC address.
    chaddr: MACAddr,
    /// Explicit padding of the remaining 10 bytes of chaddr
    pad0: [u8; 10],
    /// Padding of BOOTP legacy fields and server's irrelevant stringified name
    pad1: [u8; 196],
}

impl DHCPFixedPayload {
    pub const SIZE: usize = size_of::<DHCPFixedPayload>();

    pub fn new(
        op: DHCPOperation,
        ciaddr: IPV4Addr,
        yiaddr: IPV4Addr,
        siaddr: IPV4Addr,
        giaddr: IPV4Addr,
        chaddr: MACAddr,
    ) -> DHCPFixedPayload {
        DHCPFixedPayload {
            op: op,
            htype: 1_u8, // Always 1 for ethernet
            hlen: 6_u8,  // Always 6 byte standard mac address
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 1,
            ciaddr: ciaddr,
            yiaddr: yiaddr,
            siaddr: siaddr,
            giaddr: giaddr,
            chaddr: chaddr,
            pad0: [0_u8; 10],
            pad1: [0_u8; 196],
        }
    }

    pub fn to_be_bytes(self) -> [u8; DHCPFixedPayload::SIZE] {
        let addr = (&self) as *const _ as usize;
        let bytes = unsafe { *(addr as *const _) };
        return bytes;
    }
}

#[repr(u8)]
enum DHCPOperation {
    Request = 1,
    Reply = 2,
}

#[repr(u8)]
enum DHCPMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5, // Acknowledge
    Nak = 6, // Negative-acknowledge
    Release = 7,
    Inform = 8,
    ForceRenew = 9,
    LeaseQuery = 10,
    LeaseUnassigned = 11,
    LeaseUnknown = 12,
    LeaseActive = 13,
    BulkLeaseQuery = 14,
    LeaseQueryDone = 15,
    ActiveLeaseQuery = 16,
    LeaseQueryStatus = 17,
    Tls = 18,
}

#[cfg(test)]
mod test {

    /// Make sure actual data alignment is fully packed and safe to convert directly to byte array
    #[test]
    fn test_layout() {
        use super::{DHCPFixedPayload, DHCPOperation};
        use crate::{IPV4Addr, MACAddr};
        use core::mem::{size_of, size_of_val};
        // use core::ptr::*;

        let ip = IPV4Addr {
            value: [0, 0, 0, 0],
        };
        let mac = MACAddr {
            value: [1, 2, 3, 4, 5, 6],
        };

        let data = DHCPFixedPayload::new(DHCPOperation::Request, ip, ip, ip, ip, mac);

        let size_expected = 1 + 1 + 1 + 1 + 4 + 2 + 2 + 4 + 4 + 4 + 4 + 6 + 10 + 196;
        let size_sized = size_of::<DHCPFixedPayload>();
        let size_actual = size_of_val(&data);

        assert_eq!(size_sized, size_expected);
        assert_eq!(size_actual, size_expected);
    }
}
