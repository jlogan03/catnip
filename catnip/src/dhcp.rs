//! Dynamic Host Configuration Protocol for IPV4
//!
//! Call-response structure used by a router to assign IP addresses to devices on a local network.
//! 
//! https://datatracker.ietf.org/doc/html/rfc2131#page-22


use crate::{EtherType, IPV4Addr, MACAddr};

const Cookie: u32 = 0x63_82_53_63;
const ServerPort: u16 = 67;
const ClientPort: u16 = 68;

#[repr(C, packed)]
struct DHCPFixedPayload {
    op: DHCPOperation,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: IPV4Addr,
    yiaddr: IPV4Addr,
    siaddr: IPV4Addr,
    chaddr: [u8; 6],  // Actual field is 16 bytes; we only use 6 for standard MAC address
    pad0: [u8; 10],  // Explicit padding of the remaining 10 bytes of chaddr
    pad1: [u8, 196], // Padding of BOOTP legacy fields
}

#[repr(u8)]
enum DHCPOperation {
    Request = 1,
    Reply = 2
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
    LeaseQuery = 14,
    LeaseQueryDone = 15,
    ActiveLeaseQuery = 16,
    LeaseQueryStatus = 17,
    Tls = 18,
}
