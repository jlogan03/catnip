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
//! It can also be useful for networks with not-smart network switches where the hosts all choose their own static addresses,
//! because ARP allows each host on the network to poll the others to check if an address is already taken before assigning
//! that address to itself. The success of that method requires that all devices on the network be configured to respond to ARP requests,
//! which is not necessarily the case.

use crate::{enet, EtherType, IPV4Addr, MACAddr};

/// An ARP request or response with IPV4 addresses.
///
/// https://en.wikipedia.org/wiki/Address_Resolution_Protocol
///
/// Assumes 6-byte standard MAC addresses and 4-byte IPV4 addresses.
pub fn build_arp_message_ipv4(
    htype: u16,
    ptype: EtherType,
    operation: ARPOperation,
    sha: MACAddr,
    spa: IPV4Addr,
    tha: MACAddr,
    tpa: IPV4Addr,
) -> [u8; 28] {
    let mut msg = [0_u8; 28];
    
    let htypeparts = htype.to_be_bytes();
    msg[0] = htypeparts[0];
    msg[1] = htypeparts[1];

    let ptypeparts = (ptype as u16).to_be_bytes();
    msg[2] = ptypeparts[0];
    msg[3] = ptypeparts[1];

    msg[4] = 6_u8;  // 6-byte MAC address lengths
    msg[5] = 4_u8;  // 4-byte protocol address lengths

    let opparts = (operation as u16).to_be_bytes();
    msg[6] = opparts[0];
    msg[7] = opparts[1];

    for i in 0..6 {
        msg[8 + i] = sha.value[i];
    }

    for i in 0..4 {
        msg[14 + i] = spa.value[i];
    }

    for i in 0..6 {
        msg[20 + i] = tha.value[i];
    }

    for i in 0..4 {
        msg[24 + i] = tpa.value[i]
    }

    msg
}

/// ARP request or response flag values
#[derive(Clone, Debug)]
#[repr(u16)]
pub enum ARPOperation {
    /// This is a request to confirm target IP address and acquire associated MAC address
    Request = 1,
    /// This is a response to confirm target IP address and provide associated MAC address
    Response = 2,
}
