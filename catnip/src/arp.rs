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

use crate::{EtherType, IPV4Addr, MACAddr};

/// An ARP request or response with IPV4 addresses.
/// Assumes 6-byte standard MAC addresses and 4-byte IPV4 addresses; this function can't be as general as the parser
/// because we need to know the size of the output at compile time, whereas the parser can return references to
/// arbitrarily-sized slices of the source data that is likely an excerpt of a sized buffer.
/// See https://en.wikipedia.org/wiki/Address_Resolution_Protocol .
///
/// Hardware type is 1 for ethernet.
pub fn build_arp_msg_ipv4(
    ptype: EtherType,
    operation: ARPOperation,
    sha: MACAddr,
    spa: IPV4Addr,
    tha: MACAddr,
    tpa: IPV4Addr,
) -> [u8; 28] {
    let mut msg = [0_u8; 28];

    // Hardware type (ethernet, etc each have a numerical code)
    let htypeparts = 1_u16.to_be_bytes();
    msg[0] = htypeparts[0];
    msg[1] = htypeparts[1];
    // Protocol type
    let ptypeparts = (ptype as u16).to_be_bytes();
    msg[2] = ptypeparts[0];
    msg[3] = ptypeparts[1];
    // Assumptions
    msg[4] = 6_u8; // 6-byte MAC address lengths
    msg[5] = 4_u8; // 4-byte protocol address lengths
                   // Operation type (request or response)
    let opparts = (operation as u16).to_be_bytes();
    msg[6] = opparts[0];
    msg[7] = opparts[1];
    // Sender hardware address
    for i in 0..6 {
        msg[8 + i] = sha.value[i];
    }
    // Sender protocol address
    for i in 0..4 {
        msg[14 + i] = spa.value[i];
    }
    // Target hardware address (all zeros for request)
    for i in 0..6 {
        msg[18 + i] = tha.value[i];
    }
    // Target protocol address (what IP address are we trying to resolve?)
    for i in 0..4 {
        msg[24 + i] = tpa.value[i]
    }

    msg
}

/// Attempt to parse an ARP message from a slice.
/// Assumes 6-byte standard MAC addresses and 4-byte IPV4 addresses on ethernet.
/// but parses the "HLEN" and "PLEN" fields in order to check this assumption.
pub fn parse_arp_msg(
    msg: &[u8],
) -> Result<
    (
        u16,
        EtherType,
        u8,
        u8,
        ARPOperation,
        &[u8],
        &[u8],
        &[u8],
        &[u8],
    ),
    &str,
> {
    // Is this message long enough to contain an ARP header?
    if msg.len() < 8 {
        // Note we do not state the actual length here because it would require core::fmt
        // which takes up a massive amount of space in the binary
        return Err("ARP parser error: length should be at least 8 bytes");
    }

    // Hardware type (1 for ethernet)
    let mut htypeparts = [0_u8; 2];
    htypeparts.copy_from_slice(&msg[0..=1]);
    let htype = u16::from_be_bytes(htypeparts);
    // Protocol type
    let mut ptypeparts = [0_u8; 2];
    ptypeparts.copy_from_slice(&msg[2..=3]);
    let ptype = EtherType::from(u16::from_be_bytes(ptypeparts));
    // Hardware address length (6 for standard MAC)
    let hlen = msg[4];
    // Protocol address length (4 for IPV4)
    let plen = msg[5];

    // Check length again - is the message long enough to contain both addresses for both machines?
    // len = 28 for IPV4 with standard 6-byte MAC address
    if msg.len() < 8 + (2 * hlen as usize) + (2 * plen as usize) {
        return Err("ARP parser error: message length too short to hold addresses");
    }

    // Operation type (request=1 or response=2)
    let mut opparts = [0_u8; 2];
    opparts.copy_from_slice(&msg[6..=7]);
    let operation = ARPOperation::from(u16::from_be_bytes(opparts));

    // Variable-length parts
    // Sender hardware address
    let (start, len) = (8, hlen as usize);
    let end = start + len;
    let sha = &msg[start..end];
    // Sender protocol address
    let (start, len) = (end, plen as usize);
    let end = start + len;
    let spa = &msg[start..end];
    // Target hardware address
    let (start, len) = (end, hlen as usize);
    let end = start + len;
    let tha = &msg[start..end];
    // Target protocol address
    let (start, len) = (end, plen as usize);
    let end = start + len;
    let tpa = &msg[start..end];

    Ok((htype, ptype, hlen, plen, operation, sha, spa, tha, tpa))
}

/// ARP request or response flag values
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ARPOperation {
    /// This is a request to confirm target IP address and acquire associated MAC address
    Request = 1,
    /// This is a response to confirm our IP address and provide associated MAC address
    Response = 2,
    /// Invalid operation
    Invalid = 0,
}

impl From<u16> for ARPOperation {
    fn from(value: u16) -> Self {
        match value {
            x if x == ARPOperation::Request as u16 => ARPOperation::Request,
            x if x == ARPOperation::Response as u16 => ARPOperation::Response,
            _ => ARPOperation::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{build_arp_msg_ipv4, parse_arp_msg, ARPOperation};
    use crate::{EtherType, IPV4Addr, MACAddr};

    // extern crate std;
    // use std::println;

    fn build_dummy_msg() -> [u8; 28] {
        let ptypei = EtherType::IPV4;
        let operationi = ARPOperation::Request;
        let shai = MACAddr::new([7_u8; 6]);
        let spai = IPV4Addr::new([8_u8; 4]);
        let thai = MACAddr::new([9_u8; 6]);
        let tpai = IPV4Addr::new([10_u8; 4]);
        build_arp_msg_ipv4(ptypei, operationi, shai, spai, thai, tpai)
    }

    /// Make sure the ARP message builder doesn't generate any panic branches
    #[test]
    fn test_build_arp_msg_ipv4() {
        let _ = build_dummy_msg();
    }

    /// Build an ARP message and make sure the parser returns the same values from the input
    #[test]
    fn test_parse_arp_msg() -> Result<(), ()> {
        let ptypei = EtherType::IPV4;
        let operationi = ARPOperation::Request;
        let shai = MACAddr::new([7_u8; 6]);
        let spai = IPV4Addr::new([8_u8; 4]);
        let thai = MACAddr::new([9_u8; 6]);
        let tpai = IPV4Addr::new([10_u8; 4]);
        let msg = build_arp_msg_ipv4(ptypei, operationi, shai, spai, thai, tpai);

        match parse_arp_msg(&msg[..]) {
            Ok((htype, ptype, hlen, plen, operation, sha, spa, tha, tpa)) => {
                // println!("{tha:?}");
                // println!("{thai:?}");
                if (htype != 1)
                    || (ptype != ptypei)
                    || (hlen != 6)
                    || (plen != 4)
                    || (operation != operationi)
                    || (sha != shai.value)
                    || (spa != spai.value)
                    || (tha != thai.value)
                    || (tpa != tpai.value)
                {
                    Err(())
                } else {
                    Ok(())
                }
            }
            Err(_) => Err(()),
        }
    }

    /// Make sure the parser fails if the message is too short for the header
    #[test]
    fn test_parse_arp_msg_bad_header_len() -> Result<(), ()> {
        let msg = [0_u8; 7];
        match parse_arp_msg(&msg[..]) {
            Ok(_) => Err(()),
            Err(_) => Ok(())
        }
    }

    /// Make sure the parser fails if the message is too short for the addresses
    #[test]
    fn test_parse_arp_msg_bad_address_len() -> Result<(), ()> {
        let msg = build_dummy_msg();
        match parse_arp_msg(&msg[..20]) {
            Ok(_) => Err(()),
            Err(_) => Ok(())
        }
    }

}
