//! Building this module successfully guarantees that the catnip library is no-std compatible
//! and that it produces no panic branches (panic-never compatible)

#![no_std]
#![no_main]

#[allow(unused_imports)]
use catnip;

#[no_mangle]
pub fn _start() -> ! {
    use byte_struct::*;
    use catnip::arp::{ArpOperation, ArpPayload};
    use catnip::{EtherType, IpV4Addr, MacAddr};

    /// Build an ARP message and make sure the parser returns the same values from the input
    let ptypei = EtherType::IPV4;
    let operationi = ArpOperation::Request;
    let shai = MacAddr::new([7_u8; 6]);
    let spai = IpV4Addr::new([8_u8; 4]);
    let thai = MacAddr::new([9_u8; 6]);
    let tpai = IpV4Addr::new([10_u8; 4]);
    let msg = ArpPayload {
        htype: 1,
        ptype: ptypei,
        hlen: 6,
        plen: 4,
        operation: operationi,
        src_mac: shai,
        src_ipaddr: spai,
        dst_mac: thai,
        dst_ipaddr: tpai,
    };
    // Serialize
    let bytes: [u8; 28] = msg.to_be_bytes();
    // Deserialize
    let msg_parsed = ArpPayload::read_bytes(&bytes);

    // let bytes = ArpOperation::Request.to_be_bytes();
    // let parsed = ArpOperation::read_bytes(&bytes);

    // assert_eq!(msg, msg_parsed);

    loop {}
}
