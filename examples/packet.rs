//! Build a UDP/IP Ethernet packet and get its representation as network bytes

// extern crate std; // To show debugging output

use catnip::*;

fn main() -> () {
    // Some made-up addresses
    // MAC address in locally-administered address range
    // IP addresses in local network range
    // Ports are arbitrary
    let src_macaddr: MacAddr = MacAddr::new([0x02, 0xAF, 0xFF, 0x1A, 0xE5, 0x3C]);
    let dst_macaddr: MacAddr = MacAddr::ANY;
    let src_port: u16 = 8123;
    let dst_port: u16 = 8125;
    let src_ipaddr: IpV4Addr = IpV4Addr::new([10, 0, 0, 1]);
    let dst_ipaddr: IpV4Addr = IpV4Addr::new([10, 0, 0, 2]);

    // Some made-up data with two 32-bit words' worth of bytes
    let data = ByteArray([0, 1, 2, 3, 4, 5, 6, 7]);

}
