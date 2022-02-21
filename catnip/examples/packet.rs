//! Build a UDP/IP Ethernet packet and get its representation as network bytes

use catnip::ip::IPV4Addr;
use catnip::MACAddr;
pub fn main() -> () {
    // Some made-up addresses
    // MAC address in locally-administered address range
    // IP addresses in local network range
    let src_macaddr: MACAddr = MACAddr { value: [0x02, 0x01, 0x02, 0x03, 0x04, 0x05] };
    let src_ipaddr: IPV4Addr = IPV4Addr { value: [10, 0, 0, 1] };
    let dst_ipaddr: IPV4Addr = IPV4Addr { value: [10, 0, 0, 2] };

    // Some made-up data
    

}