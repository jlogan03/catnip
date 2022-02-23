//! Build a UDP/IP Ethernet packet and get its representation as network bytes

use catnip::enet::{EtherType, EthernetFrameUDP, EthernetHeader, EthernetPacketUDP};
use catnip::ip::{IPV4Addr, IPV4Header, DSCP};
use catnip::udp::{UDPHeader, UDPPacket};
use catnip::{Data, MACAddr};
extern crate std; // To show debugging output

fn main() -> () {
    // Some made-up addresses
    // MAC address in locally-administered address range
    // IP addresses in local network range
    // Ports are arbitrary
    let src_macaddr: MACAddr = MACAddr {
        value: [0x02, 0xAF, 0xFF, 0x1A, 0xE5, 0x3C],
    };
    let dst_macaddr = None;
    let src_port: u16 = 8123;
    let dst_port: u16 = 8123;
    let src_ipaddr: IPV4Addr = IPV4Addr {
        value: [10, 0, 0, 1],
    };
    let dst_ipaddr: IPV4Addr = IPV4Addr {
        value: [10, 0, 0, 2],
    };

    // Some made-up data with two 32-bit words' worth of bytes
    let data: Data<2> = Data {
        value: [0, 1, 2, 3, 4, 5, 6, 7],
    };
    println!("{:?}", &data);
    println!("{:?}\n", &data.to_be_bytes());

    // Build IP header with no Options section
    // Header length is populated in new()
    // Total length is populated by UDPPacket.finalize()
    let ipheader: IPV4Header<0> = IPV4Header::new()
        .src_ipaddr(src_ipaddr)
        .dst_ipaddr(dst_ipaddr)
        .dscp(DSCP::Realtime)
        .finalize();
    println!("{:?}", &ipheader);
    println!("{:?}\n", &ipheader.to_be_bytes());

    // Build UDP header
    let udpheader: UDPHeader = UDPHeader::new(src_port, dst_port);
    println!("{:?}", &udpheader);
    println!("{:?}\n", &udpheader.to_be_bytes());

    // Build UDP packet with 0 words of IP options and 2 words of data
    let udppacket: UDPPacket<0, 2> = UDPPacket {
        ip_header: ipheader,
        udp_header: udpheader,
        udp_data: data,
    }; // Populates packet length fields for both IP and UDP headers
    println!("{:?}", &udppacket);
    println!("{:?}\n", &udppacket.to_be_bytes());

    // Build Ethernet frame header
    let enetheader: EthernetHeader = EthernetHeader::new(src_macaddr, dst_macaddr, EtherType::IPV4);
    println!("{:?}", &enetheader);
    println!("{:?}\n", &enetheader.to_be_bytes());

    // Build Ethernet frame
    // Unfortunately these can't be generic until const generic expr trait bounds work
    let enetframe = EthernetFrameUDP::new(enetheader, udppacket);
    println!("{:?}", &enetframe);
    println!("{:?}\n", &enetframe.to_be_bytes());

    // Build Ethernet packet
    let enetpacket = EthernetPacketUDP::new(enetframe);
    println!("{:?}", &enetpacket);
    println!("{:?}\n", &enetpacket.to_be_bytes());
}
