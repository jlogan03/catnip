//! Build a UDP/IP Ethernet packet and get its representation as network bytes

use catnip::enet::{
    parse_header_bytes, EtherType, EthernetFrameUDP, EthernetHeader, EthernetPacketUDP,
};
use catnip::ip::IPV4Header;
use catnip::udp::{parse_packet_bytes, UDPHeader, UDPPacket};
use catnip::{Data, IPV4Addr, MACAddr, Version, DSCP};
// extern crate std; // To show debugging output

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
    let mut ipheader: IPV4Header<0> = IPV4Header::new();
    ipheader
        .src_ipaddr(src_ipaddr)
        .dst_ipaddr(dst_ipaddr)
        .version(Version::V4)
        .ttl(100)
        .dscp(DSCP::Realtime);
    println!("{:?}", &ipheader);
    println!("{:?}\n", &ipheader.to_be_bytes());

    // Build UDP header
    let udpheader: UDPHeader = UDPHeader::new(src_port, dst_port);
    println!("{:?}", &udpheader);
    println!("{:?}\n", &udpheader.to_be_bytes());

    // Build UDP packet with 0 words of IP options and 2 words of data
    let udppacket: UDPPacket<0, 2> = UDPPacket::new(ipheader, udpheader, data); // Populates packet length fields for both IP and UDP headers
    let udp_packet_bytes = udppacket.to_be_bytes();
    println!("{:?}", &udppacket);
    println!("{:?}\n", &udp_packet_bytes);

    // Build Ethernet frame header
    let enetheader: EthernetHeader = EthernetHeader::new(src_macaddr, dst_macaddr, EtherType::IPV4);
    println!("{:?}", &enetheader);
    println!("{:?}\n", &enetheader.to_be_bytes());

    // Build Ethernet frame
    // Unfortunately these can't be generic until const generic expr trait bounds work
    let enetframe = EthernetFrameUDP::new(enetheader, udppacket);
    let enet_frame_bytes = &enetframe.to_be_bytes();
    println!("{:?}", &enetframe);
    println!("{:?}\n", enet_frame_bytes);

    // Build Ethernet packet
    let enetpacket = EthernetPacketUDP::new(enetframe);
    println!("{:?}", &enetpacket);
    println!("{:?}\n", &enetpacket.to_be_bytes());

    // Test parsing
    //    Ethernet header
    let mut enet_header_bytes = [0_u8; 14];
    enet_header_bytes.copy_from_slice(&enet_frame_bytes[0..14]);
    let (src_macaddr_parsed, dst_macaddr_parsed, ethertype_parsed) =
        parse_header_bytes(&enet_header_bytes);
    assert_eq!(src_macaddr.value, src_macaddr_parsed.value);
    assert_eq!([0xFF_u8; 6], dst_macaddr_parsed.value);
    assert_eq!(EtherType::IPV4 as u32, ethertype_parsed as u32);
    //    UDP packet
    let mut header_bytes = [0_u8; 20];
    header_bytes.copy_from_slice(&udp_packet_bytes[0..20]);

    match parse_packet_bytes(&udp_packet_bytes) {
        Ok(x) => {
            let (
                data_parsed,
                options_parsed,
                src_ipaddr_parsed,
                src_port_parsed,
                dst_ipaddr_parsed,
                dst_port_parsed,
                version_parsed,
                protocol_parsed,
                checksum_parsed,
                identification_parsed,
            ) = x;
            println!(
                "
data: {data_parsed:?}
options: {options_parsed:?}
src_ipaddr: {src_ipaddr_parsed:?}
src_port: {src_port_parsed:?}
dst_ipaddr: {dst_ipaddr_parsed:?}
dst_port: {dst_port_parsed:?}
version: {version_parsed:?}
protocol: {protocol_parsed:?}
checksum: {checksum_parsed:?}
identification: {identification_parsed:?}
            "
            );
        }
        Err(x) => {
            println!("Failed to parse UDP packet: {x}")
        }
    }
}
