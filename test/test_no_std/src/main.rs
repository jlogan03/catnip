//! Building this module successfully guarantees that the catnip library is no-std compatible
//! and that it produces no panic branches (panic-never compatible).
//! However, not all tests can be run this way, because panic_never precludes the use of run-time assertions.

#![no_std]
#![no_main]

use catnip::*;

#[no_mangle]
pub fn _start() -> ! {

    test_arp();
    test_enet_ip_udp();

    loop {}
}


fn test_arp() -> () {
    // Build an ARP message and make sure the parser returns the same values from the input
    let msg = ArpPayload::new(
        MacAddr::new([7_u8; 6]),
        IpV4Addr::new([8_u8; 4]),
        MacAddr::new([9_u8; 6]),
        IpV4Addr::new([10_u8; 4]),
        ArpOperation::Request,
    );
    // Serialize
    let bytes: [u8; ArpPayload::BYTE_LEN] = msg.to_be_bytes();
    // Deserialize
    let _msg_parsed = ArpPayload::read_bytes(&bytes);
}

fn generate_sample_frame() -> EthernetFrame::<IpV4Frame<UdpFrame<ByteArray<8>>>> {
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
    let data: ByteArray<8> = ByteArray([0, 1, 2, 3, 4, 5, 6, 7]);

    let frame = EthernetFrame::<IpV4Frame<UdpFrame<ByteArray<8>>>> {
        header: EthernetHeader {
            dst_macaddr: dst_macaddr,
            src_macaddr: src_macaddr,
            ethertype: EtherType::IpV4,
        },
        data: IpV4Frame::<UdpFrame<ByteArray<8>>> {
            header: IpV4Header {
                version_and_header_length: VersionAndHeaderLength::new().with_version(4).with_header_length((IpV4Header::BYTE_LEN / 4) as u8),
                dscp: DSCP::Standard,
                total_length: IpV4Frame::<UdpFrame<ByteArray<8>>>::BYTE_LEN as u16,
                identification: 0,
                fragmentation: Fragmentation::default(),
                time_to_live: 10,
                protocol: Protocol::Udp,
                checksum: 0,
                src_ipaddr: src_ipaddr,
                dst_ipaddr: dst_ipaddr,
            },
            data: UdpFrame::<ByteArray<8>> {
                header: UdpHeader {
                    src_port: src_port,
                    dst_port: dst_port,
                    length: UdpFrame::<ByteArray<8>>::BYTE_LEN as u16,
                    checksum: 0,
                },
                data: data,
            },
        },
        checksum: 0_u32,
    };

    frame
}

fn test_enet_ip_udp() -> () {
    let frame = generate_sample_frame();

    let bytes = frame.to_be_bytes();
    let _frame_parsed = EthernetFrame::<IpV4Frame<UdpFrame<ByteArray<8>>>>::read_bytes(&bytes);

}
