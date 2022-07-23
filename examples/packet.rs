//! Build a UDP/IP Ethernet packet and get its representation as network bytes



fn main() -> () {
    use catnip::*;
    
    // Some made-up data with two 32-bit words' worth of bytes
    let data: ByteArray<8> = ByteArray([0, 1, 2, 3, 4, 5, 6, 7]);

    // Arbitrary addresses
    let src_ipaddr: IpV4Addr = IpV4Addr::new([10, 0, 0, 120]);
    let dst_ipaddr: IpV4Addr = IpV4Addr::new([10, 0, 0, 121]);

    let frame = EthernetFrame::<IpV4Frame<UdpFrame<ByteArray<8>>>> {
        header: EthernetHeader {
            dst_macaddr: MacAddr::BROADCAST,
            src_macaddr: MacAddr::new([0x02, 0xAF, 0xFF, 0x1A, 0xE5, 0x3C]),
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
                    src_port: 8123,
                    dst_port: 8125,
                    length: UdpFrame::<ByteArray<8>>::BYTE_LEN as u16,
                    checksum: 0,
                },
                data: data,
            },
        },
        checksum: 0_u32,
    };

    let bytes = frame.to_be_bytes();
    let frame_parsed = EthernetFrame::<IpV4Frame<UdpFrame<ByteArray<8>>>>::read_bytes(&bytes);

    assert_eq!(frame_parsed, frame);
}
