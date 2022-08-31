//! Build an example ARP message

fn main() -> () {
    use catnip::*;

    let msg = ArpPayload::new(
        MacAddr::new([1, 2, 3, 4, 5, 6]),
        IpV4Addr::new([7, 8, 9, 10]),
        MacAddr::new([11, 12, 13, 14, 15, 16]),
        IpV4Addr::new([17, 18, 19, 20]),
        ArpOperation::Request,
    );

    // Serialize
    let bytes: [u8; ArpPayload::BYTE_LEN] = msg.to_be_bytes();

    // Deserialize
    let msg_parsed = ArpPayload::read_bytes(&bytes);

    assert_eq!(msg, msg_parsed);
}