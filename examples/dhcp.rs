
fn main() -> () {
    use catnip::*;

    let dhcp_inform = DhcpFixedPayload::new_inform(
        IpV4Addr::new([1, 2, 3, 4]),
        MacAddr::new([5, 6, 7, 8, 9, 10]),
        12345
    );

    // Serialize
    let bytes = dhcp_inform.to_be_bytes();
    // Deserialize
    let msg_parsed = DhcpFixedPayload::read_bytes(&bytes);

    assert_eq!(msg_parsed, dhcp_inform);
}