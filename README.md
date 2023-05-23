# catnip

A no-std, panic-never, heapless, minimally-featured UDP/IP stack for bare-metal.
Intended for realtime data acquisition and controls on LAN.

Makes use of const generic expressions to provide flexibility in,
and guaranteed correctness of, lengths of headers and data segments without
dynamic allocation.

Because of this, the crate currently relies on the nightly channel, and as a result, may break regularly
until the required features stabilize.

This library is under active development; major functionality is yet to
be implemented and I'm sure some bugs are yet to be found.

Docs: https://docs.rs/catnip.

# Example

```rust
use catnip::*;

// Some made-up data with two 32-bit words' worth of bytes and some arbitrary addresses
let data: ByteArray<8> = ByteArray([0, 1, 2, 3, 4, 5, 6, 7]);

// Build frame
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
            src_ipaddr: IpV4Addr::new([10, 0, 0, 120]),
            dst_ipaddr: IpV4Addr::new([10, 0, 0, 121]),
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

// Calculate IP and UDP checksums
frame.data.data.header.checksum = calc_udp_checksum(&frame.data);
frame.data.header.checksum = calc_ip_checksum(&frame.data.header.to_be_bytes());

// Reduce to big-endian network bytes
let bytes = frame.to_be_bytes();

// Parse from bytes
let frame_parsed = EthernetFrame::<IpV4Frame<UdpFrame<ByteArray<8>>>>::read_bytes(&bytes);
assert_eq!(frame_parsed, frame);
```

# Features

- Ethernet II frames
- IPV4
- UDP
- ARP
- DHCP (INFORM only)

# To-do

- Add UDP psuedo-socket trait w/ arbitrary sync/async send & receive functions
- Move to stable once constants defined in traits become available for parametrizing generics

# License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
