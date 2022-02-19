//! Bare-bones User Datagram Protocol implementation

/// UDP datagram header structure like
/// header[0:1] source port [u16]
/// header[2:3] destination port [u16]
/// header[4:5] total length in bytes [u16], header + data
/// header[6:7] checksum [u16]
struct UDPHeader {
    header: [u8; 8]
}

impl UDPHeader {
    pub fn new() {
        // Clear any existing values in the provided container
        let content = [0_u8; 8];

        // Start a blank header
        let header: UDPHeader = UDPHeader { header: content };
    }
}