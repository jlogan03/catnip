//! Internet Protocol message header construction

/// IPV4 header per IETF-RFC-791
/// https://en.wikipedia.org/wiki/IPv4
///
/// first row
/// header[0] Version [4 bits], Header Length [4 bits]
/// header[1] Type-of-Service/IP Precedence/DSCP
/// header[2:3] Total Length [u16] in bytes
/// second row
/// header[4:5] Identification
/// header[6:7] Flags [3 bits], Fragmentation Offset [13 bits]
/// third row
/// header[8] Time-to-Live
/// header[9] Protocol
/// header[10:11] Checksum [u16]
/// fourth row
/// header[12:15] Source IP Address
/// fifth row
/// header[16:19] Destination IP Address
/// 
/// N is number of 32-bit words to reserve for the Options section
#[allow(dead_code)]
struct IPV4Header<const N: usize> where [u8; 4 * N + 20]: {
    header: &'static mut [u8; 4 * N + 20],
}

impl<const N: usize> IPV4Header<N> where [u8; 4 * N + 20]: {

    /// Start from some sensible defaults
    #[allow(dead_code)]
    pub fn new(content: &'static mut [u8; 4 * N + 20]) -> IPV4Header<N> {

        // Clear any existing values in the provided container
        for i in 0..content.len() {
            content[i] = 0u8;
        }

        // Start a blank header
        let mut header = IPV4Header { header: content };

        // Apply some defaults
        header = header
            .version(Version::V4)
            .header_length(5u8)
            .dscp(DSCP::Standard)
            .ttl(100)
            .protocol(Protocol::UDP);

        header
    }

    // Set version
    pub fn version(self, v: Version) -> Self {
        self.header[0] = self.header[0] & 0b0000_1111; // Clear existing
        self.header[0] = self.header[0] | v as u8; // Apply new
        self
    }

    // Set header length (in 32-bit words)
    pub fn header_length(self, v: u8) -> Self {
        self.header[0] = self.header[0] & 0b1111_0000; // Clear existing
        self.header[0] = self.header[0] | v as u8; // Apply new
        self
    }

    // Set DSCP (first 6 bits of second byte)
    pub fn dscp(self, v: DSCP) -> Self {
        self.header[1] = self.header[1] & 0b00000011; // Clear existing
        self.header[1] = self.header[1] | v as u8; // Apply new
        self
    }

    // Set total length of packet (header + body)
    #[allow(dead_code)]
    pub fn total_length(self, body_length: u16) -> Self {
        // Get total length
        let header_length = self.header[0] >> 4;
        let v = body_length + header_length as u16;

        // Split into two bytes
        let bytes: [u8; 2] = v.to_be_bytes();

        // Clear old
        self.header[2] = 0u8;
        self.header[3] = 0u8;

        // Apply new
        self.header[2] = bytes[0];
        self.header[3] = bytes[1];

        self
    }

    // Set identification
    #[allow(dead_code)]
    pub fn identification(self, v: u16) -> Self {
        let bytes = v.to_be_bytes();
        self.header[4] = bytes[0];
        self.header[5] = bytes[1];

        self
    }

    // Set fragmentation flags
    #[allow(dead_code)]
    pub fn flags(self, v: Flags) -> Self {
        match v {
            Flags::Clear => {
                // Clear old if requested
                self.header[6] = self.header[6] & Flags::Clear as u8;
            }
            _ => {
                // Apply new otherwise
                self.header[6] = self.header[6] | v as u8;
            }
        }

        self
    }

    // Set fragmentation offset
    #[allow(dead_code)]
    pub fn frag_offs(self, v: u16) -> Self {
        // Clip to 13 bits and split into bytes
        let v: u16 = v & 0b0001_1111_1111_1111;
        let bytes: [u8; 2] = v.to_be_bytes();
        // Clear old
        self.header[6] = self.header[6] & 0b1110_000;
        self.header[7] = 0u8;
        // Apply new
        self.header[6] = self.header[6] | bytes[0];
        self.header[7] = self.header[7] | bytes[1];

        self
    }

    /// Set Time-to-Live counter (number of bounces allowed)
    /// This counter decrements at each router and drops the packet at 0
    pub fn ttl(self, v: u8) -> Self {
        self.header[8] = v;

        self
    }

    /// Set protocol
    pub fn protocol(self, v: Protocol) -> Self {
        self.header[9] = v as u8;

        self
    }

    /// Set checksum
    #[allow(dead_code)]
    pub fn header_checksum(self, v: u16) -> Self {
        let bytes = v.to_be_bytes();
        self.header[10] = bytes[0];
        self.header[11] = bytes[1];

        self
    }

    /// Set source IP address
    #[allow(dead_code)]
    pub fn src_ipaddr(self, v: IPV4Addr) {
        for i in 0..4_usize {
            self.header[12 + i] = v.addr[i];
        }
    }

    /// Set destination IP address
    #[allow(dead_code)]
    pub fn dst_ipaddr(self, v: IPV4Addr) {
        for i in 0..4_usize {
            self.header[16 + i] = v.addr[i];
        }
    }
}

struct IPV4Addr {
    addr: [u8; 4],
}

/// Common choices of transport-layer protocols
/// and their IP header values.
/// There are many more protocols not listed here -
/// see https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
#[allow(dead_code)]
enum Protocol {
    TCP = 0x06,
    UDP = 0x11,
}

/// IP version
#[allow(dead_code)]
enum Version {
    V4 = 0b0100_0000,
    V6 = 0b0110_0000,
}

/// https://en.wikipedia.org/wiki/Differentiated_services
/// Priority 2 is low-latency class
#[allow(dead_code)]
enum DSCP {
    Standard = 0,
    NetworkControl = 48 << 2,
    Telephony = 46 << 2,
    Signaling = 40 << 2,
    Realtime = 32 << 2,
    BroadcastVideo = 24 << 2,
    OAM = 16 << 2,
    LowPriority = 8 << 2,
    AF11 = 10 << 2, // Low drop, priority 1
    AF12 = 12 << 2, // Med drop, priority 1
    AF13 = 14 << 2, // High drop, priority 1
    AF21 = 18 << 2, // Low drop, priority 2
    AF22 = 20 << 2, // Med drop, priority 2
    AF23 = 22 << 2, // High drop, priority 2
    AF31 = 26 << 2, // Low drop, priority 3
    AF32 = 28 << 2, // Med drop, priority 3
    AF33 = 30 << 2, // High drop, priority 3
}

#[allow(dead_code)]
enum Flags {
    DF = 1 << 6,         // Do not fragment
    MF = 1 << 5,         // More fragments
    Clear = 0b0001_1111, // Helper for clearing flags
}
