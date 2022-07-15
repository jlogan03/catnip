//! Internet layer: Internet Protocol message header construction

use crate::IpV4Addr;

use byte_struct::*;

bitfields!(
    #[derive(Clone, Copy, Debug)]
    Fragmentation: u16 {
        unused: 1,
        pub do_not_fragment: 1,
        pub more_fragments: 2,
        pub offset: 13
    }
);

bitfields!(
    #[derive(Clone, Copy, Debug)]
    VersionAndHeaderLength: u8 {
        pub version: 4,
        pub header_length: 4
    }
);

/// IPV4 header per IETF-RFC-791
///
/// N is number of 32-bit words to reserve for the Options section
///
/// https://en.wikipedia.org/wiki/IPv4
///
/// first 32-bit word
///
/// value [0] Version [4 bits], Header Length [4 bits]
///
/// value [1] Type-of-Service/IP Precedence/DSCP
///
/// value [2:3] Total Length [u16] in bytes
///
/// second 32-bit word
///
/// value [4:5] Identification [u16]
///
/// value [6:7] Flags [3 bits], Fragmentation Offset [13 bits]
///
/// third 32-bit word
///
/// value [8] Time-to-Live
///
/// value [9] Protocol
///
/// value [10:11] Checksum [u16]
///
/// fourth 32-bit word
///
/// value [12:15] Source IP Address
///
/// fifth 32-bit word
///
/// value [16:19] Destination IP Address
#[derive(ByteStruct, Clone, Debug)]
#[byte_struct_be]
pub struct IpV4Header {
    pub version_and_length: VersionAndHeaderLength,
    pub dscp: DSCP,
    pub total_length: u16,
    pub identification: u16,
    pub fragmentation: Fragmentation,
    pub time_to_live: u8,
    pub protocol: Protocol,
    pub checksum: u16,
    pub src_ipaddr: IpV4Addr,
    pub dst_ipaddr: IpV4Addr,
}

impl IpV4Header {
    const BYTE_LEN: usize = 20;

    /// Get length of byte representation
    fn len(&self) -> usize {
        Self::BYTE_LEN
    }

    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut header_bytes = [0_u8; Self::BYTE_LEN];
        self.write_bytes(&mut header_bytes);

        header_bytes
    }
}

#[derive(Clone, Debug)]
// #[byte_struct_be]
pub struct IpFrame<T> where T: ByteStruct {
    pub header: IpV4Header,
    /// Data such as a UDP header; should be some multiple of 4 bytes (32-bit words)
    pub data: T
}

/// Common choices of transport-layer protocols
///
/// and their IP header values.
///
/// There are many more protocols not listed here -
///
/// see https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Protocol {
    /// Transmission Control Protocol
    TCP = 0x06,
    /// User Datagram Protocol
    UDP = 0x11,
    /// Unimplemented
    Unimplemented,
}

impl ByteStructLen for Protocol {
    const BYTE_LEN: usize = 1;
}

impl ByteStruct for Protocol {
    fn read_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 1 {
            return Protocol::Unimplemented;
        } else {
            return match bytes[0] {
                x if x == (Protocol::TCP as u8) => Protocol::TCP,
                x if x == (Protocol::UDP as u8) => Protocol::UDP,
                _ => Protocol::Unimplemented,
            };
        }
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        if bytes.len() >= 1 {
            bytes[0] = *self as u8;
        } else {
            // Do nothing - no bytes to write
        }
    }
}

/// https://en.wikipedia.org/wiki/Differentiated_services
///
/// Priority 2 is low-latency class
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DSCP {
    Standard = 0,
    Realtime = 32 << 2,
    Unimplemented,
}

impl ByteStructLen for DSCP {
    const BYTE_LEN: usize = 1;
}

impl ByteStruct for DSCP {
    fn read_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 1 {
            return DSCP::Unimplemented;
        } else {
            return match bytes[0] {
                x if x == (DSCP::Standard as u8) => DSCP::Standard,
                x if x == (DSCP::Realtime as u8) => DSCP::Realtime,
                _ => DSCP::Unimplemented,
            };
        }
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        if bytes.len() >= 1 {
            bytes[0] = *self as u8;
        } else {
            // Do nothing - no bytes to write
        }
    }
}
