//! Internet layer: Internet Protocol message header construction

use crate::IpV4Addr;

use byte_struct::*;

bitfields!(
    /// Fragmentation flags and offset info
    #[derive(Clone, Copy, Debug, Default)]
    pub Fragmentation: u16 {
        unused: 1,
        /// Flag for routers to drop packets instead of fragmenting
        pub do_not_fragment: 1,
        /// Flag that there are more fragments coming
        pub more_fragments: 2,
        /// Where we are in a set of fragments
        pub offset: 13
    }
);

bitfields!(
    /// Combined IP version and header length in a single byte
    #[derive(Clone, Copy, Debug)]
    pub VersionAndHeaderLength: u8 {
        /// IP protocol version (4=>4, 6=>6, ...)
        pub version: 4,
        /// IP header length may be more than 20 if there is an Options segment
        pub header_length: 4
    }
);

/// IPV4 header per IETF-RFC-791
///
/// https://en.wikipedia.org/wiki/IPv4
#[derive(ByteStruct, Clone, Copy, Debug)]
#[byte_struct_be]
pub struct IpV4Header {
    /// Combined version and header length info in a single byte
    pub version_and_length: VersionAndHeaderLength,
    /// Type of Service
    pub dscp: DSCP,
    /// Total length including header and data
    pub total_length: u16,
    /// Mostly-legacy id field
    pub identification: u16,
    /// Mostly-legacy packet fragmentation info
    pub fragmentation: Fragmentation,
    /// TTL counter
    pub time_to_live: u8,
    /// Transport-layer protocol
    pub protocol: Protocol,
    /// CRC checksum
    pub checksum: u16,
    /// Source IP address
    pub src_ipaddr: IpV4Addr,
    /// Destination IP address
    pub dst_ipaddr: IpV4Addr,
}

impl IpV4Header {
    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0_u8; Self::BYTE_LEN];
        self.write_bytes(&mut bytes);
        bytes
    }
}

/// IPV4 frame with header and data.
///
/// Data should be sized in a multiple of 4 bytes.
#[derive(Clone, Copy, Debug)]
pub struct IpV4Frame<T>
where
    T: ByteStruct,
{
    /// IP header
    pub header: IpV4Header,
    /// Data such as a UDP header; should be some multiple of 4 bytes (32-bit words)
    pub data: T,
}

impl<T> ByteStructLen for IpV4Frame<T>
where
    T: ByteStruct,
{
    const BYTE_LEN: usize = IpV4Header::BYTE_LEN + T::BYTE_LEN;
}

impl<T> ByteStruct for IpV4Frame<T>
where
    T: ByteStruct,
{
    fn read_bytes(bytes: &[u8]) -> Self {
        IpV4Frame::<T> {
            header: IpV4Header::read_bytes(&bytes[0..IpV4Header::BYTE_LEN]),
            data: T::read_bytes(&bytes[IpV4Header::BYTE_LEN..]),
        }
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        self.header.write_bytes(&mut bytes[0..IpV4Header::BYTE_LEN]);
        self.data.write_bytes(&mut bytes[IpV4Header::BYTE_LEN..]);
    }
}

impl<T> IpV4Frame<T>
where
    T: ByteStruct,
{
    fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0_u8; Self::BYTE_LEN];
        self.write_bytes(&mut bytes);
        bytes
    }
}

/// Common choices of transport-layer protocols and their IP header values.
///
/// There are many more protocols not listed here -
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

impl Protocol {
    fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        (*self as u8).to_be_bytes()
    }
}

/// Type-of-Service for networks with differentiated services.
/// 
/// See https://en.wikipedia.org/wiki/Differentiated_services.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DSCP {
    /// Standard is almost always fine
    Standard = 0,
    /// Realtime is rarely used
    Realtime = 32 << 2,
    /// Catch-all for the many other kinds or invalid bit patterns
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

impl DSCP {
    fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        (*self as u8).to_be_bytes()
    }
}