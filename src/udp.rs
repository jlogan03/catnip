//! Transport layer: User Datagram Protocol

use crate::ip::IpV4Header;
use byte_struct::*;

/// UDP datagram header structure like
///
/// value [0] source port [u16]
///
/// value [1] destination port [u16]
///
/// value [2] total length in bytes [u16], header + data
///
/// value [3] checksum [u16]
#[derive(ByteStruct, Clone, Copy, Debug)]
#[byte_struct_be]
pub struct UdpHeader {
    /// Source port
    src_port: u16,
    /// Destination port
    dst_port: u16,
    /// Total frame length including header and data
    length: u16,
    /// CRC checksum (rarely used for UDP, but must be present)
    checksum: u16,
}

impl UdpHeader {
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

/// IPV4 message frame for UDP protocol.
#[derive(Clone, Copy, Debug)]
pub struct UdpFrame<T>
where
    T: ByteStruct,
{
    /// UDP packet header
    pub header: UdpHeader,
    /// Data to transmit; bytes must be in some multiple of 4 (32 bit words)
    pub data: T,
}

impl<T> ByteStructLen for UdpFrame<T>
where
    T: ByteStruct,
{
    const BYTE_LEN: usize = IpV4Header::BYTE_LEN + UdpHeader::BYTE_LEN + T::BYTE_LEN;
}

impl<T> ByteStruct for UdpFrame<T>
where
    T: ByteStruct,
{
    fn read_bytes(bytes: &[u8]) -> Self {
        UdpFrame::<T> {
            header: UdpHeader::read_bytes(&bytes[0..UdpHeader::BYTE_LEN]),
            data: T::read_bytes(&bytes[UdpHeader::BYTE_LEN..Self::BYTE_LEN]),
        }
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        self.header.write_bytes(&mut bytes[0..UdpHeader::BYTE_LEN]);
        self.data
            .write_bytes(&mut bytes[UdpHeader::BYTE_LEN..Self::BYTE_LEN]);
    }
}
