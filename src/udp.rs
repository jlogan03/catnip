//! Transport layer: User Datagram Protocol

use crate::ip::{IpV4Frame, IpV4Header};
use crate::{calc_ip_checksum_finalize, calc_ip_checksum_incomplete, ByteArray};
use byte_struct::*;
pub use ufmt::derive::uDebug;

/// UDP datagram header structure for IPV4.
#[derive(ByteStruct, Clone, Copy, uDebug, Debug, PartialEq, Eq)]
#[byte_struct_be]
pub struct UdpHeader {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Total frame length including header and data, in bytes
    pub length: u16,
    /// IP-style checksum (optional for UDP, and usually supplied by hardware).
    /// Calculated from a "pseudo-header" that is not the actual header.
    pub checksum: u16,
}

impl UdpHeader {
    /// Get length of byte representation
    fn len(&self) -> usize {
        Self::BYTE_LEN
    }

    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0_u8; Self::BYTE_LEN];
        self.write_bytes(&mut bytes);

        bytes
    }
}

/// IPV4 message frame for UDP protocol.
#[derive(Clone, Copy, uDebug, Debug, PartialEq, Eq)]
pub struct UdpFrame<T: ByteStruct> {
    /// UDP packet header
    pub header: UdpHeader,
    /// Data to transmit; bytes must be in some multiple of 4 (32 bit words)
    pub data: T,
}

impl<T: ByteStruct> UdpFrame<T> {
    /// Pack into big-endian (network) byte array
    pub fn to_be_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0_u8; Self::BYTE_LEN];
        self.write_bytes(&mut bytes);

        bytes
    }
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

/// UDP checksum calculation with pseudo-header that includes some info from IP header
/// This is not the most efficient possible way to do this; in general, checksum calculation
/// should be processor-offloaded and should not be run in software except for troubleshooting.
pub fn calc_udp_checksum<T: ByteStruct>(ipframe: &IpV4Frame<UdpFrame<T>>) -> u16
where
    [(); UdpFrame::<T>::BYTE_LEN]:,
{
    // Build the weirdly-formatted part
    let udp_len = ipframe.data.header.length;
    let udp_length_bytes = udp_len.to_be_bytes();
    // let ip_pseudoheader: [u8; 4] = [0, ipframe.header.protocol.to_be_bytes()[0], udp_length_bytes[0], udp_length_bytes[1]];
    let ip_pseudoheader: [u8; 4] = [
        0,
        (ipframe.header.protocol as u8).to_be(),
        udp_length_bytes[0],
        udp_length_bytes[1],
    ];
    // Sum over components
    let mut sum: u32 = 0;
    sum += calc_ip_checksum_incomplete(&ipframe.header.src_ipaddr.0); // IP addresses
    sum += calc_ip_checksum_incomplete(&ipframe.header.dst_ipaddr.0);
    sum += calc_ip_checksum_incomplete(&ip_pseudoheader); // The weirdly formatted IP header part
    let index = UdpFrame::<T>::BYTE_LEN.min(udp_len as usize); // If we don't clip here, we can consume uninitialized junk
    sum += calc_ip_checksum_incomplete(&ipframe.data.to_be_bytes()[..index]);

    // Fold the accumulator into a u16
    let checksum: u16 = calc_ip_checksum_finalize(sum);

    checksum
}
