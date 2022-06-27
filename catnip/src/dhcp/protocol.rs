//! DHCP message construction and parsing

use crate::{IPV4Addr, MACAddr};
use core::mem::size_of;
use core::ptr::addr_of;

const COOKIE: u32 = 0x63_82_53_63;

use super::{DhcpError, DhcpErrorKind};

/// The fixed-length part of the DHCP payload. The options section can vary in length, but only the first portion is important.
///
/// C-ordered, packed, and aligned to 1 byte in order to support direct conversion to byte array.
#[derive(Clone, Copy)]
#[repr(C, packed(1))]
struct DhcpFixedPayload {
    /// Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
    op: DHCPOperation,
    /// Hardware type always 1 for ethernet
    htype: u8,
    /// Hardware address length always 6 bytes for standard mac address
    hlen: u8,
    /// Legacy field, always 0
    hops: u8,
    /// Transaction ID; assigned by router; must be kept the same through a transaction
    xid: u32,
    /// Seconds elapsed since client started transaction
    secs: u16,
    /// Broadcast flag; 1 for broadcast, 0 for unicast
    flags: u16,
    /// Client IP Address; only used for renewal, otherwise zero
    ciaddr: IPV4Addr,
    /// Your IP Address; usually the one you are requesting to lease
    yiaddr: IPV4Addr,
    /// Server IP Address; usually the closest router or network switch
    siaddr: IPV4Addr,
    /// Gateway IP Address
    giaddr: IPV4Addr,
    /// Client (your) hardware address. Actual field is 16 bytes; we only use 6 for standard MAC address.
    chaddr: MACAddr,
    /// Explicit padding of the remaining 10 bytes of chaddr
    pad0: [u8; 10],
    /// Padding of BOOTP legacy fields and server's irrelevant stringified name
    pad1: [u8; 196],
    /// "Magic cookie" identifying this as a DHCP message.
    /// Must always have the value of 0x63_82_53_63 (in dhcp::COOKIE)
    cookie: u32,
}

impl DhcpFixedPayload {
    pub const SIZE: usize = size_of::<DhcpFixedPayload>();

    pub fn new(
        op: DHCPOperation,
        ciaddr: IPV4Addr,
        yiaddr: IPV4Addr,
        siaddr: IPV4Addr,
        giaddr: IPV4Addr,
        chaddr: MACAddr,
    ) -> DhcpFixedPayload {
        DhcpFixedPayload {
            op: op,
            htype: 1_u8, // Always 1 for ethernet
            hlen: 6_u8,  // Always 6 byte standard mac address
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 1,
            ciaddr: ciaddr,
            yiaddr: yiaddr,
            siaddr: siaddr,
            giaddr: giaddr,
            chaddr: chaddr,
            pad0: [0_u8; 10],
            pad1: [0_u8; 196],
            cookie: COOKIE,
        }
    }

    /// Convert to an array of big-endian (network) bytes
    ///
    /// In general, this should not be necessary because this struct is safe to interpret as bytes directly in hardware.
    pub fn to_be_bytes(self) -> [u8; DhcpFixedPayload::SIZE] {
        let addr = (&self) as *const _ as usize;
        let bytes = unsafe { *(addr as *const _) };
        return bytes;
    }

    /// Attempt to parse from an array of big-endian (network) bytes.
    ///
    /// This can fail if the operation type is invalid; all other fields can be interpreted as any value.
    ///
    /// This copies the data out of the original location. Avoiding this requires
    pub fn from_be_bytes(
        bytes: [u8; DhcpFixedPayload::SIZE],
    ) -> Result<DhcpFixedPayload, DhcpError> {
        // Check if the first byte is a valid op code
        let op = match DHCPOperation::try_from(bytes[0]) {
            Ok(x) => x,
            Err(x) => return Err(x),
        };

        // Interpret this block of data directly as the struct
        let addr = addr_of!(bytes) as usize;
        let mut data: DhcpFixedPayload = unsafe { *(addr as *const _) };

        // Check if the cookie is correct
        // It is ok to read unaligned here because we are aligned to single bytes;
        // the address is always exact, but the compiler doesn't know that
        let cookie: u32 = unsafe { addr_of!(data.cookie).read_unaligned() };
        match cookie {
            x if x == COOKIE => {}
            _ => {
                return Err(DhcpError {
                    kind: DhcpErrorKind::InvalidCookieValue,
                    msg: "Parsed cookie value does not match DHCP magic cookie",
                })
            }
        }

        // Make sure we set the op type to the parsed value
        data.op = op;

        Ok(data)
    }
}

/// Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
///
/// Legacy operation type field from BOOTP.
///
/// Still has to match and change value depending on message type even though
/// there is only one valid combination of message type and operation.
#[derive(Clone, Copy)]
#[repr(u8)]
enum DHCPOperation {
    Request = 1,
    Reply = 2,
}

impl TryFrom<u8> for DHCPOperation {
    type Error = DhcpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => return Ok(DHCPOperation::Request),
            2 => return Ok(DHCPOperation::Reply),
            _ => {
                return Err(DhcpError {
                    kind: DhcpErrorKind::InvalidOperationType,
                    msg: "Invalid operation code for DHCP payload; should be etiher 1 or 2.",
                })
            }
        }
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum DHCPMessageKind {
    /// Client broadcast to locate available servers.
    Discover = 1,
    /// Server to client in response to DHCPDISCOVER with offer of configuration parameters.
    Offer = 2,
    /// Client message to servers either (a) requesting
    /// offered parameters from one server and implicitly
    /// declining offers from all others, (b) confirming
    /// correctness of previously allocated address after,
    /// e.g., system reboot, or (c) extending the lease on a
    /// particular network address.
    Request = 3,
    /// Client to server indicating network address is already in use.
    Decline = 4,
    /// Server to client with configuration parameters, including committed network address.
    Ack = 5, // Acknowledge
    /// Server to client indicating client's notion of network address is incorrect
    /// (e.g., client has moved to new subnet) or client's lease as expired
    Nak = 6, // Negative-acknowledge
    /// Client to server relinquishing network address and cancelling remaining lease.
    Release = 7,
    /// Client to server, asking only for local configuration parameters;
    /// client already has externally configured network address.
    Inform = 8,
    ForceRenew = 9,
    LeaseQuery = 10,
    LeaseUnassigned = 11,
    LeaseUnknown = 12,
    LeaseActive = 13,
    BulkLeaseQuery = 14,
    LeaseQueryDone = 15,
    ActiveLeaseQuery = 16,
    LeaseQueryStatus = 17,
    Tls = 18,
}

/// Option type codes for parsing options section.
/// Most of these are useless.
#[derive(Clone, Copy)]
#[repr(u8)]
enum DHCPOptionKind {
    Pad = 0,
    SubnetMask = 1,
    TimeOffset = 2,
    Router = 3,
    TimeServer = 4,
    NameServer = 5,
    DomainNameServers = 6,
    LogServer = 7,
    CookieServer = 8,
    LPRServer = 9,
    ImpressServer = 10,
    ResourceLocationServer = 11,
    HostName = 12,
    BootFileSize = 13,
    MeritDumpFileSize = 14,
    DomainName = 15,
    SwapServer = 16,
    RootPath = 17,
    ExtensionsPath = 18,
    IPForwardEnable = 19,
    SourceRoutingEnable = 20,
    PolicyFilter = 21,
    MaximumDatagramSize = 22,
    DefaultIpTtl = 23,
    PathMtuTimeout = 24,
    PathMtuPlateau = 25,
    InterfaceMtu = 26,
    AllSubnetsLocal = 27,
    BroadcastAddress = 28,
    PerformMaskDiscovery = 29,
    MaskSupplier = 30,
    PerformRouterDiscovery = 31,
    RouterSolicitationAddress = 32,
    StaticRoute = 33,
    TrailerEncapsulation = 34,
    ArpCacheTimeout = 35,
    EthernetEncapsulation = 36,
    TcpDefaultTtl = 37,
    TcpKeepAliveInterval = 38,
    TcpKeepAliveGarbage = 39,
    NetworkInfoServiceDomain = 40,
    NetworkInfoSevers = 41,
    NtpServers = 42,
    VendorInfo = 43,
    NetBiosNameServer = 44,
    NetBiosDistributionServer = 45,
    NetBiosNodeType = 46,
    NetBiosScope = 47,
    XWindowFontServer = 48,
    XWindowDisplayMgr = 49,
    
    // Extensions
    RequestedIpAddress = 50,
    IpAddressLeaseTime = 51,
    OptionOverload = 52,
    DhcpMessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    Message = 56,
    MaxDhcpMessageSize = 57,
    RenewalTime = 58,
    RebindingTime = 59,
    VendorClassId = 60,
    ClientId = 61,
    TftpServerName = 62,
    BootFileName = 63,

    // More application stuff

    NisPlusDomain = 64,
    NisPlusServers = 65,
    // Where are 66-67?
    MobileIpHomeAgent = 68,
    SmtpServer = 69,
    Pop3Server = 70,
    NntpServer = 71,
    DefaultWwwServer = 72,
    DefaultFingerServer = 73,
    DefaultIrcServer = 74,
    StreetTalkServer = 75,
    StreetTalkDirectoryServer = 76,

    // More extensions
    RelayAgentInfo = 82,
    NdsServers = 85,
    NdsContext = 86,
    TimeZonePosix = 100,
    TimeZoneTz = 101,
    DhcpCaptivePortal = 114,
    DomainSearch = 119,
    ClasslessStaticRoute = 121,
    ConfigFile = 209,
    PathPrefix = 210,
    RebootTime = 211,


    End = 255
}

#[cfg(test)]
mod test {
    use super::DhcpFixedPayload;
    use core::mem::{size_of, size_of_val};

    /// Make an example of the fixed portion of a DHCP payload
    fn dummy_payload() -> DhcpFixedPayload {
        use super::DHCPOperation;
        use crate::{IPV4Addr, MACAddr};
        let ip = IPV4Addr {
            value: [0, 0, 0, 0],
        };
        let mac = MACAddr {
            value: [1, 2, 3, 4, 5, 6],
        };

        let data = DhcpFixedPayload::new(DHCPOperation::Request, ip, ip, ip, ip, mac);

        data
    }

    /// Make sure actual data alignment is fully packed and safe to convert directly to byte array
    #[test]
    fn test_layout() {
        let data = dummy_payload();
        let size_expected = 1 + 1 + 1 + 1 + 4 + 2 + 2 + 4 + 4 + 4 + 4 + 6 + 10 + 196 + 4;
        let size_sized = size_of::<DhcpFixedPayload>();
        let size_actual = size_of_val(&data); // Check for padding

        assert_eq!(size_sized, size_expected);
        assert_eq!(size_actual, size_expected);
    }

    /// Make sure we can successfully convert to a byte array
    #[test]
    fn test_to_be_bytes() {
        let data = dummy_payload();
        let bytes: [u8; DhcpFixedPayload::SIZE] = data.to_be_bytes();
        let actual_size = size_of_val(&bytes);
        let expected_size = DhcpFixedPayload::SIZE;
        assert_eq!(actual_size, expected_size);
    }
}
