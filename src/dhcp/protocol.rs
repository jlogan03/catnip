//! DHCP message construction and parsing.
//! Partial implementation of IETF-RFC-2131,2132.

use super::*;
use crate::*;

use byte_struct::*;
use ufmt::derive::uDebug;

/// The fixed-length part of the DHCP payload.
/// The options section can vary in length, and is handled separately.
#[derive(ByteStruct, uDebug, Debug, Clone, Copy, PartialEq, Eq)]
#[byte_struct_be]
struct DhcpFixedPayload {
    /// Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
    op: DhcpOperation,
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
    /// Client IP Address
    ciaddr: IpV4Addr,
    /// Your IP Address
    yiaddr: IpV4Addr,
    /// Server IP Address
    siaddr: IpV4Addr,
    /// Gateway IP Address
    giaddr: IpV4Addr,
    /// Client (your) hardware address. Actual field is 16 bytes; we only use 6 for standard MAC address.
    chaddr: MacAddr,
    /// Explicit padding of the remaining 10 bytes of chaddr
    _pad0: [u16; 5],
    /// Padding of BOOTP legacy fields and server's irrelevant stringified name
    _pad1: [u128; 12],
    /// "Magic cookie" identifying this as a DHCP message.
    /// Must always have the value of 0x63_82_53_63 (in dhcp::COOKIE)
    cookie: u32,
    /// The message kind should always be included and should be the first options field
    kind_option: DhcpMessageKindOption,
}

impl DhcpFixedPayload {
    pub fn new(
        op: DhcpOperation,
        kind: DhcpMessageKind,
        ciaddr: IpV4Addr,
        yiaddr: IpV4Addr,
        siaddr: IpV4Addr,
        giaddr: IpV4Addr,
        chaddr: MacAddr,
    ) -> DhcpFixedPayload {
        DhcpFixedPayload {
            op: op,
            htype: 1_u8, // Always 1 for ethernet
            hlen: 6_u8,  // Always 6 byte standard mac address
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: ciaddr,
            yiaddr: yiaddr,
            siaddr: siaddr,
            giaddr: giaddr,
            chaddr: chaddr,
            _pad0: [0_u16; 5],
            _pad1: [0_u128; 12],
            cookie: DHCP_COOKIE,
            kind_option: DhcpMessageKindOption {
                kind: DhcpOptionKind::DhcpMessageType,
                length: 1,
                value: kind,
            },
        }
    }
}

/// The options field for message kind is technically part of the
/// variable-length portion, but is always required and always the first option
/// so it's really part of the fixed-length portion.
#[derive(ByteStruct, uDebug, Debug, Clone, Copy, PartialEq, Eq)]
#[byte_struct_be]
pub struct DhcpMessageKindOption {
    /// Type of option field
    pub kind: DhcpOptionKind,
    /// Length (how many bytes of data is the actual option?)
    pub length: u8,
    /// The actual message kind
    pub value: DhcpMessageKind,
}

enum_with_unknown! {
    /// Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
    /// Legacy operation type field from BOOTP.
    /// Still has to match and change value depending on message type even though
    /// there is only one valid combination of message type and operation.
    pub enum DhcpOperation(u8) {
        /// Anything coming from the client
        Request = 1,
        /// Anything coming from the server
        Reply = 2
    }
}

impl ByteStructLen for DhcpOperation {
    const BYTE_LEN: usize = 1;
}

impl ByteStruct for DhcpOperation {
    fn read_bytes(bytes: &[u8]) -> Self {
        Self::from(bytes[0])
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        bytes[0] = u8::from(*self);
    }
}

enum_with_unknown! {
    /// Contents of option field kind 53
    #[allow(missing_docs)]
    pub enum DhcpMessageKind(u8) {
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
        /// Client to server, asking only for local configuration parameters.
        /// Client already has externally configured network address.
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
        Tls = 18
    }
}

impl ByteStructLen for DhcpMessageKind {
    const BYTE_LEN: usize = 1;
}

impl ByteStruct for DhcpMessageKind {
    fn read_bytes(bytes: &[u8]) -> Self {
        Self::from(bytes[0])
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        bytes[0] = u8::from(*self);
    }
}

enum_with_unknown! {
    /// Option type codes for parsing options section.
    /// Most of these are useless.
    #[allow(missing_docs)]
    pub enum DhcpOptionKind(u8) {
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

        // Extensions (these are mostly the useful ones)
        RequestedIpAddress = 50,
        IpAddressLeaseTime = 51,
        OptionOverload = 52,
        /// This option's contents indicate how the rest of the message should be parsed
        DhcpMessageType = 53,
        ServerIdentifier = 54,
        ParameterRequestList = 55,
        Message = 56,
        MaxDhcpMessageSize = 57,
        /// Time in seconds until start of renewal (half of lease duration)
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

        End = 255,
    }
}

impl ByteStructLen for DhcpOptionKind {
    const BYTE_LEN: usize = 1;
}

impl ByteStruct for DhcpOptionKind {
    fn read_bytes(bytes: &[u8]) -> Self {
        Self::from(bytes[0])
    }

    fn write_bytes(&self, bytes: &mut [u8]) {
        bytes[0] = u8::from(*self);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    // use crate::*;

    #[test]
    fn test_serialization_loop() {
        let fixed_part = DhcpFixedPayload::new(
            DhcpOperation::Request,
            DhcpMessageKind::Inform,
            IpV4Addr::new([1, 2, 3, 4]),
            IpV4Addr::new([5, 6, 7, 8]),
            IpV4Addr::new([10, 20, 30, 40]),
            IpV4Addr::new([100, 200, 255, 40]),
            MacAddr::new([11, 21, 31, 41, 51, 123]),
        );

        let mut bytes = [0_u8; DhcpFixedPayload::BYTE_LEN];
        fixed_part.write_bytes(&mut bytes);

        let fixed_part_parsed = DhcpFixedPayload::read_bytes(&bytes);

        assert_eq!(fixed_part_parsed, fixed_part);
    }
}
