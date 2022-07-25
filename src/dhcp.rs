//! Dynamic Host Configuration Protocol for IPV4.
//!
//! Client side of the call-response structure used by a router to assign IP addresses to devices on a local network.
//!
//! Partial implementation per IETF-RFC-2131; see https://datatracker.ietf.org/doc/html/rfc2131#page-22
//!
//! This is intended to provide just enough functionality to accept a statically-assigned address on
//! networks that require confirmation of static addresses with an indefinite lease duration via DHCP.
//! 
//! In this case, the server refers to the router or similar hardware orchestrating the address space,
//! while the client refers to the endpoints requesting addresses.

use crate::*;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

/// "Magic Cookie" placed at the end of the fixed portion of the DHCP payload
const DHCP_COOKIE: u32 = 0x63_82_53_63;
/// A full word containing 255 in the options segment indicates end of message
const DHCP_END: u32 = 0xff; 

use byte_struct::*;
use ufmt::derive::uDebug;

/// The fixed-length part of the DHCP payload.
/// The options section can vary in length, and is handled separately.
/// For "Inform" message kind, this is the entire message.
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
    /// Either end the message or add a gratuitous word of padding
    end_or_pad: u32
}

impl DhcpFixedPayload {
    pub fn new(
        end_of_message: bool,
        op: DhcpOperation,
        kind: DhcpMessageKind,
        transaction_id: u32,
        broadcast: bool,
        ciaddr: IpV4Addr,
        yiaddr: IpV4Addr,
        siaddr: IpV4Addr,
        chaddr: MacAddr,
    ) -> Self {
        DhcpFixedPayload {
            op: op,
            htype: 1_u8, // Always 1 for ethernet
            hlen: 6_u8,  // Always 6 byte standard mac address
            hops: 0,
            xid: transaction_id,
            secs: 0,
            flags: broadcast as u16,
            ciaddr: ciaddr,
            yiaddr: yiaddr,
            siaddr: siaddr,
            giaddr: IpV4Addr::ANY,
            chaddr: chaddr,
            _pad0: [0_u16; 5],
            _pad1: [0_u128; 12],
            cookie: DHCP_COOKIE,
            kind_option: DhcpMessageKindOption::new(kind),
            end_or_pad: DHCP_END * (end_of_message as u32)
        }
    }

    /// Build a DHCP INFORM message to broadcast to the network indicating that we are
    /// taking a pre-assigned IP address which may have already be assigned statically
    /// in the configuration of the router. This message should also be accompanied by
    /// an ARP "announce" message to broadcast the presence of the machine to others on
    /// the network that may or may not receive a forwarded copy of the DHCP INFORM.
    pub fn new_inform(ipaddr: IpV4Addr, macaddr: MacAddr, transaction_id: u32) -> Self {
        Self::new(
            true,
            DhcpOperation::Request,
            DhcpMessageKind::Inform,
            transaction_id,
            true,
            ipaddr,
            IpV4Addr::ANY,
            IpV4Addr::ANY,
            macaddr
        )
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
    length: u8,
    /// The actual message kind
    value: DhcpMessageKind,
    /// Pad to word boundary or indicate end of message
    _pad: u8
}

impl DhcpMessageKindOption {
    /// For convenience, since most values are predetermined
    pub fn new(kind: DhcpMessageKind) -> Self {
        DhcpMessageKindOption {
            kind: DhcpOptionKind::DhcpMessageType,
            length: 1,
            value: kind,
            _pad: 0
        }
    }
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
            true,
            DhcpOperation::Request,
            DhcpMessageKind::Inform,
            12345,
            true,
            IpV4Addr::new([1, 2, 3, 4]),
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
