//! DHCP Client state machine, mostly per IEC-RFC-2131 
//! with an added state to handle self-addressing via "Inform" message

use crate::{IpV4Addr, MacAddr};

/// DHCP client states with shared data.
/// 
/// Enum structure provides typefixed size in memory 
pub enum DhcpState {
    ///
    Init,
    ///
    Selecting,
    ///
    Requesting,
    ///
    Bound,
    ///
    Renewing,
    ///
    Rebinding,
    ///
    InitReboot,
    ///
    Informing,
}

/// DHCP client state machine.
pub struct Dhcp {
    /// 
    state: DhcpState,
    ///
    transaction_id: u32,
    ///
    ipaddr: Option<IpV4Addr>,
    ///
    MacAddr: MacAddr,
    ///
    serveraddr: Option<IpV4Addr>,
    ///
    router: Option<IpV4Addr>,
    ///
    gateway: Option<IpV4Addr>,
    ///
    dns: Option<[Option<IpV4Addr>; 4]>,
    ///
    lease_time: u32,
    ///
    renewal_time: u32,
    ///
    rebinding_time: u32,
}

impl Dhcp {
    fn new_informing(ipaddr: IpV4Addr, MacAddr: MacAddr) -> Self  {
        Dhcp { 
            state: DhcpState::Informing,
            transaction_id: 0,
            ipaddr: Some(ipaddr),
            MacAddr: MacAddr,
            serveraddr: None,
            router: None,
            gateway: None,
            dns: None,
            lease_time: 0_u32,
            renewal_time: 0_u32,
            rebinding_time: 0_u32,
        }
    }

    fn step(&mut self) {
        match self.state {
            DhcpState::Init => {}
            DhcpState::Selecting => {}
            DhcpState::Requesting => {}
            _ => {}
        }
    }
}