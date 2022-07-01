//! DHCP Client state machine, mostly per IEC-RFC-2131 
//! with an added state to handle self-addressing via "Inform" message

use crate::{IPV4Addr, MACAddr};
use core::marker::PhantomData;

// Nominal state flow

///
pub struct Init;
///
pub struct Selecting;
///
pub struct Requesting;
///
pub struct Bound;
///
pub struct Renewing;
///
pub struct Rebinding;

// Troubleshooting states

///
pub struct InitReboot;
///
pub struct Rebooting;

/// Self-assigned static addressing
/// Just broadcast an Inform message and wait for Ack or Nak
pub struct Informing;  // Can transition to Bound or Init

/// Empty trait for identifying structs that are valid states
pub trait State {}
impl State for Init {}
impl State for Selecting {}
impl State for Requesting {}
impl State for Bound {}
impl State for Renewing {}
impl State for Rebinding {}
impl State for InitReboot {}
impl State for Informing {}


/// DHCP client shared state.
pub struct DhcpData<T: State> {
    _marker: PhantomData<T>,
    transaction_id: u32,
    ipaddr: Option<IPV4Addr>,
    macaddr: MACAddr,
    serveraddr: Option<IPV4Addr>,
    router: Option<IPV4Addr>,
    gateway: Option<IPV4Addr>,
    dns: Option<[Option<IPV4Addr>; 4]>,
    lease_time: u32,
    renewal_time: u32,
    rebinding_time: u32,
}

/// DHCP client states with shared data.
/// 
/// Enum structure provides typefixed size in memory 
pub enum DhcpState {
    ///
    Init(DhcpData<Init>),
    ///
    Selecting(DhcpData<Selecting>),
    ///
    Requesting(DhcpData<Requesting>),
    ///
    Bound(DhcpData<Bound>),
    ///
    Renewing(DhcpData<Renewing>),
    ///
    Rebinding(DhcpData<Rebinding>),
    ///
    InitReboot(DhcpData<InitReboot>),
    ///
    Informing(DhcpData<Informing>),
}

/// DHCP client state machine.
pub struct Dhcp {
    /// 
    state: DhcpState
}

impl Dhcp {
    fn new_informing(ipaddr: IPV4Addr, macaddr: MACAddr) -> Self  {
        Dhcp { 
            state:  DhcpState::Init(
                DhcpData::<Init> {
                    _marker: PhantomData::<Init>,
                    transaction_id: 0,
                    ipaddr: Some(ipaddr),
                    macaddr: macaddr,
                    serveraddr: None,
                    router: None,
                    gateway: None,
                    dns: None,
                    lease_time: 0_u32,
                    renewal_time: 0_u32,
                    rebinding_time: 0_u32,
                }
            )
        }
    }

    fn step(&mut self) {
        match &self.state {
            DhcpState::Init(x) => {}
            DhcpState::Selecting(x) => {}
            DhcpState::Requesting(x) => {}
            _ => {}
        }
    }
}