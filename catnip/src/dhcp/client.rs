//! DHCP Client state machine, mostly per IEC-RFC-2131 
//! with an added state to handle self-addressing via "Inform" message

use crate::{IPV4Addr, MACAddr};
use core::marker::PhantomData;

// Nominal state flow
struct Init;
struct Selecting;
struct Requesting;
struct Bound;
struct Renewing;
struct Rebinding;
// Troubleshooting states
struct InitReboot;
struct Rebooting;
// Self-assigned static addressing
// Just broadcast an Inform message and wait for Ack or Nak
struct Informing;  // Can transition to Bound or Init

/// Empty trait for identifying structs that are valid states
pub trait DhcpState {}
impl DhcpState for Init {}
impl DhcpState for Selecting {}
impl DhcpState for Requesting {}
impl DhcpState for Bound {}
impl DhcpState for Renewing {}
impl DhcpState for Rebinding {}
impl DhcpState for InitReboot {}
impl DhcpState for Informing {}


/// DHCP client shared state.
pub struct DhcpSharedState {
    // client_id: u16,
    transaction_id: u32,
    ipaddr: Option<IPV4Addr>,
    macaddr: Option<MACAddr>,
    serveraddr: Option<IPV4Addr>,
    router: Option<IPV4Addr>,
    gateway: Option<IPV4Addr>,
    dns: Option<[Option<IPV4Addr>; 4]>,
    lease_time: u32,
    renewal_time: u32,
    rebinding_time: u32,
}

/// DHCP client state machine
/// Stores up to 4 DNS server addresses.
pub struct DhcpClient<T: DhcpState> {
    _marker: PhantomData<T>,
    state: DhcpSharedState,
}

impl<T: DhcpState> DhcpClient<T> {
    fn from_state(state: DhcpSharedState) -> DhcpClient<T> {
        DhcpClient::<T> {
            _marker: PhantomData,
            state: state
        }
    }
}

impl Into<DhcpClient<Informing>> for DhcpClient<Selecting> {
    fn into(self) -> DhcpClient<Informing> {
        DhcpClient::<Informing>::from_state(self.state)
    }
}

impl Into<DhcpClient<Bound>> for DhcpClient<Informing> {
    fn into(self) -> DhcpClient<Bound> {
        DhcpClient::<Bound>::from_state(self.state)
    }
}