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

const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;

enum DhcpErrorKind {
    InvalidOperationType,
    InvalidCookieValue,
}

struct DhcpError {
    kind: DhcpErrorKind,
    msg: &'static str,
}

pub mod protocol;
pub mod client;
